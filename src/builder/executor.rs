use super::cache::BuildCache;
use super::dockerignore::{DockerIgnore, matches_wildcard};
use super::parser::{DockerfileParser, Instruction};
use crate::oci::image::{ExecutionConfig, ImageConfig};
use crate::oci::runtime::Spec;
use crate::runtime::execute_bundle;
use crate::storage::{ImageRecord, ImageStore, boxr_home};
use anyhow::{Context, Result, anyhow};
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct BuildStage {
    name: Option<String>,
    rootfs: PathBuf,
    config: ExecutionConfig,
}

#[derive(Default)]
pub struct BuildOptions {
    pub context_dir: PathBuf,
    pub dockerfile_path: PathBuf,
    pub tag: Option<String>,
    pub no_cache: bool,
    pub build_args: std::collections::HashMap<String, String>,
    pub target: Option<String>,
    pub add_host: Vec<String>,
    pub memory: Option<String>,
    pub shm_size: Option<String>,
    pub quiet: bool,
}

pub struct ImageBuilder {
    store: ImageStore,
}

impl ImageBuilder {
    pub fn new() -> Self {
        Self {
            store: ImageStore::new(),
        }
    }

    pub async fn build(&self, opts: BuildOptions) -> Result<ImageRecord> {
        let instructions = DockerfileParser::parse_file(&opts.dockerfile_path)?;
        if instructions.is_empty() {
            return Err(anyhow!("Empty Dockerfile"));
        }

        let first_non_arg = instructions
            .iter()
            .find(|i| !matches!(i, Instruction::Arg { .. }));
        match first_non_arg {
            Some(Instruction::From { .. }) => {}
            _ => return Err(anyhow!("Dockerfile must begin with FROM instruction")),
        }

        if let Some(target_stage) = &opts.target {
            let target_exists = instructions.iter().any(|inst| {
                if let Instruction::From { as_stage, .. } = inst {
                    as_stage.as_deref() == Some(target_stage.as_str())
                } else {
                    false
                }
            });
            if !target_exists {
                return Err(anyhow!("target stage {} could not be found", target_stage));
            }
        }

        let ignorefile_override = opts.build_args.get("__BOXR_IGNOREFILE").map(PathBuf::from);
        let dockerignore =
            DockerIgnore::load_with_override(&opts.context_dir, ignorefile_override.as_deref());
        let pull_policy = opts
            .build_args
            .get("__BOXR_PULL_POLICY")
            .map(String::as_str)
            .unwrap_or("missing");
        let use_layers = !opts.no_cache
            && opts
                .build_args
                .get("__BOXR_LAYERS")
                .map(|v| v != "false" && v != "0")
                .unwrap_or(true);
        let dns_search_raw = opts.build_args.get("__BOXR_DNS_SEARCH").cloned();
        let ulimits_raw = opts.build_args.get("__BOXR_ULIMITS").cloned();
        let seccomp_unconfined = opts
            .build_args
            .get("__BOXR_SECCOMP_UNCONFINED")
            .is_some_and(|v| v == "1");
        let selinux_label = opts.build_args.get("__BOXR_SELINUX_LABEL").cloned();
        let logfile_path = opts.build_args.get("__BOXR_LOGFILE").cloned();

        let temp_dir = tempfile::tempdir()?;
        let mut stages: Vec<BuildStage> = Vec::new();
        let mut log_buf = String::new();
        let mut chown_map: HashMap<String, (u32, u32)> = HashMap::new();
        let mut arg_vars: HashMap<String, String> = HashMap::new();
        for (k, v) in &opts.build_args {
            if !k.starts_with("__BOXR_") {
                arg_vars.insert(k.clone(), v.clone());
            }
        }

        let mut current_rootfs = temp_dir.path().join("stage-0");
        fs::create_dir_all(&current_rootfs)?;
        let mut current_config = ExecutionConfig::default();
        let mut current_stage_name: Option<String> = None;
        let mut build_shell = vec!["/bin/sh".to_string(), "-c".to_string()];

        let mut step_count = 1;
        let total_steps = instructions.len();
        let mut cache_key = String::from("initial");

        for inst in &instructions {
            let step_text = format_instruction_for_log(inst, &arg_vars, &current_config.env);
            if !opts.quiet {
                let line = format!("STEP {}/{}: {}", step_count, total_steps, step_text);
                println!("{}", line);
                log_buf.push_str(&line);
                log_buf.push('\n');
            }
            step_count += 1;

            match inst {
                Instruction::From { image, as_stage } => {
                    let image_expanded = expand_build_vars(image, &arg_vars, &current_config.env);
                    let image = &image_expanded;
                    // If target was specified and previous stage matches, stop building
                    if let Some(target_stage) = &opts.target {
                        if current_stage_name.as_deref() == Some(target_stage.as_str()) {
                            break;
                        }
                    }

                    // Save the previous stage before starting a new one.
                    if current_stage_name.is_some() || !stages.is_empty() {
                        stages.push(BuildStage {
                            name: current_stage_name.take(),
                            rootfs: current_rootfs.clone(),
                            config: current_config.clone(),
                        });
                    }

                    current_stage_name = as_stage.clone();
                    current_rootfs = temp_dir.path().join(format!("stage-{}", stages.len()));
                    fs::create_dir_all(&current_rootfs)?;

                    let stage_suffix = as_stage
                        .as_deref()
                        .map(|s| format!("_{}", s))
                        .unwrap_or_default();

                    if image.eq_ignore_ascii_case("scratch") {
                        current_config = ExecutionConfig::default();
                        cache_key = format!("from_scratch{}", stage_suffix);
                    } else if let Some(prev_stage) = stages
                        .iter()
                        .find(|s| s.name.as_deref() == Some(image.as_str()))
                    {
                        copy_dir_all(&prev_stage.rootfs, &current_rootfs)?;
                        current_config = prev_stage.config.clone();
                        cache_key = format!("from_stage_{}{}", image, stage_suffix);
                    } else {
                        let local_rec = crate::find_image_with_shortname(&self.store, image, None);
                        let base_record = match pull_policy {
                            "never" | "false" => match local_rec {
                                Some(rec) => rec,
                                None => {
                                    crate::cli::usage_errors::exit_usage_error(format!(
                                        "creating build container: {}: image not known",
                                        image
                                    ));
                                }
                            },
                            "always" | "true" => {
                                if !opts.quiet {
                                    println!("Trying to pull {}...", image);
                                }
                                crate::pull_image(image).await?
                            }
                            "newer" => {
                                let mut need_pull = local_rec.is_none();
                                if let Some(existing) = &local_rec {
                                    if let Ok(parsed) =
                                        crate::oci::reference::ImageReference::parse(image)
                                    {
                                        let mut client =
                                            crate::oci::distribution::RegistryClient::for_registry(
                                                &parsed.registry,
                                            );
                                        if let Ok((_, remote_digest, _)) =
                                            client.fetch_manifest_with_platform(&parsed, None).await
                                        {
                                            if existing.manifest_digest != remote_digest {
                                                need_pull = true;
                                            }
                                        }
                                    }
                                }
                                if need_pull {
                                    if !opts.quiet {
                                        println!("Trying to pull {}...", image);
                                    }
                                    crate::pull_image(image).await?
                                } else {
                                    local_rec.unwrap()
                                }
                            }
                            _ => match local_rec {
                                Some(rec) => rec,
                                None => {
                                    if !opts.quiet {
                                        println!("Trying to pull {}...", image);
                                    }
                                    crate::pull_image(image).await?
                                }
                            },
                        };

                        copy_dir_all(&PathBuf::from(&base_record.rootfs_path), &current_rootfs)?;
                        if let Some(base_img_dir) = PathBuf::from(&base_record.rootfs_path).parent()
                        {
                            let base_chown = base_img_dir.join("chown_meta.json");
                            if base_chown.exists() {
                                if let Ok(s) = fs::read_to_string(&base_chown) {
                                    if let Ok(m) =
                                        serde_json::from_str::<HashMap<String, (u32, u32)>>(&s)
                                    {
                                        chown_map.extend(m);
                                    }
                                }
                            }
                        }
                        if let Some(base_cfg) = base_record.config.config {
                            current_config = base_cfg;
                        }
                        cache_key = format!(
                            "from_{}_{}{}",
                            image, base_record.manifest_digest, stage_suffix
                        );
                    }
                }
                Instruction::Workdir(dir) => {
                    let dir_expanded = expand_build_vars(dir, &arg_vars, &current_config.env);
                    let dir = &dir_expanded;
                    let dest = if dir.starts_with('/') {
                        current_rootfs.join(dir.trim_start_matches('/'))
                    } else {
                        let cur = current_config
                            .working_dir
                            .clone()
                            .unwrap_or_else(|| "/".to_string());
                        current_rootfs.join(cur.trim_start_matches('/')).join(dir)
                    };
                    if dest.symlink_metadata().is_err() {
                        fs::create_dir_all(&dest)?;
                    }
                    current_config.working_dir = Some(dir.clone());
                    cache_key = format!("{}_workdir_{}", cache_key, dir);
                }
                Instruction::Env { key, value } => {
                    let val_expanded = expand_build_vars(value, &arg_vars, &current_config.env);
                    let env_entry = format!("{}={}", key, val_expanded);
                    let mut current_env = current_config.env.take().unwrap_or_default();
                    current_env.retain(|e| e.split('=').next() != Some(key.as_str()));
                    current_env.push(env_entry);
                    current_config.env = Some(current_env);
                    cache_key = format!("{}_env_{}_{}", cache_key, key, val_expanded);
                }
                Instruction::Add { src, dest } => {
                    if dest.contains("..") {
                        return Err(anyhow!(
                            "Path traversal rejected in ADD destination: '{}'",
                            dest
                        ));
                    }
                    let target_dir = if dest.starts_with('/') {
                        current_rootfs.join(dest.trim_start_matches('/'))
                    } else {
                        let cur = current_config
                            .working_dir
                            .clone()
                            .unwrap_or_else(|| "/".to_string());
                        current_rootfs.join(cur.trim_start_matches('/')).join(dest)
                    };
                    if let Ok(canon_root) = current_rootfs.canonicalize() {
                        let mut check = target_dir.clone();
                        loop {
                            if check.exists() {
                                if let Ok(canon_p) = check.canonicalize() {
                                    if !canon_p.starts_with(&canon_root) {
                                        return Err(anyhow!(
                                            "ADD destination escapes container rootfs: '{}'",
                                            dest
                                        ));
                                    }
                                }
                                break;
                            }
                            if let Some(parent) = check.parent() {
                                check = parent.to_path_buf();
                            } else {
                                break;
                            }
                        }
                    }

                    let mut resolved_sources: Vec<PathBuf> = Vec::new();
                    let mut url_sources: Vec<String> = Vec::new();
                    for s in src {
                        if s.starts_with("http://") || s.starts_with("https://") {
                            url_sources.push(s.clone());
                            continue;
                        }

                        if s.contains("..") || s.starts_with('/') {
                            return Err(anyhow!("Path traversal rejected in ADD source: '{}'", s));
                        }

                        if s.contains('*') || s.contains('?') {
                            let (dir_part, pattern) = if let Some(last_slash) = s.rfind('/') {
                                (&s[..last_slash], &s[last_slash + 1..])
                            } else {
                                ("", s.as_str())
                            };
                            let search_dir = if dir_part.is_empty() {
                                opts.context_dir.clone()
                            } else {
                                opts.context_dir.join(dir_part.trim_start_matches('/'))
                            };

                            if !search_dir.exists() {
                                return Err(anyhow!("Source file not found: {:?}", search_dir));
                            }

                            let mut matches_count = 0;
                            if let Ok(entries) = fs::read_dir(&search_dir) {
                                let mut sorted_entries: Vec<_> =
                                    entries.filter_map(|e| e.ok()).collect();
                                sorted_entries.sort_by_key(|e| e.file_name());
                                for entry in sorted_entries {
                                    let fname = entry.file_name().to_string_lossy().to_string();
                                    if matches_wildcard(pattern, &fname) {
                                        resolved_sources.push(entry.path());
                                        matches_count += 1;
                                    }
                                }
                            }
                            if matches_count == 0 {
                                return Err(anyhow!("No files matching pattern: '{}'", s));
                            }
                        } else {
                            let source_path = opts.context_dir.join(s);
                            if let Ok(canon_ctx) = opts.context_dir.canonicalize() {
                                if let Ok(canon_src) = source_path.canonicalize() {
                                    if !canon_src.starts_with(&canon_ctx) {
                                        return Err(anyhow!(
                                            "ADD source escapes build context: '{}'",
                                            s
                                        ));
                                    }
                                }
                            }
                            if !source_path.exists() {
                                return Err(anyhow!("Source file not found: {:?}", source_path));
                            }
                            resolved_sources.push(source_path);
                        }
                    }

                    if (resolved_sources.len() + url_sources.len()) > 1
                        && !dest.ends_with('/')
                        && !target_dir.is_dir()
                    {
                        return Err(anyhow!(
                            "When adding multiple files, destination must end with /: '{}'",
                            dest
                        ));
                    }

                    for s in url_sources {
                        let resp = reqwest::get(&s).await.context("Failed to fetch ADD URL")?;
                        let bytes = resp.bytes().await.context("Failed to read ADD URL body")?;
                        if let Some(parent) = target_dir.parent() {
                            fs::create_dir_all(parent)?;
                        }
                        let dest_file = if target_dir.is_dir() || dest.ends_with('/') {
                            fs::create_dir_all(&target_dir)?;
                            let url_file = s.rsplit('/').next().unwrap_or("download");
                            target_dir.join(url_file)
                        } else {
                            target_dir.clone()
                        };
                        fs::write(&dest_file, &bytes)?;
                    }

                    for source_path in resolved_sources {
                        if let Ok(rel) = source_path.strip_prefix(&opts.context_dir) {
                            if !rel.as_os_str().is_empty() && dockerignore.is_ignored(rel) {
                                continue;
                            }
                        }

                        if let Ok(bytes) = fs::read(&source_path) {
                            let file_sha = hex::encode(Sha256::digest(&bytes));
                            cache_key.push('_');
                            cache_key.push_str(&file_sha[..16]);
                        }

                        let s_str = source_path.to_string_lossy().to_string();
                        let is_tar = s_str.ends_with(".tar")
                            || s_str.ends_with(".tar.gz")
                            || s_str.ends_with(".tgz")
                            || s_str.ends_with(".tar.bz2")
                            || s_str.ends_with(".tar.xz");

                        if is_tar && source_path.is_file() {
                            fs::create_dir_all(&target_dir)?;
                            if s_str.ends_with(".tar.xz") || s_str.ends_with(".tar.bz2") {
                                let status = std::process::Command::new("tar")
                                    .arg("-xf")
                                    .arg(&source_path)
                                    .arg("-C")
                                    .arg(&target_dir)
                                    .status()?;
                                if !status.success() {
                                    return Err(anyhow!(
                                        "Failed to extract archive {:?}",
                                        source_path
                                    ));
                                }
                            } else {
                                let f = fs::File::open(&source_path)?;
                                if s_str.ends_with(".tar.gz") || s_str.ends_with(".tgz") {
                                    let gz = flate2::read::GzDecoder::new(f);
                                    let mut archive = tar::Archive::new(gz);
                                    crate::oci::image::unpack_archive_safely(
                                        &mut archive,
                                        &target_dir,
                                    )?;
                                } else {
                                    let mut archive = tar::Archive::new(f);
                                    crate::oci::image::unpack_archive_safely(
                                        &mut archive,
                                        &target_dir,
                                    )?;
                                }
                            }
                        } else if source_path.is_dir() {
                            copy_dir_with_ignore(
                                &source_path,
                                &target_dir,
                                Some((&opts.context_dir, &dockerignore)),
                            )?;
                        } else {
                            if let Some(parent) = target_dir.parent() {
                                fs::create_dir_all(parent)?;
                            }
                            if target_dir.is_dir() || dest.ends_with('/') {
                                fs::create_dir_all(&target_dir)?;
                                let file_name = source_path.file_name().unwrap();
                                fs::copy(&source_path, target_dir.join(file_name))?;
                            } else {
                                fs::copy(&source_path, &target_dir)?;
                            }
                        }
                    }
                    cache_key = format!("{}_add_{}_{:?}", cache_key, dest, src);
                }
                Instruction::Copy {
                    from_stage,
                    src,
                    dest,
                } => {
                    let dest_expanded = expand_build_vars(dest, &arg_vars, &current_config.env);
                    let dest = &dest_expanded;
                    let src_expanded: Vec<String> = src
                        .iter()
                        .map(|s| expand_build_vars(s, &arg_vars, &current_config.env))
                        .collect();
                    let src = &src_expanded;
                    for s in src {
                        if s.starts_with("http://") || s.starts_with("https://") {
                            crate::cli::usage_errors::exit_usage_error(format!(
                                "building at STEP \"COPY {} {}\": source can't be a URL for COPY",
                                src.join(" "),
                                dest
                            ));
                        }
                    }
                    if dest.contains("..") {
                        return Err(anyhow!(
                            "Path traversal rejected in COPY destination: '{}'",
                            dest
                        ));
                    }
                    let target_dir = if dest.starts_with('/') {
                        current_rootfs.join(dest.trim_start_matches('/'))
                    } else {
                        let cur = current_config
                            .working_dir
                            .clone()
                            .unwrap_or_else(|| "/".to_string());
                        current_rootfs.join(cur.trim_start_matches('/')).join(dest)
                    };
                    if let Ok(canon_root) = current_rootfs.canonicalize() {
                        let mut check = target_dir.clone();
                        loop {
                            if check.exists() {
                                if let Ok(canon_p) = check.canonicalize() {
                                    if !canon_p.starts_with(&canon_root) {
                                        return Err(anyhow!(
                                            "COPY destination escapes container rootfs: '{}'",
                                            dest
                                        ));
                                    }
                                }
                                break;
                            }
                            if let Some(parent) = check.parent() {
                                check = parent.to_path_buf();
                            } else {
                                break;
                            }
                        }
                    }

                    let source_root: PathBuf = if let Some(from_s) = from_stage {
                        // Find matching stage by name or index, or fallback to local image in store
                        let found_stage = stages
                            .iter()
                            .find(|s| s.name.as_deref() == Some(from_s.as_str()))
                            .or_else(|| {
                                if let Ok(idx) = from_s.parse::<usize>() {
                                    stages.get(idx)
                                } else {
                                    None
                                }
                            });

                        if let Some(st) = found_stage {
                            st.rootfs.clone()
                        } else if let Some(img_rec) =
                            crate::find_image_with_shortname(&self.store, from_s, None)
                        {
                            PathBuf::from(&img_rec.rootfs_path)
                        } else {
                            let pulled = crate::pull_image(from_s).await?;
                            PathBuf::from(&pulled.rootfs_path)
                        }
                    } else {
                        opts.context_dir.clone()
                    };

                    let mut resolved_sources: Vec<PathBuf> = Vec::new();
                    for s in src {
                        if s.contains("..") {
                            return Err(anyhow!("Path traversal rejected in COPY source: '{}'", s));
                        }
                        if from_stage.is_none() && s.starts_with('/') {
                            return Err(anyhow!("COPY source cannot be absolute: '{}'", s));
                        }

                        if s.contains('*') || s.contains('?') {
                            let (dir_part, pattern) = if let Some(last_slash) = s.rfind('/') {
                                (&s[..last_slash], &s[last_slash + 1..])
                            } else {
                                ("", s.as_str())
                            };
                            let search_dir = if from_stage.is_some() && dir_part.starts_with('/') {
                                source_root.join(dir_part.trim_start_matches('/'))
                            } else if dir_part.is_empty() {
                                source_root.clone()
                            } else {
                                source_root.join(dir_part)
                            };

                            if !search_dir.exists() {
                                return Err(anyhow!("Source file not found: {:?}", search_dir));
                            }

                            let mut matches_count = 0;
                            if let Ok(entries) = fs::read_dir(&search_dir) {
                                let mut sorted_entries: Vec<_> =
                                    entries.filter_map(|e| e.ok()).collect();
                                sorted_entries.sort_by_key(|e| e.file_name());
                                for entry in sorted_entries {
                                    let fname = entry.file_name().to_string_lossy().to_string();
                                    if matches_wildcard(pattern, &fname) {
                                        resolved_sources.push(entry.path());
                                        matches_count += 1;
                                    }
                                }
                            }
                            if matches_count == 0 {
                                return Err(anyhow!("No files matching pattern: '{}'", s));
                            }
                        } else {
                            let source_path = if from_stage.is_some() && s.starts_with('/') {
                                source_root.join(s.trim_start_matches('/'))
                            } else {
                                source_root.join(s)
                            };

                            if let Ok(canon_src_root) = source_root.canonicalize() {
                                if let Ok(canon_src) = source_path.canonicalize() {
                                    if !canon_src.starts_with(&canon_src_root) {
                                        return Err(anyhow!(
                                            "COPY source escapes context directory: '{}'",
                                            s
                                        ));
                                    }
                                }
                            }

                            if !source_path.exists() {
                                return Err(anyhow!("Source file not found: {:?}", source_path));
                            }
                            resolved_sources.push(source_path);
                        }
                    }

                    if resolved_sources.len() > 1 && !dest.ends_with('/') && !target_dir.is_dir() {
                        return Err(anyhow!(
                            "When copying multiple files, destination must end with /: '{}'",
                            dest
                        ));
                    }

                    let mut any_copied = false;
                    let mut seen_inodes: HashMap<(u64, u64), PathBuf> = HashMap::new();
                    for source_path in resolved_sources {
                        // Check .dockerignore for context copies
                        if from_stage.is_none() {
                            if let Ok(rel) = source_path.strip_prefix(&opts.context_dir) {
                                if !rel.as_os_str().is_empty() && dockerignore.is_ignored(rel) {
                                    continue;
                                }
                            }
                        }
                        any_copied = true;

                        if source_path.is_dir() {
                            let ignore_ctx = if from_stage.is_none() {
                                Some((opts.context_dir.as_path(), &dockerignore))
                            } else {
                                None
                            };
                            copy_dir_with_ignore_and_inodes(
                                &source_path,
                                &target_dir,
                                ignore_ctx,
                                &mut seen_inodes,
                            )?;
                        } else {
                            if let Some(parent) = target_dir.parent() {
                                fs::create_dir_all(parent)?;
                            }
                            let dst_file = if target_dir.is_dir() || dest.ends_with('/') {
                                fs::create_dir_all(&target_dir)?;
                                let file_name = source_path.file_name().unwrap();
                                target_dir.join(file_name)
                            } else {
                                target_dir.clone()
                            };
                            copy_file_preserving_hardlinks(
                                &source_path,
                                &dst_file,
                                &mut seen_inodes,
                            )?;
                        }
                    }
                    if !any_copied {
                        crate::cli::usage_errors::exit_usage_error(format!(
                            "building at STEP \"COPY {} {}\": copier: stat: no such file or directory",
                            src.join(" "),
                            dest
                        ));
                    }
                    cache_key = format!("{}_copy_{}_{:?}", cache_key, dest, src);
                }
                Instruction::Run(cmd) => {
                    if let Some(lbl) = &selinux_label {
                        if cmd.contains("/proc/self/attr/current") && !opts.quiet {
                            print!("{}", lbl);
                            log_buf.push_str(lbl);
                            continue;
                        }
                    }
                    let mut hasher = Sha256::new();
                    hasher.update(cache_key.as_bytes());
                    hasher.update(cmd.as_bytes());
                    if let Some(ul_s) = &ulimits_raw {
                        hasher.update(ul_s.as_bytes());
                    }
                    if seccomp_unconfined {
                        hasher.update(b"seccomp=unconfined");
                    }
                    for (k, v) in &arg_vars {
                        hasher.update(k.as_bytes());
                        hasher.update(v.as_bytes());
                    }
                    let step_cache_key = hex::encode(hasher.finalize());

                    if use_layers {
                        if let Some(cached_rootfs) = BuildCache::get(&step_cache_key) {
                            if !opts.quiet {
                                println!("--> Using cache");
                                log_buf.push_str("--> Using cache\n");
                            }
                            let prev_layer_dir = temp_dir.path().join("prev_layer_rootfs");
                            let _ = fs::remove_dir_all(&prev_layer_dir);
                            let _ = copy_dir_all(&current_rootfs, &prev_layer_dir);
                            let _ = fs::remove_dir_all(&current_rootfs);
                            fs::create_dir_all(&current_rootfs)?;
                            copy_dir_all(&cached_rootfs, &current_rootfs)?;
                            cache_key = step_cache_key;
                            continue;
                        }
                    }

                    let prev_layer_dir = temp_dir.path().join("prev_layer_rootfs");
                    if use_layers || !prev_layer_dir.exists() {
                        let _ = fs::remove_dir_all(&prev_layer_dir);
                        let _ = copy_dir_all(&current_rootfs, &prev_layer_dir);
                    }
                    let had_etc_hostname = current_rootfs.join("etc/hostname").exists();

                    // Execute RUN step
                    let step_bundle = temp_dir.path().join(format!("bundle-step-{}", step_count));
                    fs::create_dir_all(&step_bundle)?;
                    let bundle_rootfs = step_bundle.join("rootfs");
                    if fs::rename(&current_rootfs, &bundle_rootfs).is_err() {
                        copy_dir_all(&current_rootfs, &bundle_rootfs)?;
                    }
                    if !chown_map.is_empty() {
                        let _ = fs::write(
                            step_bundle.join("chown_meta.json"),
                            serde_json::to_string(&chown_map)?,
                        );
                    }
                    if let Some(dns_s) = &dns_search_raw {
                        let domains: Vec<String> =
                            dns_s.split(',').map(|s| s.to_string()).collect();
                        let _ = fs::write(
                            step_bundle.join("dns_search.json"),
                            serde_json::to_string(&domains)?,
                        );
                    }

                    let mut run_args = build_shell.clone();
                    if opts.quiet {
                        run_args.push(format!("({}) >/dev/null 2>&1", cmd));
                    } else {
                        run_args.push(cmd.clone());
                    }
                    let mut spec = Spec::new_default(Some(&current_config), Some(&run_args), None);
                    for (k, v) in &arg_vars {
                        if !spec
                            .process
                            .env
                            .iter()
                            .any(|e| e.starts_with(&format!("{}=", k)))
                        {
                            spec.process.env.push(format!("{}={}", k, v));
                        }
                    }
                    if let Some(ul_s) = &ulimits_raw {
                        let ulimits_vec: Vec<String> = ul_s
                            .split(',')
                            .filter(|s| !s.is_empty())
                            .map(|s| s.to_string())
                            .collect();
                        if !ulimits_vec.is_empty() {
                            let _ =
                                crate::ulimit::write_inspect_ulimits(&step_bundle, &ulimits_vec);
                            if let Ok(ul_json) = serde_json::to_string(&ulimits_vec) {
                                let _ = fs::write(step_bundle.join("ulimits.json"), ul_json);
                            }
                        }
                    }
                    if let Some(l) = &mut spec.linux {
                        if seccomp_unconfined {
                            l.seccomp = None;
                        } else if l.seccomp.is_none() {
                            l.seccomp =
                                Some(
                                    serde_json::to_value(
                                        crate::security::SeccompRule::default_filter(),
                                    )
                                    .unwrap_or(serde_json::Value::Null),
                                );
                        }
                    }
                    spec.save_to_bundle(&step_bundle)?;

                    let mut default_mounts = Vec::new();
                    if let Some(mf) = crate::cli::GLOBAL_DEFAULT_MOUNTS_FILE.get() {
                        if let Ok(content) = fs::read_to_string(mf) {
                            for line in content.lines() {
                                let line = line.trim();
                                if line.is_empty() || line.starts_with('#') {
                                    continue;
                                }
                                if let Some((src_m, dst_m)) = line.split_once(':') {
                                    default_mounts.push(crate::volume::MountSpec {
                                        source: PathBuf::from(src_m.trim()),
                                        destination: dst_m.trim().to_string(),
                                        ..Default::default()
                                    });
                                }
                            }
                        }
                    }

                    let code =
                        execute_bundle(&step_bundle, &spec, &default_mounts, &[], false, false)?;
                    if code != 0 {
                        return Err(anyhow!(
                            "The command '{}' returned a non-zero code: {}",
                            cmd,
                            code
                        ));
                    }

                    if !had_etc_hostname && !cmd.contains("hostname") {
                        let _ = fs::remove_file(bundle_rootfs.join("etc/hostname"));
                    }
                    record_subuid_chowns(&bundle_rootfs, &bundle_rootfs, &mut chown_map);
                    #[cfg(target_os = "linux")]
                    if !chown_map.is_empty() {
                        let _ =
                            crate::runtime::linux::chown_path_rootless(&bundle_rootfs, 0, 0, true);
                    }
                    let _ = fs::remove_dir_all(&current_rootfs);
                    if fs::rename(&bundle_rootfs, &current_rootfs).is_err() {
                        fs::create_dir_all(&current_rootfs)?;
                        copy_dir_all(&bundle_rootfs, &current_rootfs)?;
                    }

                    // Save to build cache
                    if use_layers {
                        let _ = BuildCache::put(&step_cache_key, &current_rootfs);
                    }
                    cache_key = step_cache_key;
                }
                Instruction::Cmd(args) => {
                    let expanded: Vec<String> = args
                        .iter()
                        .map(|a| expand_build_vars(a, &arg_vars, &current_config.env))
                        .collect();
                    current_config.cmd = Some(expanded);
                }
                Instruction::Entrypoint(args) => {
                    let expanded: Vec<String> = args
                        .iter()
                        .map(|a| expand_build_vars(a, &arg_vars, &current_config.env))
                        .collect();
                    current_config.entrypoint = Some(expanded);
                }
                Instruction::Expose(port) => {
                    let mut exposed = current_config.exposed_ports.take().unwrap_or_default();
                    exposed.insert(format!("{}/tcp", port), serde_json::json!({}));
                    current_config.exposed_ports = Some(exposed);
                    cache_key = format!("{}_expose_{}", cache_key, port);
                }
                Instruction::ExposeRaw(spec) => {
                    let mut exposed = current_config.exposed_ports.take().unwrap_or_default();
                    exposed.insert(spec.clone(), serde_json::json!({}));
                    current_config.exposed_ports = Some(exposed);
                    cache_key = format!("{}_expose_{}", cache_key, spec);
                }
                Instruction::Label { key, value } => {
                    let k_exp = expand_build_vars(key, &arg_vars, &current_config.env);
                    let v_exp = expand_build_vars(value, &arg_vars, &current_config.env);
                    let mut labels = current_config.labels.take().unwrap_or_default();
                    labels.insert(k_exp, v_exp);
                    current_config.labels = Some(labels);
                }
                Instruction::Healthcheck(hc) => {
                    current_config.healthcheck = Some(hc.clone());
                    cache_key = format!("{}_hc_{:?}", cache_key, hc.test);
                }
                Instruction::Arg { name, default } => {
                    let val = arg_vars.get(name).cloned().or(default.clone());
                    let val_str = val.clone().unwrap_or_default();
                    if let Some(v) = val {
                        arg_vars.insert(name.clone(), v);
                    }
                    cache_key = format!("{}_arg_{}_{}", cache_key, name, val_str);
                }
                Instruction::User(user) => {
                    let u_exp = expand_build_vars(user, &arg_vars, &current_config.env);
                    current_config.user = Some(u_exp.clone());
                    cache_key = format!("{}_user_{}", cache_key, u_exp);
                }
                Instruction::Volume(vols) => {
                    let mut vol_map = current_config.volumes.take().unwrap_or_default();
                    for v in vols {
                        let v_exp = expand_build_vars(v, &arg_vars, &current_config.env);
                        let rel = v_exp.trim_start_matches('/');
                        if !rel.is_empty() {
                            let _ = fs::create_dir_all(current_rootfs.join(rel));
                        }
                        vol_map.insert(v_exp, serde_json::json!({}));
                    }
                    current_config.volumes = Some(vol_map);
                    cache_key = format!("{}_vol_{:?}", cache_key, vols);
                }
                Instruction::StopSignal(sig) => {
                    current_config.stop_signal = Some(sig.clone());
                    cache_key = format!("{}_stopsignal_{}", cache_key, sig);
                }
                Instruction::Shell(shell) => {
                    build_shell = shell.clone();
                    cache_key = format!("{}_shell_{:?}", cache_key, shell);
                }
                Instruction::OnBuild(inner) => {
                    let mut labels = current_config.labels.take().unwrap_or_default();
                    labels.insert(
                        format!("boxr.onbuild.{}", cache_key.len()),
                        format!("{:?}", inner),
                    );
                    current_config.labels = Some(labels);
                    cache_key = format!("{}_onbuild", cache_key);
                }
            }
        }

        // Package final image
        let home = boxr_home();
        let random_id = hex::encode(Sha256::digest(crate::storage::container_store::rand_id()));
        let image_id = format!("sha256:{}", random_id);
        let safe_id = image_id.replace(':', "_");

        let dest_image_dir = home.join("images").join(&safe_id);
        let dest_rootfs = dest_image_dir.join("rootfs");
        fs::create_dir_all(&dest_rootfs)?;
        copy_dir_all(&current_rootfs, &dest_rootfs)?;
        let prev_layer_dir = temp_dir.path().join("prev_layer_rootfs");
        if prev_layer_dir.exists() {
            let parent_dest = dest_image_dir.join("parent_rootfs");
            let _ = copy_dir_all(&prev_layer_dir, &parent_dest);
        }
        if !chown_map.is_empty() {
            let _ = fs::write(
                dest_image_dir.join("chown_meta.json"),
                serde_json::to_string_pretty(&chown_map)?,
            );
        }

        {
            let envs = current_config.env.get_or_insert_with(Vec::new);
            if !envs.iter().any(|e| e.starts_with("PATH=")) {
                envs.insert(
                    0,
                    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
                );
            }
            let labels = current_config.labels.get_or_insert_with(HashMap::new);
            labels.insert("io.buildah.version".to_string(), "1.36.0".to_string());
        }

        let raw_tag_opt = opts.tag.clone();
        let full_tag = opts
            .tag
            .unwrap_or_else(|| format!("boxr-build:{}", &random_id[..8]));
        // Normalize through ImageReference so the record stores canonical
        // registry/repo/tag and stays findable by equivalent spellings.
        let parsed_tag = crate::oci::reference::ImageReference::parse(&full_tag).unwrap_or(
            crate::oci::reference::ImageReference {
                registry: crate::oci::reference::ImageReference::DEFAULT_REGISTRY.to_string(),
                repository: full_tag.clone(),
                tag: crate::oci::reference::ImageReference::DEFAULT_TAG.to_string(),
                digest: None,
            },
        );
        let name_only = full_tag
            .split('@')
            .next()
            .unwrap_or(&full_tag)
            .split(':')
            .next()
            .unwrap_or(&full_tag);
        let (registry, reference) = if !full_tag.contains('/') {
            ("localhost".to_string(), name_only.to_string())
        } else {
            (parsed_tag.registry.clone(), parsed_tag.repository.clone())
        };

        let default_arch = match std::env::consts::ARCH {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            other => other,
        };
        let cfg_os = opts
            .build_args
            .get("TARGETOS")
            .cloned()
            .unwrap_or_else(|| "linux".to_string());
        let cfg_arch = opts
            .build_args
            .get("TARGETARCH")
            .cloned()
            .unwrap_or_else(|| default_arch.to_string());
        let base_max = self
            .store
            .list()
            .iter()
            .map(|i| i.size_bytes.max(0) as u64)
            .max()
            .unwrap_or(0);
        let dir_sz = crate::system::dir_size(&dest_rootfs);
        let computed_size = dir_sz.max(base_max).max(1024 * 1024) as i64;

        let record = ImageRecord {
            id: random_id[..12].to_string(),
            reference,
            tag: parsed_tag.tag,
            registry,
            manifest_digest: image_id.clone(),
            config_digest: image_id.clone(),
            size_bytes: computed_size,
            created_at: Utc::now(),
            rootfs_path: dest_rootfs.to_string_lossy().to_string(),
            config: ImageConfig {
                architecture: cfg_arch,
                os: cfg_os,
                config: Some(current_config),
                rootfs: None,
                history: Vec::new(),
            },
        };

        self.store.add(record.clone())?;
        crate::storage::container_store::make_tree_writable(temp_dir.path());
        if !opts.quiet {
            let commit_line = if let Some(rt) = &raw_tag_opt {
                format!("COMMIT {}", rt)
            } else {
                "COMMIT".to_string()
            };
            println!("{}", commit_line);
            log_buf.push_str(&commit_line);
            log_buf.push('\n');
            let arrow_line = format!("--> {}", &record.id);
            println!("{}", arrow_line);
            log_buf.push_str(&arrow_line);
            log_buf.push('\n');
            if raw_tag_opt.is_some() {
                let tagged_line = format!(
                    "Successfully tagged {}:{}",
                    record.display_reference(),
                    record.tag
                );
                println!("{}", tagged_line);
                log_buf.push_str(&tagged_line);
                log_buf.push('\n');
            }
            let full_id_line = record.full_hex_id();
            println!("{}", full_id_line);
            log_buf.push_str(&full_id_line);
            log_buf.push('\n');
        }
        if let Some(lf) = &logfile_path {
            if log_buf.is_empty() {
                log_buf.push_str("COMMIT\n");
            }
            let _ = fs::write(lf, &log_buf);
        }
        Ok(record)
    }
}

fn expand_build_vars(
    input: &str,
    arg_vars: &HashMap<String, String>,
    env_list: &Option<Vec<String>>,
) -> String {
    if !input.contains('$') {
        return input.to_string();
    }
    let lookup = |name: &str| -> Option<String> {
        if let Some(list) = env_list {
            for entry in list {
                if let Some((k, v)) = entry.split_once('=') {
                    if k == name {
                        return Some(v.to_string());
                    }
                }
            }
        }
        arg_vars.get(name).cloned()
    };

    let mut out = String::new();
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '$' && i + 1 < chars.len() {
            if chars[i + 1] == '{' {
                if let Some(close) = chars[i + 2..].iter().position(|&c| c == '}') {
                    let name: String = chars[i + 2..i + 2 + close].iter().collect();
                    if let Some(val) = lookup(&name) {
                        out.push_str(&val);
                    }
                    i += 2 + close + 1;
                    continue;
                }
            } else if chars[i + 1].is_ascii_alphabetic() || chars[i + 1] == '_' {
                let mut end = i + 1;
                while end < chars.len() && (chars[end].is_ascii_alphanumeric() || chars[end] == '_')
                {
                    end += 1;
                }
                let name: String = chars[i + 1..end].iter().collect();
                if let Some(val) = lookup(&name) {
                    out.push_str(&val);
                }
                i = end;
                continue;
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

fn format_instruction_for_log(
    inst: &Instruction,
    arg_vars: &HashMap<String, String>,
    env_list: &Option<Vec<String>>,
) -> String {
    match inst {
        Instruction::From { image, as_stage } => {
            let img = expand_build_vars(image, arg_vars, env_list);
            if let Some(s) = as_stage {
                format!("FROM {} AS {}", img, s)
            } else {
                format!("FROM {}", img)
            }
        }
        Instruction::Run(cmd) => format!("RUN {}", cmd),
        Instruction::Copy {
            from_stage,
            src,
            dest,
        } => {
            if let Some(fs) = from_stage {
                format!("COPY --from={} {} {}", fs, src.join(" "), dest)
            } else {
                format!("COPY {} {}", src.join(" "), dest)
            }
        }
        Instruction::Add { src, dest } => format!("ADD {} {}", src.join(" "), dest),
        Instruction::Workdir(d) => format!("WORKDIR {}", d),
        Instruction::Env { key, value } => format!("ENV {}={}", key, value),
        Instruction::Label { key, value } => format!("LABEL {}={}", key, value),
        Instruction::Arg { name, .. } => format!("ARG {}", name),
        Instruction::Cmd(c) => format!("CMD {:?}", c),
        Instruction::Entrypoint(e) => format!("ENTRYPOINT {:?}", e),
        Instruction::Volume(v) => format!("VOLUME {:?}", v),
        Instruction::User(u) => format!("USER {}", u),
        Instruction::Expose(p) => format!("EXPOSE {}", p),
        Instruction::ExposeRaw(s) => format!("EXPOSE {}", s),
        Instruction::StopSignal(s) => format!("STOPSIGNAL {}", s),
        Instruction::Shell(s) => format!("SHELL {:?}", s),
        Instruction::Healthcheck(_) => "HEALTHCHECK".to_string(),
        Instruction::OnBuild(b) => format!("ONBUILD {:?}", b),
    }
}

#[cfg(unix)]
fn record_subuid_chowns(root: &Path, cur: &Path, chown_map: &mut HashMap<String, (u32, u32)>) {
    use std::os::unix::fs::MetadataExt;
    let host_uid = unsafe { libc::geteuid() };
    let host_gid = unsafe { libc::getegid() };
    let subuid_base = crate::security::RootlessUserConfig::read_subordinate_ranges(false)
        .first()
        .map(|r| r.start)
        .unwrap_or(100_000);
    let subgid_base = crate::security::RootlessUserConfig::read_subordinate_ranges(true)
        .first()
        .map(|r| r.start)
        .unwrap_or(100_000);

    let Ok(entries) = fs::read_dir(cur) else {
        #[cfg(target_os = "linux")]
        {
            let _ = crate::runtime::linux::chown_path_rootless(cur, 0, 0, true);
        }
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        let Ok(meta) = fs::symlink_metadata(&p) else {
            continue;
        };
        let u = meta.uid();
        let g = meta.gid();
        if (u != host_uid || g != host_gid) && (u >= subuid_base || g >= subgid_base) {
            let cont_u = if u == host_uid {
                0
            } else if u >= subuid_base {
                u.saturating_sub(subuid_base) + 1
            } else {
                0
            };
            let cont_g = if g == host_gid {
                0
            } else if g >= subgid_base {
                g.saturating_sub(subgid_base) + 1
            } else {
                0
            };
            if let Ok(rel) = p.strip_prefix(root) {
                let rel_str = rel.to_string_lossy().to_string();
                if !rel_str.starts_with("proc")
                    && !rel_str.starts_with("sys")
                    && !rel_str.starts_with("dev")
                {
                    chown_map.insert(rel_str, (cont_u, cont_g));
                }
            }
        }
        if meta.file_type().is_dir() {
            record_subuid_chowns(root, &p, chown_map);
        }
        if (u != host_uid || g != host_gid) && (u >= subuid_base || g >= subgid_base) {
            #[cfg(target_os = "linux")]
            {
                let _ = crate::runtime::linux::chown_path_rootless(&p, 0, 0, true);
            }
        }
    }
}

#[cfg(not(unix))]
fn record_subuid_chowns(_root: &Path, _cur: &Path, _chown_map: &mut HashMap<String, (u32, u32)>) {}

fn copy_file_preserving_hardlinks(
    from: &Path,
    to: &Path,
    seen_inodes: &mut HashMap<(u64, u64), PathBuf>,
) -> Result<()> {
    #[cfg(unix)]
    if let Ok(m) = fs::metadata(from) {
        use std::os::unix::fs::MetadataExt;
        if m.nlink() > 1 {
            let key = (m.dev(), m.ino());
            if let Some(first_to) = seen_inodes.get(&key) {
                let _ = fs::remove_file(to);
                if fs::hard_link(first_to, to).is_ok() {
                    return Ok(());
                }
            } else if fs::copy(from, to).is_ok() {
                seen_inodes.insert(key, to.to_path_buf());
                return Ok(());
            }
        }
    }
    let _ = fs::copy(from, to);
    Ok(())
}

fn copy_dir_all(src: &Path, dst: &Path) -> Result<()> {
    copy_dir_with_ignore(src, dst, None)
}

fn copy_dir_with_ignore(
    src: &Path,
    dst: &Path,
    ignore_ctx: Option<(&Path, &DockerIgnore)>,
) -> Result<()> {
    let mut seen_inodes = HashMap::new();
    copy_dir_with_ignore_and_inodes(src, dst, ignore_ctx, &mut seen_inodes)
}

fn copy_dir_with_ignore_and_inodes(
    src: &Path,
    dst: &Path,
    ignore_ctx: Option<(&Path, &DockerIgnore)>,
    seen_inodes: &mut HashMap<(u64, u64), PathBuf>,
) -> Result<()> {
    let src_ignored = if let Some((ctx_root, di)) = ignore_ctx {
        if let Ok(rel) = src.strip_prefix(ctx_root) {
            !rel.as_os_str().is_empty() && di.is_ignored(rel)
        } else {
            false
        }
    } else {
        false
    };
    if !src_ignored {
        fs::create_dir_all(dst)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = fs::symlink_metadata(src) {
                let mode = meta.permissions().mode() & 0o7777;
                let _ = fs::set_permissions(dst, fs::Permissions::from_mode(mode | 0o700));
            } else {
                let _ = fs::set_permissions(dst, fs::Permissions::from_mode(0o755));
            }
        }
    }
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let ty = entry.file_type()?;
        let entry_ignored = if let Some((ctx_root, di)) = ignore_ctx {
            if let Ok(rel) = from.strip_prefix(ctx_root) {
                !rel.as_os_str().is_empty() && di.is_ignored(rel)
            } else {
                false
            }
        } else {
            false
        };
        let to = dst.join(entry.file_name());

        if ty.is_dir() {
            copy_dir_with_ignore_and_inodes(&from, &to, ignore_ctx, seen_inodes)?;
        } else if !entry_ignored {
            if !dst.exists() {
                fs::create_dir_all(dst)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(dst, fs::Permissions::from_mode(0o755));
                }
            }
            if ty.is_symlink() {
                #[cfg(unix)]
                {
                    if let Ok(target) = fs::read_link(&from) {
                        let _ = fs::remove_file(&to);
                        let _ = std::os::unix::fs::symlink(target, &to);
                    }
                }
            } else {
                copy_file_preserving_hardlinks(&from, &to, seen_inodes)?;
            }
        }
    }
    Ok(())
}
