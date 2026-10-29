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

        let dockerignore = DockerIgnore::load_from_context(&opts.context_dir);
        if !opts.quiet {
            println!("Building image from {:?}", opts.dockerfile_path);
        }

        let temp_dir = tempfile::tempdir()?;
        let mut stages: Vec<BuildStage> = Vec::new();

        let mut current_rootfs = temp_dir.path().join("stage-0");
        fs::create_dir_all(&current_rootfs)?;
        let mut current_config = ExecutionConfig::default();
        let mut current_stage_name: Option<String> = None;
        let mut build_shell = vec!["/bin/sh".to_string(), "-c".to_string()];

        let mut step_count = 1;
        let total_steps = instructions.len();
        let mut cache_key = String::from("initial");

        for inst in &instructions {
            if !opts.quiet {
                println!("Step {}/{}: {:?}", step_count, total_steps, inst);
            }
            step_count += 1;

            match inst {
                Instruction::From { image, as_stage } => {
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

                    let base_record = match self.store.find(image) {
                        Some(rec) => rec,
                        None => {
                            println!("Pulling base image '{}'...", image);
                            crate::pull_image(image).await?
                        }
                    };

                    copy_dir_all(&PathBuf::from(&base_record.rootfs_path), &current_rootfs)?;
                    if let Some(base_cfg) = base_record.config.config {
                        current_config = base_cfg;
                    }
                    let stage_suffix = as_stage
                        .as_deref()
                        .map(|s| format!("_{}", s))
                        .unwrap_or_default();
                    cache_key = format!(
                        "from_{}_{}{}",
                        image, base_record.manifest_digest, stage_suffix
                    );
                }
                Instruction::Workdir(dir) => {
                    let dest = if dir.starts_with('/') {
                        current_rootfs.join(dir.trim_start_matches('/'))
                    } else {
                        let cur = current_config
                            .working_dir
                            .clone()
                            .unwrap_or_else(|| "/".to_string());
                        current_rootfs.join(cur.trim_start_matches('/')).join(dir)
                    };
                    fs::create_dir_all(&dest)?;
                    current_config.working_dir = Some(dir.clone());
                    cache_key = format!("{}_workdir_{}", cache_key, dir);
                }
                Instruction::Env { key, value } => {
                    let env_entry = format!("{}={}", key, value);
                    let mut current_env = current_config.env.take().unwrap_or_default();
                    current_env.retain(|e| e.split('=').next() != Some(key.as_str()));
                    current_env.push(env_entry);
                    current_config.env = Some(current_env);
                    cache_key = format!("{}_env_{}_{}", cache_key, key, value);
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
                        while let Some(parent) = check.parent() {
                            if parent.exists() {
                                if let Ok(canon_p) = parent.canonicalize() {
                                    if !canon_p.starts_with(&canon_root) {
                                        return Err(anyhow!(
                                            "ADD destination escapes container rootfs: '{}'",
                                            dest
                                        ));
                                    }
                                }
                                break;
                            }
                            check = parent.to_path_buf();
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
                            if dockerignore.is_ignored(rel) {
                                continue;
                            }
                        }

                        let s_str = source_path.to_string_lossy().to_string();
                        let is_tar = s_str.ends_with(".tar")
                            || s_str.ends_with(".tar.gz")
                            || s_str.ends_with(".tgz")
                            || s_str.ends_with(".tar.bz2")
                            || s_str.ends_with(".tar.xz");

                        if is_tar && source_path.is_file() {
                            fs::create_dir_all(&target_dir)?;
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
                        } else if source_path.is_dir() {
                            copy_dir_all(&source_path, &target_dir)?;
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
                        while let Some(parent) = check.parent() {
                            if parent.exists() {
                                if let Ok(canon_p) = parent.canonicalize() {
                                    if !canon_p.starts_with(&canon_root) {
                                        return Err(anyhow!(
                                            "COPY destination escapes container rootfs: '{}'",
                                            dest
                                        ));
                                    }
                                }
                                break;
                            }
                            check = parent.to_path_buf();
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
                        } else if let Some(img_rec) = self.store.find(from_s) {
                            PathBuf::from(&img_rec.rootfs_path)
                        } else {
                            return Err(anyhow!(
                                "Stage or image '{}' not found for COPY --from",
                                from_s
                            ));
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

                    for source_path in resolved_sources {
                        // Check .dockerignore for context copies
                        if from_stage.is_none() {
                            if let Ok(rel) = source_path.strip_prefix(&opts.context_dir) {
                                if dockerignore.is_ignored(rel) {
                                    continue;
                                }
                            }
                        }

                        if source_path.is_dir() {
                            copy_dir_all(&source_path, &target_dir)?;
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
                    cache_key = format!("{}_copy_{}_{:?}", cache_key, dest, src);
                }
                Instruction::Run(cmd) => {
                    let mut hasher = Sha256::new();
                    hasher.update(cache_key.as_bytes());
                    hasher.update(cmd.as_bytes());
                    let step_cache_key = hex::encode(hasher.finalize());

                    if !opts.no_cache {
                        if let Some(cached_rootfs) = BuildCache::get(&step_cache_key) {
                            println!(" ---> Using cache");
                            let _ = fs::remove_dir_all(&current_rootfs);
                            fs::create_dir_all(&current_rootfs)?;
                            copy_dir_all(&cached_rootfs, &current_rootfs)?;
                            cache_key = step_cache_key;
                            continue;
                        }
                    }

                    // Execute RUN step
                    let step_bundle = temp_dir.path().join(format!("bundle-step-{}", step_count));
                    fs::create_dir_all(&step_bundle)?;
                    let bundle_rootfs = step_bundle.join("rootfs");
                    copy_dir_all(&current_rootfs, &bundle_rootfs)?;

                    let mut run_args = build_shell.clone();
                    run_args.push(cmd.clone());
                    let spec = Spec::new_default(Some(&current_config), Some(&run_args), None);
                    spec.save_to_bundle(&step_bundle)?;

                    let code = execute_bundle(&step_bundle, &spec, &[], &[], false, false)?;
                    if code != 0 {
                        return Err(anyhow!(
                            "The command '{}' returned a non-zero code: {}",
                            cmd,
                            code
                        ));
                    }

                    let _ = fs::remove_dir_all(&current_rootfs);
                    fs::create_dir_all(&current_rootfs)?;
                    copy_dir_all(&bundle_rootfs, &current_rootfs)?;

                    // Save to build cache
                    let _ = BuildCache::put(&step_cache_key, &current_rootfs);
                    cache_key = step_cache_key;
                }
                Instruction::Cmd(args) => {
                    current_config.cmd = Some(args.clone());
                }
                Instruction::Entrypoint(args) => {
                    current_config.entrypoint = Some(args.clone());
                }
                Instruction::Expose(port) => {
                    let mut exposed = current_config.exposed_ports.take().unwrap_or_default();
                    exposed.insert(format!("{}/tcp", port), serde_json::json!({}));
                    current_config.exposed_ports = Some(exposed);
                    cache_key = format!("{}_expose_{}", cache_key, port);
                }
                Instruction::Label { key, value } => {
                    let mut labels = current_config.labels.take().unwrap_or_default();
                    labels.insert(key.clone(), value.clone());
                    current_config.labels = Some(labels);
                }
                Instruction::Healthcheck(hc) => {
                    current_config.healthcheck = Some(hc.clone());
                    cache_key = format!("{}_hc_{:?}", cache_key, hc.test);
                }
                Instruction::Arg { name, default } => {
                    let val = opts.build_args.get(name).cloned().or(default.clone());
                    let val_str = val.clone().unwrap_or_default();
                    if let Some(v) = val {
                        let env_entry = format!("{}={}", name, v);
                        if let Some(envs) = &mut current_config.env {
                            envs.retain(|e| !e.starts_with(&format!("{}=", name)));
                            envs.push(env_entry);
                        } else {
                            current_config.env = Some(vec![env_entry]);
                        }
                    }
                    cache_key = format!("{}_arg_{}_{}", cache_key, name, val_str);
                }
                Instruction::User(user) => {
                    current_config.user = Some(user.clone());
                    cache_key = format!("{}_user_{}", cache_key, user);
                }
                Instruction::Volume(vols) => {
                    let mut vol_map = HashMap::new();
                    for v in vols {
                        vol_map.insert(v.clone(), serde_json::json!({}));
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
        let random_id = hex::encode(crate::storage::container_store::rand_id());
        let image_id = format!("sha256:{}", random_id);
        let safe_id = image_id.replace(':', "_");

        let dest_image_dir = home.join("images").join(&safe_id);
        let dest_rootfs = dest_image_dir.join("rootfs");
        fs::create_dir_all(&dest_rootfs)?;
        copy_dir_all(&current_rootfs, &dest_rootfs)?;

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
        let (registry, reference) = if !name_only.contains('/') {
            ("localhost".to_string(), name_only.to_string())
        } else {
            (parsed_tag.registry.clone(), parsed_tag.repository.clone())
        };

        let record = ImageRecord {
            id: random_id[..12].to_string(),
            reference,
            tag: parsed_tag.tag,
            registry,
            manifest_digest: image_id.clone(),
            config_digest: image_id.clone(),
            size_bytes: 1024 * 1024,
            created_at: Utc::now(),
            rootfs_path: dest_rootfs.to_string_lossy().to_string(),
            config: ImageConfig {
                architecture: std::env::consts::ARCH.to_string(),
                os: "linux".to_string(),
                config: Some(current_config),
                rootfs: None,
                history: Vec::new(),
            },
        };

        self.store.add(record.clone())?;
        println!(
            "Successfully built image {} ({}:{})",
            &record.id, record.reference, record.tag
        );
        Ok(record)
    }
}

fn copy_dir_all(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let from = entry.path();
        let to = dst.join(entry.file_name());

        if ty.is_dir() {
            copy_dir_all(&from, &to)?;
        } else if ty.is_symlink() {
            #[cfg(unix)]
            {
                if let Ok(target) = fs::read_link(&from) {
                    let _ = std::os::unix::fs::symlink(target, &to);
                }
            }
        } else {
            let _ = fs::copy(&from, &to);
        }
    }
    Ok(())
}
