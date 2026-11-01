use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

fn is_volume_mount_option_token(token: &str) -> bool {
    matches!(
        token,
        "ro" | "rw"
            | "z"
            | "Z"
            | "O"
            | "U"
            | "idmap"
            | "copy"
            | "copyup"
            | "nocopy"
            | "nocreate"
            | "cached"
            | "delegated"
            | "consistent"
            | "noexec"
            | "exec"
            | "nosuid"
            | "suid"
            | "nodev"
            | "dev"
            | "private"
            | "rprivate"
            | "shared"
            | "rshared"
            | "slave"
            | "rslave"
            | "unbindable"
            | "runbindable"
    ) || token.starts_with("idmap=")
        || token.starts_with("upperdir=")
        || token.starts_with("workdir=")
}

#[derive(Debug, Clone, Default)]
pub struct VolumeExtraOptions {
    pub idmap: bool,
    pub nocopy: bool,
    pub nocreate: bool,
    pub overlay: bool,
    pub overlay_upperdir: Option<String>,
    pub overlay_workdir: Option<String>,
    pub propagation: Option<String>,
}

pub fn parse_volume_extra_options(rest: &str) -> VolumeExtraOptions {
    let mut out = VolumeExtraOptions::default();
    let Some((path, opts_str)) = rest.split_once(':') else {
        return out;
    };
    let first_opt = opts_str.split(',').next().unwrap_or("").trim();
    if path.is_empty() || !path.starts_with('/') || !is_volume_mount_option_token(first_opt) {
        return out;
    }
    for part in opts_str.split(',') {
        let p = part.trim();
        match p {
            "idmap" => out.idmap = true,
            "nocopy" => out.nocopy = true,
            "nocreate" => out.nocreate = true,
            "O" => out.overlay = true,
            "shared" | "rshared" | "slave" | "rslave" | "private" | "rprivate" | "unbindable"
            | "runbindable" => out.propagation = Some(p.to_string()),
            _ if p.starts_with("idmap=") => out.idmap = true,
            _ if p.starts_with("upperdir=") => {
                out.overlay_upperdir = p.strip_prefix("upperdir=").map(|s| s.to_string());
            }
            _ if p.starts_with("workdir=") => {
                out.overlay_workdir = p.strip_prefix("workdir=").map(|s| s.to_string());
            }
            _ => {}
        }
    }
    out
}

/// Destination path and mount flags from `dest:z,ro` / `dest:noexec` / `dest:U` style volume suffixes.
pub fn parse_volume_dest_and_options(rest: &str) -> (String, bool, bool, bool) {
    let parts: Vec<&str> = rest.split(',').map(|p| p.trim()).collect();
    let mut read_only = parts.iter().any(|p| *p == "ro");
    let mut noexec = parts.iter().any(|p| *p == "noexec");
    let mut chown_u = parts.iter().any(|p| *p == "U");
    let head = parts.first().map(|s| *s).unwrap_or(rest).trim();
    let dest = if let Some((path, opt)) = head.rsplit_once(':') {
        let opt = opt.trim();
        if !path.is_empty() && path.starts_with('/') && is_volume_mount_option_token(opt) {
            read_only = read_only || opt == "ro";
            noexec = noexec || opt == "noexec";
            chown_u = chown_u || opt == "U";
            path.trim().to_string()
        } else {
            head.to_string()
        }
    } else {
        head.to_string()
    };
    (dest, read_only, noexec, chown_u)
}

pub fn tmpfs_mount_data_from_volume_options(options: &HashMap<String, String>) -> Option<String> {
    if options.get("type").map(|t| t.as_str()) != Some("tmpfs") {
        return None;
    }
    let mut parts: Vec<String> = Vec::new();
    if let Some(o) = options.get("o") {
        for piece in o.split(',') {
            let piece = piece.trim();
            if piece.is_empty() {
                continue;
            }
            if matches!(
                piece,
                "nodev"
                    | "dev"
                    | "nosuid"
                    | "suid"
                    | "noexec"
                    | "exec"
                    | "ro"
                    | "rw"
                    | "relatime"
                    | "noatime"
                    | "strictatime"
            ) {
                continue;
            }
            if piece.starts_with("size=") {
                let size = piece.trim_start_matches("size=");
                if size.ends_with('M') || size.ends_with('m') {
                    if let Ok(n) = size[..size.len() - 1].parse::<u64>() {
                        parts.push(format!("size={}k", n * 1024));
                        continue;
                    }
                }
            }
            parts.push(piece.to_string());
        }
    }
    if parts.is_empty() {
        Some(String::new())
    } else {
        Some(parts.join(","))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct MountSpec {
    pub source: PathBuf,
    pub destination: String,
    pub read_only: bool,
    #[serde(default)]
    pub noexec: bool,
    #[serde(default)]
    pub chown_u: bool,
    #[serde(default)]
    pub idmap: bool,
    #[serde(default)]
    pub nocopy: bool,
    #[serde(default)]
    pub notmpcopyup: bool,
    #[serde(default)]
    pub overlay: bool,
    #[serde(default)]
    pub overlay_upperdir: Option<String>,
    #[serde(default)]
    pub overlay_workdir: Option<String>,
    #[serde(default)]
    pub propagation: Option<String>,
    /// When set, mount as tmpfs inside the container instead of bind-mounting `_data`.
    #[serde(default)]
    pub tmpfs_mount_data: Option<String>,
    #[serde(default)]
    pub volume_name: Option<String>,
    #[serde(default)]
    pub subpath: Option<String>,
    #[serde(default)]
    pub no_dereference: bool,
    pub is_volume: bool,
}

fn split_mount_csv(m: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    for ch in m.chars() {
        if ch == '"' {
            in_quotes = !in_quotes;
        } else if ch == ',' && !in_quotes {
            tokens.push(cur.clone());
            cur.clear();
        } else {
            cur.push(ch);
        }
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }
    tokens
}

fn expand_path_glob(pattern: &str) -> Vec<PathBuf> {
    let parts: Vec<&str> = pattern.split('/').collect();
    let mut current = vec![PathBuf::from("/")];
    for part in parts {
        if part.is_empty() {
            continue;
        }
        if !part.contains('*') && !part.contains('?') {
            for p in &mut current {
                p.push(part);
            }
            current.retain(|p| p.exists() || p.symlink_metadata().is_ok());
        } else {
            let re_str = format!(
                "^{}$",
                regex::escape(part).replace(r"\*", ".*").replace(r"\?", ".")
            );
            if let Ok(re) = regex::Regex::new(&re_str) {
                let mut next = Vec::new();
                for dir in current {
                    if let Ok(entries) = std::fs::read_dir(dir) {
                        for entry in entries.flatten() {
                            let file_name = entry.file_name();
                            let name_str = file_name.to_string_lossy();
                            if re.is_match(&name_str) {
                                next.push(entry.path());
                            }
                        }
                    }
                }
                current = next;
            } else {
                return Vec::new();
            }
        }
    }
    current.sort();
    current
}

pub fn parse_mount_flag(
    m: &str,
    vol_store: &crate::volume::store::VolumeStore,
) -> Result<Vec<MountSpec>> {
    let m_trim = m.trim();
    if m_trim.is_empty() {
        return Ok(Vec::new());
    }

    let mut mount_type = "volume".to_string();
    let mut source = String::new();
    let mut target = String::new();
    let mut subpath: Option<String> = None;
    let mut propagation: Option<String> = None;
    let mut ro = false;
    let mut ro_count = 0usize;
    let mut noexec = false;
    let mut noswap = false;
    let mut chown_u = false;
    let mut nocopy = false;
    let mut nocreate = false;
    let mut no_dereference = false;
    let mut tmpcopyup_count = 0usize;
    let mut notmpcopyup = false;
    let mut propagation: Option<String> = None;
    let mut volume_opts: HashMap<String, String> = HashMap::new();
    let mut devpts_opts: Vec<String> = Vec::new();

    for kv in split_mount_csv(m_trim) {
        if let Some((k, v)) = kv.split_once('=') {
            match k.trim() {
                "type" => mount_type = v.trim().to_string(),
                "source" | "src" => source = v.trim().to_string(),
                "target" | "destination" | "dst" | "dest" => target = v.trim().to_string(),
                "subpath" | "volume-subpath" => subpath = Some(v.trim().to_string()),
                "uid" | "gid" | "mode" | "ptmxmode" | "newinstance" | "max" => {
                    devpts_opts.push(format!("{}={}", k.trim(), v.trim()));
                }
                "readonly" | "ro" => {
                    ro_count += 1;
                    ro = v.trim() != "false";
                }
                "rw" => {
                    ro_count += 1;
                    ro = v.trim() == "false";
                }
                "no-dereference" | "copy-symlink" => {
                    no_dereference = v.trim() != "false";
                }
                "U" | "chown" => match v.trim() {
                    "true" => chown_u = true,
                    "false" => chown_u = false,
                    other => {
                        crate::cli::usage_errors::exit_usage_error(format!(
                            "'U' or 'chown' must be set to true or false, instead received {:?}: must provide an argument for option",
                            other
                        ));
                    }
                },
                "bind-propagation" => {
                    let pv = v.trim();
                    if !matches!(
                        pv,
                        "shared"
                            | "rshared"
                            | "slave"
                            | "rslave"
                            | "private"
                            | "rprivate"
                            | "unbindable"
                            | "runbindable"
                    ) {
                        crate::cli::usage_errors::exit_usage_error(format!(
                            "invalid value \"bind-propagation={}\"",
                            pv
                        ));
                    }
                    propagation = Some(pv.to_string());
                }
                "volume-opt" => {
                    if let Some((ok, ov)) = v.trim().split_once('=') {
                        volume_opts.insert(ok.trim().to_string(), ov.trim().to_string());
                    } else {
                        volume_opts.insert(v.trim().to_string(), String::new());
                    }
                }
                _ => {}
            }
        } else {
            match kv.trim() {
                "readonly" | "ro" => {
                    ro_count += 1;
                    ro = true;
                }
                "rw" => {
                    ro_count += 1;
                    ro = false;
                }
                "noexec" => noexec = true,
                "noswap" => noswap = true,
                "U" | "chown" => chown_u = true,
                "nocopy" | "volume-nocopy" => nocopy = true,
                "nocreate" | "volume-nocreate" => nocreate = true,
                "no-dereference" | "copy-symlink" => no_dereference = true,
                "tmpcopyup" => {
                    tmpcopyup_count += 1;
                    notmpcopyup = false;
                }
                "notmpcopyup" => {
                    tmpcopyup_count += 1;
                    notmpcopyup = true;
                }
                "shared" | "rshared" | "slave" | "rslave" | "private" | "rprivate"
                | "unbindable" | "runbindable" => {
                    propagation = Some(kv.trim().to_string());
                }
                _ => {}
            }
        }
    }

    if ro_count > 1 {
        crate::cli::usage_errors::exit_usage_error(
            "cannot pass 'readonly', 'ro', or 'rw' mnt.Options more than once: must provide an argument for option",
        );
    }
    if tmpcopyup_count > 1 {
        crate::cli::usage_errors::exit_usage_error(
            "cannot pass 'tmpcopyup' and 'notmpcopyup' mnt.Options more than once: must provide an argument for option",
        );
    }
    if tmpcopyup_count > 0 && mount_type != "tmpfs" {
        let opt_name = if notmpcopyup {
            "notmpcopyup"
        } else {
            "tmpcopyup"
        };
        crate::cli::usage_errors::exit_usage_error(format!(
            "\"{}\" option not supported for \"{}\" mount types",
            opt_name, mount_type
        ));
    }

    if mount_type != "bind"
        && mount_type != "volume"
        && mount_type != "tmpfs"
        && mount_type != "ramfs"
        && mount_type != "glob"
        && mount_type != "image"
        && mount_type != "devpts"
        && mount_type != "artifact"
    {
        return Err(anyhow!("invalid filesystem type \"{}\"", mount_type));
    }

    if noswap && mount_type == "tmpfs" {
        #[cfg(target_os = "linux")]
        {
            if nix::unistd::geteuid().as_raw() != 0 {
                crate::cli::usage_errors::exit_usage_error(
                    "the 'noswap' option is only allowed with rootful tmpfs mounts: must provide an argument for option",
                );
            }
        }
    }

    match mount_type.as_str() {
        "glob" => {
            let mut res = Vec::new();
            let matched_paths = expand_path_glob(&source);
            for path in matched_paths {
                let file_name = path
                    .file_name()
                    .map(|f| f.to_string_lossy().to_string())
                    .unwrap_or_default();
                let dest = if target.is_empty() {
                    path.to_string_lossy().to_string()
                } else {
                    PathBuf::from(&target)
                        .join(&file_name)
                        .to_string_lossy()
                        .to_string()
                };
                res.push(MountSpec {
                    source: path,
                    destination: dest,
                    read_only: ro,
                    noexec,
                    chown_u,
                    propagation: propagation.clone(),
                    tmpfs_mount_data: None,
                    volume_name: None,
                    subpath: None,
                    no_dereference,
                    is_volume: false,
                    ..Default::default()
                });
            }
            if res.is_empty() {
                crate::cli::usage_errors::exit_usage_error(format!(
                    "no file paths matching glob \"{}\"",
                    source
                ));
            }
            Ok(res)
        }
        "volume" => {
            if target.is_empty() {
                crate::cli::usage_errors::exit_usage_error("must set volume destination");
            }
            let vol = if source.is_empty() {
                let opts = (!volume_opts.is_empty()).then_some(volume_opts);
                vol_store.create_with_options(None, "local", None, "local", opts)?
            } else if let Some(vol) = vol_store.find(&source) {
                vol
            } else if nocreate {
                crate::cli::usage_errors::exit_usage_error(format!(
                    "volume {} does not exist",
                    source
                ));
            } else {
                let opts = (!volume_opts.is_empty()).then_some(volume_opts);
                vol_store.create_with_options(Some(&source), "local", None, "local", opts)?
            };
            let tmpfs_mount_data = tmpfs_mount_data_from_volume_options(&vol.options);
            let mut final_src = PathBuf::from(&vol.mountpoint);
            if let Some(sp) = &subpath {
                final_src = final_src.join(sp.trim_start_matches('/'));
            }
            Ok(vec![MountSpec {
                source: final_src,
                destination: target,
                read_only: ro,
                noexec,
                chown_u: chown_u || source.is_empty(),
                nocopy,
                propagation,
                tmpfs_mount_data,
                volume_name: Some(vol.name),
                subpath,
                is_volume: true,
                ..Default::default()
            }])
        }
        "image" => {
            if target.is_empty() {
                crate::cli::usage_errors::exit_usage_error("must set volume destination");
            }
            let img_store = crate::storage::ImageStore::new();
            let Some(img_rec) = crate::find_image_with_shortname(&img_store, &source, None) else {
                crate::cli::usage_errors::exit_usage_error(format!("{}: image not known", source));
            };
            let mut final_src = PathBuf::from(&img_rec.rootfs_path);
            if let Some(sp) = &subpath {
                final_src = final_src.join(sp.trim_start_matches('/'));
            }
            Ok(vec![MountSpec {
                source: final_src,
                destination: target,
                read_only: ro,
                noexec,
                chown_u,
                propagation,
                tmpfs_mount_data: None,
                volume_name: None,
                subpath,
                is_volume: false,
                ..Default::default()
            }])
        }
        "artifact" => {
            let store = crate::artifact::ArtifactStore::new();
            store.mount_artifact_to_rootfs(m_trim, std::path::Path::new("/"), true)?;
            Ok(Vec::new())
        }
        "ramfs" => {
            if target.is_empty() {
                crate::cli::usage_errors::exit_usage_error("must set volume destination");
            }
            Ok(vec![MountSpec {
                source: PathBuf::from("ramfs"),
                destination: target,
                read_only: ro,
                noexec,
                chown_u,
                notmpcopyup,
                tmpfs_mount_data: Some("mode=755".to_string()),
                volume_name: None,
                subpath: None,
                propagation,
                is_volume: false,
                ..Default::default()
            }])
        }
        "tmpfs" => {
            if target.is_empty() {
                crate::cli::usage_errors::exit_usage_error("must set volume destination");
            }
            Ok(vec![MountSpec {
                source: PathBuf::from("tmpfs"),
                destination: target,
                read_only: ro,
                noexec,
                chown_u,
                notmpcopyup,
                tmpfs_mount_data: Some("mode=755".to_string()),
                volume_name: None,
                subpath: None,
                propagation,
                is_volume: false,
                ..Default::default()
            }])
        }
        "devpts" => {
            if target.is_empty() {
                crate::cli::usage_errors::exit_usage_error("must set volume destination");
            }
            if !devpts_opts.iter().any(|o| o.starts_with("newinstance")) {
                devpts_opts.insert(0, "newinstance".to_string());
            }
            if !devpts_opts.iter().any(|o| o.starts_with("ptmxmode=")) {
                devpts_opts.push("ptmxmode=0666".to_string());
            }
            if !devpts_opts.iter().any(|o| o.starts_with("mode=")) {
                devpts_opts.push("mode=0620".to_string());
            }
            Ok(vec![MountSpec {
                source: PathBuf::from("devpts"),
                destination: target,
                read_only: ro,
                noexec,
                chown_u,
                tmpfs_mount_data: Some(devpts_opts.join(",")),
                volume_name: None,
                subpath: None,
                is_volume: false,
                ..Default::default()
            }])
        }
        _ => {
            if target.is_empty() {
                crate::cli::usage_errors::exit_usage_error("must set volume destination");
            }
            let src_p = PathBuf::from(&source);
            if mount_type == "bind" && !src_p.exists() && src_p.symlink_metadata().is_err() {
                crate::cli::usage_errors::exit_usage_error(format!(
                    "statfs {}: no such file or directory",
                    source
                ));
            }
            Ok(vec![MountSpec {
                source: src_p,
                destination: target,
                read_only: ro,
                noexec,
                chown_u,
                propagation,
                tmpfs_mount_data: None,
                volume_name: None,
                subpath: None,
                no_dereference,
                is_volume: false,
                ..Default::default()
            }])
        }
    }
}

pub fn parse_containers_conf_mounts(
    vol_store: &crate::volume::store::VolumeStore,
) -> Result<Vec<MountSpec>> {
    let mut mounts = Vec::new();
    for var in ["CONTAINERS_CONF_OVERRIDE", "CONTAINERS_CONF"] {
        if let Ok(path) = std::env::var(var) {
            if let Ok(content) = std::fs::read_to_string(&path) {
                let mut in_containers = false;
                for line in content.lines() {
                    let trimmed = line.trim();
                    if trimmed.starts_with('[') {
                        in_containers = trimmed.eq_ignore_ascii_case("[containers]");
                        continue;
                    }
                    if in_containers && trimmed.starts_with("mounts") {
                        if let Some((_, rest)) = trimmed.split_once('=') {
                            if let Ok(re) = regex::Regex::new(r#"["']([^"']+)["']"#) {
                                for cap in re.captures_iter(rest) {
                                    let item = &cap[1];
                                    if !item.is_empty() {
                                        match parse_mount_flag(item, vol_store) {
                                            Ok(parsed) => mounts.extend(parsed),
                                            Err(e) => {
                                                crate::cli::usage_errors::exit_usage_error(
                                                    format!(
                                                        "parsing containers.conf mounts: {}",
                                                        e
                                                    ),
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(mounts)
}
