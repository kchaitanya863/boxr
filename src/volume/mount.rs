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
            | "copyup"
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
            | "nocopy"
    )
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
    /// When set, mount as tmpfs inside the container instead of bind-mounting `_data`.
    #[serde(default)]
    pub tmpfs_mount_data: Option<String>,
    #[serde(default)]
    pub volume_name: Option<String>,
    pub is_volume: bool,
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
            current.retain(|p| p.exists());
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

    let mut mount_type = "bind".to_string();
    let mut source = String::new();
    let mut target = String::new();
    let mut ro = false;
    let mut noexec = false;
    let mut noswap = false;

    for kv in m_trim.split(',') {
        if let Some((k, v)) = kv.split_once('=') {
            match k.trim() {
                "type" => mount_type = v.trim().to_string(),
                "source" | "src" => source = v.trim().to_string(),
                "target" | "destination" | "dst" => target = v.trim().to_string(),
                "readonly" | "ro" => ro = v.trim() != "false",
                "rw" => ro = v.trim() == "false",
                _ => {}
            }
        } else {
            match kv.trim() {
                "readonly" | "ro" => ro = true,
                "rw" => ro = false,
                "noexec" => noexec = true,
                "noswap" => noswap = true,
                _ => {}
            }
        }
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
                    chown_u: false,
                    tmpfs_mount_data: None,
                    volume_name: None,
                    is_volume: false,
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
            let (src_path, vol_name) = if source.is_empty() {
                let vol = vol_store.create(None, None)?;
                (vol.mountpoint, Some(vol.name))
            } else if let Some(vol) = vol_store.find(&source) {
                (vol.mountpoint, Some(vol.name))
            } else {
                let vol = vol_store.create(Some(&source), None)?;
                (vol.mountpoint, Some(vol.name))
            };
            Ok(vec![MountSpec {
                source: PathBuf::from(src_path),
                destination: target,
                read_only: ro,
                noexec,
                chown_u: false,
                tmpfs_mount_data: None,
                volume_name: vol_name,
                is_volume: true,
            }])
        }
        "artifact" => {
            let store = crate::artifact::ArtifactStore::new();
            let Some(art) = store.find(&source) else {
                let display_src = if source.contains(':') {
                    source.clone()
                } else {
                    format!("{}:latest", source)
                };
                crate::cli::usage_errors::exit_usage_error(format!(
                    "{}: artifact does not exist",
                    display_src
                ));
            };
            Ok(vec![MountSpec {
                source: PathBuf::from(art.file_path),
                destination: target,
                read_only: true,
                noexec,
                chown_u: false,
                tmpfs_mount_data: None,
                volume_name: None,
                is_volume: false,
            }])
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
                chown_u: false,
                tmpfs_mount_data: Some("mode=755".to_string()),
                volume_name: None,
                is_volume: false,
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
                chown_u: false,
                tmpfs_mount_data: Some("mode=755".to_string()),
                volume_name: None,
                is_volume: false,
            }])
        }
        _ => {
            if target.is_empty() {
                crate::cli::usage_errors::exit_usage_error("must set volume destination");
            }
            let src_p = PathBuf::from(&source);
            if mount_type == "bind" && !src_p.exists() {
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
                chown_u: false,
                tmpfs_mount_data: None,
                volume_name: None,
                is_volume: false,
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
                                                crate::cli::usage_errors::exit_usage_error(format!(
                                                    "parsing containers.conf mounts: {}",
                                                    e
                                                ));
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
