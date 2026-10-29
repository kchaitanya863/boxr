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
