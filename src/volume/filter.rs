use super::mount::MountSpec;
use anyhow::{Result, anyhow};
use std::fs;
use std::path::PathBuf;

/// Podman-compatible volume name filter (`name=volume_1.+` uses regex).
pub(crate) fn volume_used_by_container(bundle_path: &str, volume_name: &str) -> bool {
    let bundle = PathBuf::from(bundle_path);
    let mounts_json = bundle.join("mounts.json");
    if mounts_json.exists() {
        if let Ok(content) = fs::read_to_string(&mounts_json) {
            if let Ok(mounts) = serde_json::from_str::<Vec<MountSpec>>(&content) {
                for m in mounts {
                    if !m.is_volume {
                        continue;
                    }
                    if m.volume_name.as_deref() == Some(volume_name) {
                        return true;
                    }
                    let src = m.source.to_string_lossy();
                    if src.contains(&format!("volumes/{}/_data", volume_name))
                        || src.contains(&format!("/volumes/{}/", volume_name))
                    {
                        return true;
                    }
                }
            }
        }
    }
    let config_file = bundle.join("config.json");
    if let Ok(content) = fs::read_to_string(&config_file) {
        if let Ok(spec) = serde_json::from_str::<crate::oci::runtime::Spec>(&content) {
            for m in spec.mounts {
                let m_src = m.source;
                if m_src.contains(&format!("volumes/{}/_data", volume_name))
                    || m_src.contains(&format!("volumes/{}", volume_name))
                    || m_src.ends_with(&format!("/{}", volume_name))
                    || m_src == volume_name
                {
                    return true;
                }
            }
        }
    }
    false
}

pub(crate) fn validate_volume_rename_name(name: &str) -> Result<()> {
    if name != name.trim() {
        anyhow::bail!("names must match [a-zA-Z0-9][a-zA-Z0-9_.-]*: invalid argument");
    }
    if name.contains('/') {
        anyhow::bail!("invalid argument");
    }
    let re = regex::Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]*$").expect("volume name regex");
    if !re.is_match(name) {
        anyhow::bail!("names must match [a-zA-Z0-9][a-zA-Z0-9_.-]*: invalid argument");
    }
    Ok(())
}

pub(crate) fn rewrite_volume_name_in_container(bundle_path: &str, old_name: &str, new_name: &str) {
    let bundle = PathBuf::from(bundle_path);
    let mounts_json = bundle.join("mounts.json");
    if mounts_json.exists() {
        if let Ok(content) = fs::read_to_string(&mounts_json) {
            if let Ok(mut mounts) = serde_json::from_str::<Vec<MountSpec>>(&content) {
                let mut changed = false;
                for m in &mut mounts {
                    let src = m.source.to_string_lossy().to_string();
                    if src.contains(&format!("volumes/{}/", old_name)) {
                        m.source = PathBuf::from(src.replace(
                            &format!("volumes/{}/", old_name),
                            &format!("volumes/{}/", new_name),
                        ));
                        changed = true;
                    }
                }
                if changed {
                    if let Ok(encoded) = serde_json::to_string(&mounts) {
                        let _ = fs::write(&mounts_json, encoded);
                    }
                }
            }
        }
    }
}

pub fn volume_name_filter_matches(name: &str, pattern: &str) -> bool {
    let pattern = pattern.trim();
    if pattern.is_empty() {
        return true;
    }
    if name == pattern {
        return true;
    }
    if pattern.chars().any(|c| ".+*?[](){}|^$\\".contains(c)) {
        if let Ok(re) = regex::Regex::new(pattern) {
            return re.is_match(name);
        }
    }
    name.contains(pattern)
}
