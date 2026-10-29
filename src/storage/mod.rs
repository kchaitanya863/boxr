pub mod container_store;
pub mod external;
pub mod image_store;
pub mod index_lock;
pub mod overlay;
pub mod traits;

use anyhow::Result;
use std::fs;
use std::path::PathBuf;

pub use container_store::{ContainerRecord, ContainerStatus, ContainerStore};
pub use image_store::{ImageRecord, ImageStore};
pub use overlay::OverlayDriver;
pub use traits::{
    ContainerReader, ContainerStoreOps, ContainerWriter, ImageReader, ImageStoreOps, ImageWriter,
};

/// Get the base boxr directory (default: ~/.boxr)
pub fn boxr_home() -> PathBuf {
    if let Ok(custom) = std::env::var("BOXR_HOME") {
        return PathBuf::from(custom);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".boxr")
}

fn containers_conf_static_dir() -> Option<PathBuf> {
    for var in ["CONTAINERS_CONF_OVERRIDE", "CONTAINERS_CONF"] {
        if let Ok(path) = std::env::var(var) {
            if let Ok(content) = fs::read_to_string(&path) {
                for line in content.lines() {
                    let line = line.trim();
                    if line.starts_with('#') || line.is_empty() {
                        continue;
                    }
                    if let Some(rest) = line.strip_prefix("static_dir") {
                        let rest = rest.trim_start_matches('=').trim();
                        let value = rest.trim_matches('"').trim();
                        if !value.is_empty() {
                            return Some(PathBuf::from(value));
                        }
                    }
                }
            }
        }
    }
    None
}

/// Podman `[engine] static_dir` — alternate libpod DB root when `CONTAINERS_CONF*` is set.
pub fn container_state_home() -> PathBuf {
    containers_conf_static_dir().unwrap_or_else(boxr_home)
}

pub fn ensure_directories() -> Result<PathBuf> {
    let home = boxr_home();
    fs::create_dir_all(home.join("layers"))?;
    fs::create_dir_all(home.join("images"))?;
    fs::create_dir_all(home.join("containers"))?;
    let state = container_state_home();
    if state != home {
        fs::create_dir_all(state.join("containers"))?;
    }
    Ok(home)
}
