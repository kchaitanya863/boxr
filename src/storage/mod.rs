pub mod container_store;
pub mod db_config;
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

fn active_connection_meta() -> Option<serde_json::Value> {
    let globals = crate::cli::podman_globals::podman_global_options();
    let mut uri = globals.url.clone();
    if uri.is_none() {
        if let Some(conn_name) = &globals.connection {
            let cfg = crate::farm::load_connections_file();
            if let Some(dest) = cfg.connection.connections.get(conn_name) {
                uri = Some(dest.uri.clone());
            }
        }
    }
    let uri = uri?;
    if let Some(sock_path) = uri
        .strip_prefix("unix://")
        .or_else(|| uri.strip_prefix("unix:"))
    {
        let meta_path = format!("{}.meta", sock_path);
        if let Ok(raw) = fs::read_to_string(&meta_path) {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) {
                return Some(val);
            }
        }
    }
    None
}

pub fn effective_network_config_dir() -> Option<PathBuf> {
    let globals = crate::cli::podman_globals::podman_global_options();
    if let Some(dir) = globals.network_config_dir {
        return Some(dir);
    }
    if let Ok(env_dir) = std::env::var("BOXR_NETWORK_CONFIG_DIR") {
        if !env_dir.is_empty() {
            return Some(PathBuf::from(env_dir));
        }
    }
    if let Some(meta) = active_connection_meta() {
        if let Some(s) = meta.get("network_config_dir").and_then(|v| v.as_str()) {
            if !s.is_empty() {
                return Some(PathBuf::from(s));
            }
        }
    }
    None
}

pub fn effective_cdi_spec_dirs() -> Vec<PathBuf> {
    let globals = crate::cli::podman_globals::podman_global_options();
    if !globals.cdi_spec_dirs.is_empty() {
        return globals.cdi_spec_dirs;
    }
    if let Some(meta) = active_connection_meta() {
        if let Some(arr) = meta.get("cdi_spec_dirs").and_then(|v| v.as_array()) {
            let dirs: Vec<PathBuf> = arr
                .iter()
                .filter_map(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(PathBuf::from)
                .collect();
            if !dirs.is_empty() {
                return dirs;
            }
        }
    }
    vec![PathBuf::from("/etc/cdi"), PathBuf::from("/var/run/cdi")]
}

/// Get the base boxr directory (default: ~/.boxr)
pub fn boxr_home() -> PathBuf {
    let globals = crate::cli::podman_globals::podman_global_options();
    if let Some(root) = &globals.root {
        return root.clone();
    }
    if let Some(meta) = active_connection_meta() {
        if let Some(gr) = meta.get("graph_root").and_then(|v| v.as_str()) {
            if !gr.is_empty() {
                return PathBuf::from(gr);
            }
        }
    }
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
