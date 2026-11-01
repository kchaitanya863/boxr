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
    if let Some(remote_root) = remote_service_graph_root(&globals) {
        return remote_root;
    }
    if let Some(storage_conf_root) = storage_conf_graph_root() {
        return storage_conf_root;
    }
    if let Ok(custom) = std::env::var("BOXR_HOME") {
        return PathBuf::from(custom);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".boxr")
}

pub fn remote_service_meta_for_globals(
    globals: &crate::cli::podman_globals::PodmanGlobalOptions,
) -> Option<serde_json::Value> {
    let uri = globals
        .url
        .clone()
        .or_else(|| std::env::var("CONTAINER_HOST").ok())?;
    let meta_path = if let Some(rest) = uri
        .strip_prefix("tcp://")
        .or_else(|| uri.strip_prefix("tcp:"))
    {
        let port = rest.rsplit(':').next().unwrap_or("0");
        format!("/tmp/boxr-tcp-{}.meta", port)
    } else if let Some(rest) = uri
        .strip_prefix("unix://")
        .or_else(|| uri.strip_prefix("unix:"))
    {
        format!("{}.meta", rest)
    } else {
        return None;
    };
    let raw = fs::read_to_string(meta_path).ok()?;
    serde_json::from_str(&raw).ok()
}

fn remote_service_graph_root(
    globals: &crate::cli::podman_globals::PodmanGlobalOptions,
) -> Option<PathBuf> {
    let meta = remote_service_meta_for_globals(globals)?;
    let gr = meta.get("graph_root")?.as_str()?;
    if !gr.is_empty() {
        Some(PathBuf::from(gr))
    } else {
        None
    }
}

fn storage_conf_graph_root() -> Option<PathBuf> {
    let path = std::env::var("CONTAINERS_STORAGE_CONF").ok()?;
    let content = fs::read_to_string(&path).ok()?;
    #[cfg(unix)]
    let is_rootless = unsafe { libc::getuid() != 0 };
    #[cfg(not(unix))]
    let is_rootless = false;
    let mut graphroot = None;
    let mut rootless_path = None;
    for line in content.lines() {
        let trimmed = line.split('#').next().unwrap_or("").trim();
        let Some((k, v)) = trimmed.split_once('=') else {
            continue;
        };
        let k = k.trim();
        let v = v.trim().trim_matches('"').trim_matches('\'');
        if k == "graphroot" && !v.is_empty() {
            graphroot = Some(v.to_string());
        } else if k == "rootless_storage_path" && !v.is_empty() {
            rootless_path = Some(v.to_string());
        }
    }
    let raw = if is_rootless {
        rootless_path.or(graphroot)?
    } else {
        graphroot?
    };
    let home = std::env::var("HOME").unwrap_or_default();
    #[cfg(unix)]
    let uid = unsafe { libc::getuid().to_string() };
    #[cfg(not(unix))]
    let uid = "0".to_string();
    let user = std::env::var("USER").unwrap_or_else(|_| {
        #[cfg(unix)]
        unsafe {
            let pwd = libc::getpwuid(libc::getuid());
            if !pwd.is_null() {
                return std::ffi::CStr::from_ptr((*pwd).pw_name)
                    .to_string_lossy()
                    .into_owned();
            }
        }
        "root".to_string()
    });
    let expanded = raw
        .replace("$HOME", &home)
        .replace("${HOME}", &home)
        .replace("$USER", &user)
        .replace("${USER}", &user)
        .replace("$UID", &uid)
        .replace("${UID}", &uid);
    let mut cleaned = String::with_capacity(expanded.len());
    let mut prev_slash = false;
    for ch in expanded.chars() {
        if ch == '/' {
            if !prev_slash {
                cleaned.push(ch);
            }
            prev_slash = true;
        } else {
            cleaned.push(ch);
            prev_slash = false;
        }
    }
    if cleaned.len() > 1 && cleaned.ends_with('/') {
        cleaned.pop();
    }
    Some(PathBuf::from(cleaned))
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
