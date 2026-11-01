//! Podman Quadlet unit file management (.container, .kube, .volume, .network, .artifact).

use crate::storage::boxr_home;
use anyhow::{Result, anyhow};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, serde::Serialize)]
pub struct QuadletUnit {
    pub name: String,
    pub unit_type: String,
    pub path: String,
}

pub struct QuadletManager;

impl QuadletManager {
    pub fn quadlet_dir() -> PathBuf {
        if let Ok(dirs) = std::env::var("QUADLET_UNIT_DIRS") {
            if let Some(first) = dirs.split(':').find(|s| !s.is_empty()) {
                let p = PathBuf::from(first);
                let _ = fs::create_dir_all(&p);
                return p;
            }
        }
        let dir = boxr_home().join("quadlets");
        let _ = fs::create_dir_all(&dir);
        dir
    }

    pub fn systemd_quadlet_dir() -> PathBuf {
        if let Ok(dirs) = std::env::var("QUADLET_UNIT_DIRS") {
            if let Some(first) = dirs.split(':').find(|s| !s.is_empty()) {
                let p = PathBuf::from(first);
                let _ = fs::create_dir_all(&p);
                return p;
            }
        }
        #[cfg(unix)]
        let is_rootless = unsafe { libc::geteuid() != 0 };
        #[cfg(not(unix))]
        let is_rootless = false;
        let p = if is_rootless {
            let cfg = std::env::var("XDG_CONFIG_HOME").unwrap_or_else(|_| {
                let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
                format!("{}/.config", home)
            });
            PathBuf::from(cfg).join("containers").join("systemd")
        } else {
            PathBuf::from("/etc/containers/systemd")
        };
        let _ = fs::create_dir_all(&p);
        p
    }

    pub fn list() -> Result<Vec<QuadletUnit>> {
        let dir = Self::quadlet_dir();
        let mut units = Vec::new();
        if dir.exists() {
            for entry in fs::read_dir(&dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file() {
                    let ext = path
                        .extension()
                        .and_then(|e| e.to_str())
                        .unwrap_or("")
                        .to_string();
                    let name = entry.file_name().to_string_lossy().to_string();
                    if matches!(
                        ext.as_str(),
                        "container" | "kube" | "volume" | "network" | "artifact" | "image"
                    ) {
                        units.push(QuadletUnit {
                            name,
                            unit_type: ext,
                            path: path.to_string_lossy().to_string(),
                        });
                    }
                }
            }
        }
        Ok(units)
    }

    pub fn install(src: &Path) -> Result<QuadletUnit> {
        if !src.exists() {
            return Err(anyhow!("Quadlet source file '{}' not found", src.display()));
        }
        let fname = src
            .file_name()
            .ok_or_else(|| anyhow!("Invalid file path"))?;
        let dir = Self::quadlet_dir();
        let dest = dir.join(fname);
        fs::copy(src, &dest)?;
        let sys_dir = Self::systemd_quadlet_dir();
        if sys_dir != dir {
            let _ = fs::copy(src, sys_dir.join(fname));
        }

        let ext = dest
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("container")
            .to_string();

        Ok(QuadletUnit {
            name: fname.to_string_lossy().to_string(),
            unit_type: ext,
            path: dest.to_string_lossy().to_string(),
        })
    }

    pub fn print(name_or_path: &str) -> Result<String> {
        let dir = Self::quadlet_dir();
        let sys_dir = Self::systemd_quadlet_dir();
        let direct_path = PathBuf::from(name_or_path);
        let target = if direct_path.exists() {
            direct_path
        } else if dir.join(name_or_path).exists() {
            dir.join(name_or_path)
        } else {
            sys_dir.join(name_or_path)
        };

        if !target.exists() {
            return Err(anyhow!("Quadlet unit '{}' not found", name_or_path));
        }

        let content = fs::read_to_string(&target)?;
        Ok(content)
    }

    pub fn remove(name: &str) -> Result<()> {
        let dir = Self::quadlet_dir();
        let sys_dir = Self::systemd_quadlet_dir();
        let path = dir.join(name);
        let sys_path = sys_dir.join(name);
        if path.exists() {
            let _ = fs::remove_file(&path);
        }
        if sys_path.exists() {
            let _ = fs::remove_file(&sys_path);
        }
        if let Ok(entries) = fs::read_dir(&sys_dir) {
            for entry in entries.flatten() {
                if entry.path().is_dir() {
                    let sub = entry.path().join(name);
                    if sub.exists() {
                        let _ = fs::remove_file(sub);
                    }
                }
            }
        }
        Ok(())
    }
}
