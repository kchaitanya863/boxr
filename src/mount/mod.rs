//! Container filesystem mount tracking (Podman `mount` / `unmount` parity).

use crate::storage::{ContainerStore, boxr_home};
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountRecord {
    pub container_id: String,
    pub container_name: String,
    pub mount_path: String,
    pub mounted_at: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct MountIndex {
    mounts: HashMap<String, MountRecord>,
}

pub struct MountManager {
    index_file: PathBuf,
}

impl MountManager {
    pub fn new() -> Self {
        Self {
            index_file: boxr_home().join("mounts.json"),
        }
    }

    fn load(&self) -> MountIndex {
        if let Ok(content) = fs::read_to_string(&self.index_file) {
            serde_json::from_str(&content).unwrap_or_default()
        } else {
            MountIndex::default()
        }
    }

    fn save(&self, data: &MountIndex) -> Result<()> {
        let content = serde_json::to_string_pretty(data)?;
        let rand_suffix = hex::encode(crate::storage::container_store::rand_id());
        let temp = self
            .index_file
            .with_extension(format!("tmp.{}", rand_suffix));
        fs::write(&temp, content)?;
        fs::rename(&temp, &self.index_file)?;
        Ok(())
    }

    pub fn mount_container(&self, query: &str) -> Result<String> {
        #[cfg(target_os = "linux")]
        if unsafe { libc::geteuid() != 0 } {
            crate::cli::usage_errors::exit_usage_error(
                "cannot mount using driver overlay in rootless mode. You must execute `podman unshare` first",
            );
        }
        let store = ContainerStore::new();
        let cont = store
            .find(query)
            .ok_or_else(|| anyhow!("Container '{}' not found", query))?;

        let bundle = PathBuf::from(&cont.bundle_path);
        let rootfs = bundle.join("rootfs");
        if !rootfs.exists() {
            return Err(anyhow!(
                "Container '{}' rootfs not found at {}",
                query,
                rootfs.display()
            ));
        }

        let mount_path = if rootfs.is_absolute() {
            rootfs
        } else {
            rootfs.canonicalize()?
        };
        let mut data = self.load();
        let record = MountRecord {
            container_id: cont.id.clone(),
            container_name: cont.name.clone(),
            mount_path: mount_path.to_string_lossy().to_string(),
            mounted_at: chrono::Utc::now().to_rfc3339(),
        };
        data.mounts.insert(cont.id.clone(), record);
        self.save(&data)?;
        Ok(mount_path.to_string_lossy().to_string())
    }

    pub fn unmount_container(&self, query: &str) -> Result<()> {
        let store = ContainerStore::new();
        let cont = store
            .find(query)
            .ok_or_else(|| anyhow!("Container '{}' not found", query))?;

        let mut data = self.load();
        if data.mounts.remove(&cont.id).is_some() {
            self.save(&data)?;
            Ok(())
        } else {
            Err(anyhow!("Container '{}' is not mounted", query))
        }
    }

    pub fn is_mounted(&self, container_id: &str) -> bool {
        self.load().mounts.contains_key(container_id)
    }

    pub fn get_mount_path(&self, query: &str) -> Option<String> {
        let store = ContainerStore::new();
        let cont = store.find(query)?;
        self.load()
            .mounts
            .get(&cont.id)
            .map(|r| r.mount_path.clone())
    }

    pub fn mount_image(&self, query: &str) -> Result<String> {
        #[cfg(target_os = "linux")]
        if unsafe { libc::geteuid() != 0 } {
            crate::cli::usage_errors::exit_usage_error(
                "cannot mount using driver overlay in rootless mode. You must execute `podman unshare` first",
            );
        }
        let store = crate::storage::ImageStore::new();
        let img = crate::find_image_with_shortname(&store, query, None)
            .ok_or_else(|| anyhow!("Image '{}' not found", query))?;

        let rootfs = PathBuf::from(&img.rootfs_path);
        if !rootfs.exists() {
            return Err(anyhow!(
                "Image '{}' rootfs not found at {}",
                query,
                rootfs.display()
            ));
        }

        let home = boxr_home();
        let mount_path = if rootfs.starts_with(&home) {
            rootfs
        } else {
            let overlay_dir = home.join("overlay").join(&img.id);
            let _ = fs::create_dir_all(&overlay_dir);
            let merged_link = overlay_dir.join("merged");
            if !merged_link.exists() {
                #[cfg(unix)]
                {
                    let _ = std::os::unix::fs::symlink(&rootfs, &merged_link);
                }
            }
            if merged_link.exists() {
                merged_link
            } else {
                rootfs.canonicalize()?
            }
        };
        let mut data = self.load();
        let record = MountRecord {
            container_id: img.id.clone(),
            container_name: format!("{}:{}", img.reference, img.tag),
            mount_path: mount_path.to_string_lossy().to_string(),
            mounted_at: chrono::Utc::now().to_rfc3339(),
        };
        data.mounts.insert(img.id.clone(), record);
        self.save(&data)?;
        Ok(mount_path.to_string_lossy().to_string())
    }

    pub fn unmount_image(&self, query: &str) -> Result<()> {
        let store = crate::storage::ImageStore::new();
        let img = crate::find_image_with_shortname(&store, query, None)
            .ok_or_else(|| anyhow!("Image '{}' not found", query))?;

        let merged_link = boxr_home().join("overlay").join(&img.id).join("merged");
        if merged_link.symlink_metadata().is_ok() {
            let _ = fs::remove_file(&merged_link);
        }
        let mut data = self.load();
        if data.mounts.remove(&img.id).is_some() {
            self.save(&data)?;
            Ok(())
        } else {
            Err(anyhow!("Image '{}' is not mounted", query))
        }
    }

    pub fn mount_volume(&self, query: &str) -> Result<String> {
        let store = crate::volume::VolumeStore::new();
        let vol = store
            .find(query)
            .ok_or_else(|| anyhow!("Volume '{}' not found", query))?;

        let mountpoint = PathBuf::from(&vol.mountpoint);
        fs::create_dir_all(&mountpoint)?;
        let mount_path = mountpoint.canonicalize()?;
        let mut data = self.load();
        let record = MountRecord {
            container_id: vol.name.clone(),
            container_name: vol.name.clone(),
            mount_path: mount_path.to_string_lossy().to_string(),
            mounted_at: chrono::Utc::now().to_rfc3339(),
        };
        data.mounts.insert(vol.name.clone(), record);
        self.save(&data)?;
        Ok(mount_path.to_string_lossy().to_string())
    }

    pub fn unmount_volume(&self, query: &str) -> Result<()> {
        let store = crate::volume::VolumeStore::new();
        let vol = store
            .find(query)
            .ok_or_else(|| anyhow!("Volume '{}' not found", query))?;

        let mut data = self.load();
        if data.mounts.remove(&vol.name).is_some() {
            self.save(&data)?;
            Ok(())
        } else {
            Err(anyhow!("Volume '{}' is not mounted", query))
        }
    }
}
