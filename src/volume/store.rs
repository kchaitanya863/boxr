use super::filter::*;
use super::mount::*;
use crate::storage::boxr_home;
use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

fn default_volume_needs_flags() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeRecord {
    pub name: String,
    pub driver: String,
    pub mountpoint: String,
    pub created_at: DateTime<Utc>,
    pub labels: HashMap<String, String>,
    pub scope: String,
    #[serde(default)]
    pub options: HashMap<String, String>,
    /// True when created without an explicit user-provided name (`podman volume create`).
    #[serde(default)]
    pub anonymous: bool,
    #[serde(default = "default_volume_needs_flags")]
    pub needs_copy_up: bool,
    #[serde(default = "default_volume_needs_flags")]
    pub needs_chown: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct VolumeStoreData {
    volumes: Vec<VolumeRecord>,
}

pub struct VolumeStore {
    pub(crate) index_file: PathBuf,
    pub(crate) volumes_dir: PathBuf,
}

/// Interface Segregation: Volume reading abstraction
pub trait VolumeReader: Send + Sync {
    fn find(&self, name: &str) -> Option<VolumeRecord>;
    fn list(&self) -> Vec<VolumeRecord>;
}

/// Interface Segregation: Volume mutation abstraction
pub trait VolumeWriter: Send + Sync {
    fn create_with_options(
        &self,
        name: Option<&str>,
        driver: &str,
        labels: Option<HashMap<String, String>>,
        scope: &str,
        options: Option<HashMap<String, String>>,
    ) -> Result<VolumeRecord>;
    fn remove(&self, name: &str) -> Result<VolumeRecord>;
    fn prune(&self) -> Result<Vec<String>>;
}

/// Combined volume operations contract (LSP compliant)
pub trait VolumeStoreOps: VolumeReader + VolumeWriter {}
impl<T: VolumeReader + VolumeWriter> VolumeStoreOps for T {}

impl VolumeStore {
    pub fn new() -> Self {
        Self::with_home(boxr_home())
    }

    pub fn with_home(home: PathBuf) -> Self {
        let volumes_dir = crate::storage::db_config::effective_volume_path();
        let _ = fs::create_dir_all(&volumes_dir);
        Self {
            index_file: home.join("volumes.json"),
            volumes_dir,
        }
    }

    fn load_unlocked(&self) -> VolumeStoreData {
        if let Ok(content) = fs::read_to_string(&self.index_file) {
            serde_json::from_str(&content).unwrap_or_default()
        } else {
            VolumeStoreData::default()
        }
    }

    fn save_unlocked(&self, data: &VolumeStoreData) -> Result<()> {
        let content = serde_json::to_string_pretty(data)?;
        let rand_suffix = hex::encode(crate::storage::container_store::rand_id());
        let temp_file = self
            .index_file
            .with_extension(format!("tmp.{}", rand_suffix));
        fs::write(&temp_file, content)?;
        fs::rename(&temp_file, &self.index_file)?;
        Ok(())
    }

    pub fn list(&self) -> Vec<VolumeRecord> {
        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            Ok(self.load_unlocked().volumes)
        })
        .unwrap_or_default()
    }

    pub fn find(&self, name: &str) -> Option<VolumeRecord> {
        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            Ok(self
                .load_unlocked()
                .volumes
                .into_iter()
                .find(|v| v.name == name))
        })
        .ok()
        .flatten()
    }

    pub fn create(
        &self,
        name: Option<&str>,
        labels: Option<HashMap<String, String>>,
    ) -> Result<VolumeRecord> {
        self.create_with_options(name, "local", labels, "local", None)
    }

    pub fn create_with_options(
        &self,
        name: Option<&str>,
        driver: &str,
        labels: Option<HashMap<String, String>>,
        scope: &str,
        options: Option<HashMap<String, String>>,
    ) -> Result<VolumeRecord> {
        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            let mut data = self.load_unlocked();
            let user_provided_name = matches!(name, Some(n) if !n.trim().is_empty());
            let vol_name = match name {
                Some(n) if !n.trim().is_empty() => n.trim().to_string(),
                _ => crate::new_container_id(),
            };

            if vol_name == "." || vol_name == ".." {
                return Err(anyhow!(
                    "Invalid volume name '{}': '.' and '..' are reserved",
                    vol_name
                ));
            }

            if vol_name.contains('/') || vol_name.contains('\\') || vol_name.contains("..") {
                return Err(anyhow!(
                    "Invalid volume name '{}': cannot contain path separators or '..'",
                    vol_name
                ));
            }

            if !vol_name
                .chars()
                .all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.')
            {
                return Err(anyhow!(
                    "Invalid volume name '{}': must contain only alphanumeric, '_', '-', or '.' characters",
                    vol_name
                ));
            }

            if data.volumes.iter().any(|v| v.name == vol_name) {
                return Err(anyhow!("Volume with name '{}' already exists", vol_name));
            }

            let opts = options.clone().unwrap_or_default();
            let mountpoint = if opts.get("type").map(|t| t.as_str()) == Some("bind") {
                let device = opts
                    .get("device")
                    .filter(|d| !d.is_empty())
                    .ok_or_else(|| anyhow!("bind volume requires device option"))?;
                let device_path = PathBuf::from(device);
                if !device_path.exists() {
                    crate::cli::usage_errors::exit_usage_error(format!(
                        "invalid volume option device for driver 'local': faccessat {}: no such file or directory",
                        device
                    ));
                }
                device_path
            } else {
                let mp = self.volumes_dir.join(&vol_name).join("_data");
                fs::create_dir_all(&mp)?;
                if let (Ok(canon_vols), Ok(canon_mount)) =
                    (self.volumes_dir.canonicalize(), mp.canonicalize())
                {
                    if !canon_mount.starts_with(&canon_vols) {
                        return Err(anyhow!(
                            "Volume mountpoint escapes volumes directory: '{}'",
                            vol_name
                        ));
                    }
                }
                mp
            };
            if opts.get("type").map(|t| t.as_str()) != Some("bind") {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(&mountpoint, fs::Permissions::from_mode(0o777));
                }
            }

            let record = VolumeRecord {
                name: vol_name,
                driver: driver.to_string(),
                mountpoint: mountpoint.to_string_lossy().to_string(),
                created_at: Utc::now(),
                labels: labels.unwrap_or_default(),
                scope: scope.to_string(),
                options: options.unwrap_or_default(),
                anonymous: !user_provided_name,
                needs_copy_up: true,
                needs_chown: true,
            };

            data.volumes.push(record.clone());
            self.save_unlocked(&data)?;
            Ok(record)
        })
    }

    pub fn remove(&self, name: &str) -> Result<VolumeRecord> {
        self.remove_with_force(name, false)
    }

    pub fn delete_volume_record(&self, name: &str) -> Result<VolumeRecord> {
        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            let mut data = self.load_unlocked();
            if let Some(pos) = data.volumes.iter().position(|v| v.name == name) {
                let removed = data.volumes.remove(pos);
                self.save_unlocked(&data)?;

                let vol_dir = self.volumes_dir.join(&removed.name);
                if vol_dir.exists() {
                    let _ = fs::remove_dir_all(vol_dir);
                }
                Ok(removed)
            } else {
                Err(anyhow!("Volume '{}' not found", name))
            }
        })
    }

    /// Podman `volume rename` (updates index, data dir, and container mount references).
    pub fn rename(&self, old_name: &str, new_name: &str) -> Result<VolumeRecord> {
        if old_name == new_name {
            return self
                .find(old_name)
                .ok_or_else(|| anyhow!("no such volume \"{}\"", old_name));
        }
        validate_volume_rename_name(new_name)?;

        let home = self
            .index_file
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        let c_store = crate::storage::ContainerStore::with_home(home.clone());

        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            let mut data = self.load_unlocked();
            let pos = data
                .volumes
                .iter()
                .position(|v| v.name == old_name)
                .ok_or_else(|| anyhow!("no such volume \"{}\"", old_name))?;
            if data.volumes.iter().any(|v| v.name == new_name) {
                return Err(anyhow!("volume already exists"));
            }
            let mut vol = data.volumes[pos].clone();
            if vol.driver == "image" {
                return Err(anyhow!(
                    "rename is not supported for volumes using driver \"image\""
                ));
            }

            for c in c_store.list() {
                if volume_used_by_container(&c.bundle_path, old_name) {
                    return Err(anyhow!(
                        "volume {} is being used by the following container(s): {}: volume is being used",
                        old_name,
                        c.id
                    ));
                }
            }

            let old_dir = PathBuf::from(&vol.mountpoint);
            let new_mp = self.volumes_dir.join(new_name).join("_data");
            if let Some(parent) = new_mp.parent() {
                fs::create_dir_all(parent)?;
            }
            if old_dir.exists() {
                if new_mp.exists() {
                    return Err(anyhow!("volume already exists"));
                }
                fs::rename(&old_dir, &new_mp)?;
                if let Some(old_parent) = old_dir.parent() {
                    let _ = fs::remove_dir(old_parent);
                }
            } else {
                fs::create_dir_all(&new_mp)?;
            }

            vol.name = new_name.to_string();
            vol.mountpoint = new_mp.to_string_lossy().to_string();
            vol.anonymous = false;
            data.volumes[pos] = vol.clone();
            self.save_unlocked(&data)?;

            for c in c_store.list() {
                rewrite_volume_name_in_container(&c.bundle_path, old_name, new_name);
            }

            Ok(vol)
        })
    }

    pub fn remove_with_force(&self, name: &str, force: bool) -> Result<VolumeRecord> {
        let home = self
            .index_file
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        let c_store = crate::storage::ContainerStore::with_home(home);
        let containers = c_store.list();

        if !force {
            for c in containers {
                if volume_used_by_container(&c.bundle_path, name) {
                    return Err(anyhow!(
                        "volume {} is being used by the following container(s): {}: volume is being used",
                        name,
                        c.id
                    ));
                }
            }
        } else {
            for c in &containers {
                if volume_used_by_container(&c.bundle_path, name) {
                    if matches!(
                        c.status,
                        crate::storage::ContainerStatus::Running
                            | crate::storage::ContainerStatus::Paused
                    ) {
                        let _ = c_store
                            .update_status(&c.id, crate::storage::ContainerStatus::Exited(0));
                    }
                    let _ = c_store.remove(&c.id);
                }
            }
        }

        self.delete_volume_record(name)
    }

    pub fn list_filtered(&self, filters: &[String]) -> Vec<VolumeRecord> {
        self.list()
            .into_iter()
            .filter(|v| Self::matches_filters(v, filters))
            .collect()
    }

    pub fn matches_filters(vol: &VolumeRecord, filters: &[String]) -> bool {
        if filters.is_empty() {
            return true;
        }
        filters.iter().all(|f| Self::matches_filter(vol, f))
    }

    pub fn matches_filter(vol: &VolumeRecord, filter: &str) -> bool {
        if let Some((key, value)) = filter.split_once('=') {
            match key {
                "name" => volume_name_filter_matches(&vol.name, value),
                "driver" => vol.driver == value,
                "label" => {
                    if let Some((lk, lv)) = value.split_once('=') {
                        vol.labels.get(lk).map(|v| v == lv).unwrap_or(false)
                    } else {
                        vol.labels.contains_key(value)
                    }
                }
                "dangling" => value == "true" && vol.labels.is_empty(),
                _ => true,
            }
        } else {
            true
        }
    }

    fn collect_used_volume_names(&self) -> std::collections::HashSet<String> {
        let home = self
            .index_file
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        let c_store = crate::storage::ContainerStore::with_home(home);
        let mut used_volume_names = std::collections::HashSet::new();
        let volumes = self.list();
        for c in c_store.list() {
            let bundle_path = PathBuf::from(&c.bundle_path);
            let mounts_json = bundle_path.join("mounts.json");
            if mounts_json.exists() {
                if let Ok(content) = fs::read_to_string(&mounts_json) {
                    if let Ok(mounts) = serde_json::from_str::<Vec<MountSpec>>(&content) {
                        for m in mounts {
                            if !m.is_volume {
                                continue;
                            }
                            let src = m.source.to_string_lossy();
                            for v in &volumes {
                                if src.contains(&format!("volumes/{}/_data", v.name))
                                    || src.contains(&format!("/volumes/{}/", v.name))
                                {
                                    used_volume_names.insert(v.name.clone());
                                }
                            }
                        }
                    }
                }
            }
            let config_file = bundle_path.join("config.json");
            if let Ok(content) = fs::read_to_string(&config_file) {
                if let Ok(spec) = serde_json::from_str::<crate::oci::runtime::Spec>(&content) {
                    for m in spec.mounts {
                        let m_src = m.source;
                        for v in &volumes {
                            if m_src.contains(&format!("volumes/{}/_data", v.name))
                                || m_src.contains(&format!("volumes/{}", v.name))
                                || m_src.ends_with(&v.name)
                            {
                                used_volume_names.insert(v.name.clone());
                            }
                        }
                    }
                }
            }
        }
        used_volume_names
    }

    pub fn prune_with_options(&self, all: bool, filters: &[String]) -> Result<Vec<String>> {
        let used_volume_names = self.collect_used_volume_names();

        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            let mut data = self.load_unlocked();
            let mut pruned = Vec::new();
            data.volumes.retain(|v| {
                let unused = !used_volume_names.contains(&v.name);
                let matches = Self::matches_filters(v, filters);
                let eligible = if all {
                    unused && matches
                } else {
                    unused && matches && v.anonymous
                };
                if eligible {
                    if v.options.get("type").map(|t| t.as_str()) != Some("bind") {
                        let vol_dir = self.volumes_dir.join(&v.name);
                        if vol_dir.exists() {
                            let _ = fs::remove_dir_all(vol_dir);
                        }
                    }
                    pruned.push(v.name.clone());
                    false
                } else {
                    true
                }
            });
            self.save_unlocked(&data)?;
            Ok(pruned)
        })
    }

    pub fn prune(&self) -> Result<Vec<String>> {
        self.prune_with_options(false, &[])
    }

    /// Parse a volume flag string:
    /// e.g. "my-vol:/data:ro", "/host/path:/container/path", "my-vol:/data"
    pub fn resolve_mount(&self, spec_str: &str) -> Result<MountSpec> {
        let trimmed = spec_str.trim();
        if trimmed.is_empty() {
            return Err(anyhow!("Volume specification cannot be empty"));
        }

        let (source_str, dest_str, read_only, noexec, chown_u) =
            if let Some(idx) = trimmed.find(':') {
                let source_str = trimmed[..idx].to_string();
                let (dest_str, read_only, noexec, chown_u) =
                    parse_volume_dest_and_options(&trimmed[idx + 1..]);
                (source_str, dest_str, read_only, noexec, chown_u)
            } else if trimmed.starts_with('/') {
                // Podman/Docker: `-v /container/path` creates an anonymous volume at that path.
                let vol = self.create(None, None)?;
                return Ok(MountSpec {
                    source: PathBuf::from(vol.mountpoint),
                    destination: trimmed.to_string(),
                    is_volume: true,
                    volume_name: Some(vol.name),
                    ..Default::default()
                });
            } else {
                (String::new(), trimmed.to_string(), false, false, false)
            };

        if dest_str.trim().is_empty() {
            return Err(anyhow!("Volume destination path cannot be empty"));
        }

        if !dest_str.starts_with('/') || dest_str.contains("..") {
            return Err(anyhow!(
                "Invalid volume destination '{}': must be an absolute path and cannot contain '..'",
                dest_str
            ));
        }

        if source_str.is_empty() {
            // Create anonymous volume
            let vol = self.create(None, None)?;
            return Ok(MountSpec {
                source: PathBuf::from(vol.mountpoint),
                destination: dest_str.to_string(),
                read_only,
                noexec,
                is_volume: true,
                volume_name: Some(vol.name),
                ..Default::default()
            });
        }

        let is_host_path = source_str.starts_with('/')
            || source_str.starts_with('.')
            || source_str.starts_with('~');

        if is_host_path {
            if source_str.contains("..") {
                return Err(anyhow!(
                    "Path traversal rejected in volume mount: '{}'",
                    source_str
                ));
            }

            let host_path = if source_str.starts_with('~') {
                let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
                PathBuf::from(source_str.replacen('~', &home, 1))
            } else {
                PathBuf::from(&source_str)
            };

            let canonical_source = if host_path.exists() {
                host_path.canonicalize()?
            } else if fs::create_dir_all(&host_path).is_ok() {
                host_path.canonicalize().unwrap_or(host_path)
            } else {
                // Rootless Podman: missing bind sources get an empty stub dir under boxr home.
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(source_str.as_str().as_bytes());
                let stub = crate::storage::boxr_home()
                    .join("bind-stubs")
                    .join(hex::encode(hasher.finalize()));
                fs::create_dir_all(&stub)?;
                stub
            };

            Ok(MountSpec {
                source: canonical_source,
                destination: dest_str.to_string(),
                read_only,
                noexec,
                chown_u,
                is_volume: false,
                ..Default::default()
            })
        } else {
            // Named volume
            let record = match self.find(&source_str) {
                Some(v) => v,
                None => self.create(Some(&source_str), None)?,
            };
            let tmpfs_mount_data = tmpfs_mount_data_from_volume_options(&record.options);
            Ok(MountSpec {
                source: PathBuf::from(record.mountpoint),
                destination: dest_str.to_string(),
                read_only,
                noexec,
                chown_u,
                tmpfs_mount_data,
                volume_name: Some(record.name.clone()),
                subpath: None,
                is_volume: true,
            })
        }
    }

    pub fn set_volume_copy_flags(
        &self,
        name: &str,
        needs_copy_up: bool,
        needs_chown: bool,
    ) -> Result<()> {
        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            let mut data = self.load_unlocked();
            if let Some(v) = data.volumes.iter_mut().find(|v| v.name == name) {
                v.needs_copy_up = needs_copy_up;
                v.needs_chown = needs_chown;
                self.save_unlocked(&data)?;
                Ok(())
            } else {
                Err(anyhow!("Volume '{}' not found", name))
            }
        })
    }
}

impl VolumeReader for VolumeStore {
    fn find(&self, name: &str) -> Option<VolumeRecord> {
        self.find(name)
    }

    fn list(&self) -> Vec<VolumeRecord> {
        self.list()
    }
}

impl VolumeWriter for VolumeStore {
    fn create_with_options(
        &self,
        name: Option<&str>,
        driver: &str,
        labels: Option<HashMap<String, String>>,
        scope: &str,
        options: Option<HashMap<String, String>>,
    ) -> Result<VolumeRecord> {
        self.create_with_options(name, driver, labels, scope, options)
    }

    fn remove(&self, name: &str) -> Result<VolumeRecord> {
        self.remove(name)
    }

    fn prune(&self) -> Result<Vec<String>> {
        self.prune()
    }
}
