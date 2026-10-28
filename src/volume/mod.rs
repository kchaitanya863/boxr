pub mod ops;
pub use ops::VolumeOps;

use crate::storage::boxr_home;
use anyhow::{Result, anyhow};

/// Podman-compatible volume name filter (`name=volume_1.+` uses regex).
fn volume_used_by_container(bundle_path: &str, volume_name: &str) -> bool {
    let bundle = PathBuf::from(bundle_path);
    let mounts_json = bundle.join("mounts.json");
    if mounts_json.exists() {
        if let Ok(content) = fs::read_to_string(&mounts_json) {
            if let Ok(mounts) = serde_json::from_str::<Vec<MountSpec>>(&content) {
                for m in mounts {
                    if !m.is_volume {
                        continue;
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

pub fn volume_name_filter_matches(name: &str, pattern: &str) -> bool {
    let pattern = pattern.trim();
    if pattern.is_empty() {
        return true;
    }
    if name == pattern {
        return true;
    }
    if pattern
        .chars()
        .any(|c| ".+*?[](){}|^$\\".contains(c))
    {
        if let Ok(re) = regex::Regex::new(pattern) {
            return re.is_match(name);
        }
    }
    name.contains(pattern)
}

fn is_volume_mount_option_token(token: &str) -> bool {
    matches!(
        token,
        "ro" | "rw" | "z" | "Z" | "O" | "U" | "copyup" | "noexec" | "exec" | "nosuid" | "suid"
            | "nodev" | "dev" | "private" | "rprivate" | "shared" | "rshared" | "slave"
            | "rslave" | "nocopy"
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

fn default_volume_needs_flags() -> bool {
    true
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
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

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
    index_file: PathBuf,
    volumes_dir: PathBuf,
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
        let volumes_dir = home.join("volumes");
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
                _ => format!(
                    "vol-{}",
                    &hex::encode(crate::storage::container_store::rand_id())[..8]
                ),
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
                        let _ = c_store.update_status(
                            &c.id,
                            crate::storage::ContainerStatus::Exited(0),
                        );
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

        let (source_str, dest_str, read_only, noexec, chown_u) = if let Some(idx) = trimmed.find(':') {
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
                is_volume: true,
            })
        }
    }

    pub fn set_volume_copy_flags(&self, name: &str, needs_copy_up: bool, needs_chown: bool) -> Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_volume_lifecycle() {
        let temp = tempdir().unwrap();
        let store = VolumeStore {
            index_file: temp.path().join("volumes.json"),
            volumes_dir: temp.path().join("volumes"),
        };

        // Create named volume
        let vol = store.create(Some("test-data"), None).unwrap();
        assert_eq!(vol.name, "test-data");
        assert!(PathBuf::from(&vol.mountpoint).exists());

        // Find
        let found = store.find("test-data").unwrap();
        assert_eq!(found.name, "test-data");

        // List
        assert_eq!(store.list().len(), 1);

        // Resolve mount for named volume
        let mount = store.resolve_mount("test-data:/app/data:ro").unwrap();
        assert_eq!(mount.destination, "/app/data");
        assert!(mount.read_only);
        assert!(mount.is_volume);

        // Remove
        store.remove("test-data").unwrap();
        assert!(store.find("test-data").is_none());
        assert_eq!(store.list().len(), 0);

        // Relative path traversal rejection
        let err = store.resolve_mount("../../../etc:/data");
        assert!(err.is_err());
        assert!(
            err.unwrap_err()
                .to_string()
                .contains("Path traversal rejected")
        );

        // Absolute path traversal rejection
        let err = store.resolve_mount("/foo/../../../etc:/data");
        assert!(err.is_err());
        assert!(
            err.unwrap_err()
                .to_string()
                .contains("Path traversal rejected")
        );

        // Destination path traversal rejection
        let err = store.resolve_mount("/tmp/data:../../../../etc");
        assert!(err.is_err());
        assert!(
            err.unwrap_err()
                .to_string()
                .contains("Invalid volume destination")
        );

        let err2 = store.resolve_mount("/tmp/data:relative/path");
        assert!(err2.is_err());
        assert!(
            err2.unwrap_err()
                .to_string()
                .contains("Invalid volume destination")
        );

        // Named volume name traversal rejection
        let err_name = store.create(Some("../../pwn"), None);
        assert!(err_name.is_err());
        assert!(
            err_name
                .unwrap_err()
                .to_string()
                .contains("Invalid volume name")
        );

        let err_name2 = store.create(Some("sub/dir"), None);
        assert!(err_name2.is_err());
        assert!(
            err_name2
                .unwrap_err()
                .to_string()
                .contains("Invalid volume name")
        );
    }

    #[test]
    fn test_volume_prune_preserves_active_containers() {
        let temp = tempdir().unwrap();
        let home = temp.path().to_path_buf();
        let store = VolumeStore::with_home(home.clone());
        let c_store = crate::storage::ContainerStore::with_home(home.clone());

        // Create two volumes: one used, one unused
        store.create(Some("used-vol"), None).unwrap();
        store.create(Some("unused-vol"), None).unwrap();

        // Create a dummy container that mounts "used-vol"
        let bundle_dir = home.join("containers").join("c1");
        fs::create_dir_all(&bundle_dir).unwrap();
        let spec_content = r#"
        {
            "ociVersion": "1.0.2",
            "process": { "terminal": false, "user": { "uid": 0, "gid": 0 }, "args": ["sh"], "env": [], "cwd": "/" },
            "root": { "path": "rootfs", "readonly": false },
            "mounts": [
                { "destination": "/data", "type": "bind", "source": "/test/volumes/used-vol/_data" }
            ]
        }"#;
        fs::write(bundle_dir.join("config.json"), spec_content).unwrap();

        let c_record = crate::storage::ContainerRecord {
            id: "c1".to_string(),
            name: "test-c1".to_string(),
            image: "alpine".to_string(),
            command: vec!["sh".to_string()],
            created_at: chrono::Utc::now(),
            status: crate::storage::ContainerStatus::Running,
            bundle_path: bundle_dir.to_string_lossy().to_string(),
            restart_policy: crate::health::RestartPolicy::No,
            health_status: crate::health::HealthStatus::None,
            restart_count: 0,
            ports: Vec::new(),
            exposed_ports: Vec::new(),
        };
        c_store.add(c_record).unwrap();

        // Prune -a: only unused-vol must be deleted, used-vol must be preserved!
        let pruned = store.prune_with_options(true, &[]).unwrap();
        assert_eq!(pruned, vec!["unused-vol".to_string()]);
        assert!(store.find("used-vol").is_some());
        assert!(store.find("unused-vol").is_none());
    }

    #[test]
    fn test_volume_remove_in_use_validation() {
        let temp = tempdir().unwrap();
        let home = temp.path().to_path_buf();
        let store = VolumeStore::with_home(home.clone());
        let c_store = crate::storage::ContainerStore::with_home(home.clone());

        store.create(Some("mounted-vol"), None).unwrap();

        let bundle_dir = home.join("containers").join("c2");
        fs::create_dir_all(&bundle_dir).unwrap();
        let spec_content = r#"
        {
            "ociVersion": "1.0.2",
            "process": { "terminal": false, "user": { "uid": 0, "gid": 0 }, "args": ["sh"], "env": [], "cwd": "/" },
            "root": { "path": "rootfs", "readonly": false },
            "mounts": [
                { "destination": "/app/data", "type": "bind", "source": "/test/volumes/mounted-vol/_data" }
            ]
        }"#;
        fs::write(bundle_dir.join("config.json"), spec_content).unwrap();

        let c_record = crate::storage::ContainerRecord {
            id: "c2".to_string(),
            name: "test-c2".to_string(),
            image: "alpine".to_string(),
            command: vec!["sh".to_string()],
            created_at: chrono::Utc::now(),
            status: crate::storage::ContainerStatus::Running,
            bundle_path: bundle_dir.to_string_lossy().to_string(),
            restart_policy: crate::health::RestartPolicy::No,
            health_status: crate::health::HealthStatus::None,
            restart_count: 0,
            ports: Vec::new(),
            exposed_ports: Vec::new(),
        };
        c_store.add(c_record).unwrap();

        // Attempting to remove mounted volume without force must fail
        let res = store.remove("mounted-vol");
        assert!(res.is_err());
        assert!(
            res.unwrap_err()
                .to_string()
                .contains("volume is being used")
        );

        // Removing with force=true must succeed
        let res_force = store.remove_with_force("mounted-vol", true);
        assert!(res_force.is_ok());
    }
}
