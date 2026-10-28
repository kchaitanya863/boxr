pub mod ops;
pub use ops::VolumeOps;

use crate::storage::boxr_home;
use anyhow::{Result, anyhow};

/// Podman-compatible volume name filter (`name=volume_1.+` uses regex).
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

/// Destination path and read-only flag from `dest:z,ro` / `dest:ro` style volume suffixes.
pub fn parse_volume_dest_and_options(rest: &str) -> (String, bool) {
    let mut read_only = rest.split(',').any(|p| p.trim() == "ro");
    let head = rest.split(',').next().unwrap_or(rest).trim();
    let dest = if let Some((path, opt)) = head.rsplit_once(':') {
        let opt = opt.trim();
        if !path.is_empty() && path.starts_with('/') && is_volume_mount_option_token(opt) {
            read_only = read_only || opt == "ro";
            path.trim().to_string()
        } else {
            head.to_string()
        }
    } else {
        head.to_string()
    };
    (dest, read_only)
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
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct VolumeStoreData {
    volumes: Vec<VolumeRecord>,
}

pub struct VolumeStore {
    index_file: PathBuf,
    volumes_dir: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountSpec {
    pub source: PathBuf,
    pub destination: String,
    pub read_only: bool,
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

            let mountpoint = self.volumes_dir.join(&vol_name).join("_data");
            fs::create_dir_all(&mountpoint)?;
            if let (Ok(canon_vols), Ok(canon_mount)) =
                (self.volumes_dir.canonicalize(), mountpoint.canonicalize())
            {
                if !canon_mount.starts_with(&canon_vols) {
                    return Err(anyhow!(
                        "Volume mountpoint escapes volumes directory: '{}'",
                        vol_name
                    ));
                }
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&mountpoint, fs::Permissions::from_mode(0o777));
            }

            let record = VolumeRecord {
                name: vol_name,
                driver: driver.to_string(),
                mountpoint: mountpoint.to_string_lossy().to_string(),
                created_at: Utc::now(),
                labels: labels.unwrap_or_default(),
                scope: scope.to_string(),
                options: options.unwrap_or_default(),
            };

            data.volumes.push(record.clone());
            self.save_unlocked(&data)?;
            Ok(record)
        })
    }

    pub fn remove(&self, name: &str) -> Result<VolumeRecord> {
        self.remove_with_force(name, false)
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
                let bundle_path = PathBuf::from(&c.bundle_path);
                let config_file = bundle_path.join("config.json");
                if let Ok(content) = fs::read_to_string(&config_file) {
                    if let Ok(spec) = serde_json::from_str::<crate::oci::runtime::Spec>(&content) {
                        for m in spec.mounts {
                            let m_src = m.source;
                            if m_src.contains(&format!("volumes/{}/_data", name))
                                || m_src.contains(&format!("volumes/{}", name))
                                || m_src.ends_with(&format!("/{}", name))
                                || m_src == name
                            {
                                return Err(anyhow!(
                                    "conflict: unable to remove volume '{}' - volume is in use by container {}",
                                    name,
                                    c.id
                                ));
                            }
                        }
                    }
                }
            }
        }

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

    pub fn prune_with_options(&self, all: bool, filters: &[String]) -> Result<Vec<String>> {
        let home = self
            .index_file
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        let c_store = crate::storage::ContainerStore::with_home(home);
        let containers = c_store.list();
        let mut used_volume_names = std::collections::HashSet::new();

        for c in containers {
            let bundle_path = PathBuf::from(&c.bundle_path);
            let config_file = bundle_path.join("config.json");
            if let Ok(content) = fs::read_to_string(&config_file) {
                if let Ok(spec) = serde_json::from_str::<crate::oci::runtime::Spec>(&content) {
                    for m in spec.mounts {
                        let m_src = m.source;
                        for v in self.list() {
                            if m_src.contains(&format!("volumes/{}/_data", v.name))
                                || m_src.contains(&format!("volumes/{}", v.name))
                                || m_src.ends_with(&v.name)
                            {
                                used_volume_names.insert(v.name);
                            }
                        }
                    }
                }
            }
        }

        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            let mut data = self.load_unlocked();
            let mut pruned = Vec::new();
            data.volumes.retain(|v| {
                let unused = !used_volume_names.contains(&v.name);
                let matches = Self::matches_filters(v, filters);
                if unused && matches && (all || v.labels.is_empty()) {
                    let vol_dir = self.volumes_dir.join(&v.name);
                    if vol_dir.exists() {
                        let _ = fs::remove_dir_all(vol_dir);
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
        let home = self
            .index_file
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        let c_store = crate::storage::ContainerStore::with_home(home);
        let containers = c_store.list();
        let mut used_volume_names = std::collections::HashSet::new();

        for c in containers {
            let bundle_path = PathBuf::from(&c.bundle_path);
            let config_file = bundle_path.join("config.json");
            if let Ok(content) = fs::read_to_string(&config_file) {
                if let Ok(spec) = serde_json::from_str::<crate::oci::runtime::Spec>(&content) {
                    for m in spec.mounts {
                        let m_src = m.source;
                        for v in self.list() {
                            if m_src.contains(&format!("volumes/{}/_data", v.name))
                                || m_src.contains(&format!("volumes/{}", v.name))
                                || m_src.ends_with(&v.name)
                            {
                                used_volume_names.insert(v.name);
                            }
                        }
                    }
                }
            }
        }

        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            let mut data = self.load_unlocked();
            let mut pruned = Vec::new();
            data.volumes.retain(|v| {
                if !used_volume_names.contains(&v.name) {
                    let vol_dir = self.volumes_dir.join(&v.name);
                    if vol_dir.exists() {
                        let _ = fs::remove_dir_all(vol_dir);
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

    /// Parse a volume flag string:
    /// e.g. "my-vol:/data:ro", "/host/path:/container/path", "my-vol:/data"
    pub fn resolve_mount(&self, spec_str: &str) -> Result<MountSpec> {
        let trimmed = spec_str.trim();
        if trimmed.is_empty() {
            return Err(anyhow!("Volume specification cannot be empty"));
        }

        let (source_str, dest_str, read_only) = if let Some(idx) = trimmed.find(':') {
            let source_str = trimmed[..idx].to_string();
            let (dest_str, read_only) = parse_volume_dest_and_options(&trimmed[idx + 1..]);
            (source_str, dest_str, read_only)
        } else if trimmed.starts_with('/') {
            (trimmed.to_string(), trimmed.to_string(), false)
        } else {
            (String::new(), trimmed.to_string(), false)
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
                is_volume: true,
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
                is_volume: false,
            })
        } else {
            // Named volume
            let record = match self.find(&source_str) {
                Some(v) => v,
                None => self.create(Some(&source_str), None)?,
            };
            Ok(MountSpec {
                source: PathBuf::from(record.mountpoint),
                destination: dest_str.to_string(),
                read_only,
                is_volume: true,
            })
        }
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

        // Prune: only unused-vol must be deleted, used-vol must be preserved!
        let pruned = store.prune().unwrap();
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
                .contains("volume is in use by container")
        );

        // Removing with force=true must succeed
        let res_force = store.remove_with_force("mounted-vol", true);
        assert!(res_force.is_ok());
    }
}
