use crate::storage::container_state_home;
use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

pub fn rand_id() -> [u8; 6] {
    let mut bytes = [0u8; 6];
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let pid = std::process::id();
    let combined = now ^ ((pid as u128) << 32);
    let mut hasher = Sha256::new();
    hasher.update(combined.to_le_bytes());
    let hash = hasher.finalize();
    bytes.copy_from_slice(&hash[..6]);
    bytes
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContainerStatus {
    Created,
    Running,
    Stopping,
    Paused,
    Exited(i32),
    Failed(String),
}

impl std::fmt::Display for ContainerStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContainerStatus::Created => write!(f, "Created"),
            ContainerStatus::Running => write!(f, "Up"),
            ContainerStatus::Stopping => write!(f, "Stopping"),
            ContainerStatus::Paused => write!(f, "Paused"),
            ContainerStatus::Exited(code) => write!(f, "Exited ({})", code),
            ContainerStatus::Failed(err) => write!(f, "Failed: {}", err),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerRecord {
    pub id: String,
    pub name: String,
    pub image: String,
    pub command: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub status: ContainerStatus,
    pub bundle_path: String,
    #[serde(default)]
    pub restart_policy: crate::health::RestartPolicy,
    #[serde(default = "default_health_status")]
    pub health_status: crate::health::HealthStatus,
    #[serde(default)]
    pub restart_count: u32,
    #[serde(default)]
    pub ports: Vec<crate::network::PortMapping>,
    #[serde(default)]
    pub exposed_ports: Vec<String>,
}

fn default_health_status() -> crate::health::HealthStatus {
    crate::health::HealthStatus::None
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct ContainerStoreData {
    containers: Vec<ContainerRecord>,
}

pub struct ContainerStore {
    index_file: PathBuf,
}

impl ContainerStore {
    pub fn new() -> Self {
        Self::with_home(container_state_home())
    }

    pub fn with_home(home: PathBuf) -> Self {
        Self {
            index_file: home.join("containers.json"),
        }
    }

    fn load_unlocked(&self) -> ContainerStoreData {
        if let Ok(content) = fs::read_to_string(&self.index_file) {
            serde_json::from_str(&content).unwrap_or_default()
        } else {
            ContainerStoreData::default()
        }
    }

    fn save_unlocked(&self, data: &ContainerStoreData) -> Result<()> {
        let content = serde_json::to_string_pretty(data)?;
        let rand_suffix = hex::encode(rand_id());
        let temp_file = self
            .index_file
            .with_extension(format!("tmp.{}", rand_suffix));
        fs::write(&temp_file, content)?;
        fs::rename(&temp_file, &self.index_file)?;
        Ok(())
    }

    pub fn list(&self) -> Vec<ContainerRecord> {
        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            Ok(self.load_unlocked().containers)
        })
        .unwrap_or_default()
    }

    #[allow(dead_code)]
    pub fn normalize_container_name(name: &str) -> String {
        name.trim().trim_start_matches('/').to_string()
    }

    pub fn find(&self, query: &str) -> Option<ContainerRecord> {
        let q = Self::normalize_container_name(query);
        if q.is_empty() {
            return None;
        }
        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            Ok(self
                .load_unlocked()
                .containers
                .into_iter()
                .find(|c| c.id == q || c.id.starts_with(&q) || c.name == q))
        })
        .ok()
        .flatten()
    }

    pub fn add(&self, record: ContainerRecord) -> Result<()> {
        let name = Self::normalize_container_name(&record.name);
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.')
        {
            return Err(anyhow!(
                "Invalid container name '{}': must be alphanumeric, '_', '-', or '.'",
                record.name
            ));
        }

        let record = ContainerRecord {
            name,
            ..record
        };

        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            let mut data = self.load_unlocked();
            if let Some(existing) = data
                .containers
                .iter()
                .find(|c| c.name == record.name && c.id != record.id)
            {
                return Err(anyhow!(
                    "creating container storage: the container name \"{}\" is already in use by {} You have to remove that container to be able to reuse that name: that name is already in use, or use --replace to instruct Podman to do so.",
                    record.name,
                    existing.id
                ));
            }
            data.containers.retain(|c| c.id != record.id);
            data.containers.push(record);
            self.save_unlocked(&data)?;
            Ok(())
        })
    }

    pub fn update_status(&self, id_or_name: &str, status: ContainerStatus) -> Result<()> {
        let q = Self::normalize_container_name(id_or_name);
        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            let mut data = self.load_unlocked();
            if let Some(c) = data.containers.iter_mut().find(|c| {
                c.id == q || c.id.starts_with(&q) || c.name == q
            }) {
                // SIGKILL during `podman stop` (separate process) must not be downgraded.
                if matches!(c.status, ContainerStatus::Exited(137))
                    && !matches!(status, ContainerStatus::Exited(137))
                {
                    return Ok(());
                }
                c.status = status;
                self.save_unlocked(&data)?;
                Ok(())
            } else {
                Err(anyhow!("Container not found: {}", id_or_name))
            }
        })
    }

    pub fn increment_restart_count(&self, id_or_name: &str) -> Result<u32> {
        let q = Self::normalize_container_name(id_or_name);
        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            let mut data = self.load_unlocked();
            if let Some(c) = data.containers.iter_mut().find(|c| {
                c.id == q || c.id.starts_with(&q) || c.name == q
            }) {
                c.restart_count += 1;
                let count = c.restart_count;
                self.save_unlocked(&data)?;
                Ok(count)
            } else {
                Err(anyhow!("Container not found: {}", id_or_name))
            }
        })
    }

    pub fn update_health_status(
        &self,
        id_or_name: &str,
        status: crate::health::HealthStatus,
    ) -> Result<()> {
        let q = Self::normalize_container_name(id_or_name);
        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            let mut data = self.load_unlocked();
            if let Some(c) = data.containers.iter_mut().find(|c| {
                c.id == q || c.id.starts_with(&q) || c.name == q
            }) {
                c.health_status = status;
                self.save_unlocked(&data)?;
                Ok(())
            } else {
                Err(anyhow!("Container not found: {}", id_or_name))
            }
        })
    }

    pub fn rename(&self, old_query: &str, new_name: &str) -> Result<()> {
        let new_name_trimmed = Self::normalize_container_name(new_name);
        if new_name_trimmed.is_empty()
            || !new_name_trimmed
                .chars()
                .all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.')
        {
            return Err(anyhow!(
                "Invalid container name '{}': must be alphanumeric, '_', '-', or '.'",
                new_name
            ));
        }

        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            let mut data = self.load_unlocked();

            let old_q = Self::normalize_container_name(old_query);
            let old_container = data
                .containers
                .iter()
                .find(|c| c.id == old_q || c.id.starts_with(&old_q) || c.name == old_q)
                .ok_or_else(|| anyhow!("Container not found: {}", old_query))?;

            let old_id = old_container.id.clone();
            if old_container.name == new_name_trimmed {
                return Ok(());
            }

            if data
                .containers
                .iter()
                .any(|c| c.name == new_name_trimmed && c.id != old_id)
            {
                return Err(anyhow!(
                    "Container name '{}' is already in use",
                    new_name_trimmed
                ));
            }

            if let Some(c) = data.containers.iter_mut().find(|c| c.id == old_id) {
                c.name = new_name_trimmed.to_string();
                self.save_unlocked(&data)?;
                Ok(())
            } else {
                Err(anyhow!("Container not found: {}", old_query))
            }
        })
    }

    pub fn remove(&self, query: &str) -> Result<ContainerRecord> {
        let q = Self::normalize_container_name(query);
        if q.is_empty() {
            return Err(anyhow!("Container not found: ''"));
        }
        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            let mut data = self.load_unlocked();
            let pos = data
                .containers
                .iter()
                .position(|c| c.id == q || c.id.starts_with(&q) || c.name == q);

            if let Some(index) = pos {
                let removed = data.containers.remove(index);
                self.save_unlocked(&data)?;

                // Clean up bundle folder
                let bundle = PathBuf::from(&removed.bundle_path);
                if bundle.exists() {
                    #[cfg(unix)]
                    {
                        let mut pids = Vec::new();
                        if let Ok(pid_str) = std::fs::read_to_string(bundle.join("vm.pid")) {
                            if let Ok(pid) = pid_str.trim().parse::<i32>() {
                                pids.push(pid);
                            }
                        }
                        if let Ok(pid_str) = std::fs::read_to_string(bundle.join("container.pid")) {
                            if let Ok(pid) = pid_str.trim().parse::<i32>() {
                                pids.push(pid);
                            }
                        }
                        for pid in pids {
                            unsafe {
                                libc::kill(pid, libc::SIGTERM);
                                let _ = libc::kill(-pid, libc::SIGTERM);
                            }
                            for _ in 0..40 {
                                std::thread::sleep(std::time::Duration::from_millis(50));
                                if unsafe { libc::kill(pid, 0) != 0 } {
                                    break;
                                }
                            }
                            if unsafe { libc::kill(pid, 0) == 0 } {
                                unsafe {
                                    libc::kill(pid, libc::SIGKILL);
                                    let _ = libc::kill(-pid, libc::SIGKILL);
                                }
                            }
                        }
                    }
                    #[cfg(target_os = "windows")]
                    {
                        let pid_file = bundle.join("vm.pid");
                        if let Ok(pid_str) = std::fs::read_to_string(pid_file) {
                            if let Ok(pid) = pid_str.trim().parse::<u32>() {
                                let _ = std::process::Command::new("taskkill")
                                    .args(["/F", "/PID", &pid.to_string()])
                                    .output();
                            }
                        }
                    }

                    if bundle_conmon_is_current_process(&bundle) {
                        let _ = fs::write(bundle.join("deferred-bundle-rm"), "1");
                    } else {
                        let _ = fs::remove_dir_all(bundle);
                    }
                }

                Ok(removed)
            } else {
                Err(anyhow!("Container not found: {}", query))
            }
        })
    }
}

#[cfg(unix)]
fn bundle_conmon_is_current_process(bundle: &Path) -> bool {
    if let Ok(s) = fs::read_to_string(bundle.join("conmon.pid")) {
        if let Ok(cp) = s.trim().parse::<i32>() {
            return cp == unsafe { libc::getpid() };
        }
    }
    false
}

#[cfg(not(unix))]
fn bundle_conmon_is_current_process(_bundle: &Path) -> bool {
    false
}

impl super::traits::ContainerReader for ContainerStore {
    fn find(&self, id_or_name: &str) -> Option<ContainerRecord> {
        self.find(id_or_name)
    }

    fn list(&self) -> Vec<ContainerRecord> {
        self.list()
    }
}

impl super::traits::ContainerWriter for ContainerStore {
    fn add(&self, record: ContainerRecord) -> Result<()> {
        self.add(record)
    }

    fn update_status(&self, id_or_name: &str, status: ContainerStatus) -> Result<()> {
        self.update_status(id_or_name, status)
    }

    fn remove(&self, id_or_name: &str) -> Result<()> {
        self.remove(id_or_name).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_container_store_lifecycle() {
        let temp = tempdir().unwrap();
        let store = ContainerStore {
            index_file: temp.path().join("containers.json"),
        };

        let rec = ContainerRecord {
            id: "aabbccddeeff".to_string(),
            name: "test-box".to_string(),
            image: "alpine:latest".to_string(),
            command: vec!["/bin/sh".to_string()],
            created_at: Utc::now(),
            status: ContainerStatus::Running,
            bundle_path: temp.path().join("bundle").to_string_lossy().to_string(),
            restart_policy: crate::health::RestartPolicy::No,
            health_status: crate::health::HealthStatus::None,
            restart_count: 0,
            ports: Vec::new(),
            exposed_ports: Vec::new(),
        };

        store.add(rec).unwrap();
        assert_eq!(store.list().len(), 1);

        assert!(store.find("aabbcc").is_some());
        assert!(store.find("test-box").is_some());

        store
            .update_status("aabbcc", ContainerStatus::Paused)
            .unwrap();
        let updated = store.find("test-box").unwrap();
        assert_eq!(updated.status, ContainerStatus::Paused);

        store
            .update_health_status("aabbcc", crate::health::HealthStatus::Healthy)
            .unwrap();
        let updated = store.find("test-box").unwrap();
        assert_eq!(updated.health_status, crate::health::HealthStatus::Healthy);

        store.rename("test-box", "renamed-box").unwrap();
        assert!(store.find("renamed-box").is_some());
        assert!(store.find("test-box").is_none());

        store.remove("renamed-box").unwrap();
        assert_eq!(store.list().len(), 0);
    }
}
