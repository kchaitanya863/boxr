//! Podman-compatible secret storage and lifecycle management.
//!
//! Secrets are stored under `~/.boxr/secrets/<name>/` with metadata in `secrets.json`.

use crate::storage::boxr_home;
use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretRecord {
    pub id: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub labels: std::collections::HashMap<String, String>,
    pub driver: String,
    pub size: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct SecretStoreData {
    secrets: Vec<SecretRecord>,
}

pub struct SecretStore {
    index_file: PathBuf,
    secrets_dir: PathBuf,
}

impl SecretStore {
    pub fn new() -> Self {
        Self::with_home(boxr_home())
    }

    pub fn with_home(home: PathBuf) -> Self {
        let secrets_dir = home.join("secrets");
        let _ = fs::create_dir_all(&secrets_dir);
        Self {
            index_file: home.join("secrets.json"),
            secrets_dir,
        }
    }

    fn load_unlocked(&self) -> SecretStoreData {
        if let Ok(content) = fs::read_to_string(&self.index_file) {
            serde_json::from_str(&content).unwrap_or_default()
        } else {
            SecretStoreData::default()
        }
    }

    fn save_unlocked(&self, data: &SecretStoreData) -> Result<()> {
        let content = serde_json::to_string_pretty(data)?;
        let rand_suffix = hex::encode(crate::storage::container_store::rand_id());
        let temp_file = self
            .index_file
            .with_extension(format!("tmp.{}", rand_suffix));
        fs::write(&temp_file, content)?;
        fs::rename(&temp_file, &self.index_file)?;
        Ok(())
    }

    pub fn list(&self) -> Vec<SecretRecord> {
        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            Ok(self.load_unlocked().secrets)
        })
        .unwrap_or_default()
    }

    pub fn find(&self, query: &str) -> Option<SecretRecord> {
        let q = query.trim();
        if q.is_empty() {
            return None;
        }
        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            Ok(self
                .load_unlocked()
                .secrets
                .into_iter()
                .find(|s| s.id == q || s.id.starts_with(q) || s.name == q))
        })
        .ok()
        .flatten()
    }

    pub fn create(
        &self,
        name: Option<&str>,
        data: &[u8],
        labels: std::collections::HashMap<String, String>,
    ) -> Result<SecretRecord> {
        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            let mut store = self.load_unlocked();
            let random_id = hex::encode(crate::storage::container_store::rand_id());
            let secret_name = name
                .map(|n| n.trim().to_string())
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| format!("secret-{}", &random_id[..8]));

            if store.secrets.iter().any(|s| s.name == secret_name) {
                if let Some(existing) = store.secrets.iter().find(|s| s.name == secret_name) {
                    return Ok(existing.clone());
                }
            }

            let secret_dir = self.secrets_dir.join(&secret_name);
            fs::create_dir_all(&secret_dir)?;
            fs::write(secret_dir.join("data"), data)?;

            let record = SecretRecord {
                id: random_id[..12].to_string(),
                name: secret_name,
                created_at: Utc::now(),
                labels,
                driver: "file".to_string(),
                size: data.len() as u64,
            };

            store.secrets.push(record.clone());
            self.save_unlocked(&store)?;
            Ok(record)
        })
    }

    pub fn read_data(&self, query: &str) -> Result<Vec<u8>> {
        let record = self
            .find(query)
            .ok_or_else(|| anyhow!("Secret '{}' not found", query))?;
        let path = self.secrets_dir.join(&record.name).join("data");
        fs::read(path).map_err(|e| anyhow!("Failed to read secret data: {}", e))
    }

    pub fn remove(&self, query: &str) -> Result<SecretRecord> {
        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            let mut store = self.load_unlocked();
            let q = query.trim();
            if let Some(pos) = store
                .secrets
                .iter()
                .position(|s| s.id == q || s.id.starts_with(q) || s.name == q)
            {
                let removed = store.secrets.remove(pos);
                self.save_unlocked(&store)?;
                let secret_dir = self.secrets_dir.join(&removed.name);
                if secret_dir.exists() {
                    let _ = fs::remove_dir_all(secret_dir);
                }
                Ok(removed)
            } else {
                Err(anyhow!("Secret '{}' not found", query))
            }
        })
    }

    pub fn exists(&self, query: &str) -> bool {
        self.find(query).is_some()
    }
}

pub fn ensure_secret_exists(name: &str) -> Result<()> {
    let store = SecretStore::new();
    if !store.exists(name) {
        return Err(anyhow!("Secret '{}' not found", name));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_secret_lifecycle() {
        let temp = tempdir().unwrap();
        let store = SecretStore::with_home(temp.path().to_path_buf());

        let secret = store
            .create(
                Some("db-password"),
                b"s3cr3t",
                std::collections::HashMap::new(),
            )
            .unwrap();
        assert_eq!(secret.name, "db-password");
        assert_eq!(store.list().len(), 1);
        assert_eq!(store.read_data("db-password").unwrap(), b"s3cr3t");

        store.remove("db-password").unwrap();
        assert!(store.list().is_empty());
    }
}
