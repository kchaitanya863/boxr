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
    #[serde(default)]
    pub driver_opts: std::collections::HashMap<String, String>,
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
        self.find_strict(query).ok()
    }

    pub fn find_strict(&self, query: &str) -> Result<SecretRecord> {
        let q = query.trim();
        if q.is_empty() {
            return Err(anyhow!(
                "no secret with name or id {:?}: no such secret",
                query
            ));
        }
        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            let secrets = self.load_unlocked().secrets;
            if let Some(exact) = secrets.iter().find(|s| s.name == q || s.id == q) {
                return Ok(exact.clone());
            }
            let prefix_matches: Vec<SecretRecord> = secrets
                .into_iter()
                .filter(|s| s.id.starts_with(q))
                .collect();
            if prefix_matches.len() == 1 {
                Ok(prefix_matches.into_iter().next().unwrap())
            } else if prefix_matches.len() > 1 {
                Err(anyhow!(
                    "multiple secrets with prefix {:?}: secret is ambiguous",
                    q
                ))
            } else {
                Err(anyhow!(
                    "no secret with name or id {:?}: no such secret",
                    q
                ))
            }
        })
    }

    pub fn create(
        &self,
        name: Option<&str>,
        data: &[u8],
        labels: std::collections::HashMap<String, String>,
    ) -> Result<SecretRecord> {
        self.create_with_options(
            name,
            data,
            labels,
            "file",
            std::collections::HashMap::new(),
            false,
            false,
        )
    }

    pub fn create_with_options(
        &self,
        name: Option<&str>,
        data: &[u8],
        labels: std::collections::HashMap<String, String>,
        driver: &str,
        driver_opts: std::collections::HashMap<String, String>,
        ignore: bool,
        replace: bool,
    ) -> Result<SecretRecord> {
        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            let mut store = self.load_unlocked();
            let random_id = hex::encode(crate::storage::container_store::rand_id());
            let secret_name = name
                .map(|n| n.trim().to_string())
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| format!("secret-{}", &random_id[..8]));

            if secret_name.is_empty()
                || secret_name.len() > 253
                || secret_name
                    .chars()
                    .any(|c| c == '=' || c == '/' || c == ',' || c == '\0')
            {
                return Err(anyhow!(
                    "secret name {:?} can not include '=', '/', ',', or the '\\0' (NULL) and be between 1 and 253 characters: invalid secret name",
                    secret_name
                ));
            }

            if driver != "file" && driver != "pass" && driver != "shell" {
                return Err(anyhow!("invalid secret driver {:?}", driver));
            }
            if driver == "shell" {
                let has_all = ["list", "lookup", "store", "delete"]
                    .iter()
                    .all(|k| driver_opts.contains_key(*k));
                if !has_all {
                    return Err(anyhow!(
                        "missing config value: shell driver requires list, lookup, store, delete"
                    ));
                }
            }

            if let Some(pos) = store.secrets.iter().position(|s| s.name == secret_name) {
                if ignore {
                    return Ok(store.secrets[pos].clone());
                }
                if replace {
                    let old = store.secrets.remove(pos);
                    let old_dir = self.secrets_dir.join(&old.name);
                    if old_dir.exists() {
                        let _ = fs::remove_dir_all(old_dir);
                    }
                } else {
                    return Err(anyhow!("{}: secret name in use", secret_name));
                }
            }

            let secret_dir = self.secrets_dir.join(&secret_name);
            fs::create_dir_all(&secret_dir)?;
            fs::write(secret_dir.join("data"), data)?;

            let mut full_id = format!(
                "{}{}",
                random_id,
                hex::encode(crate::storage::container_store::rand_id())
            );
            full_id.truncate(25);

            let record = SecretRecord {
                id: full_id,
                name: secret_name,
                created_at: Utc::now(),
                labels,
                driver: driver.to_string(),
                driver_opts,
                size: data.len() as u64,
            };

            store.secrets.push(record.clone());
            self.save_unlocked(&store)?;
            Ok(record)
        })
    }

    pub fn read_data(&self, query: &str) -> Result<Vec<u8>> {
        let record = self.find_strict(query)?;
        let path = self.secrets_dir.join(&record.name).join("data");
        fs::read(path).map_err(|e| anyhow!("Failed to read secret data: {}", e))
    }

    pub fn remove(&self, query: &str) -> Result<SecretRecord> {
        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            let mut store = self.load_unlocked();
            let q = query.trim();
            let pos = if let Some(p) = store.secrets.iter().position(|s| s.name == q || s.id == q) {
                p
            } else {
                let prefix_matches: Vec<usize> = store
                    .secrets
                    .iter()
                    .enumerate()
                    .filter(|(_, s)| s.id.starts_with(q))
                    .map(|(i, _)| i)
                    .collect();
                if prefix_matches.len() == 1 {
                    prefix_matches[0]
                } else if prefix_matches.len() > 1 {
                    return Err(anyhow!(
                        "multiple secrets with prefix {:?}: secret is ambiguous",
                        q
                    ));
                } else {
                    return Err(anyhow!(
                        "no secret with name or id {:?}: no such secret",
                        q
                    ));
                }
            };
            let removed = store.secrets.remove(pos);
            self.save_unlocked(&store)?;
            let secret_dir = self.secrets_dir.join(&removed.name);
            if secret_dir.exists() {
                let _ = fs::remove_dir_all(secret_dir);
            }
            Ok(removed)
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
