//! Multi-architecture image builder farm manager (Podman `farm` parity).

use crate::storage::boxr_home;
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConnectionsFile {
    #[serde(default)]
    pub connection: ConnectionSection,
    #[serde(default)]
    pub farm: FarmSection,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConnectionSection {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub default: String,
    #[serde(default)]
    pub connections: BTreeMap<String, DestinationEntry>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DestinationEntry {
    #[serde(default, rename = "uri", alias = "URI")]
    pub uri: String,
    #[serde(
        default,
        skip_serializing_if = "String::is_empty",
        rename = "identity",
        alias = "Identity"
    )]
    pub identity: String,
    #[serde(
        default,
        skip_serializing_if = "String::is_empty",
        rename = "tls_cert",
        alias = "TLSCert"
    )]
    pub tls_cert: String,
    #[serde(
        default,
        skip_serializing_if = "String::is_empty",
        rename = "tls_key",
        alias = "TLSKey"
    )]
    pub tls_key: String,
    #[serde(
        default,
        skip_serializing_if = "String::is_empty",
        rename = "tls_ca",
        alias = "TLSCA"
    )]
    pub tls_ca: String,
    #[serde(
        default,
        skip_serializing_if = "std::ops::Not::not",
        rename = "is_machine",
        alias = "IsMachine"
    )]
    pub is_machine: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FarmSection {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub default: String,
    #[serde(default)]
    pub list: BTreeMap<String, Vec<String>>,
}

pub fn connections_conf_path() -> PathBuf {
    if let Ok(p) = std::env::var("PODMAN_CONNECTIONS_CONF") {
        if !p.trim().is_empty() {
            return PathBuf::from(p);
        }
    }
    boxr_home().join("connections.json")
}

pub fn load_connections_file() -> ConnectionsFile {
    let path = connections_conf_path();
    if let Ok(content) = fs::read_to_string(&path) {
        serde_json::from_str(&content).unwrap_or_default()
    } else {
        ConnectionsFile::default()
    }
}

pub fn save_connections_file(cfg: &ConnectionsFile) -> Result<()> {
    let path = connections_conf_path();
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let content = serde_json::to_string_pretty(cfg)?;
    fs::write(&path, content)?;
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FarmRecord {
    pub name: String,
    pub connections: Vec<String>,
    pub is_default: bool,
    pub read_write: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct FarmStoreIndex {
    farms: Vec<FarmRecord>,
}

pub struct FarmManager {
    store_file: PathBuf,
}

impl FarmManager {
    pub fn new() -> Self {
        Self::with_home(boxr_home())
    }

    pub fn with_home(home: PathBuf) -> Self {
        let _ = fs::create_dir_all(&home);
        Self {
            store_file: home.join("farms.json"),
        }
    }

    fn load(&self) -> FarmStoreIndex {
        if let Ok(content) = fs::read_to_string(&self.store_file) {
            serde_json::from_str(&content).unwrap_or_default()
        } else {
            FarmStoreIndex::default()
        }
    }

    fn save(&self, data: &FarmStoreIndex) -> Result<()> {
        let content = serde_json::to_string_pretty(data)?;
        let rand_suffix = hex::encode(crate::storage::container_store::rand_id());
        let temp_file = self
            .store_file
            .with_extension(format!("tmp.{}", rand_suffix));
        fs::write(&temp_file, content)?;
        fs::rename(&temp_file, &self.store_file)?;
        Ok(())
    }

    pub fn create(&self, name: &str, connections: &[String]) -> Result<FarmRecord> {
        let mut index = self.load();
        if index.farms.iter().any(|f| f.name == name) {
            return Err(anyhow!("Farm '{}' already exists", name));
        }
        let is_first = index.farms.is_empty();
        let record = FarmRecord {
            name: name.to_string(),
            connections: connections.to_vec(),
            is_default: is_first,
            read_write: true,
        };
        index.farms.push(record.clone());
        self.save(&index)?;
        Ok(record)
    }

    pub fn list(&self) -> Vec<FarmRecord> {
        self.load().farms
    }

    pub fn find(&self, name: &str) -> Option<FarmRecord> {
        self.load().farms.into_iter().find(|f| f.name == name)
    }

    pub fn remove(&self, name: &str) -> Result<FarmRecord> {
        let mut index = self.load();
        let pos = index
            .farms
            .iter()
            .position(|f| f.name == name)
            .ok_or_else(|| anyhow!("Farm '{}' not found", name))?;
        let removed = index.farms.remove(pos);
        self.save(&index)?;
        Ok(removed)
    }

    pub fn remove_all(&self) -> Result<usize> {
        let index = self.load();
        let count = index.farms.len();
        self.save(&FarmStoreIndex::default())?;
        Ok(count)
    }

    pub fn update(
        &self,
        name: &str,
        add: &[String],
        remove: &[String],
        set_default: bool,
    ) -> Result<FarmRecord> {
        let mut index = self.load();
        let pos = index
            .farms
            .iter()
            .position(|f| f.name == name)
            .ok_or_else(|| anyhow!("Farm '{}' not found", name))?;

        if set_default {
            for f in &mut index.farms {
                f.is_default = false;
            }
        }

        let farm = &mut index.farms[pos];
        if set_default {
            farm.is_default = true;
        }

        for a in add {
            if !farm.connections.contains(a) {
                farm.connections.push(a.clone());
            }
        }

        farm.connections.retain(|c| !remove.contains(c));
        let updated = farm.clone();
        self.save(&index)?;
        Ok(updated)
    }
}
