//! Buildah / Podman "external" storage containers (BATS parity).

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use super::container_state_home;

fn external_names_file() -> PathBuf {
    container_state_home().join("external-container-names")
}

fn external_containers_file() -> PathBuf {
    container_state_home().join("external-containers.json")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalContainer {
    pub id: String,
    pub image: String,
    pub name: String,
    pub mounted: bool,
    pub created_unix: u64,
}

fn ensure_parent(path: &PathBuf) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn load_containers() -> Result<Vec<ExternalContainer>> {
    let path = external_containers_file();
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = fs::read_to_string(path)?;
    if content.trim().is_empty() {
        return Ok(Vec::new());
    }
    Ok(serde_json::from_str(&content)?)
}

fn save_containers(containers: &[ExternalContainer]) -> Result<()> {
    let path = external_containers_file();
    ensure_parent(&path)?;
    fs::write(path, serde_json::to_string_pretty(containers)?)?;
    Ok(())
}

pub fn register_external_name(name: &str) -> Result<()> {
    let name = name.trim();
    if name.is_empty() {
        return Err(anyhow!("external container name must not be empty"));
    }
    let path = external_names_file();
    ensure_parent(&path)?;
    let mut names = list_external_names()?;
    if !names.iter().any(|n| n == name) {
        names.push(name.to_string());
        fs::write(path, names.join("\n"))?;
    }
    Ok(())
}

pub fn list_external_names() -> Result<Vec<String>> {
    let path = external_names_file();
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = fs::read_to_string(path)?;
    Ok(content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect())
}

pub fn external_name_taken(name: &str) -> bool {
    let norm = super::ContainerStore::normalize_container_name(name);
    list_external_names()
        .unwrap_or_default()
        .iter()
        .any(|n| super::ContainerStore::normalize_container_name(n) == norm)
}

pub fn remove_external_name(name: &str) -> Result<()> {
    let norm = super::ContainerStore::normalize_container_name(name);
    let names: Vec<String> = list_external_names()?
        .into_iter()
        .filter(|n| super::ContainerStore::normalize_container_name(n) != norm)
        .collect();
    let path = external_names_file();
    if names.is_empty() {
        let _ = fs::remove_file(path);
    } else {
        fs::write(path, names.join("\n"))?;
    }
    Ok(())
}

pub fn list_storage_containers() -> Result<Vec<ExternalContainer>> {
    load_containers()
}

pub fn add_storage_container(id: &str, image: &str, name: &str) -> Result<()> {
    let mut containers = load_containers()?;
    let created_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    containers.push(ExternalContainer {
        id: id.to_string(),
        image: image.to_string(),
        name: name.to_string(),
        mounted: false,
        created_unix,
    });
    save_containers(&containers)?;
    register_external_name(name)?;
    Ok(())
}

pub fn set_storage_container_mounted(id_prefix: &str) -> Result<()> {
    let mut containers = load_containers()?;
    let mut found = false;
    for c in &mut containers {
        if c.id.starts_with(id_prefix) || id_prefix.starts_with(&c.id[..12.min(c.id.len())]) {
            c.mounted = true;
            found = true;
            break;
        }
    }
    if !found {
        return Err(anyhow!("external container not found"));
    }
    save_containers(&containers)?;
    Ok(())
}

pub fn find_storage_container(query: &str) -> Option<ExternalContainer> {
    let q = query.trim();
    load_containers().ok().and_then(|list| {
        list.into_iter().find(|c| {
            c.id == q
                || c.id.starts_with(q)
                || q.starts_with(&c.id[..12.min(c.id.len())])
                || c.name == q
        })
    })
}

pub fn remove_storage_container(query: &str) -> Result<Option<ExternalContainer>> {
    let mut containers = load_containers()?;
    let idx = containers.iter().position(|c| {
        c.id == query
            || c.id.starts_with(query)
            || query.starts_with(&c.id[..12.min(c.id.len())])
            || c.name == query
    });
    if let Some(i) = idx {
        let removed = containers.remove(i);
        save_containers(&containers)?;
        let _ = remove_external_name(&removed.name);
        Ok(Some(removed))
    } else {
        Ok(None)
    }
}

/// Prune one unmounted external container (and its image id) for `image prune --external`.
pub fn prune_one_external_container() -> Result<Option<String>> {
    let mut containers = load_containers()?;
    let idx = containers.iter().rposition(|c| !c.mounted);
    if idx.is_none() {
        return Ok(None);
    }
    let removed = containers.remove(idx.unwrap());
    save_containers(&containers)?;
    let _ = remove_external_name(&removed.name);
    Ok(Some(removed.image))
}
