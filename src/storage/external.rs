//! Buildah / Podman "external" container name reservations (BATS parity).

use anyhow::{anyhow, Result};
use std::fs;
use std::path::PathBuf;

use super::container_state_home;

fn external_names_file() -> PathBuf {
    container_state_home().join("external-container-names")
}

pub fn register_external_name(name: &str) -> Result<()> {
    let name = name.trim();
    if name.is_empty() {
        return Err(anyhow!("external container name must not be empty"));
    }
    let path = external_names_file();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
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
    Ok(
        content
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(String::from)
            .collect(),
    )
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
