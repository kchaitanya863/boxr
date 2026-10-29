//! Cached libpod-style storage paths (`005-info.bats` database validation).

use crate::cli::podman_globals::podman_global_options;
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorageDbConfig {
    pub graph_root: String,
    pub run_root: String,
    pub tmpdir: String,
    pub volume_path: String,
}

pub fn effective_volume_path() -> PathBuf {
    let globals = podman_global_options();
    if let Some(vp) = &globals.volumepath {
        return vp.clone();
    }
    super::boxr_home().join("volumes")
}

fn current_config() -> StorageDbConfig {
    let graph_root = super::boxr_home();
    let globals = podman_global_options();
    StorageDbConfig {
        graph_root: graph_root.display().to_string(),
        run_root: globals
            .runroot
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| graph_root.display().to_string()),
        tmpdir: globals
            .tmpdir
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| std::env::temp_dir().display().to_string()),
        volume_path: effective_volume_path().display().to_string(),
    }
}

fn config_path(graph_root: &Path) -> PathBuf {
    graph_root.join("db-config.json")
}

fn volume_index_has_entries(graph_root: &Path) -> bool {
    let index = graph_root.join("volumes.json");
    if !index.exists() {
        return false;
    }
    let Ok(content) = fs::read_to_string(&index) else {
        return false;
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&content) else {
        return false;
    };
    v.get("volumes")
        .and_then(|a| a.as_array())
        .is_some_and(|a| !a.is_empty())
}

/// Sync or validate cached storage paths before volume/storage commands.
pub fn ensure_storage_db_config() -> Result<()> {
    let graph_root = super::boxr_home();
    fs::create_dir_all(&graph_root)?;
    fs::create_dir_all(effective_volume_path())?;

    let path = config_path(&graph_root);
    let current = current_config();

    if !path.exists() {
        let content = serde_json::to_string_pretty(&current)?;
        fs::write(&path, content)?;
        return Ok(());
    }

    let cached: StorageDbConfig =
        serde_json::from_str(&fs::read_to_string(&path)?).unwrap_or_else(|_| current.clone());

    if cached.volume_path != current.volume_path && volume_index_has_entries(&graph_root) {
        bail!(
            "database configuration mismatch: storage-volume-path in database ({}), does not match what was requested ({})",
            cached.volume_path,
            current.volume_path
        );
    }

    if cached != current && !volume_index_has_entries(&graph_root) {
        let content = serde_json::to_string_pretty(&current)?;
        fs::write(&path, content)?;
    }

    Ok(())
}

pub fn check_oci_runtime_exit_dir() -> Result<()> {
    let globals = podman_global_options();
    let tmpdir = globals
        .tmpdir
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(|| super::boxr_home().join("tmp"));
    let exits = tmpdir.join("exits");
    if exits.exists() && !exits.is_dir() {
        let runtime = crate::cli::info_report::default_oci_runtime_name();
        bail!(
            "default OCI runtime \"{runtime}\" failed to initialize: creating OCI runtime exit files directory: {}: not a directory",
            exits.display()
        );
    }
    Ok(())
}
