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

const MINIMAL_SQLITE_DB_HEX: &str = "53514c69746520666f726d61742033000200010100402020000000020000000300000000000000000000000200000004000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000002002e99b00d00000002016d0001b5016d0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000046020617232301557461626c65566f6c756d655374617465566f6c756d65537461746503435245415445205441424c4520566f6c756d65537461746520284e616d6520544558542949010617252501577461626c65566f6c756d65436f6e666967566f6c756d65436f6e66696702435245415445205441424c4520566f6c756d65436f6e66696720284e616d652054455854290d00000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000d00000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

const MINIMAL_SQLITE_DB_GZ_HEX: &str = "1f8b08000f3fe66a02ffedd73b0ac2401485e13b51ec443bdb81206863e3067c30821004757cb411a2041203322ec65dd8b83f132c9c42b00fff07339ccb85db9fed3a4a5da2cfc52d8f9d1e4b57949289d6221294af215fd5dcf46625ff05327a3cdb55e8e4d279951f000000000075b7085abd30543b179fb2645f64f73cd9bad8f9b131df98a935da4e6791d1de420f56719e686b8e76b854ad5ebfaf0ede9d79713da7173f073f2e7d36fea9aa9b97a51f0000000000d418fd1f0000000080fa7b03656a225700300000";

pub fn ensure_sqlite_db(graph_root: &Path) {
    let db_path = graph_root.join("db.sql");
    if !db_path.exists() {
        let _ = fs::create_dir_all(graph_root);
        if let Ok(gz_bytes) = hex::decode(MINIMAL_SQLITE_DB_GZ_HEX) {
            use std::io::Read;
            let mut decoder = flate2::read::GzDecoder::new(&gz_bytes[..]);
            let mut raw = Vec::new();
            if decoder.read_to_end(&mut raw).is_ok() {
                let _ = fs::write(&db_path, raw);
            }
        }
    }
}

/// Sync or validate cached storage paths before volume/storage commands.
pub fn ensure_storage_db_config() -> Result<()> {
    let graph_root = super::boxr_home();
    fs::create_dir_all(&graph_root)?;
    fs::create_dir_all(effective_volume_path())?;
    ensure_sqlite_db(&graph_root);

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
