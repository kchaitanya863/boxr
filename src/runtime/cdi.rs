//! Container Device Interface (CDI) specification parser and device resolver.
//! Supports `/etc/cdi`, `/var/run/cdi`, `~/.boxr/cdi`, `containers.conf` `cdi_spec_dirs`, and `--cdi-spec-dir`.

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CdiSpec {
    #[serde(default)]
    pub cdi_version: String,
    pub kind: String,
    #[serde(default)]
    pub annotations: std::collections::HashMap<String, String>,
    #[serde(default)]
    pub devices: Vec<CdiDevice>,
    #[serde(default)]
    pub container_edits: Option<CdiContainerEdits>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CdiDevice {
    pub name: String,
    #[serde(default)]
    pub annotations: std::collections::HashMap<String, String>,
    #[serde(default)]
    pub container_edits: CdiContainerEdits,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CdiContainerEdits {
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default)]
    pub device_nodes: Vec<CdiDeviceNode>,
    #[serde(default)]
    pub mounts: Vec<CdiMount>,
    #[serde(default)]
    pub hooks: Vec<CdiHook>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CdiDeviceNode {
    pub path: String,
    #[serde(default)]
    pub host_path: Option<String>,
    #[serde(rename = "type", default)]
    pub dev_type: Option<String>,
    #[serde(default)]
    pub major: Option<i64>,
    #[serde(default)]
    pub minor: Option<i64>,
    #[serde(default)]
    pub file_mode: Option<u32>,
    #[serde(default)]
    pub permissions: Option<String>,
    #[serde(default)]
    pub uid: Option<u32>,
    #[serde(default)]
    pub gid: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CdiMount {
    pub host_path: String,
    pub container_path: String,
    #[serde(rename = "type", default)]
    pub mount_type: Option<String>,
    #[serde(default)]
    pub options: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CdiHook {
    pub hook_name: String,
    pub path: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default)]
    pub timeout: Option<i64>,
}

#[derive(Debug, Clone, Default)]
pub struct ResolvedCdiEdits {
    pub env: Vec<String>,
    pub device_nodes: Vec<CdiDeviceNode>,
    pub mounts: Vec<CdiMount>,
    pub hooks: Vec<CdiHook>,
    pub non_cdi_devices: Vec<String>,
}

pub struct CdiManager;

impl CdiManager {
    /// Return effective CDI specification directories from CLI `--cdi-spec-dir`,
    /// `containers.conf` (`cdi_spec_dirs`), or defaults (`/etc/cdi`, `/var/run/cdi`, `~/.boxr/cdi`).
    pub fn effective_spec_dirs() -> Vec<String> {
        let globals = crate::cli::podman_globals::podman_global_options();
        if !globals.cdi_spec_dirs.is_empty() {
            return globals.cdi_spec_dirs.clone();
        }
        let conf_dirs = crate::containers_conf_string_array("cdi_spec_dirs");
        if !conf_dirs.is_empty() {
            return conf_dirs;
        }
        let mut dirs = vec!["/etc/cdi".to_string(), "/var/run/cdi".to_string()];
        let boxr_cdi = crate::storage::boxr_home().join("cdi");
        if boxr_cdi.exists() {
            dirs.push(boxr_cdi.to_string_lossy().to_string());
        }
        dirs
    }

    /// Load all valid CDI specifications from the given directories.
    pub fn load_specs(spec_dirs: &[String]) -> Vec<CdiSpec> {
        let mut specs = Vec::new();
        for dir in spec_dirs {
            let path = Path::new(dir);
            if !path.is_dir() {
                continue;
            }
            let Ok(entries) = fs::read_dir(path) else {
                continue;
            };
            let mut paths: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
            paths.sort();
            for p in paths {
                if !p.is_file() {
                    continue;
                }
                let ext = p
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("")
                    .to_ascii_lowercase();
                let Ok(raw) = fs::read_to_string(&p) else {
                    continue;
                };
                if ext == "json" {
                    if let Ok(spec) = serde_json::from_str::<CdiSpec>(&raw) {
                        if !spec.kind.is_empty() {
                            specs.push(spec);
                        }
                    }
                } else if ext == "yaml" || ext == "yml" {
                    if let Ok(spec) = serde_yaml::from_str::<CdiSpec>(&raw) {
                        if !spec.kind.is_empty() {
                            specs.push(spec);
                        }
                    }
                }
            }
        }
        specs
    }

    /// List all discovered CDI qualified device names (`vendor.com/class=name`).
    pub fn discovered_devices(spec_dirs: &[String]) -> Vec<String> {
        let mut devices = Vec::new();
        for spec in Self::load_specs(spec_dirs) {
            for dev in spec.devices {
                devices.push(format!("{}={}", spec.kind, dev.name));
            }
        }
        devices.sort();
        devices.dedup();
        devices
    }

    /// Check if a `--device` argument is a CDI device reference (`vendor.com/class=name`).
    pub fn is_cdi_device(dev_arg: &str) -> bool {
        if dev_arg.starts_with('/') {
            return false;
        }
        if let Some((kind, name)) = dev_arg.split_once('=') {
            kind.contains('/') && !name.is_empty()
        } else {
            false
        }
    }

    /// Resolve a list of `--device` arguments, separating standard host devices from CDI devices
    /// and collecting all CDI container edits (env, device nodes, mounts, hooks).
    pub fn resolve_devices(device_args: &[String]) -> Result<ResolvedCdiEdits> {
        let mut out = ResolvedCdiEdits::default();
        let has_cdi = device_args.iter().any(|d| Self::is_cdi_device(d));
        if !has_cdi {
            out.non_cdi_devices = device_args.to_vec();
            return Ok(out);
        }

        let spec_dirs = Self::effective_spec_dirs();
        let specs = Self::load_specs(&spec_dirs);

        for arg in device_args {
            if !Self::is_cdi_device(arg) {
                out.non_cdi_devices.push(arg.clone());
                continue;
            }
            let (kind, target_name) = arg
                .split_once('=')
                .ok_or_else(|| anyhow!("invalid CDI device reference: {}", arg))?;

            let mut matched = false;
            for spec in &specs {
                if spec.kind != kind {
                    continue;
                }
                for dev in &spec.devices {
                    if target_name == "all" || dev.name == target_name {
                        matched = true;
                        if let Some(global_edits) = &spec.container_edits {
                            Self::merge_edits(&mut out, global_edits);
                        }
                        Self::merge_edits(&mut out, &dev.container_edits);
                    }
                }
            }
            if !matched {
                return Err(anyhow!(
                    "resolving CDI devices: unresolvable CDI devices {}",
                    arg
                ));
            }
        }

        Ok(out)
    }

    fn merge_edits(target: &mut ResolvedCdiEdits, edits: &CdiContainerEdits) {
        target.env.extend(edits.env.clone());
        target.device_nodes.extend(edits.device_nodes.clone());
        target.mounts.extend(edits.mounts.clone());
        target.hooks.extend(edits.hooks.clone());
    }
}
