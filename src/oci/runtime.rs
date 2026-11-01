use crate::oci::image::ExecutionConfig;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub const OCI_VERSION: &str = "1.0.2";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub uid: u32,
    pub gid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_gids: Option<Vec<u32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LinuxCapabilities {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bounding: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inheritable: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permitted: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ambient: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Process {
    pub terminal: bool,
    pub user: User,
    pub args: Vec<String>,
    pub env: Vec<String>,
    pub cwd: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_new_privileges: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<LinuxCapabilities>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oom_score_adj: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub umask: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Root {
    pub path: String,
    pub readonly: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mount {
    pub destination: String,
    #[serde(rename = "type")]
    pub mount_type: String,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinuxNamespace {
    #[serde(rename = "type")]
    pub ns_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LinuxCpu {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shares: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quota: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub period: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpus: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mems: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LinuxDevice {
    #[serde(rename = "type")]
    pub dev_type: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub major: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minor: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_mode: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gid: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LinuxMemory {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reservation: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub swap: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub swappiness: Option<u64>,
    #[serde(rename = "disableOOMKiller", skip_serializing_if = "Option::is_none")]
    pub disable_oom_killer: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LinuxPids {
    pub limit: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LinuxResources {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<LinuxMemory>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu: Option<LinuxCpu>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pids: Option<LinuxPids>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<LinuxDevice>,
    #[serde(rename = "oomScoreAdj", skip_serializing_if = "Option::is_none")]
    pub oom_score_adj: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Linux {
    pub namespaces: Vec<LinuxNamespace>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<LinuxResources>,
    #[serde(rename = "cgroupParent", skip_serializing_if = "Option::is_none")]
    pub cgroup_parent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seccomp: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<LinuxDevice>,
    #[serde(rename = "maskedPaths", skip_serializing_if = "Option::is_none")]
    pub masked_paths: Option<Vec<String>>,
    #[serde(rename = "readonlyPaths", skip_serializing_if = "Option::is_none")]
    pub readonly_paths: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WindowsCPUResources {
    #[serde(rename = "count", skip_serializing_if = "Option::is_none")]
    pub count: Option<u64>,
    #[serde(rename = "percent", skip_serializing_if = "Option::is_none")]
    pub percent: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WindowsStorageResources {
    #[serde(rename = "bps", skip_serializing_if = "Option::is_none")]
    pub bps: Option<u64>,
    #[serde(rename = "iops", skip_serializing_if = "Option::is_none")]
    pub iops: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WindowsResources {
    #[serde(rename = "cpu", skip_serializing_if = "Option::is_none")]
    pub cpu: Option<WindowsCPUResources>,
    #[serde(rename = "storage", skip_serializing_if = "Option::is_none")]
    pub storage: Option<WindowsStorageResources>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Windows {
    #[serde(rename = "resources", skip_serializing_if = "Option::is_none")]
    pub resources: Option<WindowsResources>,
    #[serde(rename = "hyperv", skip_serializing_if = "Option::is_none")]
    pub hyperv: Option<serde_json::Value>,
}

/// The top-level OCI Runtime Specification bundle configuration (config.json).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Spec {
    #[serde(rename = "ociVersion")]
    pub oci_version: String,
    pub process: Process,
    pub root: Root,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domainname: Option<String>,
    pub mounts: Vec<Mount>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub linux: Option<Linux>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub windows: Option<Windows>,
}

impl Spec {
    /// Create a standard default OCI Spec for a given image configuration and optional command overrides.
    pub fn new_default(
        image_config: Option<&ExecutionConfig>,
        cmd_override: Option<&[String]>,
        env_override: Option<&[String]>,
    ) -> Self {
        let mut args = Vec::new();
        let has_cmd_override = cmd_override.is_some_and(|c| !c.is_empty());

        if let Some(cfg) = image_config {
            if let Some(entrypoint) = &cfg.entrypoint {
                args.extend(entrypoint.iter().filter(|s| !s.is_empty()).cloned());
            }
            if !has_cmd_override {
                if let Some(cmd) = &cfg.cmd {
                    args.extend_from_slice(cmd);
                }
            }
        }

        if let Some(overrides) = cmd_override {
            if !overrides.is_empty() {
                args.extend_from_slice(overrides);
            }
        }

        if args.is_empty() {
            let explicit_empty = image_config.is_some_and(|cfg| {
                cfg.entrypoint
                    .as_ref()
                    .is_some_and(|e| e.iter().all(|s| s.is_empty()))
                    && cfg.cmd.as_ref().is_none_or(|c| c.is_empty())
            });
            if explicit_empty {
                args.push(String::new());
            } else {
                args.push("/bin/sh".to_string());
            }
        }

        let mut env =
            vec!["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string()];

        if let Some(cfg) = image_config {
            if let Some(image_env) = &cfg.env {
                for e in image_env {
                    env.retain(|existing| existing.split('=').next() != e.split('=').next());
                    env.push(e.clone());
                }
            }
        }

        if let Some(overrides) = env_override {
            for e in overrides {
                env.retain(|existing| existing.split('=').next() != e.split('=').next());
                env.push(e.clone());
            }
        }

        let cwd = image_config
            .and_then(|c| c.working_dir.clone())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "/".to_string());

        let mounts = vec![
            Mount {
                destination: "/proc".to_string(),
                mount_type: "proc".to_string(),
                source: "proc".to_string(),
                options: None,
            },
            Mount {
                destination: "/dev".to_string(),
                mount_type: "tmpfs".to_string(),
                source: "tmpfs".to_string(),
                options: Some(vec![
                    "nosuid".to_string(),
                    "strictatime".to_string(),
                    "mode=755".to_string(),
                    "size=65536k".to_string(),
                ]),
            },
            Mount {
                destination: "/dev/pts".to_string(),
                mount_type: "devpts".to_string(),
                source: "devpts".to_string(),
                options: Some(vec![
                    "nosuid".to_string(),
                    "noexec".to_string(),
                    "newinstance".to_string(),
                    "ptmxmode=0666".to_string(),
                    "mode=0620".to_string(),
                ]),
            },
            Mount {
                destination: "/dev/shm".to_string(),
                mount_type: "tmpfs".to_string(),
                source: "shm".to_string(),
                options: Some(vec![
                    "nosuid".to_string(),
                    "noexec".to_string(),
                    "nodev".to_string(),
                    "mode=1777".to_string(),
                    "size=65536k".to_string(),
                ]),
            },
            Mount {
                destination: "/sys".to_string(),
                mount_type: "sysfs".to_string(),
                source: "sysfs".to_string(),
                options: Some(vec![
                    "nosuid".to_string(),
                    "noexec".to_string(),
                    "nodev".to_string(),
                    "ro".to_string(),
                ]),
            },
        ];

        let linux = Linux {
            namespaces: vec![
                LinuxNamespace {
                    ns_type: "pid".to_string(),
                    path: None,
                },
                LinuxNamespace {
                    ns_type: "network".to_string(),
                    path: None,
                },
                LinuxNamespace {
                    ns_type: "ipc".to_string(),
                    path: None,
                },
                LinuxNamespace {
                    ns_type: "uts".to_string(),
                    path: None,
                },
                LinuxNamespace {
                    ns_type: "mount".to_string(),
                    path: None,
                },
            ],
            resources: Some(LinuxResources {
                memory: None,
                cpu: None,
                pids: Some(LinuxPids { limit: 1024 }),
                devices: Vec::new(),
                oom_score_adj: None,
            }),
            cgroup_parent: None,
            seccomp: None,
            devices: Vec::new(),
            masked_paths: None,
            readonly_paths: None,
        };

        Self {
            oci_version: OCI_VERSION.to_string(),
            process: Process {
                terminal: false,
                user: User {
                    uid: 0,
                    gid: 0,
                    additional_gids: None,
                    username: None,
                },
                args,
                env,
                cwd,
                no_new_privileges: Some(false),
                capabilities: None,
                oom_score_adj: None,
                umask: None,
            },
            root: Root {
                path: "rootfs".to_string(),
                readonly: false,
            },
            hostname: Some("boxr-container".to_string()),
            domainname: None,
            mounts,
            annotations: None,
            linux: Some(linux),
            windows: None,
        }
    }

    /// Save the spec to a bundle config.json
    pub fn save_to_bundle(&self, bundle_dir: &Path) -> Result<()> {
        let config_file = bundle_dir.join("config.json");
        let content = serde_json::to_string_pretty(self)?;
        fs::write(config_file, content)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spec_default() {
        let spec = Spec::new_default(None, None, None);
        assert_eq!(spec.oci_version, OCI_VERSION);
        assert_eq!(spec.process.args, vec!["/bin/sh"]);
        assert_eq!(spec.root.path, "rootfs");
        assert!(spec.linux.is_some());
    }

    #[test]
    fn test_spec_overrides() {
        let cmd = vec!["/bin/echo".to_string(), "hello".to_string()];
        let env = vec!["FOO=bar".to_string()];
        let spec = Spec::new_default(None, Some(&cmd), Some(&env));
        assert_eq!(spec.process.args, vec!["/bin/echo", "hello"]);
        assert!(spec.process.env.iter().any(|e| e == "FOO=bar"));
    }
}
