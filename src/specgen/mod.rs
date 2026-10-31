//! Podman Specgen (SpecGenerator JSON) generation.

use crate::pod::PodStore;
use crate::storage::ContainerStore;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpecGenerator {
    pub name: String,
    pub image: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub command: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub entrypoint: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub env: Vec<String>,
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub labels: HashMap<String, String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub portmappings: Vec<crate::network::PortMapping>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub work_dir: Option<String>,
    #[serde(default)]
    pub terminal: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restart_policy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_limits: Option<serde_json::Value>,
}

pub struct SpecgenManager;

impl SpecgenManager {
    pub fn generate_spec(query: &str) -> Result<String> {
        Self::generate_spec_with_opts(query, false, true)
    }

    pub fn generate_spec_with_opts(
        query: &str,
        compact: bool,
        clone_name: bool,
    ) -> Result<String> {
        let store = ContainerStore::new();
        let pod_store = PodStore::new();

        if let Some(cont) = store.find(query) {
            let bundle_path = Path::new(&cont.bundle_path);
            let spec: Option<crate::oci::runtime::Spec> =
                fs::read_to_string(bundle_path.join("config.json"))
                    .ok()
                    .and_then(|s| serde_json::from_str(&s).ok());
            let mut resource_limits = None;
            if let Some(ref sp) = spec {
                if let Some(ref ann) = sp.annotations {
                    if let Some(cpus_str) = ann.get("boxr.cpus") {
                        if let Ok(cpus) = cpus_str.parse::<f64>() {
                            let quota = (cpus * 100_000.0).round() as i64;
                            resource_limits = Some(serde_json::json!({
                                "cpu": {
                                    "quota": quota,
                                    "period": 100000
                                }
                            }));
                        }
                    }
                }
            }
            let spec_gen = SpecGenerator {
                name: if clone_name {
                    format!("{}-clone", cont.name)
                } else {
                    cont.name.clone()
                },
                image: cont.image.clone(),
                command: cont.command.clone(),
                entrypoint: Vec::new(),
                env: Vec::new(),
                labels: HashMap::new(),
                portmappings: cont.ports.clone(),
                work_dir: None,
                terminal: false,
                hostname: Some(cont.name.clone()),
                restart_policy: Some(format!("{:?}", cont.restart_policy)),
                resource_limits,
            };

            let json = if compact {
                serde_json::to_string(&spec_gen)?
            } else {
                serde_json::to_string_pretty(&spec_gen)?
            };
            return Ok(json);
        }

        if let Some(pod) = pod_store.find(query) {
            let mut cpu_period = None;
            let mut cpu_quota = None;
            if let Some(ref cpus_str) = pod.cpus {
                if let Ok(cpus) = cpus_str.parse::<f64>() {
                    cpu_period = Some(100_000u64);
                    cpu_quota = Some((cpus * 100_000.0).round() as i64);
                }
            }
            let pod_val = serde_json::json!({
                "PodBasicConfig": {
                    "name": if clone_name {
                        format!("{}-clone", pod.name)
                    } else {
                        pod.name.clone()
                    },
                    "hostname": pod.hostname.clone().unwrap_or_else(|| pod.name.clone()),
                    "labels": pod.labels,
                    "no_infra": pod.infra_container_id.is_empty(),
                },
                "PodNetworkConfig": {},
                "PodCgroupConfig": {
                    "resource_limits": {
                        "cpu": {
                            "period": cpu_period,
                            "quota": cpu_quota,
                        }
                    }
                },
                " Containers": []
            });
            let json = if compact {
                serde_json::to_string(&pod_val)?
            } else {
                serde_json::to_string_pretty(&pod_val)?
            };
            return Ok(json);
        }

        crate::cli::usage_errors::exit_usage_error(format!(
            "could not find a pod or container with the id {}",
            query
        ));
    }
}
