//! Extended pod operations (pod clone, pod logs).

use crate::pod::{PodConfig, PodRecord, PodStore};
use crate::storage::container_store::{ContainerRecord, ContainerStatus, ContainerStore};
use anyhow::{Result, anyhow};
use std::fs;
use std::path::PathBuf;

pub struct PodOps;

impl PodOps {
    pub fn clone_pod(source: &str, target: &str) -> Result<PodRecord> {
        let pod_store = PodStore::new();
        let c_store = ContainerStore::new();

        let src_pod = pod_store
            .find(source)
            .ok_or_else(|| anyhow!("Source pod '{}' not found", source))?;

        if pod_store.find(target).is_some() {
            return Err(anyhow!("Target pod '{}' already exists", target));
        }

        let cfg = PodConfig {
            name: Some(target.to_string()),
            ports: src_pod.ports.clone(),
            hostname: src_pod.hostname.clone(),
            labels: src_pod.labels.clone(),
            dns: src_pod.dns.clone(),
            memory: src_pod.memory.clone(),
            cpus: src_pod.cpus.clone(),
            share_ipc: src_pod.share_ipc,
            share_net: src_pod.share_net,
            share_uts: src_pod.share_uts,
            share_pid: src_pod.share_pid,
            infra: true,
            network: src_pod.network.clone(),
            userns: src_pod.userns.clone(),
        };

        let new_pod = pod_store.create_with_config(cfg)?;

        for cid in &src_pod.containers {
            if let Some(c) = c_store.find(cid) {
                let suffix = c
                    .name
                    .strip_prefix(&format!("{}-", src_pod.name))
                    .unwrap_or(&c.name);
                let new_c_name = format!("{}-{}", target, suffix);

                let rand_bytes: [u8; 6] = crate::rand_bytes();
                let new_cid = hex::encode(rand_bytes);
                let home = crate::storage::boxr_home();
                let new_bundle = home.join("containers").join(&new_cid);
                let old_bundle = PathBuf::from(&c.bundle_path);

                fs::create_dir_all(&new_bundle)?;
                if old_bundle.exists() {
                    let old_config = old_bundle.join("config.json");
                    if old_config.exists() {
                        let _ = fs::copy(&old_config, new_bundle.join("config.json"));
                    }
                    let old_rootfs = old_bundle.join("rootfs");
                    let new_rootfs = new_bundle.join("rootfs");
                    if old_rootfs.exists() {
                        let _ = fs::create_dir_all(&new_rootfs);
                    }
                }

                let new_container = ContainerRecord {
                    id: new_cid.clone(),
                    name: new_c_name.clone(),
                    image: c.image.clone(),
                    command: c.command.clone(),
                    created_at: chrono::Utc::now(),
                    status: ContainerStatus::Created,
                    bundle_path: new_bundle.to_string_lossy().to_string(),
                    restart_policy: c.restart_policy.clone(),
                    health_status: c.health_status.clone(),
                    restart_count: 0,
                    ports: c.ports.clone(),
                    exposed_ports: c.exposed_ports.clone(),
                };

                let _ = c_store.add(new_container);
                let _ = pod_store.add_container_to_pod(&new_pod.name, &new_cid);
            }
        }

        Ok(new_pod)
    }

    pub fn pod_logs(pod_query: &str) -> Result<Vec<(String, String)>> {
        let pod_store = PodStore::new();
        let c_store = ContainerStore::new();

        let pod = pod_store
            .find(pod_query)
            .ok_or_else(|| anyhow!("Pod '{}' not found", pod_query))?;

        let mut lines = Vec::new();
        for cid in &pod.containers {
            if let Some(c) = c_store.find(cid) {
                let log_path = PathBuf::from(&c.bundle_path).join("logs.txt");
                let rootfs_log = PathBuf::from(&c.bundle_path)
                    .join("rootfs")
                    .join("logs.txt");
                let content = if log_path.exists() {
                    fs::read_to_string(&log_path).unwrap_or_default()
                } else if rootfs_log.exists() {
                    fs::read_to_string(&rootfs_log).unwrap_or_default()
                } else {
                    String::new()
                };

                for line in content.lines() {
                    lines.push((c.name.clone(), line.to_string()));
                }
            }
        }
        Ok(lines)
    }
}
