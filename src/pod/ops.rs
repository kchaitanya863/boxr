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

        let target_name = if target.trim().is_empty() {
            format!("{}-clone", src_pod.name)
        } else {
            target.trim().to_string()
        };

        if pod_store.find(&target_name).is_some() {
            return Err(anyhow!("Target pod '{}' already exists", target_name));
        }

        let cfg = PodConfig {
            name: Some(target_name.clone()),
            ports: src_pod.ports.clone(),
            hostname: src_pod.hostname.clone(),
            labels: src_pod.labels.clone(),
            dns: src_pod.dns.clone(),
            dns_search: src_pod.dns_search.clone(),
            dns_option: src_pod.dns_option.clone(),
            add_host: src_pod.add_host.clone(),
            mac_address: src_pod.mac_address.clone(),
            ip: src_pod.ip.clone(),
            infra_image: src_pod.infra_image.clone(),
            infra_command: src_pod.infra_command.clone(),
            infra_name: None,
            exit_policy: src_pod.exit_policy.clone(),
            restart_policy: src_pod.restart_policy.clone(),
            userns: src_pod.userns.clone(),
            volumes: src_pod.volumes.clone(),
            memory: src_pod.memory.clone(),
            cpus: src_pod.cpus.clone(),
            share_ipc: src_pod.share_ipc,
            share_net: src_pod.share_net,
            share_uts: src_pod.share_uts,
            share_pid: src_pod.share_pid,
            infra: src_pod.infra,
            network: src_pod.network.clone(),
        };

        let new_pod = pod_store.create_with_config(cfg)?;
        let src_infra_name = pod_store.infra_name(&src_pod);

        for cid in &src_pod.containers {
            if cid == &src_pod.infra_container_id || cid == &src_infra_name {
                continue;
            }
            if let Some(c) = c_store.find(cid) {
                if c.id == src_pod.infra_container_id || c.name == src_infra_name {
                    continue;
                }
                let suffix = c
                    .name
                    .strip_prefix(&format!("{}-", src_pod.name))
                    .unwrap_or(&c.name);
                let new_c_name = format!("{}-{}-clone", target_name, suffix);

                let new_cid = crate::new_container_id();
                let home = crate::storage::boxr_home();
                let new_bundle = home.join("containers").join(&new_cid);
                let old_bundle = PathBuf::from(&c.bundle_path);

                fs::create_dir_all(&new_bundle)?;
                if old_bundle.exists() {
                    for fname in ["config.json", "mounts.json", "create_command.json", "hosts.json"]
                    {
                        let src_f = old_bundle.join(fname);
                        if src_f.exists() {
                            let _ = fs::copy(&src_f, new_bundle.join(fname));
                        }
                    }
                    let old_rootfs = old_bundle.join("rootfs");
                    let new_rootfs = new_bundle.join("rootfs");
                    if old_rootfs.exists() {
                        let _ = crate::storage::overlay::OverlayDriver::create_hardlink_tree(
                            &old_rootfs,
                            &new_rootfs,
                        );
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
                let _ = pod_store.add_created_container_to_pod(&new_pod.name, &new_cid);
            }
        }

        Ok(new_pod)
    }

    pub fn pod_logs(pod_query: &str) -> Result<Vec<(String, String, String)>> {
        let pod_store = PodStore::new();
        let c_store = ContainerStore::new();

        let pod = pod_store
            .find(pod_query)
            .ok_or_else(|| anyhow!("Pod '{}' not found", pod_query))?;

        let mut lines = Vec::new();
        for cid in &pod.containers {
            if let Some(c) = c_store.find(cid) {
                let bundle_path = PathBuf::from(&c.bundle_path);
                let annotations = crate::load_container_labels_from_bundle(&c.bundle_path);
                let mut content = String::new();
                if let Some(path) =
                    crate::logging::resolve_container_log_path(&bundle_path, &annotations)
                {
                    if path.to_string_lossy().contains("-ctr.log")
                        || crate::logging::is_k8s_log_path(&path)
                        || annotations
                            .get("boxr.log_driver")
                            .is_some_and(|d| d == "journald")
                    {
                        content = crate::logging::decode_k8s_log_file(&path).unwrap_or_default();
                    } else if path.exists() {
                        content = fs::read_to_string(&path).unwrap_or_default();
                    }
                }
                if content.is_empty() {
                    let log_path = bundle_path.join("logs.txt");
                    let rootfs_log = bundle_path.join("rootfs").join("logs.txt");
                    if log_path.exists() {
                        content = fs::read_to_string(&log_path).unwrap_or_default();
                    } else if rootfs_log.exists() {
                        content = fs::read_to_string(&rootfs_log).unwrap_or_default();
                    }
                }

                for line in content.lines() {
                    lines.push((c.name.clone(), c.id.clone(), line.to_string()));
                }
            }
        }
        Ok(lines)
    }
}
