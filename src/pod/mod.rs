pub mod ops;
pub use ops::PodOps;

use crate::network::PortMapping;
use crate::storage::{ContainerRecord, ContainerStatus, ContainerStore, boxr_home};
use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Podman-compatible pod configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PodConfig {
    pub name: Option<String>,
    pub ports: Vec<PortMapping>,
    pub hostname: Option<String>,
    pub labels: HashMap<String, String>,
    pub dns: Vec<String>,
    #[serde(default)]
    pub dns_search: Vec<String>,
    #[serde(default)]
    pub dns_option: Vec<String>,
    #[serde(default)]
    pub add_host: Vec<String>,
    #[serde(default)]
    pub mac_address: Option<String>,
    #[serde(default)]
    pub ip: Option<String>,
    #[serde(default)]
    pub infra_image: Option<String>,
    #[serde(default)]
    pub infra_command: Option<String>,
    #[serde(default)]
    pub infra_name: Option<String>,
    #[serde(default = "default_exit_policy")]
    pub exit_policy: String,
    #[serde(default)]
    pub restart_policy: Option<String>,
    #[serde(default)]
    pub userns: Option<String>,
    #[serde(default)]
    pub volumes: Vec<String>,
    pub memory: Option<String>,
    pub cpus: Option<String>,
    /// Namespace sharing flags (Podman defaults: ipc, net, uts shared).
    #[serde(default = "default_share_ipc")]
    pub share_ipc: bool,
    #[serde(default = "default_share_net")]
    pub share_net: bool,
    #[serde(default = "default_share_uts")]
    pub share_uts: bool,
    #[serde(default)]
    pub share_pid: bool,
    #[serde(default = "default_true")]
    pub infra: bool,
    pub network: Option<String>,
}

fn default_exit_policy() -> String {
    "continue".to_string()
}
fn default_share_ipc() -> bool {
    true
}
fn default_share_net() -> bool {
    true
}
fn default_share_uts() -> bool {
    true
}
fn default_true() -> bool {
    true
}

impl Default for PodConfig {
    fn default() -> Self {
        Self {
            name: None,
            ports: Vec::new(),
            hostname: None,
            labels: HashMap::new(),
            dns: Vec::new(),
            dns_search: Vec::new(),
            dns_option: Vec::new(),
            add_host: Vec::new(),
            mac_address: None,
            ip: None,
            infra_image: None,
            infra_command: None,
            infra_name: None,
            exit_policy: "continue".to_string(),
            restart_policy: None,
            userns: None,
            volumes: Vec::new(),
            memory: None,
            cpus: None,
            share_ipc: true,
            share_net: true,
            share_uts: true,
            share_pid: false,
            infra: true,
            network: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PodRecord {
    pub id: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub status: String,
    pub infra_container_id: String,
    pub containers: Vec<String>,
    pub ports: Vec<PortMapping>,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub labels: HashMap<String, String>,
    #[serde(default)]
    pub dns: Vec<String>,
    #[serde(default)]
    pub dns_search: Vec<String>,
    #[serde(default)]
    pub dns_option: Vec<String>,
    #[serde(default)]
    pub add_host: Vec<String>,
    #[serde(default)]
    pub mac_address: Option<String>,
    #[serde(default)]
    pub ip: Option<String>,
    #[serde(default)]
    pub infra_image: Option<String>,
    #[serde(default)]
    pub infra_command: Option<String>,
    #[serde(default)]
    pub infra_name: Option<String>,
    #[serde(default = "default_exit_policy")]
    pub exit_policy: String,
    #[serde(default)]
    pub restart_policy: Option<String>,
    #[serde(default)]
    pub userns: Option<String>,
    #[serde(default)]
    pub volumes: Vec<String>,
    #[serde(default)]
    pub memory: Option<String>,
    #[serde(default)]
    pub cpus: Option<String>,
    #[serde(default = "default_share_ipc")]
    pub share_ipc: bool,
    #[serde(default = "default_share_net")]
    pub share_net: bool,
    #[serde(default = "default_share_uts")]
    pub share_uts: bool,
    #[serde(default)]
    pub share_pid: bool,
    #[serde(default = "default_true")]
    pub infra: bool,
    #[serde(default)]
    pub network: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct PodStoreData {
    pods: Vec<PodRecord>,
}

/// Interface Segregation: Pod querying abstraction
pub trait PodReader: Send + Sync {
    fn find(&self, query: &str) -> Option<PodRecord>;
    fn list(&self) -> Vec<PodRecord>;
}

/// Interface Segregation: Pod modification abstraction
pub trait PodWriter: Send + Sync {
    fn create(&self, name: Option<&str>, ports: Vec<PortMapping>) -> Result<PodRecord>;
    fn remove(&self, query: &str) -> Result<PodRecord>;
}

/// Combined pod store operations contract (LSP compliant)
pub trait PodStoreOps: PodReader + PodWriter {}
impl<T: PodReader + PodWriter> PodStoreOps for T {}

pub struct PodStore {
    index_file: PathBuf,
    home: PathBuf,
}

impl PodStore {
    pub fn new() -> Self {
        Self::with_home(boxr_home())
    }

    pub fn with_home(home: PathBuf) -> Self {
        Self {
            index_file: home.join("pods.json"),
            home,
        }
    }

    fn load_unlocked(&self) -> PodStoreData {
        if let Ok(content) = fs::read_to_string(&self.index_file) {
            serde_json::from_str(&content).unwrap_or_default()
        } else {
            PodStoreData::default()
        }
    }

    fn save_unlocked(&self, data: &PodStoreData) -> Result<()> {
        let content = serde_json::to_string_pretty(data)?;
        let rand_suffix = hex::encode(crate::storage::container_store::rand_id());
        let temp_file = self
            .index_file
            .with_extension(format!("tmp.{}", rand_suffix));
        fs::write(&temp_file, content)?;
        fs::rename(&temp_file, &self.index_file)?;
        Ok(())
    }

    pub fn list(&self) -> Vec<PodRecord> {
        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            Ok(self.load_unlocked().pods)
        })
        .unwrap_or_default()
    }

    pub fn find(&self, query: &str) -> Option<PodRecord> {
        let q = query.trim();
        if q.is_empty() {
            return None;
        }
        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            let pods = self.load_unlocked().pods;
            if let Some(exact) = pods.iter().find(|p| p.name == q || p.id == q).cloned() {
                return Ok(Some(exact));
            }
            Ok(pods.into_iter().find(|p| p.id.starts_with(q)))
        })
        .ok()
        .flatten()
    }

    pub fn exists(&self, query: &str) -> bool {
        self.find(query).is_some()
    }

    pub fn infra_name(&self, pod: &PodRecord) -> String {
        if let Some(name) = &pod.infra_name {
            if !name.trim().is_empty() {
                return name.trim().to_string();
            }
        }
        if let Some(custom) = pod.labels.get("boxr.pod.infra_name") {
            if !custom.is_empty() {
                return custom.clone();
            }
        }
        format!("{}-infra", pod.name)
    }

    pub fn create(&self, name: Option<&str>, ports: Vec<PortMapping>) -> Result<PodRecord> {
        let mut cfg = PodConfig::default();
        cfg.name = name.map(|n| n.to_string());
        cfg.ports = ports;
        self.create_with_config(cfg)
    }

    pub fn create_with_config(&self, config: PodConfig) -> Result<PodRecord> {
        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            let mut data = self.load_unlocked();
            let random_id = format!(
                "{}{}{}{}{}{}",
                hex::encode(crate::storage::container_store::rand_id()),
                hex::encode(crate::storage::container_store::rand_id()),
                hex::encode(crate::storage::container_store::rand_id()),
                hex::encode(crate::storage::container_store::rand_id()),
                hex::encode(crate::storage::container_store::rand_id()),
                hex::encode(crate::storage::container_store::rand_id()),
            )[..64]
                .to_string();
            let pod_name = config
                .name
                .map(|n| n.trim().to_string())
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| format!("pod-{}", &random_id[..6]));

            if data.pods.iter().any(|p| p.name == pod_name) {
                return Err(anyhow!("Pod name '{}' already exists", pod_name));
            }

            let infra_name = if config.infra {
                config
                    .infra_name
                    .clone()
                    .filter(|s| !s.trim().is_empty())
                    .or_else(|| {
                        config
                            .labels
                            .get("boxr.pod.infra_name")
                            .cloned()
                            .filter(|s| !s.is_empty())
                    })
                    .unwrap_or_else(|| format!("{}-infra", pod_name))
            } else {
                String::new()
            };
            let pod = PodRecord {
                id: random_id,
                name: pod_name,
                created_at: Utc::now(),
                status: "Created".to_string(),
                infra_container_id: infra_name,
                containers: Vec::new(),
                ports: config.ports,
                hostname: config.hostname,
                labels: config.labels,
                dns: config.dns,
                dns_search: config.dns_search,
                dns_option: config.dns_option,
                add_host: config.add_host,
                mac_address: config.mac_address,
                ip: config.ip,
                infra_image: config.infra_image,
                infra_command: config.infra_command,
                infra_name: config.infra_name,
                exit_policy: config.exit_policy,
                restart_policy: config.restart_policy,
                userns: config.userns,
                volumes: config.volumes,
                memory: config.memory,
                cpus: config.cpus,
                share_ipc: config.share_ipc,
                share_net: config.share_net,
                share_uts: config.share_uts,
                share_pid: config.share_pid,
                infra: config.infra,
                network: config.network,
            };

            data.pods.push(pod.clone());
            self.save_unlocked(&data)?;
            Ok(pod)
        })
    }

    pub fn set_infra_container_id(&self, pod_query: &str, infra_id: &str) -> Result<()> {
        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            let mut data = self.load_unlocked();
            let pos = data
                .pods
                .iter()
                .position(|p| p.name == pod_query || p.id == pod_query)
                .or_else(|| data.pods.iter().position(|p| p.id.starts_with(pod_query)));
            if let Some(idx) = pos {
                data.pods[idx].infra_container_id = infra_id.to_string();
                self.save_unlocked(&data)?;
                Ok(())
            } else {
                Err(anyhow!("Pod '{}' not found", pod_query))
            }
        })
    }

    pub fn rename_container_in_pods(&self, old_name: &str, new_name: &str, container_id: &str) {
        let _ = crate::storage::index_lock::with_index_lock(&self.index_file, || {
            let mut data = self.load_unlocked();
            let mut changed = false;
            for p in &mut data.pods {
                if p.infra_container_id == old_name || p.infra_container_id == container_id {
                    if p.infra_name.as_deref() == Some(old_name) {
                        p.infra_name = Some(new_name.to_string());
                        changed = true;
                    }
                    if p.infra_container_id == old_name {
                        p.infra_container_id = new_name.to_string();
                        changed = true;
                    }
                }
                for c in &mut p.containers {
                    if c == old_name {
                        *c = new_name.to_string();
                        changed = true;
                    }
                }
            }
            if changed {
                self.save_unlocked(&data)?;
            }
            Ok(())
        });
    }

    pub fn remove(&self, query: &str) -> Result<PodRecord> {
        self.remove_with_force(query, false)
    }

    pub fn remove_with_force(&self, query: &str, force: bool) -> Result<PodRecord> {
        let q = query.trim();
        if q.is_empty() {
            return Err(anyhow!("Pod '' not found"));
        }
        let _ = crate::guardrails::ProcessReaper::reap_stale_containers();
        let home = self.home.clone();
        let removed = crate::storage::index_lock::with_index_lock(&self.index_file, || {
            let mut data = self.load_unlocked();
            let c_store = ContainerStore::with_home(home.clone());

            let pos = data
                .pods
                .iter()
                .position(|p| p.name == q || p.id == q)
                .or_else(|| data.pods.iter().position(|p| p.id.starts_with(q)));
            if let Some(pos) = pos {
                let pod = &data.pods[pos];
                let infra_name = self.infra_name(pod);

                if !force {
                    let mut running_errors = Vec::new();
                    for cid in &pod.containers {
                        if cid == &infra_name || cid == &pod.infra_container_id {
                            continue;
                        }
                        if let Some(c) = c_store.find(cid) {
                            if c.name == infra_name || c.id == pod.infra_container_id {
                                continue;
                            }
                            if matches!(c.status, ContainerStatus::Running) {
                                running_errors.push(format!(
                                    "cannot remove container {} as it is running - running or paused containers cannot be removed without force: container state improper",
                                    c.id
                                ));
                            }
                        }
                    }
                    if !running_errors.is_empty() {
                        return Err(anyhow!(
                            "cannot remove running pod: not all containers could be removed from pod {}: removing pod containers:\n{}",
                            pod.id,
                            running_errors.join("\n")
                        ));
                    }
                    if let Some(infra) = c_store
                        .find(&infra_name)
                        .or_else(|| c_store.find(&pod.infra_container_id))
                    {
                        if pod.containers.is_empty()
                            && pod.status == "Running"
                            && matches!(infra.status, ContainerStatus::Running)
                        {
                            return Err(anyhow!(
                                "conflict: cannot remove running pod {}. Stop the pod or use force",
                                pod.name
                            ));
                        }
                    }
                }

                let removed = data.pods.remove(pos);
                self.save_unlocked(&data)?;
                Ok(removed)
            } else {
                Err(anyhow!(
                    "no pod with name or ID {} found: no such pod",
                    query
                ))
            }
        })?;

        for cid in &removed.containers {
            if force {
                let _ = crate::stop_container_with_home_and_timeout(
                    cid,
                    None,
                    Some(0),
                    None,
                    true,
                    None,
                );
            }
            let _ = crate::remove_container_quiet(cid, true, false);
        }
        if removed.infra {
            let c_store = ContainerStore::with_home(self.home.clone());
            let infra_name = self.infra_name(&removed);
            if let Some(infra) = c_store
                .find(&infra_name)
                .or_else(|| c_store.find(&removed.infra_container_id))
            {
                let _ = crate::stop_container_with_home_and_timeout(
                    &infra.id,
                    None,
                    Some(0),
                    None,
                    true,
                    None,
                );
                let _ = crate::remove_container_quiet(&infra.id, true, false);
            }
        }
        if let Some(sc) = removed.labels.get("boxr.service_container") {
            let _ = crate::remove_container_quiet(sc, true, false);
        }
        if let Ok(cg) = crate::cgroups::CgroupV2Manager::path_only(&removed.id).cleanup() {
            let _ = cg;
        }
        Ok(removed)
    }

    pub fn prune(&self) -> Result<Vec<String>> {
        let home = self.home.clone();
        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            let mut data = self.load_unlocked();
            let c_store = ContainerStore::with_home(home);
            let mut pruned = Vec::new();

            data.pods.retain(|p| {
                let any_running = p.containers.iter().any(|cid| {
                    c_store
                        .find(cid)
                        .map(|c| matches!(c.status, ContainerStatus::Running))
                        .unwrap_or(false)
                });
                let infra_running = c_store
                    .find(&format!("{}-infra", p.name))
                    .or_else(|| c_store.find(&p.infra_container_id))
                    .map(|c| matches!(c.status, ContainerStatus::Running))
                    .unwrap_or(false);

                if !any_running && !infra_running && p.status != "Running" {
                    pruned.push(p.name.clone());
                    false
                } else {
                    true
                }
            });

            if !pruned.is_empty() {
                self.save_unlocked(&data)?;
            }
            Ok(pruned)
        })
    }

    pub fn update_status(&self, pod_query: &str, status: &str) -> Result<()> {
        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            let mut data = self.load_unlocked();
            let pos = data
                .pods
                .iter()
                .position(|p| p.name == pod_query || p.id == pod_query)
                .or_else(|| data.pods.iter().position(|p| p.id.starts_with(pod_query)));
            if let Some(idx) = pos {
                data.pods[idx].status = status.to_string();
                self.save_unlocked(&data)?;
                Ok(())
            } else {
                Err(anyhow!("Pod '{}' not found", pod_query))
            }
        })
    }

    pub fn add_container_to_pod(&self, pod_query: &str, container_id: &str) -> Result<()> {
        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            let mut data = self.load_unlocked();
            let pos = data
                .pods
                .iter()
                .position(|p| p.name == pod_query || p.id == pod_query)
                .or_else(|| data.pods.iter().position(|p| p.id.starts_with(pod_query)));
            if let Some(idx) = pos {
                let p = &mut data.pods[idx];
                if !p.containers.contains(&container_id.to_string()) {
                    p.containers.push(container_id.to_string());
                    p.status = "Running".to_string();
                    self.save_unlocked(&data)?;
                }
                Ok(())
            } else {
                Err(anyhow!("Pod '{}' not found", pod_query))
            }
        })
    }

    pub fn add_created_container_to_pod(&self, pod_query: &str, container_id: &str) -> Result<()> {
        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            let mut data = self.load_unlocked();
            let pos = data
                .pods
                .iter()
                .position(|p| p.name == pod_query || p.id == pod_query)
                .or_else(|| data.pods.iter().position(|p| p.id.starts_with(pod_query)));
            if let Some(idx) = pos {
                let p = &mut data.pods[idx];
                if !p.containers.contains(&container_id.to_string()) {
                    p.containers.push(container_id.to_string());
                    self.save_unlocked(&data)?;
                }
                Ok(())
            } else {
                Err(anyhow!("Pod '{}' not found", pod_query))
            }
        })
    }

    pub fn remove_container_from_pods(
        &self,
        container_id: &str,
        container_name: &str,
    ) -> Result<()> {
        let home = self.home.clone();
        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            let mut data = self.load_unlocked();
            let c_store = ContainerStore::with_home(home);
            let mut changed = false;
            for p in &mut data.pods {
                let before = p.containers.len();
                p.containers
                    .retain(|cid| cid != container_id && cid != container_name);
                if p.containers.len() != before {
                    changed = true;
                    let infra_name = p
                        .infra_name
                        .clone()
                        .unwrap_or_else(|| format!("{}-infra", p.name));
                    let non_infra_remaining: Vec<&String> = p
                        .containers
                        .iter()
                        .filter(|cid| *cid != &infra_name && *cid != &p.infra_container_id)
                        .collect();
                    if non_infra_remaining.is_empty() && p.status == "Degraded" {
                        let infra_running = if p.infra {
                            c_store
                                .find(&p.infra_container_id)
                                .or_else(|| c_store.find(&infra_name))
                                .map(|c| matches!(c.status, ContainerStatus::Running))
                                .unwrap_or(false)
                        } else {
                            false
                        };
                        if infra_running {
                            p.status = "Running".to_string();
                        }
                    }
                }
            }
            if changed {
                self.save_unlocked(&data)?;
            }
            Ok(())
        })
    }

    pub fn member_container_ids(&self, pod: &PodRecord) -> Vec<String> {
        let mut ids = pod.containers.clone();
        if pod.infra {
            let infra = self.infra_name(pod);
            if !infra.is_empty() && !ids.contains(&infra) && !ids.contains(&pod.infra_container_id)
            {
                ids.insert(0, infra);
            }
        }
        ids
    }
}

/// Resolve a container namespace path for joining (e.g. `/proc/123/ns/net`).
pub fn container_namespace_path(container_query: &str, ns: &str) -> Result<String> {
    let store = ContainerStore::new();
    let cont = store.find(container_query).ok_or_else(|| {
        anyhow!(
            "Container '{}' not found for namespace join",
            container_query
        )
    })?;
    container_pid_namespace_path(&cont, ns)
}

pub fn read_container_pid_from_bundle(bundle_path: &Path) -> Option<i32> {
    for _ in 0..40 {
        for name in ["container.pid", "vm.pid"] {
            let pid_path = bundle_path.join(name);
            if let Ok(raw) = fs::read_to_string(&pid_path) {
                if let Ok(pid) = raw.trim().parse::<i32>() {
                    if pid > 0 {
                        return Some(pid);
                    }
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    None
}

pub fn container_pid_namespace_path(cont: &ContainerRecord, ns: &str) -> Result<String> {
    let bundle = PathBuf::from(&cont.bundle_path);
    let pid = read_container_pid_from_bundle(&bundle).ok_or_else(|| {
        anyhow!(
            "Container '{}' is not running; cannot join {} namespace",
            cont.name,
            ns
        )
    })?;
    Ok(format!("/proc/{}/ns/{}", pid, ns))
}

fn missing_namespace_path_error(ns_type: &str, ns_path: &str) -> anyhow::Error {
    match ns_type {
        "network" | "net" => anyhow!(
            "network namespace cannot be found: stat {}: no such file or directory",
            ns_path
        ),
        "uts" => anyhow!(
            "cannot find specified ut namespace path: stat {}: no such file or directory",
            ns_path
        ),
        "cgroup" | "cgroupns" => anyhow!(
            "cannot find specified cgroup namespace path: stat {}: no such file or directory",
            ns_path
        ),
        other => anyhow!(
            "cannot find specified {} namespace path: stat {}: no such file or directory",
            other,
            ns_path
        ),
    }
}

/// Parse `container:<name>` or return the value as a namespace path.
pub fn resolve_namespace_spec(spec: &str, ns_type: &str) -> Result<Option<String>> {
    let trimmed = spec.trim();
    if trimmed.is_empty() || trimmed == "private" || trimmed == "shareable" || trimmed == "none" {
        return Ok(None);
    }
    if trimmed == "host" {
        return Ok(Some("host".to_string()));
    }
    if let Some(target) = trimmed
        .strip_prefix("container:")
        .or_else(|| trimmed.strip_prefix("container://"))
    {
        return Ok(Some(container_namespace_path(target, ns_type)?));
    }
    if let Some(ns_path) = trimmed.strip_prefix("ns:") {
        if !Path::new(ns_path).exists() {
            return Err(missing_namespace_path_error(ns_type, ns_path));
        }
        return Ok(Some(ns_path.to_string()));
    }
    if trimmed.starts_with('/') {
        if !Path::new(trimmed).exists() {
            return Err(missing_namespace_path_error(ns_type, trimmed));
        }
        return Ok(Some(trimmed.to_string()));
    }
    Ok(None)
}

/// Apply pod namespace sharing settings onto run arguments.
pub fn apply_pod_to_run_args(pod: &PodRecord, infra_name: &str, args: &mut crate::cli::RunArgs) {
    if pod.share_uts && args.hostname.is_some() {
        crate::cli::usage_errors::exit_usage_error(
            "invalid config provided: cannot set hostname when joining the pod UTS namespace: invalid configuration",
        );
    }
    if pod.share_net && (!args.ports.is_empty() || !args.expose.is_empty() || args.publish_all) {
        crate::cli::usage_errors::exit_usage_error(
            "invalid config provided: published or exposed ports must be defined when the pod is created: network cannot be configured when it is shared with a pod",
        );
    }
    let has_infra = pod.infra && !infra_name.is_empty();
    if pod.network.as_deref() == Some("host") {
        args.network = "host".to_string();
    } else if pod.network.as_deref() == Some("none") {
        args.network = "none".to_string();
    } else if pod.share_net {
        if has_infra {
            args.network = format!("container:{}", infra_name);
        } else if let Some(net) = &pod.network {
            args.network = net.clone();
        }
    } else if let Some(net) = &pod.network {
        args.network = net.clone();
    }
    if pod.labels.get("boxr.pod.shm_size").is_some() && args.ipc.as_deref() == Some("host") {
        crate::cli::usage_errors::exit_usage_error("cannot set --shm-size with --ipc=host");
    }
    if pod.share_ipc && args.ipc.is_none() {
        if let Some(pod_ipc) = pod.labels.get("boxr.pod.ipc") {
            args.ipc = Some(pod_ipc.clone());
        } else if has_infra {
            args.ipc = Some(format!("container:{}", infra_name));
        }
    }
    if pod.share_uts && args.uts.is_none() {
        if let Some(pod_uts) = pod.labels.get("boxr.pod.uts") {
            args.uts = Some(pod_uts.clone());
        } else if has_infra {
            args.uts = Some(format!("container:{}", infra_name));
        }
    }
    if pod.share_pid && args.pid.is_none() {
        if let Some(pod_pid) = pod.labels.get("boxr.pod.pid") {
            args.pid = Some(pod_pid.clone());
        } else if has_infra {
            args.pid = Some(format!("container:{}", infra_name));
        }
    }
    if pod.labels.get("boxr.pod.share_cgroup").map(|s| s.as_str()) == Some("true")
        && args.cgroupns.is_none()
        && has_infra
    {
        args.cgroupns = Some(format!("container:{}", pod.infra_container_id));
    }
    if pod.labels.get("boxr.pod.share_parent").map(|s| s.as_str()) == Some("false")
        && args.cgroup_parent.is_none()
    {
        let cgm = crate::cli::podman_globals::podman_global_options()
            .cgroup_manager
            .unwrap_or_else(|| "systemd".to_string());
        if cgm == "systemd" && unsafe { libc::getuid() != 0 } {
            args.cgroup_parent = Some("user.slice".to_string());
        }
    }
    if pod.labels.get("boxr.pod.no_hosts").map(|s| s.as_str()) == Some("true") {
        let _ = crate::cli::RUN_NO_HOSTS.set(true);
    }
    if pod.labels.get("boxr.pod.no_hostname").map(|s| s.as_str()) == Some("true") {
        args.no_hostname = true;
    }
    if args.shm_size.is_none() {
        if let Some(shm) = pod.labels.get("boxr.pod.shm_size") {
            args.shm_size = Some(shm.clone());
        }
    }
    if let Some(sec_json) = pod.labels.get("boxr.pod.security_opt") {
        if let Ok(sec_opts) = serde_json::from_str::<Vec<String>>(sec_json) {
            for so in sec_opts {
                if !args.security_opt.contains(&so) {
                    args.security_opt.push(so);
                }
            }
        }
    }
    if let Some(dev_json) = pod.labels.get("boxr.pod.devices") {
        if let Ok(devs) = serde_json::from_str::<Vec<String>>(dev_json) {
            for d in devs {
                if !args.devices.contains(&d) {
                    args.devices.push(d);
                }
            }
        }
    }
    if args.cpuset_cpus.is_none() {
        if let Some(cs) = pod.labels.get("boxr.pod.cpuset_cpus") {
            args.cpuset_cpus = Some(cs.clone());
        }
    }
    if args.hostname.is_none() && !args.no_hostname {
        if pod.labels.get("boxr.pod.uts").map(|s| s.as_str()) == Some("host") {
            if let Ok(out) = std::process::Command::new("hostname").output() {
                let h = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if !h.is_empty() {
                    args.hostname = Some(h);
                }
            }
        } else {
            args.hostname = pod.hostname.clone().or_else(|| Some(pod.name.clone()));
        }
    }
    if args.dns.is_empty() && !pod.dns.is_empty() {
        args.dns = pod.dns.clone();
    }
    if args.dns_search.is_empty() && !pod.dns_search.is_empty() {
        args.dns_search = pod.dns_search.clone();
    }
    if args.dns_option.is_empty() && !pod.dns_option.is_empty() {
        args.dns_option = pod.dns_option.clone();
    }
    for ah in &pod.add_host {
        if !args.add_host.contains(ah) {
            args.add_host.push(ah.clone());
        }
    }
    for v in &pod.volumes {
        if !args.volumes.contains(v) {
            args.volumes.push(v.clone());
        }
    }
    if (args.restart.is_empty() || args.restart == "no") && pod.restart_policy.is_some() {
        if let Some(rp) = &pod.restart_policy {
            args.restart = rp.clone();
        }
    }
    if args.memory.is_none() {
        args.memory = pod.memory.clone();
    }
    if args.cpus.is_none() {
        args.cpus = pod.cpus.clone();
    }
    if args.userns.is_empty() {
        if let Some(u) = &pod.userns {
            args.userns.push(u.clone());
        }
    }
    if let Some(ah_json) = pod.labels.get("boxr.pod.add_host") {
        if let Ok(ah_list) = serde_json::from_str::<Vec<String>>(ah_json) {
            for entry in ah_list {
                if !args.add_host.contains(&entry) {
                    args.add_host.push(entry);
                }
            }
        }
    }
    for (k, v) in &pod.labels {
        if !k.starts_with("boxr.pod.") {
            args.labels.push(format!("{}={}", k, v));
        }
    }
}

impl PodReader for PodStore {
    fn find(&self, query: &str) -> Option<PodRecord> {
        self.find(query)
    }

    fn list(&self) -> Vec<PodRecord> {
        self.list()
    }
}

impl PodWriter for PodStore {
    fn create(&self, name: Option<&str>, ports: Vec<PortMapping>) -> Result<PodRecord> {
        self.create(name, ports)
    }

    fn remove(&self, query: &str) -> Result<PodRecord> {
        self.remove(query)
    }
}

#[cfg(test)]
mod tests;
