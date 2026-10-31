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
    #[serde(default)]
    pub userns: Option<String>,
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
            memory: None,
            cpus: None,
            share_ipc: true,
            share_net: true,
            share_uts: true,
            share_pid: false,
            infra: true,
            network: None,
            userns: None,
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
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default)]
    pub userns: Option<String>,
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
            Ok(self
                .load_unlocked()
                .pods
                .into_iter()
                .find(|p| p.id == q || p.id.starts_with(q) || p.name == q))
        })
        .ok()
        .flatten()
    }

    pub fn exists(&self, query: &str) -> bool {
        self.find(query).is_some()
    }

    pub fn infra_name(&self, pod: &PodRecord) -> String {
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
            let random_id = hex::encode(crate::storage::container_store::rand_id());
            let pod_name = config
                .name
                .map(|n| n.trim().to_string())
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| format!("pod-{}", &random_id[..6]));

            if data.pods.iter().any(|p| p.name == pod_name) {
                return Err(anyhow!("Pod name '{}' already exists", pod_name));
            }

            let infra_name = config
                .labels
                .get("boxr.pod.infra_name")
                .cloned()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| format!("{}-infra", pod_name));
            let pod = PodRecord {
                id: random_id[..12].to_string(),
                name: pod_name,
                created_at: Utc::now(),
                status: "Created".to_string(),
                infra_container_id: infra_name,
                containers: Vec::new(),
                ports: config.ports,
                hostname: config.hostname,
                labels: config.labels,
                dns: config.dns,
                memory: config.memory,
                cpus: config.cpus,
                share_ipc: config.share_ipc,
                share_net: config.share_net,
                share_uts: config.share_uts,
                share_pid: config.share_pid,
                network: config.network,
                userns: config.userns,
            };

            data.pods.push(pod.clone());
            self.save_unlocked(&data)?;
            Ok(pod)
        })
    }

    pub fn set_infra_container_id(&self, pod_query: &str, infra_id: &str) -> Result<()> {
        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            let mut data = self.load_unlocked();
            if let Some(p) = data
                .pods
                .iter_mut()
                .find(|p| p.id.starts_with(pod_query) || p.name == pod_query)
            {
                p.infra_container_id = infra_id.to_string();
                self.save_unlocked(&data)?;
                Ok(())
            } else {
                Err(anyhow!("Pod '{}' not found", pod_query))
            }
        })
    }

    pub fn remove(&self, query: &str) -> Result<PodRecord> {
        self.remove_with_force(query, false)
    }

    pub fn remove_with_force(&self, query: &str, force: bool) -> Result<PodRecord> {
        let q = query.trim();
        if q.is_empty() {
            return Err(anyhow!("Pod '' not found"));
        }
        let home = self.home.clone();
        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            let mut data = self.load_unlocked();
            let c_store = ContainerStore::with_home(home.clone());

            if let Some(pos) = data
                .pods
                .iter()
                .position(|p| p.id == q || p.id.starts_with(q) || p.name == q)
            {
                let pod = &data.pods[pos];
                let infra_name = self.infra_name(pod);

                if !force {
                    for cid in &pod.containers {
                        if let Some(c) = c_store.find(cid) {
                            if matches!(c.status, ContainerStatus::Running) {
                                return Err(anyhow!(
                                    "conflict: cannot remove running pod {}. Stop the pod or use force",
                                    pod.name
                                ));
                            }
                        }
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

                for cid in &removed.containers {
                    if c_store.find(cid).is_some() {
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
                        let _ = crate::remove_container_quiet(cid, force, false);
                    }
                }
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
                if let Some(sc) = removed.labels.get("boxr.service_container") {
                    let _ = crate::remove_container_quiet(sc, true, false);
                }
                Ok(removed)
            } else {
                Err(anyhow!("Pod '{}' not found", query))
            }
        })
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
            if let Some(p) = data
                .pods
                .iter_mut()
                .find(|p| p.id.starts_with(pod_query) || p.name == pod_query)
            {
                p.status = status.to_string();
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
            if let Some(p) = data
                .pods
                .iter_mut()
                .find(|p| p.id.starts_with(pod_query) || p.name == pod_query)
            {
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
            if let Some(p) = data
                .pods
                .iter_mut()
                .find(|p| p.id.starts_with(pod_query) || p.name == pod_query)
            {
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

    pub fn member_container_ids(&self, pod: &PodRecord) -> Vec<String> {
        let mut ids = pod.containers.clone();
        let infra = self.infra_name(pod);
        if !ids.contains(&infra) {
            ids.insert(0, infra);
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
    if pod.network.as_deref() == Some("host") {
        args.network = "host".to_string();
    } else if pod.share_net {
        args.network = format!("container:{}", infra_name);
    } else if let Some(net) = &pod.network {
        args.network = net.clone();
    }
    if pod.share_ipc && args.ipc.is_none() {
        args.ipc = Some(format!("container:{}", infra_name));
    }
    if pod.share_uts && args.uts.is_none() {
        args.uts = Some(format!("container:{}", infra_name));
    }
    if pod.share_pid && args.pid.is_none() {
        args.pid = Some(format!("container:{}", infra_name));
    }
    if args.hostname.is_none() {
        args.hostname = pod.hostname.clone().or_else(|| Some(pod.name.clone()));
    }
    if args.dns.is_empty() && !pod.dns.is_empty() {
        args.dns = pod.dns.clone();
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
