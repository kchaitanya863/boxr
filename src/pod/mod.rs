pub mod ops;
pub use ops::PodOps;

use crate::network::PortMapping;
use crate::storage::{ContainerRecord, ContainerStatus, ContainerStore, boxr_home};
use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

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

            let infra_name = format!("{}-infra", pod_name);
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
                let infra_name = format!("{}-infra", pod.name);

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
                        if matches!(infra.status, ContainerStatus::Running) {
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
                    let _ = crate::remove_container(cid, force);
                }
                if let Some(infra) = c_store
                    .find(&infra_name)
                    .or_else(|| c_store.find(&removed.infra_container_id))
                {
                    let _ = crate::remove_container(&infra.id, force);
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

pub fn container_pid_namespace_path(cont: &ContainerRecord, ns: &str) -> Result<String> {
    let pid_file = PathBuf::from(&cont.bundle_path).join("container.pid");
    if pid_file.exists() {
        let pid = fs::read_to_string(&pid_file)?.trim().to_string();
        if !pid.is_empty() {
            return Ok(format!("/proc/{}/ns/{}", pid, ns));
        }
    }
    Err(anyhow!(
        "Container '{}' is not running; cannot join {} namespace",
        cont.name,
        ns
    ))
}

/// Parse `container:<name>` or return the value as a namespace path.
pub fn resolve_namespace_spec(spec: &str, ns_type: &str) -> Result<Option<String>> {
    let trimmed = spec.trim();
    if trimmed.is_empty() || trimmed == "private" {
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
    if trimmed.starts_with('/') {
        return Ok(Some(trimmed.to_string()));
    }
    Ok(None)
}

/// Apply pod namespace sharing settings onto run arguments.
pub fn apply_pod_to_run_args(pod: &PodRecord, infra_name: &str, args: &mut crate::cli::RunArgs) {
    if pod.share_net {
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
    for (k, v) in &pod.labels {
        args.labels.push(format!("{}={}", k, v));
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
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_pod_store_lifecycle() {
        let temp = tempdir().unwrap();
        let store = PodStore::with_home(temp.path().to_path_buf());

        let pod = store.create(Some("test-pod"), Vec::new()).unwrap();
        assert_eq!(pod.name, "test-pod");
        assert_eq!(store.list().len(), 1);
        assert!(pod.share_ipc);
        assert!(pod.share_net);

        assert!(store.find("test-pod").is_some());
        assert!(store.exists("test-pod"));

        store.add_container_to_pod("test-pod", "cont123").unwrap();
        let updated = store.find("test-pod").unwrap();
        assert_eq!(updated.containers, vec!["cont123".to_string()]);
        assert_eq!(updated.status, "Running");

        store.remove("test-pod").unwrap();
        assert_eq!(store.list().len(), 0);
    }

    #[test]
    fn test_pod_config_defaults() {
        let cfg = PodConfig::default();
        assert!(cfg.share_ipc);
        assert!(cfg.share_net);
        assert!(!cfg.share_pid);
    }

    #[test]
    fn test_resolve_namespace_spec_host() {
        let r = resolve_namespace_spec("host", "net").unwrap();
        assert_eq!(r, Some("host".to_string()));
    }

    #[test]
    fn test_pod_prune_removes_exited() {
        let temp = tempdir().unwrap();
        let store = PodStore::with_home(temp.path().to_path_buf());
        let pod = store.create(Some("exited-pod"), Vec::new()).unwrap();
        store.update_status(&pod.name, "Exited").unwrap();
        let pruned = store.prune().unwrap();
        assert!(pruned.contains(&"exited-pod".to_string()));
        assert!(store.find("exited-pod").is_none());
    }

    #[test]
    fn test_apply_pod_to_run_args() {
        let pod = PodRecord {
            id: "abc".to_string(),
            name: "mypod".to_string(),
            created_at: Utc::now(),
            status: "Created".to_string(),
            infra_container_id: "mypod-infra".to_string(),
            containers: vec![],
            ports: vec![],
            hostname: Some("podhost".to_string()),
            labels: HashMap::from([("app".to_string(), "web".to_string())]),
            dns: vec!["8.8.8.8".to_string()],
            memory: Some("512m".to_string()),
            cpus: None,
            share_ipc: true,
            share_net: true,
            share_uts: true,
            share_pid: false,
            network: None,
        };
        let mut args = crate::cli::RunArgs {
            registry_auth: Default::default(),
            interactive: false,
            tty: None,
            detach: true,
            rm: false,
            rmi: false,
            name: Some("worker".to_string()),
            env: vec![],
            unsetenv: vec![],
            unsetenv_all: false,
            systemd: None,
            ports: vec![],
            volumes: vec![],
            memory: None,
            labels: vec![],
            dns: vec![],
            cidfile: None,
            cpus: None,
            pids_limit: None,
            rootless: true,
            restart: "no".to_string(),
            health_cmd: None,
            platform: None,
            privileged: false,
            network: "bridge".to_string(),
            disable_content_trust: false,
            gpus: None,
            entrypoint: None,
            tz: Vec::new(),
            env_file: None,
            user: None,
            hostname: None,
            add_host: vec![],
            shm_size: None,
            cap_add: vec![],
            cap_drop: vec![],
            read_only: false,
            init: false,
            tmpfs: vec![],
            devices: vec![],
            security_opt: vec![],
            cpu_shares: None,
            cpuset_cpus: None,
            memory_swap: None,
            memory_reservation: None,
            dns_search: vec![],
            dns_option: vec![],
            expose: vec![],
            sysctl: vec![],
            stop_timeout: None,
            stop_signal: None,
            annotations: vec![],
            ulimits: vec![],
            ipc: None,
            pid: None,
            uts: None,
            userns: Vec::new(),
            cgroupns: None,
            cgroup_parent: None,
            isolation: None,
            cpu_count: None,
            cpu_percent: None,
            io_maxbandwidth: None,
            io_maxiops: None,
            publish_all: false,
            ip: None,
            ip6: None,
            mac_address: None,
            link: vec![],
            network_alias: vec![],
            mount: vec![],
            health_interval: None,
            health_timeout: None,
            health_retries: None,
            health_start_period: None,
            health_start_interval: None,
            no_healthcheck: false,
            attach: vec![],
            pull: None,
            quiet: false,
            log_driver: vec![],
            log_opt: vec![],
            oom_kill_disable: false,
            oom_score_adj: None,
            group_add: vec![],
            label_file: None,
            umask: None,
            domainname: None,
            detach_keys: None,
            blkio_weight: None,
            blkio_weight_device: vec![],
            cpu_period: None,
            cpu_quota: None,
            cpu_rt_period: None,
            cpu_rt_runtime: None,
            cpuset_mems: None,
            device_cgroup_rule: vec![],
            device_read_bps: vec![],
            device_read_iops: vec![],
            device_write_bps: vec![],
            device_write_iops: vec![],
            link_local_ip: vec![],
            memory_swappiness: None,
            runtime: None,
            sig_proxy: true,
            storage_opt: vec![],
            use_api_socket: false,
            volume_driver: None,
            volumes_from: vec![],
            workdir: None,
            pod: Some("mypod".to_string()),
            timeout: None,
            image: "alpine".to_string(),
            command: vec![],
        };
        apply_pod_to_run_args(&pod, "mypod-infra", &mut args);
        assert_eq!(args.network, "container:mypod-infra");
        assert_eq!(args.ipc, Some("container:mypod-infra".to_string()));
        assert_eq!(args.hostname, Some("podhost".to_string()));
        assert_eq!(args.dns, vec!["8.8.8.8".to_string()]);
        assert!(args.labels.iter().any(|l| l.contains("app=web")));
    }
}
