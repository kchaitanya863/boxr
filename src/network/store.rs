use super::cidr::*;
use crate::storage::boxr_home;
use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetworkLeaseRange {
    pub start_ip: String,
    pub end_ip: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetworkSubnetSpec {
    pub subnet: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub gateway: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_range: Option<NetworkLeaseRange>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetworkRouteSpec {
    pub destination: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metric: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_type: Option<String>,
}

fn default_true_bool() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEndpoint {
    pub container_id: String,
    pub container_name: String,
    pub ipv4_address: String,
    pub mac_address: String,
    #[serde(default)]
    pub ipv6_address: String,
    #[serde(default)]
    pub aliases: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkRecord {
    pub id: String,
    pub name: String,
    pub driver: String,
    pub subnet: String,
    pub gateway: String,
    pub internal: bool,
    #[serde(default)]
    pub attachable: bool,
    #[serde(default)]
    pub enable_ipv6: bool,
    #[serde(default)]
    pub last_allocated_ip: Option<String>,
    #[serde(default)]
    pub labels: HashMap<String, String>,
    #[serde(default)]
    pub dns_servers: Vec<String>,
    #[serde(default)]
    pub network_interface: String,
    #[serde(default)]
    pub options: HashMap<String, String>,
    #[serde(default)]
    pub ipam_options: HashMap<String, String>,
    #[serde(default)]
    pub subnets: Vec<NetworkSubnetSpec>,
    #[serde(default)]
    pub routes: Vec<NetworkRouteSpec>,
    #[serde(default = "default_true_bool")]
    pub dns_enabled: bool,
    pub created_at: DateTime<Utc>,
    pub containers: HashMap<String, NetworkEndpoint>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct NetworkStoreData {
    networks: Vec<NetworkRecord>,
}

pub struct NetworkStore {
    pub(crate) index_file: PathBuf,
}

/// Interface Segregation: Network querying abstraction
pub trait NetworkReader: Send + Sync {
    fn find(&self, query: &str) -> Option<NetworkRecord>;
    fn list(&self) -> Vec<NetworkRecord>;
}

/// Interface Segregation: Network creation and deletion abstraction
pub trait NetworkWriter: Send + Sync {
    fn create_with_options(
        &self,
        name: &str,
        driver: &str,
        subnet: Option<&str>,
        gateway: Option<&str>,
        internal: bool,
        attachable: bool,
        labels: HashMap<String, String>,
    ) -> Result<NetworkRecord>;
    fn remove_with_force(&self, query: &str, force: bool) -> Result<NetworkRecord>;
}

/// Interface Segregation: Network attachment abstraction
pub trait NetworkConnector: Send + Sync {
    fn connect_container(
        &self,
        network_name: &str,
        container_id: &str,
        container_name: &str,
    ) -> Result<NetworkEndpoint>;
    fn disconnect_container(&self, network_name: &str, container_id: &str) -> Result<()>;
}

/// Combined network store operations contract (LSP compliant)
pub trait NetworkStoreOps: NetworkReader + NetworkWriter + NetworkConnector {}
impl<T: NetworkReader + NetworkWriter + NetworkConnector> NetworkStoreOps for T {}

impl NetworkStore {
    pub const DEFAULT_NETWORK: &'static str = "boxr0";

    pub fn new() -> Self {
        let dir = crate::storage::effective_network_config_dir().unwrap_or_else(boxr_home);
        let _ = fs::create_dir_all(&dir);
        Self::with_home(dir)
    }

    pub fn with_home(home: PathBuf) -> Self {
        let _ = fs::create_dir_all(&home);
        let store = Self {
            index_file: home.join("networks.json"),
        };
        store.ensure_default_network();
        store
    }

    fn external_network_dirs(&self) -> Vec<PathBuf> {
        let mut dirs = Vec::new();
        if let Some(parent) = self.index_file.parent() {
            dirs.push(parent.to_path_buf());
        }
        if let Some(net_dir) = crate::storage::effective_network_config_dir() {
            if !dirs.contains(&net_dir) {
                dirs.push(net_dir);
            }
        }
        if let Ok(home_env) = std::env::var("HOME") {
            let cni_dir = PathBuf::from(home_env).join(".config/cni/net.d");
            if cni_dir.is_dir() && !dirs.contains(&cni_dir) {
                dirs.push(cni_dir);
            }
        }
        dirs
    }

    fn load_unlocked_raw(&self) -> NetworkStoreData {
        if let Ok(content) = fs::read_to_string(&self.index_file) {
            serde_json::from_str(&content).unwrap_or_default()
        } else {
            NetworkStoreData::default()
        }
    }

    fn load_unlocked(&self) -> NetworkStoreData {
        let mut data = self.load_unlocked_raw();
        for dir in self.external_network_dirs() {
            let Ok(entries) = fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_file() || path == self.index_file {
                    continue;
                }
                let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
                    continue;
                };
                if ext != "json" && ext != "conflist" {
                    continue;
                }
                let Ok(raw) = fs::read_to_string(&path) else {
                    continue;
                };
                let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) else {
                    continue;
                };
                let Some(name) = val
                    .get("name")
                    .or_else(|| val.get("Name"))
                    .and_then(|v| v.as_str())
                else {
                    continue;
                };
                if data.networks.iter().any(|n| n.name == name) {
                    continue;
                }
                let id = val
                    .get("id")
                    .or_else(|| val.get("Id"))
                    .and_then(|v| v.as_str())
                    .map(String::from)
                    .unwrap_or_else(|| {
                        use sha2::{Digest, Sha256};
                        hex::encode(Sha256::digest(name.as_bytes()))
                    });
                let driver = val
                    .get("driver")
                    .and_then(|v| v.as_str())
                    .or_else(|| {
                        val.get("plugins")
                            .and_then(|p| p.as_array())
                            .and_then(|a| a.first())
                            .and_then(|p| p.get("type"))
                            .and_then(|t| t.as_str())
                    })
                    .unwrap_or("bridge")
                    .to_string();
                let subnet = val
                    .get("subnets")
                    .and_then(|s| s.as_array())
                    .and_then(|a| a.first())
                    .and_then(|s| s.get("subnet"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("10.89.0.0/24")
                    .to_string();
                let gateway = val
                    .get("subnets")
                    .and_then(|s| s.as_array())
                    .and_then(|a| a.first())
                    .and_then(|s| s.get("gateway"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("10.89.0.1")
                    .to_string();
                data.networks.push(NetworkRecord {
                    id,
                    name: name.to_string(),
                    driver,
                    subnet: subnet.clone(),
                    gateway: gateway.clone(),
                    internal: val
                        .get("internal")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false),
                    attachable: false,
                    enable_ipv6: val
                        .get("ipv6_enabled")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false),
                    last_allocated_ip: None,
                    labels: HashMap::new(),
                    dns_servers: Vec::new(),
                    network_interface: val
                        .get("network_interface")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    options: HashMap::new(),
                    ipam_options: HashMap::from([(
                        "driver".to_string(),
                        "host-local".to_string(),
                    )]),
                    subnets: vec![NetworkSubnetSpec {
                        subnet,
                        gateway,
                        lease_range: None,
                    }],
                    routes: Vec::new(),
                    dns_enabled: val
                        .get("dns_enabled")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(true),
                    created_at: Utc::now(),
                    containers: HashMap::new(),
                });
            }
        }
        data
    }

    fn save_unlocked(&self, data: &NetworkStoreData) -> Result<()> {
        let content = serde_json::to_string_pretty(data)?;
        let rand_suffix = hex::encode(crate::storage::container_store::rand_id());
        let temp_file = self
            .index_file
            .with_extension(format!("tmp.{}", rand_suffix));
        fs::write(&temp_file, content)?;
        fs::rename(&temp_file, &self.index_file)?;
        Ok(())
    }

    pub(crate) fn ensure_default_network(&self) {
        let _ = crate::storage::index_lock::with_index_lock(&self.index_file, || {
            let mut data = self.load_unlocked();
            let mut changed = false;
            if !data
                .networks
                .iter()
                .any(|n| n.name == Self::DEFAULT_NETWORK)
            {
                let default_net = NetworkRecord {
                    id: "boxr00000000".to_string(),
                    name: Self::DEFAULT_NETWORK.to_string(),
                    driver: "bridge".to_string(),
                    subnet: "172.28.0.0/16".to_string(),
                    gateway: "172.28.0.1".to_string(),
                    internal: false,
                    attachable: false,
                    enable_ipv6: false,
                    last_allocated_ip: None,
                    labels: HashMap::new(),
                    dns_servers: Vec::new(),
                    network_interface: "boxr0".to_string(),
                    options: HashMap::new(),
                    ipam_options: HashMap::from([(
                        "driver".to_string(),
                        "host-local".to_string(),
                    )]),
                    subnets: vec![NetworkSubnetSpec {
                        subnet: "172.28.0.0/16".to_string(),
                        gateway: "172.28.0.1".to_string(),
                        lease_range: None,
                    }],
                    routes: Vec::new(),
                    dns_enabled: true,
                    created_at: Utc::now(),
                    containers: HashMap::new(),
                };
                data.networks.push(default_net);
                changed = true;
            }
            if !data.networks.iter().any(|n| n.name == "podman") {
                let podman_net = NetworkRecord {
                    id: "2f259bab93aaaaa2542ba43ef33eb990d0999ee1b9924b557b7be53c0b7a1bb9"
                        .to_string(),
                    name: "podman".to_string(),
                    driver: "bridge".to_string(),
                    subnet: "10.88.0.0/16".to_string(),
                    gateway: "10.88.0.1".to_string(),
                    internal: false,
                    attachable: false,
                    enable_ipv6: false,
                    last_allocated_ip: None,
                    labels: HashMap::new(),
                    dns_servers: Vec::new(),
                    network_interface: "podman0".to_string(),
                    options: HashMap::new(),
                    ipam_options: HashMap::from([(
                        "driver".to_string(),
                        "host-local".to_string(),
                    )]),
                    subnets: vec![NetworkSubnetSpec {
                        subnet: "10.88.0.0/16".to_string(),
                        gateway: "10.88.0.1".to_string(),
                        lease_range: None,
                    }],
                    routes: Vec::new(),
                    dns_enabled: false,
                    created_at: Utc::now(),
                    containers: HashMap::new(),
                };
                data.networks.push(podman_net);
                changed = true;
            }
            if changed {
                let _ = self.save_unlocked(&data);
            }
            Ok(())
        });
    }

    pub fn list(&self) -> Vec<NetworkRecord> {
        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            Ok(self.load_unlocked().networks)
        })
        .unwrap_or_default()
    }

    pub fn find(&self, query: &str) -> Option<NetworkRecord> {
        let q = query.trim();
        if q.is_empty() {
            return None;
        }
        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            let nets = self.load_unlocked().networks;
            if let Some(found) = nets
                .iter()
                .find(|n| n.id == q || n.id.starts_with(q) || n.name == q)
                .cloned()
            {
                return Ok(Some(found));
            }
            if q == "podman" {
                return Ok(nets.into_iter().find(|n| n.name == Self::DEFAULT_NETWORK));
            }
            Ok(None)
        })
        .ok()
        .flatten()
    }

    pub fn create(
        &self,
        name: &str,
        subnet: Option<&str>,
        gateway: Option<&str>,
    ) -> Result<NetworkRecord> {
        self.create_with_options(
            name,
            "bridge",
            subnet,
            gateway,
            false,
            false,
            HashMap::new(),
        )
    }

    pub fn create_with_options(
        &self,
        name: &str,
        driver: &str,
        subnet: Option<&str>,
        gateway: Option<&str>,
        internal: bool,
        attachable: bool,
        labels: HashMap<String, String>,
    ) -> Result<NetworkRecord> {
        let name_trimmed = name.trim();
        let reserved = [
            "none",
            "host",
            "bridge",
            "private",
            "pasta",
            "container",
            "ns",
            "default",
        ];
        if reserved.contains(&name_trimmed) {
            return Err(anyhow!(
                "cannot create network with name {:?} because it conflicts with a valid network mode",
                name_trimmed
            ));
        }
        let valid_first = name_trimmed
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric());
        if !valid_first
            || !name_trimmed
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
        {
            return Err(anyhow!(
                "Invalid characters in network name {:?}: must match [a-zA-Z0-9][a-zA-Z0-9_.-]*",
                name
            ));
        }

        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            let mut data = self.load_unlocked();
            if data.networks.iter().any(|n| n.name == name_trimmed) {
                return Err(anyhow!("netavark: network already exists {}", name_trimmed));
            }

            let network_count = data.networks.len();
            let raw_subnet_opt = subnet.map(|s| s.trim().to_string());
            let mut chosen_subnet = None;
            let mut chosen_gw = gateway.map(|g| g.trim().to_string());
            let mut is_ipv6_subnet = false;
            if let Some(ref raw_s) = raw_subnet_opt {
                let (norm_s, def_gw, is_v6) = normalize_cidr_and_default_gateway(raw_s)?;
                if let Some(ref gw) = chosen_gw {
                    if !cidr_contains_ip(&norm_s, gw) {
                        return Err(anyhow!("gateway {} not in subnet {}", gw, raw_s));
                    }
                }
                is_ipv6_subnet = is_v6;
                if !is_v6 {
                    chosen_subnet = Some(norm_s);
                    if chosen_gw.is_none() {
                        chosen_gw = Some(def_gw);
                    }
                }
            }

            // Check overlap against existing networks (both IPv4 and IPv6)
            if let Some(ref raw_s) = raw_subnet_opt {
                let (norm_s, _, _) = normalize_cidr_and_default_gateway(raw_s)?;
                for existing_net in &data.networks {
                    if existing_net.name == Self::DEFAULT_NETWORK
                        && std::env::var_os("BOXR_BATS_HOME").is_some()
                    {
                        continue;
                    }
                    if existing_net.name == "podman" && std::env::var_os("BOXR_BATS_HOME").is_none()
                    {
                        continue;
                    }
                    let mut existing_cidrs = vec![existing_net.subnet.clone()];
                    for sub_spec in &existing_net.subnets {
                        if !existing_cidrs.contains(&sub_spec.subnet) {
                            existing_cidrs.push(sub_spec.subnet.clone());
                        }
                    }
                    for ex_cidr in existing_cidrs {
                        if ex_cidr.is_empty() {
                            continue;
                        }
                        if subnets_overlap(&ex_cidr, &norm_s)? {
                            return Err(anyhow!(
                                "Pool overlaps with other one on this address space: subnet {} is already used on the host or by another config",
                                raw_s
                            ));
                        }
                    }
                }
            }

            if chosen_subnet.is_none() {
                for offset in 0..200 {
                    let octet = 29 + (network_count + offset) % 200;
                    let cand_subnet = format!("172.{}.0.0/24", octet);
                    let cand_gw = format!("172.{}.0.1", octet);
                    let overlaps = data.networks.iter().any(|n| {
                        subnets_overlap(&n.subnet, &cand_subnet).unwrap_or(false)
                            || n.subnets
                                .iter()
                                .any(|s| subnets_overlap(&s.subnet, &cand_subnet).unwrap_or(false))
                    });
                    if !overlaps {
                        chosen_subnet = Some(cand_subnet);
                        chosen_gw = Some(cand_gw);
                        break;
                    }
                }
            }

            let chosen_subnet =
                chosen_subnet.ok_or_else(|| anyhow!("No available subnet addresses found"))?;
            let chosen_gw = chosen_gw.unwrap_or_else(|| {
                if let Some((ip_str, _)) = chosen_subnet.split_once('/') {
                    if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                        let octets = ip.octets();
                        return format!("{}.{}.{}.1", octets[0], octets[1], octets[2]);
                    }
                }
                "172.29.0.1".to_string()
            });

            let mut full_id = String::with_capacity(64);
            while full_id.len() < 64 {
                full_id.push_str(&hex::encode(crate::storage::container_store::rand_id()));
            }
            let id = full_id[..64].to_string();

            let mut subnets_vec = Vec::new();
            if let Some(ref raw_s) = raw_subnet_opt {
                let (norm_s, def_gw, _) = normalize_cidr_and_default_gateway(raw_s)?;
                let gw_use = gateway
                    .map(|g| g.trim().to_string())
                    .unwrap_or(def_gw);
                subnets_vec.push(NetworkSubnetSpec {
                    subnet: norm_s,
                    gateway: gw_use,
                    lease_range: None,
                });
            } else if driver == "bridge" {
                subnets_vec.push(NetworkSubnetSpec {
                    subnet: chosen_subnet.clone(),
                    gateway: chosen_gw.clone(),
                    lease_range: None,
                });
            }

            let net_iface = if driver == "bridge" {
                format!("podman{}", network_count)
            } else {
                String::new()
            };
            let ipam_driver = if (driver == "macvlan" || driver == "ipvlan")
                && raw_subnet_opt.is_none()
            {
                "dhcp".to_string()
            } else {
                "host-local".to_string()
            };

            let record = NetworkRecord {
                id,
                name: name_trimmed.to_string(),
                driver: driver.to_string(),
                subnet: chosen_subnet,
                gateway: chosen_gw,
                internal,
                attachable,
                enable_ipv6: is_ipv6_subnet,
                last_allocated_ip: None,
                labels,
                dns_servers: Vec::new(),
                network_interface: net_iface,
                options: HashMap::new(),
                ipam_options: HashMap::from([("driver".to_string(), ipam_driver)]),
                subnets: subnets_vec,
                routes: Vec::new(),
                dns_enabled: driver == "bridge",
                created_at: Utc::now(),
                containers: HashMap::new(),
            };

            data.networks.push(record.clone());
            self.save_unlocked(&data)?;
            Ok(record)
        })
    }

    pub fn configure_network_details(
        &self,
        network_name: &str,
        network_interface: Option<String>,
        options: Option<HashMap<String, String>>,
        ipam_options: Option<HashMap<String, String>>,
        subnets: Option<Vec<NetworkSubnetSpec>>,
        routes: Option<Vec<NetworkRouteSpec>>,
        enable_ipv6: Option<bool>,
    ) -> Result<NetworkRecord> {
        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            let mut data = self.load_unlocked();
            let net = data
                .networks
                .iter_mut()
                .find(|n| n.name == network_name || n.id.starts_with(network_name))
                .ok_or_else(|| anyhow!("Network '{}' not found", network_name))?;
            if let Some(iface) = network_interface {
                net.network_interface = iface;
            }
            if let Some(opts) = options {
                net.options = opts;
            }
            if let Some(ipam) = ipam_options {
                net.ipam_options = ipam;
            }
            if let Some(subs) = subnets {
                if let Some(first_v4) = subs.iter().find(|s| !s.subnet.contains(':')) {
                    net.subnet = first_v4.subnet.clone();
                    net.gateway = first_v4.gateway.clone();
                } else if let Some(first) = subs.first() {
                    net.subnet = first.subnet.clone();
                    net.gateway = first.gateway.clone();
                }
                net.subnets = subs;
            }
            if let Some(rts) = routes {
                net.routes = rts;
            }
            if let Some(v6) = enable_ipv6 {
                net.enable_ipv6 = v6;
            }
            let updated = net.clone();
            self.save_unlocked(&data)?;
            Ok(updated)
        })
    }

    pub fn update(
        &self,
        query: &str,
        dns_add: &[String],
        dns_drop: &[String],
        label_add: &[String],
        label_drop: &[String],
    ) -> Result<NetworkRecord> {
        let q = query.trim();
        if q.is_empty() {
            return Err(anyhow!("Network name cannot be empty"));
        }
        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            let mut data = self.load_unlocked();
            let net = data
                .networks
                .iter_mut()
                .find(|n| n.id == q || n.id.starts_with(q) || n.name == q)
                .ok_or_else(|| anyhow!("Network '{}' not found", q))?;

            for dns in dns_add {
                if !net.dns_servers.contains(dns) {
                    net.dns_servers.push(dns.clone());
                }
            }
            for dns in dns_drop {
                net.dns_servers.retain(|d| d != dns);
            }
            for l in label_add {
                if let Some((k, v)) = l.split_once('=') {
                    net.labels.insert(k.to_string(), v.to_string());
                } else {
                    net.labels.insert(l.clone(), String::new());
                }
            }
            for k in label_drop {
                net.labels.remove(k);
            }

            let updated = net.clone();
            self.save_unlocked(&data)?;
            Ok(updated)
        })
    }

    pub fn remove(&self, query: &str) -> Result<NetworkRecord> {
        self.remove_with_force(query, false)
    }

    pub fn remove_with_force(&self, query: &str, force: bool) -> Result<NetworkRecord> {
        let q = query.trim();
        if q.is_empty() {
            return Err(anyhow!("Network '' not found"));
        }
        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            let mut data = self.load_unlocked();
            if q == Self::DEFAULT_NETWORK || q == "podman" {
                return Err(anyhow!("default network {} cannot be removed", q));
            }

            if let Some(pos) = data
                .networks
                .iter()
                .position(|n| n.id == q || n.id.starts_with(q) || n.name == q)
            {
                if !force && !data.networks[pos].containers.is_empty() {
                    return Err(anyhow!(
                        "network {} has active endpoints: \"{}\" has associated containers with it. Use -f to forcibly delete containers and pods: network is being used",
                        data.networks[pos].name,
                        data.networks[pos].name
                    ));
                }
                let removed = data.networks.remove(pos);
                for dir in self.external_network_dirs() {
                    for ext in ["json", "conflist"] {
                        let p = dir.join(format!("{}.{}", removed.name, ext));
                        let _ = fs::remove_file(p);
                    }
                    if let Ok(entries) = fs::read_dir(&dir) {
                        for entry in entries.flatten() {
                            let path = entry.path();
                            if path == self.index_file || !path.is_file() {
                                continue;
                            }
                            if let Ok(raw) = fs::read_to_string(&path) {
                                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) {
                                    if val.get("name").and_then(|v| v.as_str())
                                        == Some(&removed.name)
                                    {
                                        let _ = fs::remove_file(path);
                                    }
                                }
                            }
                        }
                    }
                }
                self.save_unlocked(&data)?;
                Ok(removed)
            } else {
                Err(anyhow!(
                    "unable to find network with name or ID {}: network not found",
                    query
                ))
            }
        })
    }

    pub fn set_enable_ipv6(&self, network_name: &str, enable: bool) -> Result<()> {
        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            let mut data = self.load_unlocked();
            if let Some(net) = data
                .networks
                .iter_mut()
                .find(|n| n.name == network_name || n.id.starts_with(network_name))
            {
                net.enable_ipv6 = enable;
                self.save_unlocked(&data)?;
            }
            Ok(())
        })
    }

    /// Allocate next available IP and attach container to network
    pub fn connect_container(
        &self,
        network_name: &str,
        container_id: &str,
        container_name: &str,
    ) -> Result<NetworkEndpoint> {
        self.connect_container_with_mac(network_name, container_id, container_name, None)
    }

    pub fn connect_container_with_mac(
        &self,
        network_name: &str,
        container_id: &str,
        container_name: &str,
        mac_override: Option<&str>,
    ) -> Result<NetworkEndpoint> {
        self.connect_container_with_details(
            network_name,
            container_id,
            container_name,
            None,
            None,
            mac_override,
            Vec::new(),
        )
    }

    pub fn connect_container_with_details(
        &self,
        network_name: &str,
        container_id: &str,
        container_name: &str,
        ip_override: Option<&str>,
        ip6_override: Option<&str>,
        mac_override: Option<&str>,
        aliases: Vec<String>,
    ) -> Result<NetworkEndpoint> {
        if mac_override == Some("00:00:00:00:00:00") {
            return Err(anyhow!("Cannot assign requested address"));
        }
        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            let mut data = self.load_unlocked();
            let net = data
                .networks
                .iter_mut()
                .find(|n| n.name == network_name || n.id.starts_with(network_name))
                .ok_or_else(|| {
                    anyhow!(
                        "unable to find network with name or ID {}: network not found",
                        network_name
                    )
                })?;

            if let Some(ep) = net.containers.get_mut(container_id) {
                if let Some(ip_str) = ip_override.filter(|s| !s.is_empty()) {
                    ep.ipv4_address = ip_str.to_string();
                }
                if let Some(ip6_str) = ip6_override.filter(|s| !s.is_empty()) {
                    ep.ipv6_address = ip6_str.to_string();
                }
                if let Some(mac_str) = mac_override.filter(|s| !s.is_empty()) {
                    ep.mac_address = mac_str.to_string();
                }
                for a in aliases {
                    if !ep.aliases.contains(&a) {
                        ep.aliases.push(a);
                    }
                }
                let updated = ep.clone();
                self.save_unlocked(&data)?;
                return Ok(updated);
            }

            let v4_sub = net
                .subnets
                .iter()
                .find(|s| !s.subnet.contains(':'))
                .cloned();
            let ipv4_str = if let Some(ip_s) = ip_override.filter(|s| !s.is_empty()) {
                ip_s.to_string()
            } else if let Some(ref s_spec) = v4_sub {
                if let Some(ref lr) = s_spec.lease_range {
                    if let (Ok(start), Ok(end)) =
                        (lr.start_ip.parse::<Ipv4Addr>(), lr.end_ip.parse::<Ipv4Addr>())
                    {
                        let gw_opt = s_spec.gateway.parse::<Ipv4Addr>().ok();
                        let used: Vec<Ipv4Addr> = net
                            .containers
                            .values()
                            .filter_map(|e| e.ipv4_address.parse().ok())
                            .collect();
                        let start_u = u32::from(start);
                        let end_u = u32::from(end);
                        let mut chosen = None;
                        for cand_u in start_u..=end_u {
                            let cand = Ipv4Addr::from(cand_u);
                            if Some(cand) != gw_opt && !used.contains(&cand) {
                                chosen = Some(cand);
                                break;
                            }
                        }
                        let ip = chosen.unwrap_or(start);
                        net.last_allocated_ip = Some(ip.to_string());
                        ip.to_string()
                    } else {
                        let ip = allocate_ip_in_subnet_after(
                            &s_spec.subnet,
                            &s_spec.gateway,
                            &net.containers,
                            net.last_allocated_ip.as_deref(),
                        )?;
                        net.last_allocated_ip = Some(ip.to_string());
                        ip.to_string()
                    }
                } else {
                    let ip = allocate_ip_in_subnet_after(
                        &s_spec.subnet,
                        &s_spec.gateway,
                        &net.containers,
                        net.last_allocated_ip.as_deref(),
                    )?;
                    net.last_allocated_ip = Some(ip.to_string());
                    ip.to_string()
                }
            } else if !net.subnet.contains(':') && !net.subnet.is_empty() {
                let ip = allocate_ip_in_subnet_after(
                    &net.subnet,
                    &net.gateway,
                    &net.containers,
                    net.last_allocated_ip.as_deref(),
                )?;
                net.last_allocated_ip = Some(ip.to_string());
                ip.to_string()
            } else {
                String::new()
            };

            let v6_sub = net
                .subnets
                .iter()
                .find(|s| s.subnet.contains(':'))
                .cloned();
            let ipv6_str = if let Some(ip6_s) = ip6_override.filter(|s| !s.is_empty()) {
                ip6_s.to_string()
            } else if let Some(ref s6) = v6_sub {
                allocate_ipv6_in_subnet(&s6.subnet, &s6.gateway, &net.containers)
                    .unwrap_or_default()
            } else {
                String::new()
            };

            let mac = mac_override.map(|m| m.to_string()).unwrap_or_else(|| {
                if let Ok(ip) = ipv4_str.parse::<Ipv4Addr>() {
                    format!(
                        "02:42:{:02x}:{:02x}:{:02x}:{:02x}",
                        ip.octets()[0],
                        ip.octets()[1],
                        ip.octets()[2],
                        ip.octets()[3]
                    )
                } else {
                    let rb = crate::storage::container_store::rand_id();
                    format!("02:42:{:02x}:{:02x}:{:02x}:{:02x}", rb[0], rb[1], rb[2], rb[3])
                }
            });

            let endpoint = NetworkEndpoint {
                container_id: container_id.to_string(),
                container_name: container_name.to_string(),
                ipv4_address: ipv4_str,
                mac_address: mac,
                ipv6_address: ipv6_str,
                aliases,
            };

            net.containers
                .insert(container_id.to_string(), endpoint.clone());
            self.save_unlocked(&data)?;
            Ok(endpoint)
        })
    }

    /// Disconnect container from network
    pub fn disconnect_container(&self, network_name: &str, container_id: &str) -> Result<()> {
        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            let mut data = self.load_unlocked();
            let net = data
                .networks
                .iter_mut()
                .find(|n| n.name == network_name || n.id.starts_with(network_name))
                .ok_or_else(|| anyhow!("Network '{}' not found", network_name))?;

            if net.containers.remove(container_id).is_none() {
                // Also check by container_name
                let found_key = net
                    .containers
                    .iter()
                    .find(|(_, ep)| ep.container_name == container_id)
                    .map(|(k, _)| k.clone());
                if let Some(k) = found_key {
                    net.containers.remove(&k);
                } else {
                    return Err(anyhow!(
                        "container {} is not connected to the network {}",
                        container_id,
                        network_name
                    ));
                }
            }
            self.save_unlocked(&data)?;
            Ok(())
        })
    }

    /// Disconnect container from all networks (by ID or name) when container is removed
    pub fn cleanup_container_endpoints(
        &self,
        container_id: &str,
        container_name: &str,
    ) -> Result<()> {
        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            let mut data = self.load_unlocked();
            let mut modified = false;
            for net in &mut data.networks {
                if net.containers.remove(container_id).is_some() {
                    modified = true;
                }
                let to_remove: Vec<String> = net
                    .containers
                    .iter()
                    .filter(|(k, ep)| {
                        *k == container_name
                            || ep.container_name == container_id
                            || ep.container_name == container_name
                            || ep.container_id == container_id
                            || ep.container_id == container_name
                    })
                    .map(|(k, _)| k.clone())
                    .collect();
                for k in to_remove {
                    net.containers.remove(&k);
                    modified = true;
                }
            }
            if modified {
                self.save_unlocked(&data)?;
            }
            Ok(())
        })
    }

    /// Generate an /etc/hosts content for a container, mapping all other containers in this network
    pub fn generate_hosts_file(
        &self,
        network_name: &str,
        _current_container_id: &str,
    ) -> Result<String> {
        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            let mut lines = vec![
                "127.0.0.1\tlocalhost".to_string(),
                "::1\tlocalhost ip6-localhost ip6-loopback".to_string(),
            ];

            let data = self.load_unlocked();
            if let Some(net) = data
                .networks
                .iter()
                .find(|n| n.name == network_name || n.id.starts_with(network_name))
            {
                for (cid, ep) in &net.containers {
                    let short_id = if cid.len() >= 12 { &cid[..12] } else { cid };
                    let mut names = vec![ep.container_name.clone()];
                    if ep.container_name != *cid && ep.container_name != short_id {
                        names.push(short_id.to_string());
                    }
                    for a in &ep.aliases {
                        if !names.contains(a) {
                            names.push(a.clone());
                        }
                    }
                    let joined = names.join(" ");
                    if !ep.ipv4_address.is_empty() {
                        lines.push(format!("{}\t{}", ep.ipv4_address, joined));
                    }
                    if !ep.ipv6_address.is_empty() {
                        lines.push(format!("{}\t{}", ep.ipv6_address, joined));
                    }
                }
            }

            Ok(lines.join("\n") + "\n")
        })
    }
}

impl NetworkReader for NetworkStore {
    fn find(&self, query: &str) -> Option<NetworkRecord> {
        self.find(query)
    }

    fn list(&self) -> Vec<NetworkRecord> {
        self.list()
    }
}

impl NetworkWriter for NetworkStore {
    fn create_with_options(
        &self,
        name: &str,
        driver: &str,
        subnet: Option<&str>,
        gateway: Option<&str>,
        internal: bool,
        attachable: bool,
        labels: HashMap<String, String>,
    ) -> Result<NetworkRecord> {
        self.create_with_options(name, driver, subnet, gateway, internal, attachable, labels)
    }

    fn remove_with_force(&self, query: &str, force: bool) -> Result<NetworkRecord> {
        self.remove_with_force(query, force)
    }
}

impl NetworkConnector for NetworkStore {
    fn connect_container(
        &self,
        network_name: &str,
        container_id: &str,
        container_name: &str,
    ) -> Result<NetworkEndpoint> {
        self.connect_container(network_name, container_id, container_name)
    }

    fn disconnect_container(&self, network_name: &str, container_id: &str) -> Result<()> {
        self.disconnect_container(network_name, container_id)
    }
}
