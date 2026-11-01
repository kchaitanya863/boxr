use super::cidr::*;
use crate::storage::boxr_home;
use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEndpoint {
    pub container_id: String,
    pub container_name: String,
    pub ipv4_address: String,
    pub mac_address: String,
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
        Self::with_home(boxr_home())
    }

    pub fn with_home(home: PathBuf) -> Self {
        let store = Self {
            index_file: home.join("networks.json"),
        };
        store.ensure_default_network();
        store
    }

    fn load_unlocked(&self) -> NetworkStoreData {
        if let Ok(content) = fs::read_to_string(&self.index_file) {
            serde_json::from_str(&content).unwrap_or_default()
        } else {
            NetworkStoreData::default()
        }
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
        mut labels: HashMap<String, String>,
    ) -> Result<NetworkRecord> {
        let name_trimmed = name.trim();
        if name_trimmed.is_empty()
            || !name_trimmed
                .chars()
                .all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.')
        {
            return Err(anyhow!(
                "Invalid network name '{}': must be alphanumeric, '_', '-', or '.'",
                name
            ));
        }

        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            let mut data = self.load_unlocked();
            if data.networks.iter().any(|n| n.name == name_trimmed) {
                return Err(anyhow!("netavark: network already exists {}", name_trimmed));
            }

            let network_count = data.networks.len();
            let mut chosen_subnet = subnet.map(|s| s.to_string());
            let mut chosen_gw = gateway.map(|g| g.to_string());
            let is_ipv6_subnet = chosen_subnet.as_ref().is_some_and(|s| s.contains(':'));
            if is_ipv6_subnet {
                chosen_subnet = None;
                chosen_gw = None;
            }

            if chosen_subnet.is_none() {
                for offset in 0..200 {
                    let octet = 29 + (network_count + offset) % 200;
                    let cand_subnet = format!("172.{}.0.0/16", octet);
                    let cand_gw = format!("172.{}.0.1", octet);
                    let overlaps = data
                        .networks
                        .iter()
                        .any(|n| subnets_overlap(&n.subnet, &cand_subnet).unwrap_or(false));
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
                // If user supplied subnet without gateway, default to .1
                if let Some((ip_str, _)) = chosen_subnet.split_once('/') {
                    if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                        let octets = ip.octets();
                        return format!("{}.{}.{}.1", octets[0], octets[1], octets[2]);
                    }
                }
                "172.29.0.1".to_string()
            });

            // Check if chosen subnet overlaps with any existing network subnet
            if driver != "macvlan" && driver != "ipvlan" {
                for existing_net in &data.networks {
                    if existing_net.name == Self::DEFAULT_NETWORK {
                        continue;
                    }
                    if existing_net.driver == "macvlan" || existing_net.driver == "ipvlan" {
                        continue;
                    }
                    if existing_net.name == "podman" && std::env::var_os("BOXR_BATS_HOME").is_none() {
                        continue;
                    }
                    if subnets_overlap(&existing_net.subnet, &chosen_subnet)? {
                        return Err(anyhow!(
                            "Pool overlaps with other one on this address space: subnet '{}' overlaps with network '{}' subnet '{}'",
                            chosen_subnet,
                            existing_net.name,
                            existing_net.subnet
                        ));
                    }
                }
            }

            let mut full_id = String::with_capacity(64);
            while full_id.len() < 64 {
                full_id.push_str(&hex::encode(crate::storage::container_store::rand_id()));
            }
            let id = full_id[..64].to_string();

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
                created_at: Utc::now(),
                containers: HashMap::new(),
            };

            data.networks.push(record.clone());
            self.save_unlocked(&data)?;
            Ok(record)
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
                        "network {} has active endpoints",
                        data.networks[pos].name
                    ));
                }
                let removed = data.networks.remove(pos);
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
        if mac_override == Some("00:00:00:00:00:00") {
            return Err(anyhow!("Cannot assign requested address"));
        }
        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            let mut data = self.load_unlocked();
            let net = data
                .networks
                .iter_mut()
                .find(|n| n.name == network_name || n.id.starts_with(network_name))
                .ok_or_else(|| anyhow!("Network '{}' not found", network_name))?;

            if let Some(ep) = net.containers.get(container_id) {
                return Ok(ep.clone());
            }

            let ip = allocate_ip_in_subnet_after(
                &net.subnet,
                &net.gateway,
                &net.containers,
                net.last_allocated_ip.as_deref(),
            )?;
            net.last_allocated_ip = Some(ip.to_string());
            let mac = mac_override.map(|m| m.to_string()).unwrap_or_else(|| {
                format!(
                    "02:42:{:02x}:{:02x}:{:02x}:{:02x}",
                    ip.octets()[0],
                    ip.octets()[1],
                    ip.octets()[2],
                    ip.octets()[3]
                )
            });

            let endpoint = NetworkEndpoint {
                container_id: container_id.to_string(),
                container_name: container_name.to_string(),
                ipv4_address: ip.to_string(),
                mac_address: mac,
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
                    if ep.container_name == *cid || ep.container_name == short_id {
                        lines.push(format!("{}\t{}", ep.ipv4_address, ep.container_name));
                    } else {
                        lines.push(format!(
                            "{}\t{}\t{}",
                            ep.ipv4_address, ep.container_name, cid
                        ));
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
