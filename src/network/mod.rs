pub mod pasta;
pub mod rootless;
pub mod usernet;

use crate::storage::boxr_home;
use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortMapping {
    pub host_ip: Option<String>,
    pub host_port: u16,
    pub container_port: u16,
    pub protocol: String, // "tcp" or "udp"
}

/// Resolve a user-facing network flag to a NetworkStore name for bridge attachment.
pub fn resolved_bridge_network_name(network: &str) -> Option<String> {
    let mode = pasta::NetworkMode::parse(network);
    if mode != pasta::NetworkMode::Bridge {
        return None;
    }
    let name = match network {
        "bridge" | "default" | "auto" | "" => NetworkStore::DEFAULT_NETWORK,
        other => other,
    };
    Some(name.to_string())
}

/// Register a running container on its bridge network (if applicable).
pub fn connect_container_to_bridge_network(
    network: &str,
    container_id: &str,
    container_name: &str,
    home: Option<&std::path::Path>,
) -> Result<()> {
    let net_name = resolved_bridge_network_name(network)
        .ok_or_else(|| anyhow!("network {} is not a bridge network", network))?;
    let store = match home {
        Some(h) => NetworkStore::with_home(h.to_path_buf()),
        None => NetworkStore::new(),
    };
    if store.find(&net_name).is_none() {
        return Err(anyhow!("network {} not found", net_name));
    }
    let _ = store.connect_container(&net_name, container_id, container_name)?;
    Ok(())
}

impl PortMapping {
    fn parse_port_or_range(s: &str) -> Result<Vec<u16>> {
        if let Some((start, end)) = s.split_once('-') {
            let start = start.parse::<u16>()?;
            let end = end.parse::<u16>()?;
            if start > end {
                return Err(anyhow!("invalid port range: {}", s));
            }
            Ok((start..=end).collect())
        } else {
            Ok(vec![s.parse()?])
        }
    }

    /// Parse port string, expanding ranges into multiple mappings.
    /// e.g. "8080:80", "127.0.0.1:3000:3000/tcp", "8000-8002:8000-8002"
    pub fn parse_all(spec: &str) -> Result<Vec<Self>> {
        let (proto, port_spec) = if let Some((p, pr)) = spec.split_once('/') {
            (pr.to_lowercase(), p)
        } else {
            ("tcp".to_string(), spec)
        };

        let parts: Vec<&str> = port_spec.split(':').collect();
        match parts.len() {
            1 => {
                let ports = Self::parse_port_or_range(parts[0])?;
                Ok(ports
                    .into_iter()
                    .map(|c_port| Self {
                        host_ip: None,
                        host_port: c_port,
                        container_port: c_port,
                        protocol: proto.clone(),
                    })
                    .collect())
            }
            2 => {
                let host_ports = Self::parse_port_or_range(parts[0])?;
                let container_ports = Self::parse_port_or_range(parts[1])?;
                if host_ports.len() != container_ports.len() {
                    return Err(anyhow!(
                        "host and container port ranges must have equal length: {}",
                        spec
                    ));
                }
                Ok(host_ports
                    .into_iter()
                    .zip(container_ports)
                    .map(|(h_port, c_port)| Self {
                        host_ip: None,
                        host_port: h_port,
                        container_port: c_port,
                        protocol: proto.clone(),
                    })
                    .collect())
            }
            3 => {
                let ip = parts[0].to_string();
                let host_ports = Self::parse_port_or_range(parts[1])?;
                let container_ports = Self::parse_port_or_range(parts[2])?;
                if host_ports.len() != container_ports.len() {
                    return Err(anyhow!(
                        "host and container port ranges must have equal length: {}",
                        spec
                    ));
                }
                Ok(host_ports
                    .into_iter()
                    .zip(container_ports)
                    .map(|(h_port, c_port)| Self {
                        host_ip: Some(ip.clone()),
                        host_port: h_port,
                        container_port: c_port,
                        protocol: proto.clone(),
                    })
                    .collect())
            }
            _ => Err(anyhow!("Invalid port specification: {}", spec)),
        }
    }

    /// Parse a single port mapping (no ranges).
    pub fn parse(spec: &str) -> Result<Self> {
        let all = Self::parse_all(spec)?;
        if all.len() != 1 {
            return Err(anyhow!(
                "port range '{}' expands to {} mappings; use parse_all",
                spec,
                all.len()
            ));
        }
        Ok(all[0].clone())
    }
}

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
    index_file: PathBuf,
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

/// Open/Closed: IP allocation strategy
pub trait IpAllocator: Send + Sync {
    fn allocate(
        &self,
        subnet_str: &str,
        gateway_str: &str,
        existing: &HashMap<String, NetworkEndpoint>,
    ) -> Result<Ipv4Addr>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SubnetIpAllocator;

impl IpAllocator for SubnetIpAllocator {
    fn allocate(
        &self,
        subnet_str: &str,
        gateway_str: &str,
        existing: &HashMap<String, NetworkEndpoint>,
    ) -> Result<Ipv4Addr> {
        allocate_ip_in_subnet(subnet_str, gateway_str, existing)
    }
}

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

    fn ensure_default_network(&self) {
        let _ = crate::storage::index_lock::with_index_lock(&self.index_file, || {
            let mut data = self.load_unlocked();
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
                    labels: HashMap::new(),
                    dns_servers: Vec::new(),
                    created_at: Utc::now(),
                    containers: HashMap::new(),
                };
                data.networks.push(default_net);
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
            Ok(self
                .load_unlocked()
                .networks
                .into_iter()
                .find(|n| n.id == q || n.id.starts_with(q) || n.name == q))
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
        if name_trimmed.is_empty()
            || !name_trimmed
                .chars()
                .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
        {
            return Err(anyhow!(
                "Invalid network name '{}': must be alphanumeric, '_', or '-'",
                name
            ));
        }

        crate::storage::index_lock::with_index_lock(&self.index_file, || {
            let mut data = self.load_unlocked();
            if data.networks.iter().any(|n| n.name == name_trimmed) {
                return Err(anyhow!("Network '{}' already exists", name_trimmed));
            }

            let network_count = data.networks.len();
            let default_subnet = format!("172.{}.0.0/16", 29 + network_count);
            let default_gw = format!("172.{}.0.1", 29 + network_count);

            let chosen_subnet = subnet.unwrap_or(&default_subnet).to_string();
            let chosen_gw = gateway.unwrap_or(&default_gw).to_string();

            let id = hex::encode(crate::storage::container_store::rand_id());

            let record = NetworkRecord {
                id,
                name: name_trimmed.to_string(),
                driver: driver.to_string(),
                subnet: chosen_subnet,
                gateway: chosen_gw,
                internal,
                attachable,
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
            if q == Self::DEFAULT_NETWORK {
                return Err(anyhow!("Cannot remove the default bridge network"));
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
                Err(anyhow!("Network '{}' not found", query))
            }
        })
    }

    /// Allocate next available IP and attach container to network
    pub fn connect_container(
        &self,
        network_name: &str,
        container_id: &str,
        container_name: &str,
    ) -> Result<NetworkEndpoint> {
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

            // Allocate next IP using IpAllocator strategy (Open/Closed & DIP)
            let ip = SubnetIpAllocator.allocate(&net.subnet, &net.gateway, &net.containers)?;
            let mac = format!(
                "02:42:{:02x}:{:02x}:{:02x}:{:02x}",
                ip.octets()[0],
                ip.octets()[1],
                ip.octets()[2],
                ip.octets()[3]
            );

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

fn allocate_ip_in_subnet(
    subnet_str: &str,
    gateway_str: &str,
    existing: &HashMap<String, NetworkEndpoint>,
) -> Result<Ipv4Addr> {
    let (ip_part, mask_part) = subnet_str
        .split_once('/')
        .ok_or_else(|| anyhow!("Invalid CIDR subnet {}", subnet_str))?;

    let base_ip: Ipv4Addr = ip_part.parse()?;
    let prefix_len: u32 = mask_part.parse().context("Invalid CIDR prefix length")?;
    let gateway: Ipv4Addr = gateway_str.parse()?;

    if prefix_len > 30 || prefix_len < 8 {
        return Err(anyhow!("Unsupported subnet prefix length /{}", prefix_len));
    }

    let mask_u32 = if prefix_len == 0 {
        0
    } else {
        (!0u32) << (32 - prefix_len)
    };
    let base_u32 = u32::from(base_ip) & mask_u32;
    let bcast_u32 = base_u32 | (!mask_u32);

    let used_ips: Vec<Ipv4Addr> = existing
        .values()
        .filter_map(|e| e.ipv4_address.parse().ok())
        .collect();

    // Valid host range is from (base_u32 + 1) to (bcast_u32 - 1)
    let start_host = base_u32 + 1;
    let end_host = bcast_u32.saturating_sub(1);

    for host_int in start_host..=end_host {
        let candidate = Ipv4Addr::from(host_int);
        if candidate != gateway && !used_ips.contains(&candidate) {
            return Ok(candidate);
        }
    }

    Err(anyhow!(
        "No available IP addresses in subnet {}",
        subnet_str
    ))
}

fn probe_published_port(mapping: &PortMapping) -> bool {
    let host = mapping.host_ip.as_deref().unwrap_or("127.0.0.1");
    let connect_host = match host {
        "0.0.0.0" | "" => "127.0.0.1",
        "::" => "::1",
        other => other,
    };
    let addr: SocketAddr = match format!("{}:{}", connect_host, mapping.host_port).parse() {
        Ok(a) => a,
        Err(_) => return false,
    };

    TcpStream::connect_timeout(&addr, Duration::from_secs(2)).is_ok()
}

/// Wait until all published TCP ports accept connections on the host.
pub fn wait_for_published_ports(ports: &[PortMapping], timeout: Duration) -> Result<()> {
    let targets: Vec<&PortMapping> = ports.iter().filter(|p| p.protocol == "tcp").collect();
    if targets.is_empty() {
        return Ok(());
    }

    let start = Instant::now();
    while start.elapsed() < timeout {
        let ready = targets.iter().all(|p| probe_published_port(p));
        if ready {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(500));
    }

    Err(anyhow!(
        "timed out waiting for published TCP ports to become reachable"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_port_mapping_parse() {
        let p1 = PortMapping::parse("8080:80").unwrap();
        assert_eq!(p1.host_port, 8080);
        assert_eq!(p1.container_port, 80);
        assert_eq!(p1.protocol, "tcp");

        let p2 = PortMapping::parse("127.0.0.1:5432:5432/udp").unwrap();
        assert_eq!(p2.host_ip.as_deref(), Some("127.0.0.1"));
        assert_eq!(p2.host_port, 5432);
        assert_eq!(p2.container_port, 5432);
        assert_eq!(p2.protocol, "udp");
    }

    #[test]
    fn test_network_lifecycle_and_ipam() {
        let temp = tempdir().unwrap();
        let store = NetworkStore {
            index_file: temp.path().join("networks.json"),
        };
        store.ensure_default_network();

        // Check default network
        let default_net = store.find("boxr0").unwrap();
        assert_eq!(default_net.name, "boxr0");

        // Create custom network
        let custom = store.create("custom-net", None, None).unwrap();
        assert_eq!(custom.name, "custom-net");

        // Connect container
        let ep = store
            .connect_container("custom-net", "c123456", "web-server")
            .unwrap();
        assert_eq!(ep.container_name, "web-server");
        assert!(ep.ipv4_address.starts_with("172."));

        // Generate hosts
        let hosts = store.generate_hosts_file("custom-net", "c123456").unwrap();
        assert!(hosts.contains("web-server"));

        // Disconnect
        store.disconnect_container("custom-net", "c123456").unwrap();
        let updated = store.find("custom-net").unwrap();
        assert!(updated.containers.is_empty());

        // Remove
        store.remove("custom-net").unwrap();
        assert!(store.find("custom-net").is_none());
    }

    #[test]
    fn test_issue_416_readiness_probe_non_http_tcp() {
        use std::net::TcpListener;
        // Bind an ephemeral TCP listener representing a non-HTTP service on host
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        // Spawn a thread that accepts TCP connections and immediately closes or sends raw non-HTTP bytes
        let handle = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                use std::io::Write;
                let _ = stream.write_all(b"SSH-2.0-OpenSSH\r\n");
            }
        });

        // Even if container_port is 80 (previously forced HTTP), probe must succeed with raw TCP
        let mapping = PortMapping {
            host_ip: Some("127.0.0.1".to_string()),
            host_port: port,
            container_port: 80,
            protocol: "tcp".to_string(),
        };

        let result = wait_for_published_ports(&[mapping], Duration::from_secs(3));
        assert!(
            result.is_ok(),
            "Non-HTTP TCP service should be probed successfully without requiring HTTP"
        );
        let _ = handle.join();
    }

    #[test]
    fn test_issue_420_cleanup_container_endpoints() {
        let dir = tempdir().unwrap();
        let store = NetworkStore::with_home(dir.path().to_path_buf());
        store.create("test-proj_default", None, None).unwrap();

        // Connect two containers like compose does
        store
            .connect_container("test-proj_default", "test-proj_web_1", "web")
            .unwrap();
        store
            .connect_container("test-proj_default", "test-proj_api_1", "api")
            .unwrap();

        let net = store.find("test-proj_default").unwrap();
        assert_eq!(net.containers.len(), 2);

        // Before cleanup, remove without force fails
        assert!(store.remove("test-proj_default").is_err());

        // Cleanup first container by name/id
        store
            .cleanup_container_endpoints("test-proj_web_1", "web")
            .unwrap();
        let net = store.find("test-proj_default").unwrap();
        assert_eq!(net.containers.len(), 1);

        // Cleanup second container
        store
            .cleanup_container_endpoints("test-proj_api_1", "api")
            .unwrap();
        let net = store.find("test-proj_default").unwrap();
        assert_eq!(net.containers.len(), 0);

        // Now remove succeeds without force
        assert!(store.remove("test-proj_default").is_ok());
        assert!(store.find("test-proj_default").is_none());
    }
}
