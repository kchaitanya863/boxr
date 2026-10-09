//! macOS compose inter-service TCP relay via host gateway ports.
//!
//! Each compose service gets a host relay port; peers reach it at
//! `192.168.64.1:<relay_port>` once guest eth0 is configured.

use crate::network::NetworkStore;
use crate::network::rootless::RootlessPortForwarder;
use anyhow::Result;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

const MESH_BASE_PORT: u16 = 28000;

/// Inspect bundle for container port and IP metadata (macOS compose mesh helper)
pub fn resolve_target_endpoint(bundle: &std::path::Path) -> (String, u16) {
    let mut target_port: u16 = 80;
    let mut target_ip_str = "192.168.64.2".to_string();

    let ports_path = bundle.join("ports.json");
    if ports_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&ports_path) {
            if let Ok(mappings) = serde_json::from_str::<Vec<crate::network::PortMapping>>(&content) {
                if let Some(first_tcp) = mappings.iter().find(|m| m.protocol.eq_ignore_ascii_case("tcp")) {
                    target_port = first_tcp.container_port;
                }
            }
        }
    }
    let net_meta_path = bundle.join("compose_net.json");
    if net_meta_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&net_meta_path) {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(ip) = val.get("self_ip").and_then(|v| v.as_str()) {
                    target_ip_str = ip.to_string();
                }
            }
        }
    }
    (target_ip_str, target_port)
}

/// Start TCP relays for every endpoint on a compose project network (macOS only).
pub async fn start_compose_mesh(network_name: &str) -> Result<()> {
    let store = NetworkStore::new();
    let net = store
        .find(network_name)
        .ok_or_else(|| anyhow::anyhow!("network {} not found", network_name))?;

    let mut forwarders = Vec::new();
    for (idx, ep) in net.containers.values().enumerate() {
        let relay_port = MESH_BASE_PORT + idx as u16;
        let host_addr: SocketAddr = format!("0.0.0.0:{}", relay_port)
            .parse()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], relay_port)));

        // Resolve target port and target IP dynamically from bundle metadata when available
        let bundle_opt = find_bundle_for_endpoint(ep);
        let (target_ip_str, target_port) = if let Some(ref bundle) = bundle_opt {
            resolve_target_endpoint(bundle)
        } else {
            ("192.168.64.2".to_string(), 80)
        };

        let target_addr: SocketAddr = format!("{}:{}", target_ip_str, target_port)
            .parse()
            .unwrap_or_else(|_| SocketAddr::from(([192, 168, 64, 2], target_port)));
        let forwarder = Arc::new(RootlessPortForwarder::new_tcp(host_addr, target_addr));
        forwarder.start().await?;
        forwarders.push(forwarder);

        // Record relay port for guest env injection
        if let Some(bundle) = bundle_opt {
            let peers_path = bundle.join("compose_peers.json");
            let mut peers: HashMap<String, u16> = if peers_path.exists() {
                serde_json::from_str(&std::fs::read_to_string(&peers_path)?).unwrap_or_default()
            } else {
                HashMap::new()
            };
            peers.insert(ep.container_name.clone(), relay_port);
            let _ = std::fs::write(&peers_path, serde_json::to_string(&peers)?);
        }
    }

    // Keep relays alive for the compose project lifetime (detached task).
    let keep = Arc::new(Mutex::new(forwarders));
    tokio::spawn(async move {
        let _guard = keep;
        std::future::pending::<()>().await;
    });
    Ok(())
}

fn find_bundle_for_endpoint(ep: &crate::network::NetworkEndpoint) -> Option<PathBuf> {
    let store = crate::storage::ContainerStore::new();
    let rec = store
        .find(&ep.container_id)
        .or_else(|| store.find(&ep.container_name))?;
    Some(PathBuf::from(&rec.bundle_path))
}
