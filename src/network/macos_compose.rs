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
        let target_addr: SocketAddr = format!("192.168.64.2:80")
            .parse()
            .unwrap_or_else(|_| SocketAddr::from(([192, 168, 64, 2], 80)));
        let forwarder = Arc::new(RootlessPortForwarder::new_tcp(host_addr, target_addr));
        forwarder.start().await?;
        forwarders.push(forwarder);

        // Record relay port for guest env injection
        if let Some(bundle) = find_bundle_for_endpoint(ep) {
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
