use super::pasta;
use super::store::NetworkStore;
use crate::storage::ContainerStore;
use anyhow::{Result, anyhow};
use std::fs;
use std::path::{Path, PathBuf};

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

/// Write `/etc/hosts` into a container bundle (rootfs and overlay upper when present).
pub fn write_bundle_hosts_file(bundle_path: &Path, content: &str) -> Result<()> {
    let rootfs_hosts = bundle_path.join("rootfs/etc/hosts");
    if let Some(parent) = rootfs_hosts.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&rootfs_hosts, content)?;

    let upper_hosts = bundle_path.join("upper/etc/hosts");
    if let Some(parent) = upper_hosts.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if bundle_path.join("upper").exists() {
        fs::write(&upper_hosts, content)?;
    }
    Ok(())
}

fn load_bundle_host_context(bundle_path: &Path) -> (Option<String>, Vec<String>) {
    let mut hostname = None;
    let config_path = bundle_path.join("config.json");
    if let Ok(raw) = fs::read_to_string(&config_path) {
        if let Ok(spec) = serde_json::from_str::<crate::oci::runtime::Spec>(&raw) {
            hostname = spec.hostname;
        }
    }
    let hosts_json = bundle_path.join("hosts.json");
    let add_host = if hosts_json.exists() {
        fs::read_to_string(&hosts_json)
            .ok()
            .and_then(|c| serde_json::from_str(&c).ok())
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    (hostname, add_host)
}

/// Build full `/etc/hosts` content for a container on a bridge network (matches runtime layout).
pub fn assemble_bridge_hosts_content(
    net_store: &NetworkStore,
    network_name: &str,
    container_id: &str,
    bundle_path: &Path,
) -> Result<String> {
    let (hostname, add_host_entries) = load_bundle_host_context(bundle_path);
    let mut lines = vec![
        "127.0.0.1\tlocalhost".to_string(),
        "::1\tlocalhost ip6-localhost ip6-loopback".to_string(),
    ];
    if let Some(h) = &hostname {
        lines.push(format!("127.0.0.1\t{}", h));
    }
    for entry in &add_host_entries {
        if let Some((host, ip)) = entry.split_once(':') {
            lines.push(format!("{}\t{}", ip.trim(), host.trim()));
        }
    }
    let bridge_body = net_store.generate_hosts_file(network_name, container_id)?;
    for line in bridge_body.lines().skip(2) {
        if !line.is_empty() {
            lines.push(line.to_string());
        }
    }
    Ok(lines.join("\n") + "\n")
}

/// Push updated synthetic DNS (`/etc/hosts`) to every container registered on a bridge network.
pub fn refresh_bridge_hosts_for_network(network_name: &str, home: Option<&Path>) -> Result<()> {
    let net_store = match home {
        Some(h) => NetworkStore::with_home(h.to_path_buf()),
        None => NetworkStore::new(),
    };
    let c_store = match home {
        Some(h) => ContainerStore::with_home(h.to_path_buf()),
        None => ContainerStore::new(),
    };
    let net = net_store
        .find(network_name)
        .ok_or_else(|| anyhow!("network {} not found", network_name))?;
    let endpoints: Vec<(String, String)> = net
        .containers
        .iter()
        .map(|(id, ep)| (id.clone(), ep.container_name.clone()))
        .collect();
    for (container_id, container_name) in endpoints {
        let record = c_store
            .find(&container_id)
            .or_else(|| c_store.find(&container_name));
        if let Some(record) = record {
            let bundle = PathBuf::from(&record.bundle_path);
            if !bundle.exists() {
                continue;
            }
            let content =
                assemble_bridge_hosts_content(&net_store, &net.name, &container_id, &bundle)?;
            write_bundle_hosts_file(&bundle, &content)?;
        }
    }
    Ok(())
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
    refresh_bridge_hosts_for_network(&net_name, home)?;
    Ok(())
}
