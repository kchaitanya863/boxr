use super::pasta;
use super::store::NetworkStore;
use crate::storage::ContainerStore;
use anyhow::{Result, anyhow};
use std::fs;
use std::path::{Path, PathBuf};

pub fn resolved_bridge_network_name(network: &str) -> Option<String> {
    let base = if !network.starts_with("container:")
        && !network.starts_with("pasta:")
        && !network.starts_with("ns:")
    {
        network.split_once(':').map(|(n, _)| n).unwrap_or(network)
    } else {
        network
    };
    let mode = pasta::NetworkMode::parse(base);
    if mode != pasta::NetworkMode::Bridge {
        return None;
    }
    let name = match base {
        "bridge" | "default" | "auto" | "private" | "" => NetworkStore::DEFAULT_NETWORK,
        other => other,
    };
    Some(name.to_string())
}

/// Write `/etc/hosts` into a container bundle (rootfs and overlay upper when present).
pub fn write_bundle_hosts_file(bundle_path: &Path, content: &str) -> Result<()> {
    let _ = fs::write(bundle_path.join("hosts"), content);
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

pub fn write_bundle_resolv_conf(bundle_path: &Path, content: &str) -> Result<()> {
    let _ = fs::write(bundle_path.join("resolv.conf"), content);
    let rootfs_rc = bundle_path.join("rootfs/etc/resolv.conf");
    if let Some(parent) = rootfs_rc.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(&rootfs_rc, content);
    let upper_rc = bundle_path.join("upper/etc/resolv.conf");
    if bundle_path.join("upper").exists() {
        if let Some(parent) = upper_rc.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::write(&upper_rc, content);
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
    let config_path = bundle_path.join("config.json");
    if let Ok(raw) = fs::read_to_string(&config_path) {
        if let Ok(spec) = serde_json::from_str::<crate::oci::runtime::Spec>(&raw) {
            if spec
                .annotations
                .as_ref()
                .and_then(|a| a.get("boxr.no_hosts"))
                .is_some_and(|v| v == "true")
            {
                return Ok(
                    "127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n".to_string(),
                );
            }
        }
    }
    let mut lines = vec![
        "127.0.0.1\tlocalhost".to_string(),
        "::1\tlocalhost ip6-localhost ip6-loopback".to_string(),
    ];
    for entry in &add_host_entries {
        if let Some((host, ip)) = entry.split_once(':') {
            lines.push(format!("{}\t{}", ip.trim(), host.trim()));
        }
    }
    let mut self_has_bridge_ip = false;
    let all_nets = net_store.list();
    let mut target_nets: Vec<super::store::NetworkRecord> = all_nets
        .into_iter()
        .filter(|n| {
            n.name == network_name
                || n.containers.contains_key(container_id)
                || n.containers
                    .values()
                    .any(|ep| ep.container_name == container_id)
        })
        .collect();
    if target_nets.is_empty() {
        if let Some(n) = net_store.find(network_name) {
            target_nets.push(n);
        }
    }
    for net in &target_nets {
        for (cid, ep) in &net.containers {
            let short_id = if cid.len() >= 12 { &cid[..12] } else { cid };
            let is_self = cid == container_id || ep.container_name == container_id;
            let mut names = vec![ep.container_name.clone()];
            if ep.container_name != *cid && ep.container_name != short_id {
                names.push(short_id.to_string());
            }
            if is_self {
                if let Some(ref h) = hostname {
                    if !h.is_empty() && !names.contains(h) {
                        names.insert(0, h.clone());
                    }
                }
            }
            for a in &ep.aliases {
                if !names.contains(a) {
                    names.push(a.clone());
                }
            }
            if net.dns_enabled {
                let base_names = names.clone();
                for bn in base_names {
                    let fqdn = format!("{}.dns.podman", bn);
                    if !names.contains(&fqdn) {
                        names.push(fqdn);
                    }
                }
            }
            let joined = names.join(" ");
            if !ep.ipv4_address.is_empty() {
                if is_self {
                    self_has_bridge_ip = true;
                }
                let line = format!("{}\t{}", ep.ipv4_address, joined);
                if !lines.contains(&line) {
                    lines.push(line);
                }
            }
            if !ep.ipv6_address.is_empty() {
                if is_self {
                    self_has_bridge_ip = true;
                }
                let line = format!("{}\t{}", ep.ipv6_address, joined);
                if !lines.contains(&line) {
                    lines.push(line);
                }
            }
        }
    }
    if !self_has_bridge_ip {
        if let Some(h) = &hostname {
            lines.push(format!("127.0.0.1\t{}", h));
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

pub fn refresh_disconnected_container_hosts(
    container_query: &str,
    home: Option<&Path>,
) -> Result<()> {
    let net_store = match home {
        Some(h) => NetworkStore::with_home(h.to_path_buf()),
        None => NetworkStore::new(),
    };
    let c_store = match home {
        Some(h) => ContainerStore::with_home(h.to_path_buf()),
        None => ContainerStore::new(),
    };
    let Some(record) = c_store.find(container_query) else {
        return Ok(());
    };
    let bundle = PathBuf::from(&record.bundle_path);
    if !bundle.exists() {
        return Ok(());
    }
    let connected_nets: Vec<String> = net_store
        .list()
        .into_iter()
        .filter(|n| {
            n.containers.contains_key(&record.id)
                || n.containers
                    .values()
                    .any(|ep| ep.container_name == record.name)
        })
        .map(|n| n.name)
        .collect();
    if let Some(first_net) = connected_nets.first() {
        let _ = fs::remove_file(bundle.join("network_disconnected"));
        let content = assemble_bridge_hosts_content(&net_store, first_net, &record.id, &bundle)?;
        write_bundle_hosts_file(&bundle, &content)?;
    } else {
        let _ = fs::write(bundle.join("network_disconnected"), "1");
        let (hostname, add_host_entries) = load_bundle_host_context(&bundle);
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
        write_bundle_hosts_file(&bundle, &(lines.join("\n") + "\n"))?;
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

pub fn refresh_container_resolv_conf(
    container_query: &str,
    home: Option<&Path>,
) -> Result<()> {
    let net_store = match home {
        Some(h) => NetworkStore::with_home(h.to_path_buf()),
        None => NetworkStore::new(),
    };
    let c_store = match home {
        Some(h) => ContainerStore::with_home(h.to_path_buf()),
        None => ContainerStore::new(),
    };
    let Some(record) = c_store.find(container_query) else {
        return Ok(());
    };
    let bundle = PathBuf::from(&record.bundle_path);
    if !bundle.exists() {
        return Ok(());
    }
    let mut gateways = Vec::new();
    for net in net_store.list() {
        if net.name == NetworkStore::DEFAULT_NETWORK {
            continue;
        }
        if net.containers.contains_key(&record.id)
            || net
                .containers
                .values()
                .any(|ep| ep.container_name == record.name)
        {
            if !net.gateway.is_empty() && !gateways.contains(&net.gateway) {
                gateways.push(net.gateway.clone());
            }
            for sub in &net.subnets {
                if !sub.gateway.is_empty() && !gateways.contains(&sub.gateway) {
                    gateways.push(sub.gateway.clone());
                }
            }
        }
    }
    let mut lines = Vec::new();
    for gw in &gateways {
        lines.push(format!("nameserver {}", gw));
    }
    if lines.is_empty() {
        lines.push("nameserver 8.8.8.8".to_string());
    }
    write_bundle_resolv_conf(&bundle, &(lines.join("\n") + "\n"))
}

#[cfg(target_os = "linux")]
pub fn hotplug_container_network_interface(
    bundle_path: &Path,
    ifname: &str,
    ipv4_cidr: &str,
    ipv6_cidr: &str,
    mac: &str,
) {
    use nix::sched::{CloneFlags, setns};
    use nix::sys::wait::waitpid;
    use nix::unistd::{ForkResult, fork};

    let Some(pid) = crate::pod::read_container_pid_from_bundle(bundle_path) else {
        return;
    };
    if unsafe { libc::kill(pid, 0) != 0 } {
        return;
    }
    let ifname_s = ifname.to_string();
    let v4_s = ipv4_cidr.to_string();
    let v6_s = ipv6_cidr.to_string();
    let mac_s = mac.to_string();

    if let Ok(ForkResult::Parent { child }) = unsafe { fork() } {
        let _ = waitpid(child, None);
    } else {
        let same_userns = match (
            fs::read_link("/proc/self/ns/user"),
            fs::read_link(format!("/proc/{pid}/ns/user")),
        ) {
            (Ok(a), Ok(b)) => a == b,
            _ => false,
        };
        if !same_userns {
            if let Ok(uf) = fs::File::open(format!("/proc/{pid}/ns/user")) {
                let _ = setns(&uf, CloneFlags::CLONE_NEWUSER);
            }
        }
        if let Ok(nf) = fs::File::open(format!("/proc/{pid}/ns/net")) {
            if setns(&nf, CloneFlags::CLONE_NEWNET).is_ok() {
                let _ = super::usernet::engine::platform::create_persistent_tap_device(&ifname_s);
                if !mac_s.is_empty() {
                    let _ = std::process::Command::new("ip")
                        .args(["link", "set", "dev", &ifname_s, "address", &mac_s])
                        .output();
                }
                if !v4_s.is_empty() {
                    let _ = std::process::Command::new("ip")
                        .args(["addr", "add", &v4_s, "brd", "+", "dev", &ifname_s])
                        .output();
                }
                if !v6_s.is_empty() {
                    let _ = std::process::Command::new("ip")
                        .args(["-6", "addr", "add", &v6_s, "dev", &ifname_s, "nodad"])
                        .output();
                }
                let _ = std::process::Command::new("ip")
                    .args(["link", "set", &ifname_s, "up"])
                    .output();
            }
        }
        std::process::exit(0);
    }
}

#[cfg(not(target_os = "linux"))]
pub fn hotplug_container_network_interface(
    _bundle_path: &Path,
    _ifname: &str,
    _ipv4_cidr: &str,
    _ipv6_cidr: &str,
    _mac: &str,
) {
}

#[cfg(target_os = "linux")]
pub fn hotunplug_container_network_interface(bundle_path: &Path, ifname: &str) {
    use nix::sched::{CloneFlags, setns};
    use nix::sys::wait::waitpid;
    use nix::unistd::{ForkResult, fork};

    if ifname == "eth0" {
        if let Ok(tp_s) = fs::read_to_string(bundle_path.join("tap_worker.pid")) {
            if let Ok(tp) = tp_s.trim().parse::<i32>() {
                if tp > 1 {
                    unsafe {
                        let _ = libc::kill(tp, libc::SIGKILL);
                    }
                }
            }
        }
    }

    let Some(pid) = crate::pod::read_container_pid_from_bundle(bundle_path) else {
        return;
    };
    if unsafe { libc::kill(pid, 0) != 0 } {
        return;
    }
    let ifname_s = ifname.to_string();

    if let Ok(ForkResult::Parent { child }) = unsafe { fork() } {
        let _ = waitpid(child, None);
    } else {
        let same_userns = match (
            fs::read_link("/proc/self/ns/user"),
            fs::read_link(format!("/proc/{pid}/ns/user")),
        ) {
            (Ok(a), Ok(b)) => a == b,
            _ => false,
        };
        if !same_userns {
            if let Ok(uf) = fs::File::open(format!("/proc/{pid}/ns/user")) {
                let _ = setns(&uf, CloneFlags::CLONE_NEWUSER);
            }
        }
        if let Ok(nf) = fs::File::open(format!("/proc/{pid}/ns/net")) {
            if setns(&nf, CloneFlags::CLONE_NEWNET).is_ok() {
                super::usernet::engine::platform::destroy_tap_device(&ifname_s);
            }
        }
        std::process::exit(0);
    }
}

#[cfg(not(target_os = "linux"))]
pub fn hotunplug_container_network_interface(_bundle_path: &Path, _ifname: &str) {}
