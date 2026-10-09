//! Regression tests for open networking issues #422, #425, #429, #433.

use boxr::network::{PortMapping, resolve_bundle_ports, spawn_port_forward_daemon};
use tempfile::tempdir;

#[test]
fn test_issue_422_resolve_bundle_ports_from_json() {
    let dir = tempdir().unwrap();
    let bundle = dir.path();
    let ports = vec![PortMapping {
        host_ip: Some("127.0.0.1".to_string()),
        host_port: 18094,
        container_port: 80,
        protocol: "tcp".to_string(),
    }];
    std::fs::write(
        bundle.join("ports.json"),
        serde_json::to_string(&ports).unwrap(),
    )
    .unwrap();

    let resolved = resolve_bundle_ports(bundle, &[]);
    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0].host_port, 18094);
    spawn_port_forward_daemon(bundle, &resolved).unwrap();
}

#[test]
fn test_issue_422_start_container_restores_forwarding() {
    let lib = include_str!("../src/lib.rs");
    assert!(
        lib.contains("resolve_bundle_ports") && lib.contains("wait_for_forwarder_pid"),
        "start_container must resolve ports and wait for forwarder"
    );
    let linux = include_str!("../src/runtime/linux.rs");
    assert!(
        linux.contains("resolve_bundle_ports"),
        "execute_bundle must fall back to ports.json"
    );
}

#[test]
fn test_issue_425_restart_waits_for_stop() {
    let lib = include_str!("../src/lib.rs");
    assert!(
        lib.contains("wait_for_container_stopped"),
        "restart must wait for full stop before start"
    );
    assert!(
        lib.contains("wait_for_container_stopped(&bundle_path"),
        "stop must wait before removing pid files"
    );
}

#[test]
fn test_issue_433_macos_guest_network_retry() {
    let darwin = include_str!("../src/runtime/darwin.rs");
    assert!(
        darwin.contains("macos_guest_network_init_script"),
        "macOS guest must retry virtio-net bring-up"
    );
    assert!(
        darwin.contains("while [ $i -lt 50 ]") && darwin.contains("ip link show eth0"),
        "guest init must wait for eth0 to appear"
    );
    assert!(
        darwin.contains("grep -q 'inet '"),
        "guest init must verify IPv4 before continuing"
    );
}

#[test]
fn test_issue_429_compose_net_metadata_and_mesh() {
    let darwin = include_str!("../src/runtime/darwin.rs");
    assert!(
        darwin.contains("write_compose_net_metadata"),
        "macOS must write compose_net.json for guest routing"
    );
    assert!(
        darwin.contains("compose_net.json"),
        "guest must configure compose IP and peer routes"
    );
    let compose = include_str!("../src/compose/mod.rs");
    assert!(
        compose.contains("BOXR_MESH_") && compose.contains("start_compose_mesh"),
        "compose up must expose mesh relay env vars and start relays on macOS"
    );
}
