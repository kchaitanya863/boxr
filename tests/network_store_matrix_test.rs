//! In-process integration tests for the networking domain (IPAM, port specs, guardrails).
//! Uses isolated `NetworkStore` homes so tests do not mutate the developer's `~/.boxr`.

use boxr::guardrails::{PortCollisionGuard, validate_network_port_compatibility};
use boxr::network::{
    NetworkStore, PortMapping, connect_container_to_bridge_network, resolved_bridge_network_name,
};
use boxr::storage::{ContainerRecord, ContainerStatus};
use std::collections::HashMap;
use tempfile::tempdir;

fn isolated_network_store() -> (tempfile::TempDir, NetworkStore) {
    let dir = tempdir().unwrap();
    let store = NetworkStore::with_home(dir.path().to_path_buf());
    (dir, store)
}

#[test]
fn test_resolved_bridge_network_name_matrix() {
    let bridge_cases = [
        ("bridge", "boxr0"),
        ("boxr0", "boxr0"),
        ("my_app_net", "my_app_net"),
    ];
    for (input, expected) in bridge_cases {
        let got = resolved_bridge_network_name(input).expect(input);
        assert_eq!(got, expected, "input={}", input);
    }
    for non_bridge in ["none", "host", "usernet", "pasta", "auto", "default", ""] {
        assert!(
            resolved_bridge_network_name(non_bridge).is_none(),
            "{} should not resolve to bridge",
            non_bridge
        );
    }
}

#[test]
fn test_validate_network_port_compatibility_matrix() {
    let ports = vec![PortMapping {
        host_ip: None,
        host_port: 8080,
        container_port: 80,
        protocol: "tcp".to_string(),
    }];
    for ok_net in ["bridge", "boxr0", "custom", "usernet", "pasta", "auto", ""] {
        assert!(
            validate_network_port_compatibility(ok_net, &ports).is_ok(),
            "ports should be allowed on {}",
            ok_net
        );
    }
    for bad_net in ["none", "host"] {
        let err = validate_network_port_compatibility(bad_net, &ports).unwrap_err();
        assert!(
            err.to_string()
                .contains("published ports are not supported"),
            "bad_net={}: {}",
            bad_net,
            err
        );
    }
    assert!(validate_network_port_compatibility("none", &[]).is_ok());
}

#[test]
fn test_port_mapping_parse_all_expands_ranges() {
    let mappings = PortMapping::parse_all("8000-8002:9000-9002/tcp").unwrap();
    assert_eq!(mappings.len(), 3);
    assert_eq!(mappings[0].host_port, 8000);
    assert_eq!(mappings[0].container_port, 9000);
    assert_eq!(mappings[2].host_port, 8002);
    assert_eq!(mappings[2].container_port, 9002);
    assert_eq!(mappings[0].protocol, "tcp");

    let with_ip = PortMapping::parse_all("127.0.0.1:3000-3001:4000-4001/udp").unwrap();
    assert_eq!(with_ip.len(), 2);
    assert_eq!(with_ip[0].host_ip.as_deref(), Some("127.0.0.1"));
    assert_eq!(with_ip[1].protocol, "udp");
}

#[test]
fn test_port_collision_guard_host_ip_overlap_rules() {
    let running = ContainerRecord {
        id: "cccccccccccc".to_string(),
        name: "peer".to_string(),
        image: "alpine:latest".to_string(),
        command: vec!["sleep".to_string()],
        created_at: chrono::Utc::now(),
        status: ContainerStatus::Running,
        bundle_path: "/tmp".to_string(),
        restart_policy: boxr::health::RestartPolicy::No,
        health_status: boxr::health::HealthStatus::None,
        restart_count: 0,
        ports: vec![PortMapping {
            host_ip: Some("127.0.0.1".to_string()),
            host_port: 9090,
            container_port: 80,
            protocol: "tcp".to_string(),
        }],
        exposed_ports: Vec::new(),
    };

    // Wildcard host bind collides with specific 127.0.0.1 on same port/proto.
    let wildcard = vec![PortMapping {
        host_ip: None,
        host_port: 9090,
        container_port: 8080,
        protocol: "tcp".to_string(),
    }];
    assert!(
        PortCollisionGuard::ensure_no_conflicts_with_containers(&wildcard, &[running.clone()])
            .is_err()
    );

    // Different loopback port is fine.
    let other_port = vec![PortMapping {
        host_ip: Some("127.0.0.1".to_string()),
        host_port: 9091,
        container_port: 80,
        protocol: "tcp".to_string(),
    }];
    assert!(
        PortCollisionGuard::ensure_no_conflicts_with_containers(&other_port, &[running.clone()])
            .is_ok()
    );

    // Same port on a distinct host IP that does not overlap 127.0.0.1 is allowed.
    let other_ip = vec![PortMapping {
        host_ip: Some("192.168.55.10".to_string()),
        host_port: 9090,
        container_port: 80,
        protocol: "tcp".to_string(),
    }];
    assert!(
        PortCollisionGuard::ensure_no_conflicts_with_containers(&other_ip, &[running.clone()])
            .is_ok()
    );
}

#[test]
fn test_network_store_ipam_hosts_and_lifecycle() {
    let (_dir, store) = isolated_network_store();
    let net_name = "matrix-net";
    store
        .create_with_options(
            net_name,
            "bridge",
            Some("10.88.0.0/16"),
            None,
            false,
            false,
            HashMap::from([("env".to_string(), "qa".to_string())]),
        )
        .unwrap();

    let ep_a = store
        .connect_container(net_name, "aaaaaaaaaaaa", "svc-a")
        .unwrap();
    let ep_b = store
        .connect_container(net_name, "bbbbbbbbbbbb", "svc-b")
        .unwrap();
    assert_ne!(ep_a.ipv4_address, ep_b.ipv4_address);
    assert!(ep_a.ipv4_address.starts_with("10.88."));
    assert!(ep_b.ipv4_address.starts_with("10.88."));

    let hosts_a = store.generate_hosts_file(net_name, "aaaaaaaaaaaa").unwrap();
    assert!(hosts_a.contains("svc-b"));
    assert!(hosts_a.contains(&ep_b.ipv4_address));

    store
        .disconnect_container(net_name, "aaaaaaaaaaaa")
        .unwrap();
    let ep_a_again = store
        .connect_container(net_name, "aaaaaaaaaaaa", "svc-a")
        .unwrap();
    assert!(
        !ep_a_again.ipv4_address.is_empty(),
        "reconnect should allocate an address"
    );

    assert!(store.remove(net_name).is_err(), "active endpoints block rm");
    store
        .disconnect_container(net_name, "bbbbbbbbbbbb")
        .unwrap();
    store
        .disconnect_container(net_name, "aaaaaaaaaaaa")
        .unwrap();
    store.remove(net_name).unwrap();
    assert!(store.find(net_name).is_none());
}

#[test]
fn test_connect_container_to_bridge_network_isolated_home() {
    let dir = tempdir().unwrap();
    let home = dir.path();
    let store = NetworkStore::with_home(home.to_path_buf());
    store.create("edge-net", None, None).unwrap();

    connect_container_to_bridge_network("edge-net", "cid1", "web", Some(home)).unwrap();
    let net = store.find("edge-net").unwrap();
    assert_eq!(net.containers.len(), 1);
    assert!(net.containers.values().any(|e| e.container_name == "web"));
}

#[test]
fn test_duplicate_network_create_rejected() {
    let (_dir, store) = isolated_network_store();
    let name = "dup-net-matrix";
    store.create(name, None, None).unwrap();
    let err = store.create(name, None, None).unwrap_err();
    assert!(err.to_string().contains("already exists"));
}
