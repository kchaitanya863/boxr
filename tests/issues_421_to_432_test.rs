//! Regression tests for networking issues #421–#432 (port forwarding, guardrails,
//! compose exec flags, bridge registration, rootless EPERM, UDP protocol).

use boxr::guardrails::validate_network_port_compatibility;
use boxr::network::pasta::NetworkMode;
use boxr::network::rootless::{forward_sock_name, forward_udp_sock_name};
use boxr::network::{NetworkStore, PortMapping, connect_container_to_bridge_network, resolved_bridge_network_name};
use tempfile::tempdir;

#[test]
fn test_issue_423_none_and_host_reject_published_ports() {
    let ports = vec![PortMapping {
        host_ip: None,
        host_port: 8080,
        container_port: 80,
        protocol: "tcp".to_string(),
    }];
    let err = validate_network_port_compatibility("none", &ports).unwrap_err();
    assert!(
        err.to_string().contains("published ports are not supported"),
        "expected none+p rejection, got: {}",
        err
    );
    let err = validate_network_port_compatibility("host", &ports).unwrap_err();
    assert!(
        err.to_string().contains("published ports are not supported"),
        "expected host+p rejection, got: {}",
        err
    );
    assert!(validate_network_port_compatibility("bridge", &ports).is_ok());
    assert!(validate_network_port_compatibility("custom_net", &ports).is_ok());
    assert!(validate_network_port_compatibility("bridge", &[]).is_ok());
}

#[test]
fn test_issue_424_udp_forward_socket_names() {
    assert_eq!(forward_sock_name(80), "forward-80.sock");
    assert_eq!(forward_udp_sock_name(53), "forward-udp-53.sock");
    let mapping = PortMapping::parse("5353:53/udp").unwrap();
    assert_eq!(mapping.protocol, "udp");
}

#[test]
fn test_issue_426_427_macos_port_forward_and_guest_networking_sources() {
    let darwin = include_str!("../src/runtime/darwin.rs");
    assert!(
        darwin.contains("__internal-port-forward"),
        "macOS must spawn host port-forward daemon"
    );
    assert!(
        darwin.contains("boxr_bundle="),
        "macOS must virtio-fs share bundle for Unix socket relays"
    );
    assert!(
        darwin.contains("ip link set eth0 up"),
        "macOS guest must bring eth0 up"
    );
    assert!(
        darwin.contains("__internal-port-forward"),
        "macOS must use host forward daemon dialing guest NAT"
    );

    let vz = include_str!("../src/runtime/boxr-vz.m");
    assert!(
        !vz.contains("port_forward_listener_thread"),
        "boxr-vz must not dial unreachable VM IPs for port forwarding"
    );
    assert!(
        vz.contains("boxr-run.sh"),
        "boxr-vz must delegate port forwarding to guest run script relays"
    );
}

#[test]
fn test_issue_428_compose_exec_tty_flags() {
    let cli_src = include_str!("../src/cli/image.rs");
    assert!(
        cli_src.contains("short = 'T'") && cli_src.contains("no_tty"),
        "ComposeExecArgs must expose Docker -T / --no-TTY"
    );
    assert!(
        cli_src.contains("short = 'd'") && cli_src.contains("detach"),
        "ComposeExecArgs must expose Docker -d / --detach"
    );

    let lib_src = include_str!("../src/lib.rs");
    assert!(
        lib_src.contains("opts.no_tty") && lib_src.contains("opts.detach"),
        "compose exec must map -T and -d into ExecArgs"
    );
}

#[test]
fn test_issue_430_rootless_setgroups_deny_before_gid_map() {
    let linux = include_str!("../src/runtime/linux.rs");
    assert!(
        linux.contains("/proc/self/setgroups") && linux.contains("deny"),
        "rootless child must write setgroups deny before gid_map"
    );
}

#[test]
fn test_issue_432_run_registers_custom_bridge_network_endpoint() {
    let dir = tempdir().unwrap();
    let home = dir.path();
    let net_name = "issue432_net";
    let store = NetworkStore::with_home(home.to_path_buf());
    store.create(net_name, None, None).unwrap();

    assert!(resolved_bridge_network_name(net_name).is_some());
    assert!(resolved_bridge_network_name("none").is_none());
    assert!(resolved_bridge_network_name("host").is_none());

    connect_container_to_bridge_network(
        net_name,
        "cid432",
        "ctr432",
        Some(home),
    )
    .unwrap();

    let net = store.find(net_name).unwrap();
    assert_eq!(net.containers.len(), 1);
    let ep = net.containers.get("cid432").expect("endpoint keyed by container id");
    assert_eq!(ep.container_id, "cid432");
    assert_eq!(ep.container_name, "ctr432");
}

#[test]
fn test_issue_421_forward_helper_forked_outside_usernet_only_block() {
    let linux = include_str!("../src/runtime/linux.rs");
    assert!(
        linux.contains("run_forward_helper") && linux.contains("!use_pasta"),
        "forward helper must run for all non-pasta published ports"
    );
}

#[test]
fn test_bridge_network_mode_parses_for_custom_names() {
    assert_eq!(NetworkMode::parse("my_custom"), NetworkMode::Bridge);
    assert!(NetworkMode::parse("my_custom").requires_new_netns());
}
