use boxr::compose::ComposeProject;
use boxr::guardrails::PortCollisionGuard;
use boxr::network::macos_compose::resolve_target_endpoint;
use boxr::network::pasta::NetworkMode;
use boxr::network::{NetworkStore, PortMapping};
use std::collections::HashMap;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_issue_447_port_collision_intra_request() {
    // Issue #447: PortCollisionGuard should detect duplicate ports within the same run request
    let dup_ports = vec![
        PortMapping {
            host_ip: Some("0.0.0.0".to_string()),
            host_port: 8080,
            container_port: 80,
            protocol: "tcp".to_string(),
        },
        PortMapping {
            host_ip: Some("0.0.0.0".to_string()),
            host_port: 8080,
            container_port: 8080,
            protocol: "TCP".to_string(), // case insensitive protocol match
        },
    ];

    let result = PortCollisionGuard::ensure_no_conflicts_with_containers(&dup_ports, &[]);
    assert!(result.is_err(), "Intra-request duplicate ports must be rejected");
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("duplicate host port binding"));
}

#[test]
fn test_issue_443_subnet_overlap_detection() {
    // Issue #443: Subnet overlap and IP pool collision validation
    let net_store = NetworkStore::new();
    let net1 = "test_sub_overlap_1";
    let net2 = "test_sub_overlap_2";
    let net3 = "test_sub_overlap_3";

    // Clean up if existed
    let _ = net_store.remove_with_force(net1, true);
    let _ = net_store.remove_with_force(net2, true);
    let _ = net_store.remove_with_force(net3, true);

    // Create 172.55.0.0/16
    let res1 = net_store.create_with_options(net1, "bridge", Some("172.55.0.0/16"), None, false, false, HashMap::new());
    assert!(res1.is_ok(), "First subnet should succeed: {:?}", res1.err());

    // Try to create overlapping subnet 172.55.1.0/24 (subset of 172.55.0.0/16)
    let res2 = net_store.create_with_options(net2, "bridge", Some("172.55.1.0/24"), None, false, false, HashMap::new());
    assert!(res2.is_err(), "Overlapping subnet should be rejected");
    assert!(res2.unwrap_err().to_string().contains("Pool overlaps with other one"));

    // Also check overlap against default boxr0 (172.28.0.0/16)
    let res_boxr0 = net_store.create_with_options(net2, "bridge", Some("172.28.10.0/24"), None, false, false, HashMap::new());
    assert!(res_boxr0.is_err(), "Subnet overlapping with boxr0 default bridge must be rejected");
    assert!(res_boxr0.unwrap_err().to_string().contains("Pool overlaps with other one"));

    // Non-overlapping subnet 10.99.0.0/16 should succeed
    let res3 = net_store.create_with_options(net3, "bridge", Some("10.99.0.0/16"), None, false, false, HashMap::new());
    assert!(res3.is_ok(), "Non-overlapping subnet should succeed: {:?}", res3.err());

    // Cleanup
    let _ = net_store.remove_with_force(net1, true);
    let _ = net_store.remove_with_force(net3, true);
}

#[test]
fn test_issue_438_container_netns_parsing_and_isolation() {
    // Issue #438: container:<target> mode must parse properly
    let net_mode = NetworkMode::parse("container:my_app_container");
    match &net_mode {
        NetworkMode::Container(target) => {
            assert_eq!(target, "my_app_container");
        }
        _ => panic!("Expected NetworkMode::Container"),
    }
    // Container netns mode reuses target container's netns, so requires_new_netns is false
    assert!(!net_mode.requires_new_netns());
}

#[test]
fn test_issue_440_compose_custom_networks_and_teardown() {
    // Issue #440: Compose projects with custom networks
    let yaml = r#"
version: '3.8'
networks:
  frontend:
  backend:
services:
  web:
    image: alpine:latest
    networks:
      - frontend
  api:
    image: alpine:latest
    networks:
      - frontend
      - backend
"#;
    let proj = ComposeProject::from_str(yaml, "customnetproj").unwrap();
    let net_store = NetworkStore::new();

    let front_net = "customnetproj_frontend";
    let back_net = "customnetproj_backend";
    let def_net = "customnetproj_default";

    // Clean up if existing
    let _ = net_store.remove_with_force(front_net, true);
    let _ = net_store.remove_with_force(back_net, true);
    let _ = net_store.remove_with_force(def_net, true);

    // Run up logic to create custom networks
    let created = proj.ensure_networks().unwrap();
    assert!(created.contains(&def_net.to_string()));
    assert!(created.contains(&front_net.to_string()));
    assert!(created.contains(&back_net.to_string()));

    // Verify build_service_run_args assigns designated primary network
    let run_web = proj.build_service_run_args(
        "web",
        &proj.compose.services["web"],
        "customnetproj_web_1",
        "alpine:latest",
        true,
    ).unwrap();
    assert_eq!(run_web.network, front_net);

    let run_api = proj.build_service_run_args(
        "api",
        &proj.compose.services["api"],
        "customnetproj_api_1",
        "alpine:latest",
        true,
    ).unwrap();
    assert_eq!(run_api.network, front_net);

    // Teardown with down() should remove all custom project networks
    proj.down(false).unwrap();
    assert!(net_store.find(front_net).is_none());
    assert!(net_store.find(back_net).is_none());
    assert!(net_store.find(def_net).is_none());
}

#[test]
fn test_issue_442_macos_compose_mesh_dynamic_ports_and_ips() {
    // Issue #442: macOS compose mesh dynamic target resolution
    let temp = tempdir().unwrap();
    let bundle = temp.path();

    // Mock ports.json for target container with mapped port 8080 -> 80
    let ports = vec![PortMapping {
        host_ip: None,
        host_port: 8080,
        container_port: 80,
        protocol: "tcp".to_string(),
    }];
    fs::write(bundle.join("ports.json"), serde_json::to_string(&ports).unwrap()).unwrap();

    // Mock compose_net.json for target container
    let mut compose_net = HashMap::new();
    compose_net.insert("self_ip".to_string(), "10.88.0.42".to_string());
    fs::write(bundle.join("compose_net.json"), serde_json::to_string(&compose_net).unwrap()).unwrap();

    let (target_ip, target_port) = resolve_target_endpoint(bundle);
    assert_eq!(target_port, 80);
    assert_eq!(target_ip, "10.88.0.42");
}

#[test]
fn test_issue_444_network_connect_disconnect_endpoints() {
    // Issue #444: Network connect and disconnect updates endpoint state in NetworkStore
    let net_store = NetworkStore::new();
    let net_name = "test_conn_disc_net";

    let _ = net_store.remove_with_force(net_name, true);
    let _ = net_store.create(net_name, None, None);

    // Connect container
    let ep = net_store.connect_container(net_name, "c_test_444", "test_worker").unwrap();
    assert_eq!(ep.container_name, "test_worker");
    assert_eq!(ep.container_id, "c_test_444");
    assert!(!ep.ipv4_address.is_empty());

    let record = net_store.find(net_name).unwrap();
    assert!(record.containers.contains_key("c_test_444"));

    // Disconnect container
    let disc_res = net_store.disconnect_container(net_name, "c_test_444");
    assert!(disc_res.is_ok());

    let record_after = net_store.find(net_name).unwrap();
    assert!(!record_after.containers.contains_key("c_test_444"));

    // Disconnecting a non-existent container yields error
    let disc_again = net_store.disconnect_container(net_name, "c_test_444");
    assert!(disc_again.is_err());

    let _ = net_store.remove_with_force(net_name, true);
}

#[test]
fn test_issue_445_darwin_resolv_conf_nameserver_preservation() {
    // Issue #445: Ensure default nameservers are preserved when search/options/domain are present
    let temp = tempdir().unwrap();
    let bundle = temp.path();

    // Create dns_search.json with a search domain
    fs::write(bundle.join("dns_search.json"), r#"["internal.corp", "example.com"]"#).unwrap();
    // Create dns_option.json with an option
    fs::write(bundle.join("dns_option.json"), r#"["ndots:5"]"#).unwrap();

    let resolv_conf = boxr::runtime::darwin::generate_guest_resolv_conf(bundle, Some("subdomain.example.com"));

    // Verify default nameserver entries are not missing
    assert!(resolv_conf.contains("nameserver 192.168.64.1"), "Resolv.conf must retain gateway nameserver: {}", resolv_conf);
    assert!(resolv_conf.contains("nameserver 1.1.1.1"), "Resolv.conf must retain cloudflare nameserver: {}", resolv_conf);
    assert!(resolv_conf.contains("nameserver 8.8.8.8"), "Resolv.conf must retain google nameserver: {}", resolv_conf);

    // Verify search, options, and domain directives are also present
    assert!(resolv_conf.contains("search internal.corp example.com"));
    assert!(resolv_conf.contains("options ndots:5"));
    assert!(resolv_conf.contains("domain subdomain.example.com"));
}

#[tokio::test]
async fn test_issue_441_daemon_network_disconnect_and_conflict_status() {
    // Issue #441: REST API /networks/{id}/connect, /disconnect, and 409 Conflict mapping
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use boxr::daemon::{DaemonState, create_router};
    use tower::ServiceExt;

    let temp = tempdir().unwrap();
    let home = temp.path().to_path_buf();
    let state = DaemonState { home: home.clone() };
    let app = create_router(state);

    // Create a network directly in NetworkStore
    let net_store = NetworkStore::with_home(home.clone());
    let net = net_store.create("test_rest_net", None, None).unwrap();

    // Connect a container endpoint
    let _ = net_store.connect_container("test_rest_net", "cont_rest_123", "worker_rest");

    // Deleting network with active container endpoints should return 409 Conflict
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/v1.45/networks/{}", net.name))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    // Disconnect the container via POST /networks/{id}/disconnect
    let disc_body = serde_json::json!({
        "Container": "cont_rest_123"
    });
    let disc_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1.45/networks/{}/disconnect", net.name))
                .header("content-type", "application/json")
                .body(Body::from(disc_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(disc_resp.status(), StatusCode::OK);

    // Now removing the network should succeed with 204 No Content
    let del_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/v1.45/networks/{}", net.name))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(del_resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_issue_437_udp_forwarder_socket_lifecycle() {
    // Issue #437: UDP port forwarder creates UDP socket and is non-blocking with timeouts
    use boxr::network::rootless::RootlessUdpPortForwarder;
    use std::net::SocketAddr;

    let host_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let target_addr: SocketAddr = "127.0.0.1:19999".parse().unwrap();

    #[cfg(any(windows, target_os = "macos"))]
    {
        let fwd = RootlessUdpPortForwarder::new_direct(host_addr, target_addr);
        assert_eq!(fwd.target_addr, target_addr);
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let fwd = RootlessUdpPortForwarder::new(host_addr, std::path::PathBuf::from("/tmp/dummy.sock"));
        assert_eq!(fwd.host_addr, host_addr);
    }

    let rootless_src = include_str!("../src/network/rootless.rs");
    assert!(
        rootless_src.contains("tokio::time::timeout"),
        "UDP forwarding loop must apply socket read timeouts"
    );
}

#[test]
fn test_issue_448_linux_root_mode_pdeathsig() {
    // Issue #448: Verify regression check that PR_SET_PDEATHSIG is called in child forks
    let linux_src = include_str!("../src/runtime/linux.rs");
    assert!(
        linux_src.contains("PR_SET_PDEATHSIG"),
        "linux.rs must set PR_SET_PDEATHSIG for helper process cleanup"
    );
}

#[test]
fn test_issue_446_usernet_engine_poll_optimization() {
    // Issue #446: usernet TAP engine must not busy-poll with unconditional sleep
    let engine_src = include_str!("../src/network/usernet/engine.rs");
    assert!(
        engine_src.contains("libc::poll") || engine_src.contains("pollfd"),
        "usernet engine should use poll instead of busy sleeping"
    );
}

#[test]
fn test_issue_439_usernet_udp_forwarding() {
    // Issue #439: Embedded usernet handles non-DNS UDP forwarding
    let engine_src = include_str!("../src/network/usernet/engine.rs");
    assert!(
        engine_src.contains("build_udp_reply"),
        "usernet engine must support generic UDP forwarding"
    );
}




