use super::*;
use crate::storage::ContainerStore;
use chrono::Utc;
use std::fs;
use std::time::Duration;
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
fn test_refresh_bridge_hosts_writes_bundle_files() {
    let dir = tempdir().unwrap();
    let home = dir.path();
    let net_store = NetworkStore::with_home(home.to_path_buf());
    let net_name = "refresh-net";
    net_store.create(net_name, None, None).unwrap();
    net_store
        .connect_container(net_name, "aaa111", "alpha")
        .unwrap();
    net_store
        .connect_container(net_name, "bbb222", "beta")
        .unwrap();

    let bundle = home.join("bundles/alpha");
    fs::create_dir_all(bundle.join("rootfs/etc")).unwrap();
    fs::write(
        bundle.join("config.json"),
        r#"{"hostname":"alpha","process":{"args":["sleep"]}}"#,
    )
    .unwrap();
    let c_store = ContainerStore::with_home(home.to_path_buf());
    c_store
        .add(crate::storage::ContainerRecord {
            id: "aaa111".to_string(),
            name: "alpha".to_string(),
            image: "alpine:latest".to_string(),
            command: vec!["sleep".to_string()],
            created_at: Utc::now(),
            status: crate::storage::ContainerStatus::Running,
            bundle_path: bundle.to_string_lossy().to_string(),
            restart_policy: crate::health::RestartPolicy::No,
            health_status: crate::health::HealthStatus::None,
            restart_count: 0,
            ports: Vec::new(),
            exposed_ports: Vec::new(),
        })
        .unwrap();

    refresh_bridge_hosts_for_network(net_name, Some(home)).unwrap();
    let hosts = fs::read_to_string(bundle.join("rootfs/etc/hosts")).unwrap();
    assert!(
        hosts.contains("beta"),
        "running peer must appear in refreshed hosts: {}",
        hosts
    );
    assert!(hosts.contains("localhost"));
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
