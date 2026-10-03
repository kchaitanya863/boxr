use boxr::compose::ComposeProject;
use boxr::network::pasta::NetworkMode;
use boxr::network::rootless::run_port_forward_daemon;
use boxr::network::{NetworkStore, PortMapping, wait_for_published_ports};
use boxr::runtime::kill::ContainerKiller;
use boxr::storage::{ContainerRecord, ContainerStatus};
use std::net::TcpListener;
use std::time::Duration;
use tempfile::tempdir;

#[test]
fn test_issue_413_root_and_bridge_network_isolation() {
    // Issue #413: Default (auto), bridge, and named networks (e.g. boxr0)
    // must isolate network namespaces (requires_new_netns = true).
    assert!(
        NetworkMode::Auto.requires_new_netns(),
        "Auto network mode must require a new network namespace"
    );
    assert!(
        NetworkMode::Bridge.requires_new_netns(),
        "Bridge network mode must require a new network namespace"
    );
    assert!(
        NetworkMode::UserNet.requires_new_netns(),
        "UserNet network mode must require a new network namespace"
    );
    assert!(
        NetworkMode::Pasta.requires_new_netns(),
        "Pasta network mode must require a new network namespace"
    );
    assert!(
        NetworkMode::None.requires_new_netns(),
        "None network mode must require a new network namespace"
    );
    assert!(
        !NetworkMode::Host.requires_new_netns(),
        "Host network mode should share host netns"
    );

    // Named networks like boxr0 and compose_default must parse as Bridge and require new netns
    assert_eq!(NetworkMode::parse("boxr0"), NetworkMode::Bridge);
    assert!(NetworkMode::parse("boxr0").requires_new_netns());

    assert_eq!(NetworkMode::parse("compose_default"), NetworkMode::Bridge);
    assert!(NetworkMode::parse("compose_default").requires_new_netns());

    assert_eq!(NetworkMode::parse("custom_net"), NetworkMode::Bridge);
    assert!(NetworkMode::parse("custom_net").requires_new_netns());
}

#[test]
fn test_issue_414_usernet_tap_and_netns_interface_configuration() {
    // Issue #414: usernet and bridge modes must activate user-mode networking
    assert!(
        NetworkMode::UserNet.should_use_native_usernet(),
        "UserNet must activate native usernet TAP networking"
    );
    assert!(
        NetworkMode::Bridge.should_use_native_usernet(),
        "Bridge must activate native usernet TAP networking"
    );

    // Verify default network configuration constants
    use boxr::network::usernet::{DEFAULT_CONTAINER_IP, DEFAULT_DNS_IP, DEFAULT_GATEWAY_IP};
    assert_eq!(DEFAULT_CONTAINER_IP.to_string(), "10.0.2.15");
    assert_eq!(DEFAULT_GATEWAY_IP.to_string(), "10.0.2.2");
    assert_eq!(DEFAULT_DNS_IP.to_string(), "10.0.2.3");
}

#[tokio::test]
async fn test_issue_415_published_ports_persistent_daemon_lifetime() {
    // Issue #415: Published ports must stay forwarded via background daemon
    let dir = tempdir().unwrap();
    let bundle_path = dir.path().to_path_buf();

    let dummy_target = TcpListener::bind("127.0.0.1:0").unwrap();
    let container_port = dummy_target.local_addr().unwrap().port();

    let host_port = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };

    let ports = vec![PortMapping {
        host_ip: Some("127.0.0.1".to_string()),
        host_port,
        container_port,
        protocol: "tcp".to_string(),
    }];
    std::fs::write(
        bundle_path.join("ports.json"),
        serde_json::to_string(&ports).unwrap(),
    )
    .unwrap();

    let mut mock_process = std::process::Command::new("sleep")
        .arg("5")
        .spawn()
        .unwrap();
    let pid = mock_process.id() as i32;
    std::fs::write(bundle_path.join("vm.pid"), pid.to_string()).unwrap();

    let bpath = bundle_path.clone();
    let handle = tokio::spawn(async move {
        run_port_forward_daemon(&bpath).await.unwrap();
    });

    // Verify daemon starts and port becomes listening
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(bundle_path.join("forwarder.pid").exists());

    let probe = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", host_port)).await;
    assert!(
        probe.is_ok(),
        "Published port must be listening in background daemon"
    );

    // Stop container
    let _ = mock_process.kill();
    let _ = mock_process.wait();

    // Daemon terminates on container stop
    let _ = tokio::time::timeout(Duration::from_secs(3), handle).await;
    assert!(!bundle_path.join("forwarder.pid").exists());
}

#[test]
fn test_issue_416_readiness_probe_raw_tcp_on_http_ports() {
    // Issue #416: Ports 80/443/8080/8443 must succeed with TCP connect without requiring HTTP protocol data
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let (stop_tx, stop_rx) = std::sync::mpsc::channel();
    let server_thread = std::thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        while stop_rx.try_recv().is_err() {
            if let Ok((mut stream, _)) = listener.accept() {
                use std::io::Write;
                let _ = stream.write_all(b"\x00\x00\x00\x08rawdata");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    });

    // Test port 80 mapping
    let mapping_80 = PortMapping {
        host_ip: Some("127.0.0.1".to_string()),
        host_port: port,
        container_port: 80,
        protocol: "tcp".to_string(),
    };
    assert!(
        wait_for_published_ports(&[mapping_80], Duration::from_secs(3)).is_ok(),
        "Port 80 must succeed for non-HTTP TCP service"
    );

    // Test port 8080 mapping
    let mapping_8080 = PortMapping {
        host_ip: Some("127.0.0.1".to_string()),
        host_port: port,
        container_port: 8080,
        protocol: "tcp".to_string(),
    };
    assert!(
        wait_for_published_ports(&[mapping_8080], Duration::from_secs(3)).is_ok(),
        "Port 8080 must succeed for non-HTTP TCP service"
    );

    let _ = stop_tx.send(());
    let _ = server_thread.join();
}

#[test]
fn test_issue_417_process_group_termination() {
    // Issue #417: kill must target process group leader to terminate entire container process tree
    let mut child = std::process::Command::new("sleep")
        .arg("10")
        .spawn()
        .unwrap();

    let pid = child.id() as i32;
    let dir = tempdir().unwrap();
    let bundle_path = dir.path().to_path_buf();
    std::fs::write(bundle_path.join("vm.pid"), pid.to_string()).unwrap();

    let cont = ContainerRecord {
        id: "stoptest_417".to_string(),
        name: "stoptest_417".to_string(),
        image: "alpine:latest".to_string(),
        command: vec!["sleep".to_string(), "10".to_string()],
        created_at: chrono::Utc::now(),
        status: ContainerStatus::Running,
        bundle_path: bundle_path.to_string_lossy().to_string(),
        restart_policy: boxr::health::RestartPolicy::No,
        health_status: boxr::health::HealthStatus::None,
        restart_count: 0,
        ports: Vec::new(),
        exposed_ports: Vec::new(),
    };

    ContainerKiller::kill(&cont, Some("SIGKILL")).unwrap();
    let status = child.wait().unwrap();
    assert!(!status.success());
}

#[test]
fn test_issue_418_compose_up_ports_forwarding_configuration() {
    // Issue #418: compose up preserves declared ports for port forwarding
    let yaml = r#"
version: '3.8'
services:
  web:
    image: alpine:latest
    ports:
      - "18082:80"
      - "18083:443"
"#;
    let proj = ComposeProject::from_str(yaml, "portproj").unwrap();
    let svc = &proj.compose.services["web"];
    let run_args = proj
        .build_service_run_args("web", svc, "portproj_web_1", "alpine:latest", true)
        .unwrap();

    assert_eq!(run_args.ports, vec!["18082:80", "18083:443"]);
}

#[test]
fn test_issue_419_compose_service_discovery_hosts_synthesis() {
    // Issue #419: Compose services get synthetic /etc/hosts entries mapping
    // service names and container names to their assigned IPAM addresses.
    let yaml = r#"
version: '3.8'
services:
  web:
    image: alpine:latest
  api:
    image: alpine:latest
"#;
    let proj = ComposeProject::from_str(yaml, "testdiscovery").unwrap();
    let net_store = NetworkStore::new();
    let net_name = "testdiscovery_default";

    let _ = net_store.create(net_name, None, None);
    let ep_web = net_store
        .connect_container(net_name, "testdiscovery_web_1", "web")
        .unwrap();
    let ep_api = net_store
        .connect_container(net_name, "testdiscovery_api_1", "api")
        .unwrap();

    let run_args = proj
        .build_service_run_args(
            "web",
            &proj.compose.services["web"],
            "testdiscovery_web_1",
            "alpine:latest",
            true,
        )
        .unwrap();

    assert_eq!(run_args.hostname, Some("web".to_string()));
    assert_eq!(run_args.network, "testdiscovery_default");
    assert!(
        run_args
            .add_host
            .contains(&format!("api:{}", ep_api.ipv4_address))
    );
    assert!(
        run_args
            .add_host
            .contains(&format!("web:{}", ep_web.ipv4_address))
    );
    assert!(
        run_args
            .add_host
            .contains(&format!("testdiscovery_api_1:{}", ep_api.ipv4_address))
    );
    assert!(
        run_args
            .add_host
            .contains(&format!("testdiscovery_web_1:{}", ep_web.ipv4_address))
    );

    let _ = net_store.remove_with_force(net_name, true);
}

#[test]
fn test_issue_420_compose_down_removes_project_network_and_endpoints() {
    // Issue #420: compose down removes project network and active endpoints
    let yaml = r#"
version: '3.8'
services:
  web:
    image: alpine:latest
  api:
    image: alpine:latest
"#;
    let proj = ComposeProject::from_str(yaml, "cleanupproj").unwrap();
    let net_store = NetworkStore::new();
    let net_name = "cleanupproj_default";

    let _ = net_store.create(net_name, None, None);
    let _ = net_store.connect_container(net_name, "cleanupproj_web_1", "web");
    let _ = net_store.connect_container(net_name, "cleanupproj_api_1", "api");

    assert!(net_store.find(net_name).is_some());

    proj.down(false).unwrap();

    assert!(
        net_store.find(net_name).is_none(),
        "Project network must be completely removed by compose down"
    );
}
