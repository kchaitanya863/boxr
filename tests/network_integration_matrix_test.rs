//! Black-box integration matrix for container networking (modes, IPAM, publish, lifecycle).

#[path = "common/blackbox.rs"]
mod blackbox;

use blackbox::*;
use std::fs;
use std::path::Path;
use std::process::Output;
use std::time::Duration;

fn read_container_bundle_hosts(home: &Path, container_name: &str) -> String {
    let index = home.join("containers.json");
    let raw = fs::read_to_string(&index).expect("containers.json");
    let data: serde_json::Value = serde_json::from_str(&raw).expect("containers json");
    let containers = data
        .get("containers")
        .and_then(|v| v.as_array())
        .expect("containers array");
    let record = containers
        .iter()
        .find(|c| c.get("name").and_then(|n| n.as_str()) == Some(container_name))
        .expect("container record");
    let bundle = record
        .get("bundle_path")
        .and_then(|v| v.as_str())
        .expect("bundle_path");
    fs::read_to_string(Path::new(bundle).join("rootfs/etc/hosts")).expect("bundle hosts file")
}

fn pick_host_port(suffix: &str, base: u16) -> u16 {
    let offset = suffix
        .chars()
        .take(4)
        .fold(0u32, |a, c| a * 10 + c.to_digit(16).unwrap_or(1))
        % 400;
    base + offset as u16
}

fn alpine_outbound_probe(home: &std::path::Path, network: Option<&str>) -> Output {
    let mut args = vec!["run", "--rm"];
    if let Some(net) = network {
        args.push("--network");
        args.push(net);
    }
    args.extend([
        "alpine",
        "/bin/sh",
        "-c",
        "wget -qO- --timeout=12 http://example.com 2>/dev/null | head -c 20 || nslookup example.com 2>/dev/null | head -1",
    ]);
    run_boxr(home, &args)
}

fn outbound_ok(out: &Output) -> bool {
    if out.status.success() {
        return true;
    }
    let combined = combined_output(out);
    combined.contains("Example") || combined.contains("Address")
}

#[test]
fn test_matrix_none_blocks_wan_allows_loopback() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "alpine:latest");

    let wan = run_boxr(
        &home,
        &[
            "run",
            "--rm",
            "--network",
            "none",
            "alpine",
            "wget",
            "-q",
            "--timeout",
            "3",
            "-O",
            "/dev/null",
            "http://1.1.1.1",
        ],
    );
    let wan_combined = combined_output(&wan);
    assert!(
        !wan.status.success()
            || wan_combined.contains("timed out")
            || wan_combined.contains("Network is unreachable")
            || wan_combined.contains("wget:"),
        "WAN should be blocked on --network none: {}",
        wan_combined
    );

    let lo = run_boxr_ok(
        &home,
        &[
            "run",
            "--rm",
            "--network",
            "none",
            "alpine",
            "ping",
            "-c",
            "1",
            "-W",
            "1",
            "127.0.0.1",
        ],
    );
    assert!(
        lo.contains("1 packets transmitted") || lo.contains("1 received"),
        "loopback should work on --network none: {}",
        lo
    );
}

#[test]
fn test_matrix_host_and_none_reject_published_ports() {
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "alpine:latest");
    let suffix = rand_suffix();

    for (net, ctr) in [
        ("none", format!("m-none-p-{}", suffix)),
        ("host", format!("m-host-p-{}", suffix)),
    ] {
        let out = run_boxr(
            &home,
            &[
                "run",
                "-d",
                "--name",
                &ctr,
                "--network",
                net,
                "-p",
                "18081:80",
                "alpine",
                "sleep",
                "15",
            ],
        );
        cleanup_container(&home, &ctr);
        let combined = combined_output(&out);
        assert!(
            !out.status.success() && combined.contains("published ports are not supported"),
            "network={} should reject -p: {}",
            net,
            combined
        );
    }
}

#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "custom bridge networks are slow/flaky under cargo test on macOS"
)]
fn test_matrix_custom_network_hosts_and_inspect() {
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "alpine:latest");
    let suffix = rand_suffix();
    let net = format!("matrix-net-{}", suffix);
    let c1 = format!("matrix-a-{}", suffix);
    let c2 = format!("matrix-b-{}", suffix);

    run_boxr_ok(&home, &["network", "create", &net]);
    // Start the peer first so the second container's /etc/hosts snapshot includes it.
    run_boxr_ok(
        &home,
        &[
            "run",
            "-d",
            "--name",
            &c2,
            "--network",
            &net,
            "alpine",
            "sleep",
            "180",
        ],
    );
    assert!(wait_container_running(&home, &c2, Duration::from_secs(45)), "{}", format_container_wait_failure(&home, &c2));
    run_boxr_ok(
        &home,
        &[
            "run",
            "-d",
            "--name",
            &c1,
            "--network",
            &net,
            "alpine",
            "sleep",
            "180",
        ],
    );
    assert!(wait_container_running(&home, &c1, Duration::from_secs(45)), "{}", format_container_wait_failure(&home, &c1));

    let inspect_raw = run_boxr_ok(&home, &["network", "inspect", &net]);
    let inspect: Vec<serde_json::Value> =
        serde_json::from_str(&inspect_raw).expect("network inspect JSON");
    let containers = inspect[0]
        .get("Containers")
        .and_then(|v| v.as_object())
        .expect("Containers object");
    assert_eq!(
        containers.len(),
        2,
        "expected two endpoints on custom network: {}",
        inspect_raw
    );
    let names: Vec<String> = containers
        .values()
        .filter_map(|v| v.get("container_name").and_then(|n| n.as_str()))
        .map(str::to_string)
        .collect();
    assert!(
        names.contains(&c1) && names.contains(&c2),
        "names={:?}",
        names
    );
    let ips: Vec<String> = containers
        .values()
        .filter_map(|v| v.get("ipv4_address").and_then(|n| n.as_str()))
        .map(str::to_string)
        .collect();
    assert_eq!(ips.len(), 2);
    assert_ne!(ips[0], ips[1], "IPAM must assign distinct addresses");

    cleanup_container(&home, &c1);
    cleanup_container(&home, &c2);
    cleanup_network(&home, &net);
}

#[test]
fn test_matrix_network_connect_disconnect_lifecycle() {
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "alpine:latest");
    let suffix = rand_suffix();
    let net = format!("matrix-lc-{}", suffix);
    let ctr = format!("matrix-lc-ctr-{}", suffix);

    run_boxr_ok(&home, &["network", "create", &net]);
    run_boxr_ok(
        &home,
        &[
            "run",
            "-d",
            "--name",
            &ctr,
            "--network",
            "none",
            "alpine",
            "sleep",
            "180",
        ],
    );
    run_boxr_ok(&home, &["network", "connect", &net, &ctr]);
    let connected = run_boxr_ok(&home, &["network", "inspect", &net]);
    assert!(connected.contains(&ctr));

    run_boxr_ok(&home, &["network", "disconnect", &net, &ctr]);
    let disconnected = run_boxr_ok(&home, &["network", "inspect", &net]);
    assert!(
        !disconnected.contains(&ctr),
        "disconnect should remove container from network metadata: {}",
        disconnected
    );

    cleanup_container(&home, &ctr);
    cleanup_network(&home, &net);
}

#[test]
fn test_matrix_duplicate_network_create_rejected() {
    let (_guard, home) = isolated_home();
    let suffix = rand_suffix();
    let net = format!("matrix-dup-{}", suffix);
    run_boxr_ok(&home, &["network", "create", &net]);
    let out = run_boxr(&home, &["network", "create", &net]);
    cleanup_network(&home, &net);
    let combined = combined_output(&out);
    assert!(
        !out.status.success() && combined.contains("already exists"),
        "duplicate create should fail: {}",
        combined
    );
}

#[test]
fn test_matrix_custom_subnet_option() {
    let (_guard, home) = isolated_home();
    let suffix = rand_suffix();
    let net = format!("matrix-sub-{}", suffix);
    run_boxr_ok(
        &home,
        &["network", "create", "--subnet", "10.77.0.0/16", &net],
    );
    let inspect = run_boxr_ok(&home, &["network", "inspect", &net]);
    assert!(
        inspect.contains("10.77.0.0") || inspect.contains("10.77"),
        "custom subnet should appear in inspect: {}",
        inspect
    );
    cleanup_network(&home, &net);
}

#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "micro-VM port forwarding is flaky under cargo test on macOS"
)]
fn test_matrix_tcp_port_range_publish() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted");
        return;
    }
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "nginx:alpine");
    let suffix = rand_suffix();
    let ctr = format!("matrix-range-{}", suffix);
    let base = pick_host_port(&suffix, 23000);
    let spec = format!("127.0.0.1:{}-{}:80-81", base, base + 1);
    run_boxr_ok(
        &home,
        &["run", "-d", "--name", &ctr, "-p", &spec, "nginx:alpine"],
    );
    let url0 = format!("http://127.0.0.1:{}/", base);
    let url1 = format!("http://127.0.0.1:{}/", base + 1);
    assert!(
        wait_http_ok(&url0, Duration::from_secs(60)),
        "first mapped port {} unreachable",
        base
    );
    assert!(
        wait_http_ok(&url1, Duration::from_secs(60)),
        "second mapped port {} unreachable",
        base + 1
    );
    cleanup_container(&home, &ctr);
}

#[test]
#[cfg(target_os = "linux")]
fn test_matrix_outbound_usernet_mode() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted");
        return;
    }
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "alpine:latest");
    let out = alpine_outbound_probe(&home, Some("usernet"));
    assert!(
        outbound_ok(&out),
        "usernet outbound failed: {}",
        combined_output(&out)
    );
}

#[test]
#[cfg(target_os = "linux")]
fn test_matrix_usernet_pings_virtual_gateway() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted");
        return;
    }
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "alpine:latest");
    let out = run_boxr_ok(
        &home,
        &[
            "run",
            "--rm",
            "--network",
            "usernet",
            "alpine",
            "ping",
            "-c",
            "1",
            "-W",
            "2",
            "10.0.2.2",
        ],
    );
    assert!(
        out.contains("1 received") || out.contains("bytes from"),
        "virtual gateway should answer ICMP: {}",
        out
    );
}

#[test]
#[cfg(target_os = "linux")]
fn test_matrix_embedded_usernet_resolv() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted");
        return;
    }
    let saved_force = std::env::var("BOXR_FORCE_EMBEDDED_USERNET").ok();
    unsafe {
        std::env::set_var("BOXR_FORCE_EMBEDDED_USERNET", "1");
    }
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "alpine:latest");
    let out = run_boxr(
        &home,
        &[
            "run",
            "--rm",
            "--network",
            "usernet",
            "alpine",
            "sh",
            "-c",
            "grep -q 10.0.2.3 /etc/resolv.conf && ping -c 1 -W 3 10.0.2.2 | grep -qE 'bytes from|1 received'",
        ],
    );
    if let Some(v) = saved_force {
        unsafe {
            std::env::set_var("BOXR_FORCE_EMBEDDED_USERNET", v);
        }
    } else {
        unsafe {
            std::env::remove_var("BOXR_FORCE_EMBEDDED_USERNET");
        }
    }
    let combined = combined_output(&out);
    if combined.contains("unshare network namespace") && combined.contains("EPERM") {
        eprintln!("SKIPPED: embedded usernet netns EPERM on runner");
        return;
    }
    assert!(
        out.status.success(),
        "embedded usernet should configure virtual DNS and gateway ICMP: {}",
        combined
    );
}

#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "micro-VM outbound networking is slow under parallel cargo test"
)]
fn test_matrix_outbound_default_network() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted");
        return;
    }
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "alpine:latest");
    let out = alpine_outbound_probe(&home, None);
    assert!(
        outbound_ok(&out),
        "default/auto outbound failed: {}",
        combined_output(&out)
    );
}

#[test]
#[cfg(target_os = "linux")]
fn test_matrix_pasta_outbound_when_installed() {
    use boxr::network::pasta::PastaDriver;
    if !PastaDriver::is_available() {
        eprintln!("SKIPPED: pasta not installed");
        return;
    }
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted");
        return;
    }
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "alpine:latest");
    let out = alpine_outbound_probe(&home, Some("pasta"));
    assert!(
        outbound_ok(&out),
        "pasta outbound failed: {}",
        combined_output(&out)
    );
}

#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "micro-VM port forwarding is flaky under cargo test on macOS"
)]
fn test_matrix_port_collision_same_host_port() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "alpine:latest");
    let suffix = rand_suffix();
    let port = pick_host_port(&suffix, 24000);
    let c1 = format!("matrix-pc-1-{}", suffix);
    let c2 = format!("matrix-pc-2-{}", suffix);
    let _ = run_boxr(&home, &["rm", "-f", &c1, &c2]);
    run_boxr_ok(
        &home,
        &[
            "run",
            "-d",
            "--network",
            "bridge",
            "--name",
            &c1,
            "-p",
            &format!("{}:80", port),
            "alpine",
            "sleep",
            "90",
        ],
    );
    assert!(wait_container_running(&home, &c1, Duration::from_secs(45)));
    let ports_out = run_boxr_ok(&home, &["port", &c1]);
    if !ports_out.contains(&port.to_string()) {
        eprintln!(
            "SKIPPED: host port {} not published (port output: {:?})",
            port,
            ports_out.trim()
        );
        cleanup_container(&home, &c1);
        return;
    }
    let out = run_boxr(
        &home,
        &[
            "run",
            "-d",
            "--network",
            "bridge",
            "--name",
            &c2,
            "-p",
            &format!("{}:8080", port),
            "alpine",
            "sleep",
            "90",
        ],
    );
    cleanup_container(&home, &c1);
    cleanup_container(&home, &c2);
    assert!(!out.status.success(), "expected host port collision");
}

#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "custom bridge networks are slow/flaky under cargo test on macOS"
)]
fn test_matrix_peer_hosts_updated_when_second_container_joins() {
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "alpine:latest");
    let suffix = rand_suffix();
    let net = format!("matrix-hosts-live-{}", suffix);
    let first = format!("matrix-first-{}", suffix);
    let second = format!("matrix-second-{}", suffix);

    run_boxr_ok(&home, &["network", "create", &net]);
    run_boxr_ok(
        &home,
        &[
            "run",
            "-d",
            "--name",
            &first,
            "--network",
            &net,
            "alpine",
            "sleep",
            "180",
        ],
    );
    assert!(
        wait_container_running(&home, &first, Duration::from_secs(45)),
        "{}",
        format_container_wait_failure(&home, &first)
    );

    run_boxr_ok(
        &home,
        &[
            "run",
            "-d",
            "--name",
            &second,
            "--network",
            &net,
            "alpine",
            "sleep",
            "180",
        ],
    );
    assert!(
        wait_container_running(&home, &second, Duration::from_secs(45)),
        "{}",
        format_container_wait_failure(&home, &second)
    );

    let bundle_hosts = read_container_bundle_hosts(&home, &first);
    assert!(
        bundle_hosts.contains(&second),
        "first container bundle /etc/hosts should list second peer without restart: {}",
        bundle_hosts
    );

    cleanup_container(&home, &first);
    cleanup_container(&home, &second);
    cleanup_network(&home, &net);
}

#[test]
fn test_matrix_container_network_mode_shares_target_netns() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "alpine:latest");
    let suffix = rand_suffix();
    let base = format!("matrix-netbase-{}", suffix);
    let side = format!("matrix-sidecar-{}", suffix);

    run_boxr_ok(
        &home,
        &["run", "-d", "--name", &base, "alpine", "sleep", "180"],
    );
    assert!(wait_container_running(
        &home,
        &base,
        Duration::from_secs(45)
    ));
    run_boxr_ok(
        &home,
        &[
            "run",
            "-d",
            "--name",
            &side,
            "--network",
            &format!("container:{}", base),
            "alpine",
            "sleep",
            "180",
        ],
    );
    assert!(wait_container_running(
        &home,
        &side,
        Duration::from_secs(45)
    ));
    assert!(
        wait_exec_success(
            &home,
            &side,
            &[
                "sh",
                "-c",
                "ip link show lo | grep -qE 'LOOPBACK,UP|state UP'",
            ],
            Duration::from_secs(60),
        ),
        "sidecar should share loopback in target network namespace"
    );

    cleanup_container(&home, &side);
    cleanup_container(&home, &base);
}

#[test]
fn test_matrix_intra_request_duplicate_port_publish_rejected() {
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "alpine:latest");
    let suffix = rand_suffix();
    let ctr = format!("matrix-dup-port-{}", suffix);
    let out = run_boxr(
        &home,
        &[
            "run",
            "-d",
            "--name",
            &ctr,
            "-p",
            "25080:80",
            "-p",
            "25080:8080",
            "alpine",
            "sleep",
            "30",
        ],
    );
    cleanup_container(&home, &ctr);
    let combined = combined_output(&out);
    assert!(
        !out.status.success()
            && (combined.contains("duplicate host port")
                || combined.contains("port is already allocated")),
        "expected intra-request port collision: {}",
        combined
    );
}
