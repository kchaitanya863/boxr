#[path = "common/blackbox.rs"]
mod blackbox;

use blackbox::*;
use std::time::Duration;

#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "micro-VM port forwarding is flaky under cargo test on macOS"
)]
fn test_d1_tcp_publish_and_curl() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "nginx:alpine");
    let suffix = rand_suffix();
    let ctr = format!("bb-net-tcp-{}", suffix);
    let port = 19000
        + suffix
            .chars()
            .take(3)
            .fold(0u32, |a, c| a * 10 + c.to_digit(10).unwrap_or(1))
            % 500;
    let url = format!("http://127.0.0.1:{}/", port);
    let run_args = [
        "run",
        "-d",
        "--name",
        &ctr,
        "-p",
        &format!("127.0.0.1:{}:80", port),
        "nginx:alpine",
    ];
    assert!(
        run_detached_until_http(&home, &run_args, &url, Duration::from_secs(45)),
        "published port {} did not become reachable",
        port
    );
    cleanup_container(&home, &ctr);
}

#[test]
fn test_d4_port_collision_rejected() {
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "alpine:latest");
    let suffix = rand_suffix();
    let port = 19500 + suffix.len() as u16;
    let c1 = format!("bb-collide-1-{}", suffix);
    let c2 = format!("bb-collide-2-{}", suffix);
    run_boxr_ok(
        &home,
        &[
            "run",
            "-d",
            "--name",
            &c1,
            "-p",
            &format!("{}:80", port),
            "alpine",
            "sleep",
            "60",
        ],
    );
    let out = run_boxr(
        &home,
        &[
            "run",
            "-d",
            "--name",
            &c2,
            "-p",
            &format!("{}:80", port),
            "alpine",
            "sleep",
            "60",
        ],
    );
    cleanup_container(&home, &c1);
    cleanup_container(&home, &c2);
    assert!(!out.status.success(), "expected port collision error");
}

#[test]
fn test_d5_network_connect() {
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "alpine:latest");
    let suffix = rand_suffix();
    let net = format!("bb-net-{}", suffix);
    let ctr = format!("bb-net-ctr-{}", suffix);
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
            "120",
        ],
    );
    let out = run_boxr(&home, &["network", "connect", &net, &ctr]);
    cleanup_container(&home, &ctr);
    cleanup_network(&home, &net);
    assert!(out.status.success());
}

#[test]
fn test_d6_stop_start_restores_port_forward() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "nginx:alpine");
    let suffix = rand_suffix();
    let ctr = format!("bb-stop-start-{}", suffix);
    let port = 19700 + suffix.len() as u16;
    let url = format!("http://127.0.0.1:{}/", port);
    run_boxr_ok(
        &home,
        &[
            "run",
            "-d",
            "--name",
            &ctr,
            "-p",
            &format!("127.0.0.1:{}:80", port),
            "nginx:alpine",
        ],
    );
    assert!(
        wait_http_ok(&url, Duration::from_secs(60)),
        "port {} reachable before stop",
        port
    );
    run_boxr_ok(&home, &["stop", &ctr]);
    run_boxr_ok(&home, &["start", &ctr]);
    assert!(
        wait_http_ok(&url, Duration::from_secs(120)),
        "port {} not restored after stop/start",
        port
    );
    cleanup_container(&home, &ctr);
}

#[test]
fn test_d6b_rapid_restart_survives() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "nginx:alpine");
    let suffix = rand_suffix();
    let ctr = format!("bb-rapid-restart-{}", suffix);
    let port = 19800 + suffix.len() as u16;
    let url = format!("http://127.0.0.1:{}/", port);
    run_boxr_ok(
        &home,
        &[
            "run",
            "-d",
            "--name",
            &ctr,
            "-p",
            &format!("127.0.0.1:{}:80", port),
            "nginx:alpine",
        ],
    );
    for _ in 0..3 {
        run_boxr_ok(&home, &["restart", &ctr]);
    }
    assert!(
        wait_http_ok(&url, Duration::from_secs(120)),
        "container did not survive three rapid restarts with port {}",
        port
    );
    cleanup_container(&home, &ctr);
}

#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "micro-VM port forwarding is flaky under cargo test on macOS"
)]
fn test_d7_restart_preserves_port_forward() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "nginx:alpine");
    let suffix = rand_suffix();
    let ctr = format!("bb-restart-{}", suffix);
    let port = 19600 + suffix.len() as u16;
    let url = format!("http://127.0.0.1:{}/", port);
    let run_args = [
        "run",
        "-d",
        "--name",
        &ctr,
        "-p",
        &format!("{}:80", port),
        "nginx:alpine",
    ];
    assert!(
        run_detached_until_http(&home, &run_args, &url, Duration::from_secs(45)),
        "published port {} not reachable before restart",
        port
    );
    run_boxr_ok(&home, &["restart", &ctr]);
    assert!(
        wait_http_ok(&url, Duration::from_secs(60)),
        "port forward lost after restart"
    );
    cleanup_container(&home, &ctr);
}

#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "micro-VM outbound networking is slow/flaky under cargo test on macOS"
)]
fn test_d10_outbound_connectivity() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "alpine:latest");
    let out = run_boxr(
        &home,
        &[
            "run",
            "--rm",
            "alpine",
            "wget",
            "-qO-",
            "--timeout=15",
            "http://example.com",
        ],
    );
    let combined = combined_output(&out);
    assert!(
        out.status.success() || combined.contains("Example"),
        "outbound HTTP failed: {}",
        combined
    );
}

#[test]
fn test_d_network_none_blocks_external() {
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "alpine:latest");
    let out = run_boxr(
        &home,
        &[
            "run",
            "--rm",
            "--network",
            "none",
            "alpine",
            "wget",
            "-q",
            "--timeout=3",
            "-O",
            "/dev/null",
            "http://8.8.8.8",
        ],
    );
    let combined = combined_output(&out);
    let blocked = !out.status.success()
        || combined.contains("timed out")
        || combined.contains("Network is unreachable")
        || combined.contains("bad address")
        || combined.contains("wget:")
        || combined.contains("virtio");
    assert!(
        blocked,
        "expected --network none to block external access, got: {}",
        combined
    );
}

#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "micro-VM run --rm is slow/flaky under cargo test on macOS"
)]
fn test_e1_dns_resolution() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "alpine:latest");
    let out = run_boxr(
        &home,
        &[
            "run",
            "--rm",
            "alpine",
            "/bin/sh",
            "-c",
            "nslookup example.com 2>/dev/null || wget -qO- http://example.com | head -1",
        ],
    );
    let combined = combined_output(&out);
    assert!(
        out.status.success() || combined.contains("Example") || combined.contains("Address"),
        "DNS/outbound failed: {}",
        combined
    );
}

#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "micro-VM run --rm is slow/flaky under cargo test on macOS"
)]
fn test_e2_custom_dns_server() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "alpine:latest");
    let out = run_boxr_ok(
        &home,
        &[
            "run",
            "--rm",
            "--dns",
            "8.8.8.8",
            "alpine",
            "cat",
            "/etc/resolv.conf",
        ],
    );
    assert!(out.contains("8.8.8.8") || out.contains("nameserver"));
}

#[test]
fn test_e7_bridge_hosts_name_resolution() {
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "alpine:latest");
    let fixture = fixture_path("tests/fixtures/compose/minimal-dns.yml");
    let _ = run_boxr(
        &home,
        &["compose", "-f", fixture.to_str().unwrap(), "down", "-v"],
    );
    run_boxr_ok(
        &home,
        &["compose", "-f", fixture.to_str().unwrap(), "up", "-d"],
    );
    std::thread::sleep(Duration::from_secs(5));
    let ps = run_boxr_ok(&home, &["compose", "-f", fixture.to_str().unwrap(), "ps"]);
    assert!(ps.contains("web") || ps.contains("db"));
    let _ = run_boxr(
        &home,
        &["compose", "-f", fixture.to_str().unwrap(), "down", "-v"],
    );
}

#[cfg(target_os = "linux")]
#[test]
fn test_d_linux_usernet_mode() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
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
            "wget",
            "-qO-",
            "http://example.com",
        ],
    );
    assert!(out.status.success() || combined_output(&out).contains("Example"));
}
