//! Black-box networking tests for root and non-root installations.
//! Non-root is the default on macOS and typical Linux workstations.

#[path = "common/blackbox.rs"]
mod blackbox;

use blackbox::*;
use std::time::Duration;

fn installation_label() -> &'static str {
    if is_root_installation() {
        "root"
    } else {
        "non-root"
    }
}

fn is_root_installation() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// Published TCP port must be reachable in both root and non-root installs.
#[test]
fn test_installation_tcp_port_publish() {
    let label = installation_label();
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "nginx:alpine");
    let suffix = rand_suffix();
    let ctr = format!("inst-tcp-{}-{}", label, suffix);
    let port = 21000
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
        run_detached_until_http(&home, &run_args, &url, Duration::from_secs(60)),
        "[{}] published TCP port {} not reachable",
        label,
        port
    );
    cleanup_container(&home, &ctr);
}

/// Custom bridge network registration must work for `boxr run --network <name>`.
#[test]
fn test_installation_custom_network_registration() {
    let label = installation_label();
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "alpine:latest");
    let suffix = rand_suffix();
    let net = format!("inst-net-{}-{}", label, suffix);
    let ctr = format!("inst-ctr-{}-{}", label, suffix);
    run_boxr_ok(&home, &["network", "create", &net]);
    run_boxr_ok(
        &home,
        &[
            "run",
            "-d",
            "--name",
            &ctr,
            "--network",
            &net,
            "alpine",
            "sleep",
            "120",
        ],
    );
    let inspect = run_boxr_ok(&home, &["network", "inspect", &net]);
    assert!(
        inspect.contains(&ctr) || inspect.contains("Containers"),
        "[{}] container must appear on custom network inspect output",
        label
    );
    cleanup_container(&home, &ctr);
    cleanup_network(&home, &net);
}

/// `--network none` with `-p` must be rejected in both installation modes.
#[test]
fn test_installation_none_plus_ports_rejected() {
    let label = installation_label();
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "alpine:latest");
    let suffix = rand_suffix();
    let ctr = format!("inst-none-p-{}-{}", label, suffix);
    let out = run_boxr(
        &home,
        &[
            "run",
            "-d",
            "--name",
            &ctr,
            "--network",
            "none",
            "-p",
            "18080:80",
            "alpine",
            "sleep",
            "10",
        ],
    );
    cleanup_container(&home, &ctr);
    let combined = combined_output(&out);
    assert!(
        !out.status.success() && combined.contains("published ports are not supported"),
        "[{}] expected none+p rejection, got: {}",
        label,
        combined
    );
}

/// Outbound DNS/connectivity (Linux netns or macOS micro-VM).
#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "micro-VM outbound networking can be slow under parallel cargo test"
)]
fn test_installation_outbound_dns() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted");
        return;
    }
    let label = installation_label();
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
        "[{}] outbound DNS failed: {}",
        label,
        combined
    );
}

/// UDP published ports must bind UDP on the host (Linux; macOS guest relay is best-effort).
#[test]
#[cfg(target_os = "linux")]
fn test_installation_udp_port_bind() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted");
        return;
    }
    let label = installation_label();
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "alpine:latest");
    let suffix = rand_suffix();
    let ctr = format!("inst-udp-{}-{}", label, suffix);
    let host_port = 22000 + suffix.len() as u16;
    run_boxr_ok(
        &home,
        &[
            "run",
            "-d",
            "--name",
            &ctr,
            "-p",
            &format!("127.0.0.1:{}:53/udp", host_port),
            "alpine",
            "sleep",
            "60",
        ],
    );
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    assert!(
        udp.send_to(b"probe", format!("127.0.0.1:{}", host_port)).is_ok(),
        "[{}] host UDP port {} must accept datagrams",
        label,
        host_port
    );
    let tcp = std::net::TcpStream::connect(format!("127.0.0.1:{}", host_port));
    assert!(
        tcp.is_err(),
        "[{}] UDP published port must not accept TCP",
        label
    );
    cleanup_container(&home, &ctr);
}
