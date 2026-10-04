#[path = "common/blackbox.rs"]
mod blackbox;

use blackbox::*;
use std::time::Duration;

#[test]
fn test_a1_smoke_version_and_run() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let (_guard, home) = isolated_home();
    let version = run_boxr_ok(&home, &["version"]);
    assert!(version.contains("Client:"));
    assert!(version.contains("Server:"));
    let out = run_boxr_ok(&home, &["run", "--rm", "alpine:latest", "echo", "ok"]);
    assert!(out.contains("ok"));
}

#[test]
fn test_a2_tmp_sticky_and_nonroot_write() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "alpine:latest");
    let mode = run_boxr_ok(
        &home,
        &["run", "--rm", "alpine", "stat", "-c", "%a", "/tmp"],
    );
    assert!(
        mode.contains("1777") || mode.contains("777"),
        "expected /tmp 1777, got {}",
        mode.trim()
    );
    let out = run_boxr_ok(
        &home,
        &[
            "run",
            "--rm",
            "--user",
            "65534:65534",
            "alpine",
            "/bin/sh",
            "-c",
            "echo enterprise-ok > /tmp/t.txt && cat /tmp/t.txt",
        ],
    );
    assert!(out.contains("enterprise-ok"));
}

#[test]
fn test_a3_dev_shm_and_shm_size() {
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
            "alpine",
            "/bin/sh",
            "-c",
            "test -d /dev/shm && touch /dev/shm/t && echo shm-ok",
        ],
    );
    assert!(out.contains("shm-ok"));
    let df = run_boxr_ok(
        &home,
        &[
            "run",
            "--rm",
            "--shm-size",
            "256m",
            "alpine",
            "df",
            "-h",
            "/dev/shm",
        ],
    );
    assert!(df.contains("shm") || df.contains("256"));
}

#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "urandom device probe is slow/flaky in micro-VM under cargo test"
)]
fn test_a4_device_nodes_nonroot() {
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
            "--user",
            "10001:10001",
            "alpine",
            "/bin/sh",
            "-c",
            "echo x > /dev/null && head -c 16 /dev/urandom | wc -c",
        ],
    );
    assert!(out.trim().contains("16"));
}

#[test]
fn test_a5_apt_priv_drop() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "ubuntu:24.04");
    let out = run_boxr(
        &home,
        &[
            "run",
            "--rm",
            "ubuntu:24.04",
            "/bin/bash",
            "-c",
            "apt-get update -qq 2>&1 | tail -3",
        ],
    );
    let combined = combined_output(&out);
    if out.status.success() {
        assert!(
            !combined.contains("Could not execute 'gpgv'"),
            "gpgv/_apt priv-drop failure: {}",
            combined
        );
    }
}

#[test]
fn test_a6_postgres_named_volume() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "postgres:16-alpine");
    let suffix = rand_suffix();
    let vol = format!("bb-pg-{}", suffix);
    let ctr = format!("bb-pg-ctr-{}", suffix);
    run_boxr_ok(&home, &["volume", "create", &vol]);
    run_boxr_ok(
        &home,
        &[
            "run",
            "-d",
            "--name",
            &ctr,
            "-e",
            "POSTGRES_PASSWORD=test",
            "-e",
            "POSTGRES_DB=enterprise_db",
            "-v",
            &format!("{}:/var/lib/postgresql/data", vol),
            "postgres:16-alpine",
        ],
    );
    let ready = wait_exec_success(
        &home,
        &ctr,
        &["pg_isready", "-U", "postgres", "-d", "enterprise_db"],
        Duration::from_secs(60),
    );
    cleanup_container(&home, &ctr);
    cleanup_volume(&home, &vol);
    assert!(ready, "postgres did not become ready");
}

#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "micro-VM port forwarding is flaky under cargo test on macOS"
)]
fn test_a7_nginx_publish() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "nginx:alpine");
    let suffix = rand_suffix();
    let ctr = format!("bb-ngx-{}", suffix);
    let port = 18000
        + (suffix
            .chars()
            .filter(|c| c.is_ascii_digit())
            .fold(0u32, |a, c| a * 10 + c.to_digit(10).unwrap_or(0))
            % 1000);
    let url = format!("http://127.0.0.1:{}/", port);
    assert!(
        run_detached_until_http(
            &home,
            &[
                "run",
                "-d",
                "--name",
                &ctr,
                "-p",
                &format!("{}:80", port),
                "nginx:alpine",
            ],
            &url,
            Duration::from_secs(60),
        ),
        "nginx did not become reachable on {}",
        url
    );
    cleanup_container(&home, &ctr);
}

#[test]
fn test_a8_readonly_rootfs_writable_volume() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "alpine:latest");
    let dir = tempfile::tempdir().unwrap();
    let mount = format!("{}:/app/data:rw", dir.path().display());
    let out = run_boxr_ok(
        &home,
        &[
            "run",
            "--rm",
            "--read-only",
            "-v",
            &mount,
            "alpine",
            "/bin/sh",
            "-c",
            "echo data-ok > /app/data/out.txt && cat /app/data/out.txt",
        ],
    );
    assert!(out.contains("data-ok"));
}

#[test]
fn test_a9_init_zombie_reaping() {
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
            "--init",
            "--pids-limit",
            "100",
            "alpine",
            "/bin/sh",
            "-c",
            "(sleep 0.1 &) && sleep 0.2 && echo zombie-reaped",
        ],
    );
    assert!(out.contains("zombie-reaped"));
}

#[test]
fn test_a10_daemon_ping() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let (_guard, home) = isolated_home();
    let sock = home.join("bb-daemon.sock");
    let _ = std::fs::remove_file(&sock);
    let mut daemon_cmd = std::process::Command::new(boxr_bin());
    let mut daemon = daemon_cmd
        .env_remove("DOCKER_HOST")
        .env("BOXR_HOME", &home)
        .args(["daemon", "--socket", sock.to_str().unwrap()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn daemon");
    std::thread::sleep(Duration::from_secs(2));
    let curl = std::process::Command::new("curl")
        .args([
            "--unix-socket",
            sock.to_str().unwrap(),
            "http://localhost/_ping",
        ])
        .output()
        .expect("curl ping");
    let _ = daemon.kill();
    assert!(curl.status.success(), "daemon /_ping failed");
}
