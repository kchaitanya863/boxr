#[path = "common/blackbox.rs"]
mod blackbox;

use blackbox::*;
use std::fs;

#[test]
fn test_c1_volume_crud_lifecycle() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let (_guard, home) = isolated_home();
    let vol = format!("bb-vol-{}", rand_suffix());
    run_boxr_ok(&home, &["volume", "create", &vol]);
    let ls = run_boxr_ok(&home, &["volume", "ls"]);
    assert!(ls.contains(&vol));
    run_boxr_ok(&home, &["volume", "inspect", &vol]);
    run_boxr_ok(&home, &["volume", "rm", &vol]);
}

#[test]
fn test_c2_bind_mount_rw() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "alpine:latest");
    let dir = tempfile::tempdir().unwrap();
    let mount = format!("{}:/data:rw", dir.path().display());
    run_boxr_ok(
        &home,
        &[
            "run",
            "--rm",
            "-v",
            &mount,
            "alpine",
            "/bin/sh",
            "-c",
            "echo bind-ok > /data/file.txt",
        ],
    );
    assert!(dir.path().join("file.txt").exists());
    assert_eq!(
        fs::read_to_string(dir.path().join("file.txt")).unwrap(),
        "bind-ok\n"
    );
}

#[test]
fn test_c3_bind_mount_ro_rejects_write() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "alpine:latest");
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("seed.txt"), "seed").unwrap();
    let mount = format!("{}:/data:ro", dir.path().display());
    let out = run_boxr(
        &home,
        &[
            "run",
            "--rm",
            "-v",
            &mount,
            "alpine",
            "/bin/sh",
            "-c",
            "echo fail > /data/new.txt",
        ],
    );
    assert!(!out.status.success() || !dir.path().join("new.txt").exists());
}

#[test]
fn test_c4_mount_readonly_flag() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "alpine:latest");
    let dir = tempfile::tempdir().unwrap();
    let mount = format!(
        "type=bind,source={},target=/data,readonly",
        dir.path().display()
    );
    let out = run_boxr(
        &home,
        &[
            "run",
            "--rm",
            "--mount",
            &mount,
            "alpine",
            "/bin/sh",
            "-c",
            "echo x > /data/x.txt",
        ],
    );
    assert!(!out.status.success() || !dir.path().join("x.txt").exists());
}

#[test]
fn test_c6_chown_chmod_on_volume() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "alpine:latest");
    let dir = tempfile::tempdir().unwrap();
    let mount = format!("{}:/srv/data:rw", dir.path().display());
    let out = run_boxr_ok(
        &home,
        &[
            "run",
            "--rm",
            "-v",
            &mount,
            "alpine",
            "/bin/sh",
            "-c",
            "mkdir -p /srv/data/pg && chmod 0700 /srv/data/pg && chown 70:70 /srv/data/pg && echo ok > /srv/data/pg/wal.dat && cat /srv/data/pg/wal.dat",
        ],
    );
    assert!(out.contains("ok"));
}

#[test]
fn test_c8_volume_persistence_across_recreate() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "alpine:latest");
    let vol = format!("bb-persist-{}", rand_suffix());
    let ctr1 = format!("bb-persist-c1-{}", rand_suffix());
    run_boxr_ok(&home, &["volume", "create", &vol]);
    run_boxr_ok(
        &home,
        &[
            "run",
            "--rm",
            "--name",
            &ctr1,
            "-v",
            &format!("{}:/data", vol),
            "alpine",
            "/bin/sh",
            "-c",
            "echo marker-persist > /data/marker.txt",
        ],
    );
    let ctr2 = format!("bb-persist-c2-{}", rand_suffix());
    let out = run_boxr_ok(
        &home,
        &[
            "run",
            "--rm",
            "--name",
            &ctr2,
            "-v",
            &format!("{}:/data", vol),
            "alpine",
            "cat",
            "/data/marker.txt",
        ],
    );
    cleanup_volume(&home, &vol);
    assert!(out.contains("marker-persist"));
}

#[test]
fn test_c11_duplicate_volume_name_fails() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let (_guard, home) = isolated_home();
    let vol = format!("bb-dup-{}", rand_suffix());
    run_boxr_ok(&home, &["volume", "create", &vol]);
    run_boxr_fail(&home, &["volume", "create", &vol]);
    cleanup_volume(&home, &vol);
}

#[test]
fn test_c15_cp_host_container_roundtrip() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "alpine:latest");
    let suffix = rand_suffix();
    let ctr = format!("bb-cp-{}", suffix);
    let host_dir = tempfile::tempdir().unwrap();
    let host_file = host_dir.path().join("upload.txt");
    fs::write(&host_file, "host-content").unwrap();
    run_boxr_ok(
        &home,
        &["run", "-d", "--name", &ctr, "alpine", "sleep", "120"],
    );
    run_boxr_ok(
        &home,
        &[
            "cp",
            host_file.to_str().unwrap(),
            &format!("{}:/tmp/upload.txt", ctr),
        ],
    );
    let out = run_boxr_ok(&home, &["exec", &ctr, "cat", "/tmp/upload.txt"]);
    assert!(out.contains("host-content"));
    let dl = host_dir.path().join("download.txt");
    run_boxr_ok(
        &home,
        &[
            "cp",
            &format!("{}:/tmp/upload.txt", ctr),
            dl.to_str().unwrap(),
        ],
    );
    cleanup_container(&home, &ctr);
    assert_eq!(fs::read_to_string(dl).unwrap(), "host-content");
}

#[test]
fn test_h8_executable_on_volume() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "alpine:latest");
    let dir = tempfile::tempdir().unwrap();
    let mount = format!("{}:/scripts:rw", dir.path().display());
    run_boxr_ok(
        &home,
        &[
            "run",
            "--rm",
            "-v",
            &mount,
            "alpine",
            "/bin/sh",
            "-c",
            "echo '#!/bin/sh' > /scripts/run.sh && echo 'echo exec-ok' >> /scripts/run.sh && chmod +x /scripts/run.sh",
        ],
    );
    let out = run_boxr_ok(
        &home,
        &["run", "--rm", "-v", &mount, "alpine", "/scripts/run.sh"],
    );
    assert!(out.contains("exec-ok"));
}
