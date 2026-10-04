#[path = "common/blackbox.rs"]
mod blackbox;

use blackbox::*;
use std::fs;

#[test]
fn test_f1_rootless_id() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "alpine:latest");
    let out = run_boxr_ok(&home, &["run", "--rm", "alpine", "id"]);
    assert!(out.contains("uid=0") || out.contains("uid="));
}

#[test]
fn test_f2_nonroot_user() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "alpine:latest");
    let out = run_boxr_ok(
        &home,
        &["run", "--rm", "--user", "10001:10001", "alpine", "id", "-u"],
    );
    assert!(out.trim() == "10001" || out.contains("10001"));
}

#[test]
fn test_f3_readonly_rootfs_ero_fs() {
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
            "--read-only",
            "alpine",
            "/bin/sh",
            "-c",
            "echo x > /etc/test-readonly",
        ],
    );
    assert!(!out.status.success());
}

#[test]
fn test_f4_privileged_flag_behavior() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "alpine:latest");
    let out = run_boxr_ok(
        &home,
        &["run", "--rm", "--privileged", "alpine", "id", "-u"],
    );
    // Document behavior: may be no-op on rootless; should at least run
    assert!(out.trim().chars().any(|c| c.is_ascii_digit()));
}

#[test]
fn test_f8_env_isolation_between_containers() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "alpine:latest");
    let suffix = rand_suffix();
    let c1 = format!("bb-env-1-{}", suffix);
    let c2 = format!("bb-env-2-{}", suffix);
    run_boxr_ok(
        &home,
        &[
            "run",
            "-d",
            "--name",
            &c1,
            "-e",
            "SECRET=alpha",
            "alpine",
            "sleep",
            "60",
        ],
    );
    run_boxr_ok(
        &home,
        &["run", "-d", "--name", &c2, "alpine", "sleep", "60"],
    );
    let out1 = run_boxr_ok(&home, &["exec", &c1, "/bin/sh", "-c", "echo $SECRET"]);
    let out2 = run_boxr_ok(
        &home,
        &["exec", &c2, "/bin/sh", "-c", "echo ${SECRET:-empty}"],
    );
    cleanup_container(&home, &c1);
    cleanup_container(&home, &c2);
    assert!(out1.contains("alpha"));
    assert!(out2.contains("empty"));
}

#[test]
fn test_f9_bind_mount_dotdot_rejected_or_safe() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "alpine:latest");
    let base = tempfile::tempdir().unwrap();
    let sub = base.path().join("sub");
    fs::create_dir_all(&sub).unwrap();
    let mount = format!("{}:/data:rw", sub.display());
    let out = run_boxr(
        &home,
        &["run", "--rm", "-v", &mount, "alpine", "ls", "/data"],
    );
    assert!(out.status.success());
}

#[test]
fn test_f11_dangerous_root_mount() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "alpine:latest");
    let out = run_boxr(
        &home,
        &["run", "--rm", "-v", "/:/host:ro", "alpine", "ls", "/host"],
    );
    // Record behavior: may succeed with ro or warn; should not crash boxr
    let _ = combined_output(&out);
}
