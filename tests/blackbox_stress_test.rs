#[path = "common/blackbox.rs"]
mod blackbox;

use blackbox::*;
use std::time::Duration;

#[test]
#[ignore]
fn test_j_concurrent_runs() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "alpine:latest");
    let mut children = Vec::new();
    for i in 0..5 {
        let name = format!("bb-conc-{}-{}", rand_suffix(), i);
        let out = run_boxr_ok(
            &home,
            &["run", "-d", "--name", &name, "alpine", "sleep", "15"],
        );
        assert!(!out.trim().is_empty());
        children.push(name);
    }
    let ps = run_boxr_ok(&home, &["ps", "-a"]);
    for name in &children {
        assert!(ps.contains(name.as_str()));
        cleanup_container(&home, name);
    }
}

#[test]
#[ignore]
fn test_j_rapid_restart_nginx() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "nginx:alpine");
    let ctr = format!("bb-rapid-{}", rand_suffix());
    let port = 19700 + ctr.len() as u16;
    run_boxr_ok(
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
    );
    for _ in 0..3 {
        run_boxr_ok(&home, &["restart", &ctr]);
        std::thread::sleep(Duration::from_secs(1));
    }
    cleanup_container(&home, &ctr);
}
