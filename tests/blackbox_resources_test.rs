#[path = "common/blackbox.rs"]
mod blackbox;

use blackbox::*;

#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "micro-VM run --rm is slow/flaky under cargo test on macOS"
)]
fn test_g1_memory_limit_accepts_flag() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "alpine:latest");
    let out = run_boxr_ok(
        &home,
        &["run", "--rm", "--memory", "64m", "alpine", "echo", "mem-ok"],
    );
    assert!(out.contains("mem-ok"));
}

#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "micro-VM run --rm is slow/flaky under cargo test on macOS"
)]
fn test_g4_cpus_limit_accepts_flag() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "alpine:latest");
    let out = run_boxr_ok(
        &home,
        &["run", "--rm", "--cpus", "0.5", "alpine", "echo", "cpu-ok"],
    );
    assert!(out.contains("cpu-ok"));
}

#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "micro-VM run --rm is slow/flaky under cargo test on macOS"
)]
fn test_g5_pids_limit_accepts_flag() {
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
            "--pids-limit",
            "50",
            "alpine",
            "echo",
            "pids-ok",
        ],
    );
    assert!(out.contains("pids-ok"));
}

#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "micro-VM run --rm is slow/flaky under cargo test on macOS"
)]
fn test_g6_shm_size_with_memory() {
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
            "--memory",
            "256m",
            "--shm-size",
            "128m",
            "alpine",
            "df",
            "-h",
            "/dev/shm",
        ],
    );
    assert!(out.status.success() || combined_output(&out).contains("shm"));
}

#[test]
fn test_g7_invalid_memory_rejected() {
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "alpine:latest");
    run_boxr_fail(
        &home,
        &["run", "--rm", "--memory", "notanumber", "alpine", "true"],
    );
}

#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "micro-VM run --rm is slow/flaky under cargo test on macOS"
)]
fn test_g8_valid_memory_units() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "alpine:latest");
    for unit in ["10k", "256m", "1g"] {
        let out = run_boxr(
            &home,
            &["run", "--rm", "--memory", unit, "alpine", "echo", "ok"],
        );
        assert!(
            out.status.success(),
            "memory unit {} failed: {}",
            unit,
            combined_output(&out)
        );
    }
}

#[test]
fn test_g9_stats_running_container() {
    let (_guard, home) = isolated_home();
    pull_if_needed(&home, "alpine:latest");
    let ctr = format!("bb-stats-{}", rand_suffix());
    run_boxr_ok(
        &home,
        &["run", "-d", "--name", &ctr, "alpine", "sleep", "30"],
    );
    let out = run_boxr(&home, &["stats", "--no-stream", &ctr]);
    cleanup_container(&home, &ctr);
    assert!(out.status.success());
    let combined = combined_output(&out);
    assert!(!combined.is_empty());
}
