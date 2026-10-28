//! Podman upstream-aligned parity tests.
//!
//! Each test maps to one or more files under podman's `test/e2e/` (see docs/PODMAN_TEST_MAPPING.md).
//! These are behavioral smokes for boxr scope — not a fork of Podman's Ginkgo suite.

#[path = "common/blackbox.rs"]
mod blackbox;

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use tempfile::TempDir;
use tempfile::tempdir;

struct HomeCtx {
    _guard: TempDir,
    home: PathBuf,
}

fn home_ctx() -> Option<HomeCtx> {
    if !blackbox::boxr_bin().exists() {
        eprintln!("SKIPPED: boxr binary not built");
        return None;
    }
    let (_guard, home) = blackbox::isolated_home();
    Some(HomeCtx { _guard, home })
}

fn runtime_ctx() -> Option<HomeCtx> {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted");
        return None;
    }
    home_ctx()
}

/// `test/e2e/secret_test.go`, `exists_test.go`
#[test]
fn test_secret_lifecycle() {
    let Some(ctx) = home_ctx() else {
        return;
    };
    let home = &ctx.home;
    let temp = tempdir().unwrap();
    let secret_file = temp.path().join("pw.txt");
    fs::write(&secret_file, b"super-secret").unwrap();
    let name = format!("sec-{}", blackbox::rand_suffix());

    let create = blackbox::run_boxr(
        home,
        &[
            "secret",
            "create",
            "--name",
            &name,
            "-f",
            secret_file.to_str().unwrap(),
        ],
    );
    assert!(
        create.status.success(),
        "{}",
        String::from_utf8_lossy(&create.stderr)
    );

    let bin = blackbox::boxr_bin();
    assert!(
        Command::new(&bin)
            .env("BOXR_HOME", home)
            .args(["secret", "exists", &name])
            .status()
            .unwrap()
            .success()
    );

    let ls = blackbox::run_boxr(home, &["secret", "ls"]);
    assert!(ls.status.success());
    assert!(String::from_utf8_lossy(&ls.stdout).contains(&name));

    let rm = blackbox::run_boxr(home, &["secret", "rm", &name]);
    assert!(rm.status.success());
    let missing = Command::new(&bin)
        .env("BOXR_HOME", home)
        .args(["secret", "exists", &name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(!missing.success());
}

/// `test/e2e/exists_test.go` (pod)
#[test]
fn test_pod_exists_exit_codes() {
    let Some(ctx) = home_ctx() else {
        return;
    };
    let home = &ctx.home;
    let bin = blackbox::boxr_bin();

    assert!(
        !Command::new(&bin)
            .env("BOXR_HOME", home)
            .args(["pod", "exists", "missing-pod-parity"])
            .status()
            .unwrap()
            .success()
    );

    let pod = format!("pod-ex-{}", blackbox::rand_suffix());
    assert!(
        blackbox::run_boxr(home, &["pod", "create", "--name", &pod])
            .status
            .success()
    );
    assert!(
        Command::new(&bin)
            .env("BOXR_HOME", home)
            .args(["pod", "exists", &pod])
            .status()
            .unwrap()
            .success()
    );
    let _ = blackbox::run_boxr(home, &["pod", "rm", "-f", &pod]);
}

/// `test/e2e/exists_test.go` (image) — complements blackbox K7
#[test]
fn test_image_exists_after_pull() {
    let Some(ctx) = home_ctx() else {
        return;
    };
    let home = &ctx.home;
    let bin = blackbox::boxr_bin();
    blackbox::pull_if_needed(home, "alpine:3.20");
    assert!(
        Command::new(&bin)
            .env("BOXR_HOME", home)
            .args(["image", "exists", "alpine:3.20"])
            .status()
            .unwrap()
            .success()
    );
}

fn pod_with_sleeping_container(home: &std::path::Path) -> (String, String) {
    blackbox::pull_if_needed(home, "alpine:latest");
    let pod = format!("pod-{}", blackbox::rand_suffix());
    assert!(
        blackbox::run_boxr(home, &["pod", "create", "--name", &pod])
            .status
            .success()
    );
    let cname = format!("{}-wk", pod);
    assert!(
        blackbox::run_boxr(
            home,
            &[
                "run",
                "-d",
                "--pod",
                &pod,
                "--name",
                &cname,
                "alpine:latest",
                "sleep",
                "300",
            ],
        )
        .status
        .success()
    );
    (pod, cname)
}

/// `test/e2e/pod_pause_test.go`
#[test]
fn test_pod_pause_unpause() {
    let Some(ctx) = runtime_ctx() else {
        return;
    };
    let home = &ctx.home;
    let (pod, _cname) = pod_with_sleeping_container(home);

    let pause = blackbox::run_boxr(home, &["pod", "pause", &pod]);
    assert!(
        pause.status.success(),
        "{}",
        String::from_utf8_lossy(&pause.stderr)
    );
    let inspect = blackbox::run_boxr(home, &["pod", "inspect", &pod]);
    assert!(inspect.status.success());
    assert!(String::from_utf8_lossy(&inspect.stdout).contains("Paused"));

    let unpause = blackbox::run_boxr(home, &["pod", "unpause", &pod]);
    assert!(unpause.status.success());
    let _ = blackbox::run_boxr(home, &["pod", "rm", "-f", &pod]);
}

/// `test/e2e/pod_stop_test.go`, `pod_start_test.go`, `pod_restart_test.go`
#[test]
fn test_pod_stop_start_restart() {
    let Some(ctx) = runtime_ctx() else {
        return;
    };
    let home = &ctx.home;
    let (pod, _cname) = pod_with_sleeping_container(home);

    assert!(
        blackbox::run_boxr(home, &["pod", "stop", &pod])
            .status
            .success()
    );
    assert!(
        blackbox::run_boxr(home, &["pod", "start", &pod])
            .status
            .success()
    );
    assert!(
        blackbox::run_boxr(home, &["pod", "restart", &pod])
            .status
            .success()
    );
    let _ = blackbox::run_boxr(home, &["pod", "rm", "-f", &pod]);
}

/// `test/e2e/pod_inspect_test.go`
#[test]
fn test_pod_inspect_json() {
    let Some(ctx) = runtime_ctx() else {
        return;
    };
    let home = &ctx.home;
    let (pod, _cname) = pod_with_sleeping_container(home);
    let out = blackbox::run_boxr(home, &["pod", "inspect", &pod]);
    assert!(out.status.success());
    let body = String::from_utf8_lossy(&out.stdout);
    assert!(body.contains("\"Name\""));
    assert!(body.contains(&pod));
    let _ = blackbox::run_boxr(home, &["pod", "rm", "-f", &pod]);
}

/// `test/e2e/pod_stats_test.go`
#[test]
fn test_pod_stats_no_stream() {
    let Some(ctx) = runtime_ctx() else {
        return;
    };
    let home = &ctx.home;
    let (pod, _cname) = pod_with_sleeping_container(home);
    let stats = blackbox::run_boxr(home, &["pod", "stats", "--no-stream", &pod]);
    assert!(
        stats.status.success(),
        "{}",
        String::from_utf8_lossy(&stats.stderr)
    );
    let _ = blackbox::run_boxr(home, &["pod", "rm", "-f", &pod]);
}

/// `test/e2e/pod_prune_test.go`
#[test]
fn test_pod_prune_removes_stopped_pod() {
    let Some(ctx) = runtime_ctx() else {
        return;
    };
    let home = &ctx.home;
    let (pod, _cname) = pod_with_sleeping_container(home);
    assert!(
        blackbox::run_boxr(home, &["pod", "stop", &pod])
            .status
            .success()
    );
    let prune = blackbox::run_boxr(home, &["pod", "prune", "-f"]);
    assert!(prune.status.success());
    assert!(
        !Command::new(blackbox::boxr_bin())
            .env("BOXR_HOME", home)
            .args(["pod", "exists", &pod])
            .status()
            .unwrap()
            .success()
    );
}

/// `test/e2e/pod_clone_test.go`
#[test]
fn test_pod_clone_metadata() {
    let Some(ctx) = runtime_ctx() else {
        return;
    };
    let home = &ctx.home;
    let (source, _cname) = pod_with_sleeping_container(home);
    let target = format!("{}-clone", source);
    let clone = blackbox::run_boxr(home, &["pod", "clone", &source, &target]);
    assert!(
        clone.status.success(),
        "{}",
        String::from_utf8_lossy(&clone.stderr)
    );
    assert!(
        Command::new(blackbox::boxr_bin())
            .env("BOXR_HOME", home)
            .args(["pod", "exists", &target])
            .status()
            .unwrap()
            .success()
    );
    let _ = blackbox::run_boxr(home, &["pod", "rm", "-f", &source, &target]);
}

/// `test/e2e/generate_kube_test.go`
#[test]
fn test_generate_kube_from_running_pod() {
    let Some(ctx) = runtime_ctx() else {
        return;
    };
    let home = &ctx.home;
    let (pod, _cname) = pod_with_sleeping_container(home);
    let out = blackbox::run_boxr(home, &["generate", "kube", &pod]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let yaml = String::from_utf8_lossy(&out.stdout);
    assert!(yaml.contains("kind: Pod") || yaml.contains("kind: pod"));
    assert!(yaml.contains("alpine"));
    let _ = blackbox::run_boxr(home, &["pod", "rm", "-f", &pod]);
}

/// `test/e2e/generate_systemd_test.go`
#[test]
fn test_generate_systemd_stdout() {
    let Some(ctx) = runtime_ctx() else {
        return;
    };
    let home = &ctx.home;
    blackbox::pull_if_needed(home, "alpine:latest");
    let name = format!("sysd-{}", blackbox::rand_suffix());
    assert!(
        blackbox::run_boxr(
            home,
            &[
                "run",
                "-d",
                "--name",
                &name,
                "alpine:latest",
                "sleep",
                "120"
            ],
        )
        .status
        .success()
    );
    let out = blackbox::run_boxr(home, &["generate", "systemd", &name]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let unit = String::from_utf8_lossy(&out.stdout);
    assert!(unit.contains("[Container]") || unit.contains("Image="));
    let _ = blackbox::run_boxr(home, &["rm", "-f", &name]);
}

/// `test/e2e/pod_top_test.go`
#[test]
fn test_pod_top_lists_processes() {
    let Some(ctx) = runtime_ctx() else {
        return;
    };
    let home = &ctx.home;
    let (pod, _cname) = pod_with_sleeping_container(home);
    let top = blackbox::run_boxr(home, &["pod", "top", &pod]);
    assert!(
        top.status.success(),
        "{}",
        String::from_utf8_lossy(&top.stderr)
    );
    let _ = blackbox::run_boxr(home, &["pod", "rm", "-f", &pod]);
}

/// `test/e2e/logs_test.go` (pod members)
#[test]
fn test_pod_logs_smoke() {
    let Some(ctx) = runtime_ctx() else {
        return;
    };
    let home = &ctx.home;
    let (pod, _cname) = pod_with_sleeping_container(home);
    let logs = blackbox::run_boxr(home, &["pod", "logs", &pod]);
    assert!(
        logs.status.success(),
        "{}",
        String::from_utf8_lossy(&logs.stderr)
    );
    let _ = blackbox::run_boxr(home, &["pod", "rm", "-f", &pod]);
}

/// `test/e2e/network_connect_disconnect_test.go`
#[test]
fn test_network_connect_disconnect() {
    let Some(ctx) = runtime_ctx() else {
        return;
    };
    let home = &ctx.home;
    blackbox::pull_if_needed(home, "alpine:latest");
    let net = format!("nd-{}", blackbox::rand_suffix());
    let cname = format!("ndc-{}", blackbox::rand_suffix());
    assert!(
        blackbox::run_boxr(home, &["network", "create", &net])
            .status
            .success()
    );
    assert!(
        blackbox::run_boxr(
            home,
            &[
                "run",
                "-d",
                "--name",
                &cname,
                "alpine:latest",
                "sleep",
                "120",
            ],
        )
        .status
        .success()
    );
    assert!(
        blackbox::run_boxr(home, &["network", "connect", &net, &cname])
            .status
            .success()
    );
    let disconnect = blackbox::run_boxr(home, &["network", "disconnect", &net, &cname]);
    assert!(
        disconnect.status.success(),
        "{}",
        String::from_utf8_lossy(&disconnect.stderr)
    );
    let _ = blackbox::run_boxr(home, &["rm", "-f", &cname]);
    let _ = blackbox::run_boxr(home, &["network", "rm", &net]);
}

/// `test/e2e/volume_rename_test.go`, BATS `160-volumes.bats`
#[test]
fn test_volume_rename_updates_store() {
    let Some(ctx) = home_ctx() else {
        return;
    };
    let home = &ctx.home;
    let bin = blackbox::boxr_bin();
    let old = format!("vol-old-{}", blackbox::rand_suffix());
    let new = format!("vol-new-{}", blackbox::rand_suffix());
    assert!(
        blackbox::run_boxr(home, &["volume", "create", &old])
            .status
            .success()
    );
    let rename = blackbox::run_boxr(home, &["volume", "rename", &old, &new]);
    assert!(
        rename.status.success(),
        "{}",
        String::from_utf8_lossy(&rename.stderr)
    );
    assert!(
        Command::new(&bin)
            .env("BOXR_HOME", home)
            .args(["volume", "exists", &new])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        !Command::new(&bin)
            .env("BOXR_HOME", home)
            .args(["volume", "exists", &old])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    let _ = blackbox::run_boxr(home, &["volume", "rm", &new]);
}

/// `test/e2e/container_clone_test.go`
#[test]
fn test_container_clone_created_state() {
    let Some(ctx) = home_ctx() else {
        return;
    };
    let home = &ctx.home;
    let bin = blackbox::boxr_bin();
    blackbox::pull_if_needed(home, "alpine:latest");
    let src = format!("clone-src-{}", blackbox::rand_suffix());
    let dst = format!("clone-dst-{}", blackbox::rand_suffix());
    assert!(
        blackbox::run_boxr(
            home,
            &["create", "--name", &src, "alpine:latest", "sleep", "999"],
        )
        .status
        .success()
    );
    let clone = blackbox::run_boxr(home, &["container", "clone", &src, &dst]);
    assert!(
        clone.status.success(),
        "{}",
        String::from_utf8_lossy(&clone.stderr)
    );
    assert!(
        Command::new(&bin)
            .env("BOXR_HOME", home)
            .args(["container", "exists", &dst])
            .status()
            .unwrap()
            .success()
    );
    let inspect = blackbox::run_boxr(home, &["inspect", &dst, "--format", "{{.Config.Image}}"]);
    assert!(inspect.status.success());
    assert!(String::from_utf8_lossy(&inspect.stdout).contains("alpine"));
    let _ = blackbox::run_boxr(home, &["rm", "-f", &src, &dst]);
}

/// `test/e2e/container_clone_test.go` (`--run`)
#[test]
fn test_container_clone_run_starts_target() {
    let Some(ctx) = runtime_ctx() else {
        return;
    };
    let home = &ctx.home;
    let bin = blackbox::boxr_bin();
    blackbox::pull_if_needed(home, "alpine:latest");
    let src = format!("clone-run-src-{}", blackbox::rand_suffix());
    let dst = format!("clone-run-dst-{}", blackbox::rand_suffix());
    assert!(
        blackbox::run_boxr(
            home,
            &["run", "-d", "--name", &src, "alpine:latest", "sleep", "300",],
        )
        .status
        .success()
    );
    let clone = blackbox::run_boxr(home, &["container", "clone", "--run", &src, &dst]);
    assert!(
        clone.status.success(),
        "{}",
        String::from_utf8_lossy(&clone.stderr)
    );
    let ps = blackbox::run_boxr(home, &["ps", "--filter", &format!("name={}", dst), "-q"]);
    assert!(ps.status.success());
    assert!(!String::from_utf8_lossy(&ps.stdout).trim().is_empty());
    assert!(
        Command::new(&bin)
            .env("BOXR_HOME", home)
            .args(["container", "exists", &dst])
            .status()
            .unwrap()
            .success()
    );
    let _ = blackbox::run_boxr(home, &["rm", "-f", &src, &dst]);
}

/// `test/e2e/unshare_test.go`, BATS `170-run-userns.bats` (rootless user namespace entry)
#[test]
fn test_unshare_runs_command_in_user_namespace() {
    let bin = blackbox::boxr_bin();
    if !bin.exists() {
        eprintln!("SKIPPED: boxr binary not built");
        return;
    }
    if !cfg!(target_os = "linux") {
        eprintln!("SKIPPED: unshare parity is Linux-first");
        return;
    }
    let out = Command::new(&bin)
        .args(["unshare", "/bin/sh", "-c", "echo boxr-unshare-ok"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout)
            .trim()
            .contains("boxr-unshare-ok")
    );
}
