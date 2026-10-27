//! Podman-compatible black-box parity (P0): exists, compose service, kube, specgen, quadlet, checkpoint, volume, artifact.

#[path = "common/blackbox.rs"]
mod blackbox;

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tempfile::tempdir;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/podman")
        .join(name)
}

fn compose_replacement_stack() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/compose/docker-replacement-stack/docker-compose.yml")
}

#[test]
fn test_podman_regression_contract_strings() {
    let cli_rs = include_str!("../src/cli/image.rs");
    assert!(cli_rs.contains("pub services: Vec<String>"));
    let compose_mod = include_str!("../src/compose/mod.rs");
    assert!(compose_mod.contains("interpolate::interpolate_yaml"));
    let net_mod = include_str!("../src/network/mod.rs");
    assert!(net_mod.contains("refresh_bridge_hosts_for_network"));
    let lib_rs = include_str!("../src/lib.rs");
    assert!(lib_rs.contains("reload_container_networks"));
}

#[test]
fn test_exists_exit_codes() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted");
        return;
    }
    let bin = blackbox::boxr_bin();
    if !bin.exists() {
        return;
    }
    let (_guard, home) = blackbox::isolated_home();

    let missing = Command::new(&bin)
        .env("BOXR_HOME", home.as_path())
        .args(["container", "exists", "definitely-missing-container"])
        .status()
        .unwrap();
    assert!(!missing.success());

    blackbox::pull_if_needed(&home, "alpine:latest");
    let name = format!("exists-{}", blackbox::rand_suffix());
    let run = blackbox::run_boxr(
        &home,
        &[
            "run",
            "-d",
            "--name",
            &name,
            "alpine:latest",
            "sleep",
            "120",
        ],
    );
    assert!(run.status.success());

    let present = Command::new(&bin)
        .env("BOXR_HOME", home.as_path())
        .args(["container", "exists", &name])
        .status()
        .unwrap();
    assert!(present.success());

    let _ = blackbox::run_boxr(&home, &["rm", "-f", &name]);
}

#[test]
fn test_volume_exists_and_network_exists() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted");
        return;
    }
    let bin = blackbox::boxr_bin();
    if !bin.exists() {
        return;
    }
    let (_guard, home) = blackbox::isolated_home();
    let vol = format!("vol-{}", blackbox::rand_suffix());
    assert!(
        blackbox::run_boxr(&home, &["volume", "create", &vol])
            .status
            .success()
    );
    assert!(
        Command::new(&bin)
            .env("BOXR_HOME", home.as_path())
            .args(["volume", "exists", &vol])
            .status()
            .unwrap()
            .success()
    );
    let _ = blackbox::run_boxr(&home, &["volume", "rm", &vol]);
}

#[test]
fn test_compose_up_service_target() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted");
        return;
    }
    let bin = blackbox::boxr_bin();
    if !bin.exists() {
        return;
    }
    let (_guard, home) = blackbox::isolated_home();
    blackbox::pull_if_needed(&home, "alpine:3.20");
    blackbox::pull_if_needed(&home, "nginx:alpine");
    blackbox::pull_if_needed(&home, "postgres:16-alpine");

    let compose = compose_replacement_stack();
    let out = blackbox::run_boxr(
        &home,
        &[
            "compose",
            "-f",
            compose.to_str().unwrap(),
            "up",
            "-d",
            "web",
        ],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("unexpected argument"), "{}", stderr);
    assert!(out.status.success(), "{}", stderr);
    let _ = blackbox::run_boxr(
        &home,
        &["compose", "-f", compose.to_str().unwrap(), "down", "-v"],
    );
}

#[test]
fn test_play_kube_minimal_pod() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted");
        return;
    }
    let bin = blackbox::boxr_bin();
    if !bin.exists() {
        return;
    }
    let (_guard, home) = blackbox::isolated_home();
    blackbox::pull_if_needed(&home, "alpine:3.20");
    let yaml = fixture("minimal-pod.yaml");
    let up = blackbox::run_boxr(&home, &["play", "kube", yaml.to_str().unwrap()]);
    assert!(
        up.status.success(),
        "{}",
        String::from_utf8_lossy(&up.stderr)
    );
    let down = blackbox::run_boxr(&home, &["play", "kube", "--down", yaml.to_str().unwrap()]);
    assert!(down.status.success());
}

#[test]
fn test_generate_spec_json_smoke() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted");
        return;
    }
    let bin = blackbox::boxr_bin();
    if !bin.exists() {
        return;
    }
    let (_guard, home) = blackbox::isolated_home();
    blackbox::pull_if_needed(&home, "alpine:latest");
    let name = format!("spec-{}", blackbox::rand_suffix());
    assert!(
        blackbox::run_boxr(
            &home,
            &["run", "-d", "--name", &name, "alpine:latest", "sleep", "60"],
        )
        .status
        .success()
    );
    let out = blackbox::run_boxr(&home, &["generate", "spec", &name]);
    assert!(out.status.success());
    let body = String::from_utf8_lossy(&out.stdout);
    assert!(body.contains("\"name\""));
    assert!(body.contains("alpine"));
    let _ = blackbox::run_boxr(&home, &["rm", "-f", &name]);
}

#[test]
fn test_quadlet_install_and_print() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted");
        return;
    }
    let bin = blackbox::boxr_bin();
    if !bin.exists() {
        return;
    }
    let (_guard, home) = blackbox::isolated_home();
    let sample = fixture("sample.container");
    let install = blackbox::run_boxr(&home, &["quadlet", "install", sample.to_str().unwrap()]);
    assert!(install.status.success());
    let print = blackbox::run_boxr(&home, &["quadlet", "print", "sample.container"]);
    assert!(print.status.success());
    let body = String::from_utf8_lossy(&print.stdout);
    assert!(body.contains("Container") || body.contains("alpine"));
}

#[test]
fn test_checkpoint_restore_metadata_roundtrip() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted");
        return;
    }
    let bin = blackbox::boxr_bin();
    if !bin.exists() {
        return;
    }
    let (_guard, home) = blackbox::isolated_home();
    blackbox::pull_if_needed(&home, "alpine:latest");
    let name = format!("cp-{}", blackbox::rand_suffix());
    assert!(
        blackbox::run_boxr(
            &home,
            &[
                "run",
                "-d",
                "--name",
                &name,
                "alpine:latest",
                "sleep",
                "300"
            ],
        )
        .status
        .success()
    );
    let cp = blackbox::run_boxr(&home, &["container", "checkpoint", &name]);
    assert!(
        cp.status.success(),
        "{}",
        String::from_utf8_lossy(&cp.stderr)
    );
    let _ = blackbox::run_boxr(&home, &["stop", &name]);
    let restore = blackbox::run_boxr(&home, &["container", "restore", &name]);
    assert!(
        restore.status.success(),
        "{}",
        String::from_utf8_lossy(&restore.stderr)
    );
    let _ = blackbox::run_boxr(&home, &["rm", "-f", &name]);
}

#[test]
fn test_volume_export_import_roundtrip() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted");
        return;
    }
    let bin = blackbox::boxr_bin();
    if !bin.exists() {
        return;
    }
    let (_guard, home) = blackbox::isolated_home();
    let vol = format!("vex-{}", blackbox::rand_suffix());
    let vol2 = format!("vim-{}", blackbox::rand_suffix());
    assert!(
        blackbox::run_boxr(&home, &["volume", "create", &vol])
            .status
            .success()
    );
    let temp = tempdir().unwrap();
    let archive = temp.path().join("vol.tar");
    let export = blackbox::run_boxr(
        &home,
        &["volume", "export", &vol, "-o", archive.to_str().unwrap()],
    );
    assert!(
        export.status.success(),
        "{}",
        String::from_utf8_lossy(&export.stderr)
    );
    let import = blackbox::run_boxr(
        &home,
        &["volume", "import", &vol2, archive.to_str().unwrap()],
    );
    assert!(
        import.status.success(),
        "{}",
        String::from_utf8_lossy(&import.stderr)
    );
    let _ = blackbox::run_boxr(&home, &["volume", "rm", &vol]);
    let _ = blackbox::run_boxr(&home, &["volume", "rm", &vol2]);
}

#[test]
fn test_artifact_add_ls_rm() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted");
        return;
    }
    let bin = blackbox::boxr_bin();
    if !bin.exists() {
        return;
    }
    let (_guard, home) = blackbox::isolated_home();
    let temp = tempdir().unwrap();
    let blob = temp.path().join("data.bin");
    fs::write(&blob, b"artifact-parity").unwrap();
    let name = format!("art-{}", blackbox::rand_suffix());
    let add = blackbox::run_boxr(
        &home,
        &[
            "artifact",
            "add",
            &name,
            blob.to_str().unwrap(),
            "--type",
            "application/octet-stream",
        ],
    );
    assert!(
        add.status.success(),
        "{}",
        String::from_utf8_lossy(&add.stderr)
    );
    let ls = blackbox::run_boxr(&home, &["artifact", "ls"]);
    assert!(ls.status.success());
    assert!(String::from_utf8_lossy(&ls.stdout).contains(&name));
    let rm = blackbox::run_boxr(&home, &["artifact", "rm", &name]);
    assert!(rm.status.success());
}

#[test]
fn test_pod_lifecycle_smoke() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted");
        return;
    }
    let bin = blackbox::boxr_bin();
    if !bin.exists() {
        return;
    }
    let (_guard, home) = blackbox::isolated_home();
    blackbox::pull_if_needed(&home, "alpine:latest");
    let pod = format!("pod-{}", blackbox::rand_suffix());
    assert!(
        blackbox::run_boxr(&home, &["pod", "create", "--name", &pod])
            .status
            .success()
    );
    let cname = format!("{}-c1", pod);
    assert!(
        blackbox::run_boxr(
            &home,
            &[
                "run",
                "-d",
                "--pod",
                &pod,
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
    let ps = blackbox::run_boxr(&home, &["pod", "ps"]);
    assert!(ps.status.success());
    assert!(String::from_utf8_lossy(&ps.stdout).contains(&pod));
    let _ = blackbox::run_boxr(&home, &["pod", "rm", "-f", &pod]);
}

#[test]
fn test_machine_linux_returns_clear_error() {
    if cfg!(target_os = "macos") {
        eprintln!("SKIPPED: Linux-only machine n/a test");
        return;
    }
    let bin = blackbox::boxr_bin();
    if !bin.exists() {
        return;
    }
    let out = Command::new(&bin)
        .args(["machine", "start"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.to_lowercase().contains("linux")
            || combined.to_lowercase().contains("not available")
            || combined.to_lowercase().contains("rootless"),
        "expected Podman-aligned machine error, got: {}",
        combined
    );
}

#[test]
fn test_farm_create_list_remove() {
    let bin = blackbox::boxr_bin();
    if !bin.exists() {
        return;
    }
    let (_guard, home) = blackbox::isolated_home();
    let farm = format!("farm-{}", blackbox::rand_suffix());
    let create = blackbox::run_boxr(&home, &["farm", "create", &farm, "node-a", "node-b"]);
    assert!(
        create.status.success(),
        "{}",
        String::from_utf8_lossy(&create.stderr)
    );
    let ls = blackbox::run_boxr(&home, &["farm", "ls"]);
    assert!(ls.status.success());
    let out = String::from_utf8_lossy(&ls.stdout);
    assert!(out.contains(&farm));
    let rm = blackbox::run_boxr(&home, &["farm", "rm", &farm]);
    assert!(rm.status.success());
}

#[test]
fn test_auto_update_dry_run_exits_zero() {
    let bin = blackbox::boxr_bin();
    if !bin.exists() {
        return;
    }
    let out = Command::new(&bin)
        .args(["auto-update", "--dry-run"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn test_system_connection_list() {
    let bin = blackbox::boxr_bin();
    if !bin.exists() {
        return;
    }
    let out = Command::new(&bin)
        .args(["system", "connection", "ls"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(combined.contains("local") || combined.contains("NAME"));
}

#[test]
fn test_network_reload_after_connect() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted");
        return;
    }
    let bin = blackbox::boxr_bin();
    if !bin.exists() {
        return;
    }
    let (_guard, home) = blackbox::isolated_home();
    blackbox::pull_if_needed(&home, "alpine:latest");
    let net = format!("net-{}", blackbox::rand_suffix());
    let cname = format!("c-{}", blackbox::rand_suffix());
    assert!(
        blackbox::run_boxr(&home, &["network", "create", &net])
            .status
            .success()
    );
    assert!(
        blackbox::run_boxr(
            &home,
            &[
                "run",
                "-d",
                "--name",
                &cname,
                "alpine:latest",
                "sleep",
                "120"
            ],
        )
        .status
        .success()
    );
    let connect = blackbox::run_boxr(&home, &["network", "connect", &net, &cname]);
    assert!(connect.status.success());
    let reload = blackbox::run_boxr(&home, &["network", "reload", &cname]);
    assert!(
        reload.status.success(),
        "{}",
        String::from_utf8_lossy(&reload.stderr)
    );
    let _ = blackbox::run_boxr(&home, &["rm", "-f", &cname]);
    let _ = blackbox::run_boxr(&home, &["network", "rm", &net]);
}
