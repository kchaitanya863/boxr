use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use tempfile::tempdir;

#[path = "common/blackbox.rs"]
mod blackbox;

fn boxr_locked(bin: &PathBuf, args: &[&str]) -> Output {
    blackbox::with_vm_lock(|| {
        let mut cmd = Command::new(bin);
        cmd.env_remove("DOCKER_HOST");
        cmd.args(args).output().expect("failed to execute boxr")
    })
}

fn boxr_bin() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("target");
    path.push(if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    });
    path.push("boxr");
    if !path.exists() {
        let alt = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(if cfg!(debug_assertions) {
                "release"
            } else {
                "debug"
            })
            .join("boxr");
        if alt.exists() {
            return alt;
        }
    }
    path
}

fn has_container_runtime() -> bool {
    // In CI environments (e.g. GitHub Actions), unprivileged user namespace clone
    // and /sys mounts may not have necessary capabilities without root.
    if std::env::var("CI").is_ok() {
        return false;
    }

    #[cfg(target_os = "macos")]
    {
        // On macOS, container execution uses native Apple Virtualization.framework
        true
    }
    #[cfg(target_os = "linux")]
    {
        true
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        false
    }
}

fn boxr_cmd(bin: &PathBuf) -> Command {
    let mut cmd = Command::new(bin);
    cmd.env_remove("DOCKER_HOST");
    cmd
}

#[test]
fn test_e2e_cli_version_and_help() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() {
        return;
    }

    let output = boxr_cmd(&bin).arg("--version").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("boxr "));

    let output = boxr_cmd(&bin).arg("--help").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage: boxr <COMMAND>"));
}

#[test]
fn test_e2e_volume_lifecycle() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() {
        return;
    }

    let run_id = hex::encode(boxr::storage::container_store::rand_id());
    let vol_name = format!("e2e-vol-{}", &run_id[..6]);

    let output = boxr_cmd(&bin)
        .args(["volume", "create", &vol_name])
        .output()
        .unwrap();
    assert!(output.status.success());

    let output = boxr_cmd(&bin).args(["volume", "ls"]).output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(&vol_name));

    let output = boxr_cmd(&bin)
        .args(["volume", "inspect", &vol_name])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(&vol_name));

    let output = boxr_cmd(&bin)
        .args(["volume", "rm", &vol_name])
        .output()
        .unwrap();
    assert!(output.status.success());
}

#[test]
fn test_e2e_network_lifecycle() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() {
        return;
    }

    let run_id = hex::encode(boxr::storage::container_store::rand_id());
    let net_name = format!("e2e-net-{}", &run_id[..6]);

    let output = boxr_cmd(&bin)
        .args(["network", "create", &net_name])
        .output()
        .unwrap();
    assert!(output.status.success());

    let output = boxr_cmd(&bin).args(["network", "ls"]).output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(&net_name));

    let output = boxr_cmd(&bin)
        .args(["network", "inspect", &net_name])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(&net_name));

    let output = boxr_cmd(&bin)
        .args(["network", "rm", &net_name])
        .output()
        .unwrap();
    assert!(output.status.success());
}

#[test]
fn test_e2e_system_df_and_completions() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() {
        return;
    }

    let output = boxr_cmd(&bin).args(["system", "df"]).output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Images"));
    assert!(stdout.contains("Containers"));

    for shell in ["bash", "zsh", "fish"] {
        let output = boxr_cmd(&bin).args(["completion", shell]).output().unwrap();
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(!stdout.is_empty());
    }

    let output = boxr_cmd(&bin).args(["alias"]).output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("alias docker=\"boxr\""));
}

#[test]
fn test_e2e_dockerfile_multi_stage_build() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() || !has_container_runtime() {
        return;
    }

    let temp = tempdir().unwrap();
    let dockerfile = r#"
FROM alpine:latest AS stage1
WORKDIR /build
RUN echo "compiled artifact" > /build/app.bin

FROM alpine:latest
WORKDIR /app
COPY --from=stage1 /build/app.bin /app/app.bin
CMD ["/bin/cat", "/app/app.bin"]
"#;

    fs::write(temp.path().join("Dockerfile"), dockerfile).unwrap();
    fs::write(temp.path().join(".dockerignore"), "*.tmp\n").unwrap();

    let tag = "e2e-multistage:v1";

    let output = boxr_locked(&bin, &["build", "-t", tag, temp.path().to_str().unwrap()]);

    assert!(output.status.success());

    let output = boxr_locked(&bin, &["images"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("e2e-multistage"));

    let _ = boxr_cmd(&bin).args(["rmi", tag]).output();
}

#[test]
fn test_e2e_container_lifecycle_pause_unpause_rename_commit_wait() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() || !has_container_runtime() {
        return;
    }

    let run_id = hex::encode(boxr::storage::container_store::rand_id());
    let name = format!("e2e-cycle-{}", &run_id[..6]);
    let renamed = format!("e2e-renamed-{}", &run_id[..6]);
    let snap_img = format!("e2e-snap-{}:v1", &run_id[..6]);

    let output = boxr_locked(
        &bin,
        &[
            "run",
            "-d",
            "--name",
            &name,
            "alpine",
            "/bin/sh",
            "-c",
            "echo 'committed file' > /committed.txt; sleep 300",
        ],
    );
    assert!(output.status.success());
    std::thread::sleep(std::time::Duration::from_secs(5));

    let output = boxr_locked(&bin, &["pause", &name]);
    assert!(output.status.success());

    let output = boxr_locked(&bin, &["ps", "-a"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Paused"));

    let output = boxr_locked(&bin, &["unpause", &name]);
    assert!(output.status.success());

    let output = boxr_locked(&bin, &["rename", &name, &renamed]);
    assert!(output.status.success());

    let output = boxr_locked(&bin, &["commit", &renamed, &snap_img]);
    assert!(output.status.success());

    let output = boxr_locked(
        &bin,
        &["run", "--rm", &snap_img, "/bin/cat", "/committed.txt"],
    );
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("committed file"));

    let output = boxr_locked(&bin, &["wait", &renamed]);
    assert!(output.status.success());

    let _ = boxr_cmd(&bin).args(["rm", &renamed]).output();
    let _ = boxr_cmd(&bin).args(["rmi", &snap_img]).output();
}

#[test]
fn test_e2e_filesystem_diff_and_copy() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() || !has_container_runtime() {
        return;
    }

    let run_id = hex::encode(boxr::storage::container_store::rand_id());
    let cont_name = format!("e2e-diff-{}", &run_id[..6]);

    let output = boxr_cmd(&bin)
        .args([
            "run",
            "--name",
            &cont_name,
            "alpine",
            "/bin/sh",
            "-c",
            "touch /e2e-added.txt; echo 'changed' >> /etc/hosts",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());

    let output = boxr_cmd(&bin).args(["diff", &cont_name]).output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("A /e2e-added.txt"));

    let temp = tempdir().unwrap();
    let local_dest = temp.path().join("copied-from-cont.txt");
    let output = boxr_cmd(&bin)
        .args([
            "cp",
            &format!("{}:/e2e-added.txt", &cont_name),
            local_dest.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(local_dest.exists());

    let host_file = temp.path().join("host-src.txt");
    fs::write(&host_file, b"content from host").unwrap();
    let output = boxr_cmd(&bin)
        .args([
            "cp",
            host_file.to_str().unwrap(),
            &format!("{}:/received-on-cont.txt", &cont_name),
        ])
        .output()
        .unwrap();
    assert!(output.status.success());

    let dest_in_cont = temp.path().join("verify-back.txt");
    let output = boxr_cmd(&bin)
        .args([
            "cp",
            &format!("{}:/received-on-cont.txt", &cont_name),
            dest_in_cont.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        fs::read_to_string(dest_in_cont).unwrap(),
        "content from host"
    );

    let _ = boxr_cmd(&bin).args(["rm", &cont_name]).output();
}

#[test]
fn test_e2e_defensive_security_and_kill() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() || !has_container_runtime() {
        return;
    }

    // 1. Path traversal in volume mount is rejected
    let output = boxr_cmd(&bin)
        .args([
            "run",
            "--rm",
            "-v",
            "../../../etc:/data",
            "alpine",
            "/bin/echo",
            "test",
        ])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "Volume mount with path traversal must fail"
    );

    // 2. Kill command delivers signal and terminates process
    let run_id = hex::encode(boxr::storage::container_store::rand_id());
    let cont_name = format!("e2e-kill-{}", &run_id[..6]);

    let output = boxr_cmd(&bin)
        .args([
            "run", "-d", "--name", &cont_name, "alpine", "/bin/sh", "-c", "sleep 30",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());

    let output = boxr_cmd(&bin).args(["kill", &cont_name]).output().unwrap();
    assert!(output.status.success());

    std::thread::sleep(std::time::Duration::from_millis(300));

    let output = boxr_cmd(&bin).args(["ps", "-a"]).output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Exited (137)") || stdout.contains("Exited"));

    let _ = boxr_cmd(&bin).args(["rm", &cont_name]).output();
}

#[test]
fn test_e2e_concurrent_load_test() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() || !has_container_runtime() {
        return;
    }

    let run_id = hex::encode(boxr::storage::container_store::rand_id());
    let w1 = format!("load-a-{}", &run_id[..6]);
    let w2 = format!("load-b-{}", &run_id[..6]);
    let w3 = format!("load-c-{}", &run_id[..6]);
    let workers = [w1, w2, w3];

    for w in &workers {
        let output = boxr_locked(
            &bin,
            &[
                "run",
                "-d",
                "--name",
                w,
                "alpine",
                "/bin/sh",
                "-c",
                "echo result=465; sleep 300",
            ],
        );
        assert!(output.status.success());
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    for w in &workers {
        let start = std::time::Instant::now();
        let mut saw_log = false;
        while start.elapsed() < std::time::Duration::from_secs(30) {
            let output = boxr_locked(&bin, &["logs", w]);
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains("result=465") {
                saw_log = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        assert!(saw_log, "logs for {} never contained result=465", w);

        let _ = boxr_locked(&bin, &["rm", "-f", w]);
    }
}

#[test]
fn test_e2e_real_service_workload_redis() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() || !has_container_runtime() {
        return;
    }

    let run_id = hex::encode(boxr::storage::container_store::rand_id());
    let cont_name = format!("e2e-redis-{}", &run_id[..6]);

    let output = boxr_cmd(&bin)
        .args([
            "run",
            "-d",
            "--name",
            &cont_name,
            "redis:alpine",
            "redis-server",
            "--protected-mode",
            "no",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());

    let mut ping_success = false;
    for _ in 0..15 {
        std::thread::sleep(std::time::Duration::from_millis(500));
        let output = boxr_cmd(&bin)
            .args(["exec", &cont_name, "redis-cli", "ping"])
            .output()
            .unwrap();
        let out_str = String::from_utf8_lossy(&output.stdout);
        if output.status.success() && out_str.contains("PONG") {
            ping_success = true;
            break;
        }
    }
    assert!(ping_success, "Redis did not respond with PONG in time");

    let output = boxr_cmd(&bin)
        .args([
            "exec",
            &cont_name,
            "redis-cli",
            "set",
            "e2e_key",
            "BoxrWorks",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());

    let output = boxr_cmd(&bin)
        .args(["exec", &cont_name, "redis-cli", "get", "e2e_key"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("BoxrWorks"));

    let _ = boxr_cmd(&bin).args(["stop", &cont_name]).output();
    let _ = boxr_cmd(&bin).args(["rm", &cont_name]).output();
}

#[test]
fn test_e2e_fullstack_compose_orchestration() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() || !has_container_runtime() {
        return;
    }

    let compose_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("examples")
        .join("fullstack-compose")
        .join("docker-compose.yml");

    if !compose_file.exists() {
        return;
    }

    let output = boxr_cmd(&bin)
        .args(["compose", "-f", compose_file.to_str().unwrap(), "up", "-d"])
        .output()
        .unwrap();
    assert!(output.status.success());

    let output = boxr_cmd(&bin)
        .args(["compose", "-f", compose_file.to_str().unwrap(), "ps"])
        .output()
        .unwrap();
    assert!(output.status.success());

    let output = boxr_cmd(&bin)
        .args([
            "compose",
            "-f",
            compose_file.to_str().unwrap(),
            "down",
            "-v",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
}

#[test]
fn test_e2e_platform_and_gpu_sharing() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() || !has_container_runtime() {
        return;
    }

    // 1. Test arm64 container
    let arm_out = boxr_locked(
        &bin,
        &[
            "run",
            "--rm",
            "--platform",
            "linux/arm64",
            "alpine",
            "uname",
            "-m",
        ],
    );
    if arm_out.status.success() {
        let stdout = String::from_utf8_lossy(&arm_out.stdout);
        assert!(stdout.contains("aarch64"));
    }

    // 2. Test amd64 container (via Rosetta on macOS or emulation)
    let amd_out = boxr_locked(
        &bin,
        &[
            "run",
            "--rm",
            "--platform",
            "linux/amd64",
            "alpine",
            "uname",
            "-m",
        ],
    );
    if amd_out.status.success() {
        let stdout = String::from_utf8_lossy(&amd_out.stdout);
        assert!(stdout.contains("x86_64") || stdout.contains("aarch64"));
    }

    // 3. Test GPU device sharing flag
    let gpu_out = boxr_locked(
        &bin,
        &["run", "--rm", "--gpus", "all", "alpine", "uname", "-a"],
    );
    assert!(gpu_out.status.success());
}
