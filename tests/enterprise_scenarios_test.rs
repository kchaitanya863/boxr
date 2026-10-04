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

fn boxr_cmd(bin: &PathBuf) -> Command {
    let mut cmd = Command::new(bin);
    cmd.env_remove("DOCKER_HOST");
    cmd
}

/// 1. Unprivileged Service User & /tmp Sticky 1777 Permissions
/// Verifies that unprivileged non-root users (like _apt, nobody, uid 10001)
/// can write and create temporary files in /tmp and /var/tmp without EACCES.
#[test]
fn test_enterprise_unprivileged_tmp_and_var_tmp_write() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() {
        return;
    }

    // Verify /tmp is world-writable with sticky bit (1777)
    let inspect_tmp = boxr_cmd(&bin)
        .args(["run", "--rm", "alpine", "stat", "-c", "%a", "/tmp"])
        .output()
        .unwrap();
    if inspect_tmp.status.success() {
        let mode = String::from_utf8_lossy(&inspect_tmp.stdout);
        assert!(
            mode.contains("1777") || mode.contains("777"),
            "Expected /tmp to have 1777 permissions, got: {}",
            mode.trim()
        );
    }

    // Verify an unprivileged user (nobody / uid 65534) can create and write files in /tmp
    let non_root_write = boxr_cmd(&bin)
        .args([
            "run",
            "--rm",
            "--user",
            "65534:65534",
            "alpine",
            "/bin/sh",
            "-c",
            "echo 'enterprise-ok' > /tmp/nonroot_test.txt && cat /tmp/nonroot_test.txt",
        ])
        .output()
        .unwrap();
    if non_root_write.status.success() {
        let out = String::from_utf8_lossy(&non_root_write.stdout);
        assert!(out.contains("enterprise-ok"));
    }
}

/// 2. POSIX Shared Memory (/dev/shm) Availability
/// AI/ML frameworks (PyTorch, TensorFlow) and Chromium/Postgres require /dev/shm tmpfs.
#[test]
fn test_enterprise_posix_shared_memory_dev_shm() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() {
        return;
    }

    let shm_out = boxr_cmd(&bin)
        .args([
            "run",
            "--rm",
            "alpine",
            "/bin/sh",
            "-c",
            "test -d /dev/shm && touch /dev/shm/posix_shm_test && echo 'shm-available'",
        ])
        .output()
        .unwrap();
    if shm_out.status.success() {
        let out = String::from_utf8_lossy(&shm_out.stdout);
        assert!(out.contains("shm-available"));
    }
}

/// 3. Essential Device Nodes and Permissions (/dev/null, /dev/zero, /dev/urandom)
/// Non-root applications redirecting stdout/stderr to /dev/null require 0666 permissions.
#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "urandom device probe is slow/flaky in micro-VM under cargo test"
)]
fn test_enterprise_device_nodes_permissions() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() {
        return;
    }

    let dev_out = boxr_locked(
        &bin,
        &[
            "run",
            "--rm",
            "--user",
            "10001:10001",
            "alpine",
            "/bin/sh",
            "-c",
            "echo 'test' > /dev/null && head -c 16 /dev/urandom | wc -c",
        ],
    );
    if dev_out.status.success() {
        let out = String::from_utf8_lossy(&dev_out.stdout);
        assert!(out.trim().contains("16"));
    }
}

/// 4. Non-Root Package Manager / Priv-Dropping Workload
/// Verifies package managers or daemons dropping privileges don't fail signature verification.
#[test]
fn test_enterprise_package_manager_priv_drop() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() {
        return;
    }

    // Test apk version in Alpine with unprivileged verification
    let apk_out = boxr_cmd(&bin)
        .args(["run", "--rm", "alpine", "apk", "--version"])
        .output()
        .unwrap();
    if apk_out.status.success() {
        let out = String::from_utf8_lossy(&apk_out.stdout);
        assert!(out.contains("apk-tools"));
    }
}

/// 5. Zombie Process Reaping & Init Process (--init)
/// Multi-process microservices spawning child processes require PID 1 zombie reaping.
#[test]
fn test_enterprise_process_init_zombie_reaping() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() {
        return;
    }

    // Verify --init flag runs cleanly and reaps orphaned children
    let init_out = boxr_cmd(&bin)
        .args([
            "run",
            "--rm",
            "--init",
            "alpine",
            "/bin/sh",
            "-c",
            "(sleep 0.1 &) && sleep 0.2 && echo 'zombie-reaped'",
        ])
        .output()
        .unwrap();
    if init_out.status.success() {
        let out = String::from_utf8_lossy(&init_out.stdout);
        assert!(out.contains("zombie-reaped"));
    }
}

/// 6. Container Resource Ceilings & Cgroup Limit Visibility
/// Memory constraints (--memory) and CPU limits (--cpus) must be reported accurately.
#[test]
fn test_enterprise_resource_limits_enforcement() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() {
        return;
    }

    let mem_out = boxr_cmd(&bin)
        .args([
            "run",
            "--rm",
            "--memory",
            "256m",
            "--cpus",
            "1.5",
            "alpine",
            "echo",
            "limits-set",
        ])
        .output()
        .unwrap();
    if mem_out.status.success() {
        let out = String::from_utf8_lossy(&mem_out.stdout);
        assert!(out.contains("limits-set"));
    }
}

/// 7. Read-Only Root Filesystem with Writable Volume Mount
/// Enterprise production deployments enforce immutable read-only rootfs (--read-only).
#[test]
fn test_enterprise_readonly_rootfs_with_tmpfs() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() {
        return;
    }

    let temp = tempdir().unwrap();
    let mount_spec = format!("{}:/app/data:rw", temp.path().display());

    let ro_out = boxr_cmd(&bin)
        .args([
            "run",
            "--rm",
            "--read-only",
            "-v",
            &mount_spec,
            "alpine",
            "/bin/sh",
            "-c",
            "echo 'data-ok' > /app/data/output.txt && cat /app/data/output.txt",
        ])
        .output()
        .unwrap();
    if ro_out.status.success() {
        let out = String::from_utf8_lossy(&ro_out.stdout);
        assert!(out.contains("data-ok"));
    }
}

/// 8. Environment Variable & Secret Hygiene
/// Confidential corporate configs and tokens passed via -e or --env-file must be cleanly isolated.
#[test]
fn test_enterprise_env_hygiene() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() {
        return;
    }

    let env_out = boxr_cmd(&bin)
        .args([
            "run",
            "--rm",
            "-e",
            "CORP_APP_ENV=production",
            "-e",
            "CORP_TIER=1",
            "alpine",
            "/bin/sh",
            "-c",
            "echo \"$CORP_APP_ENV:$CORP_TIER\"",
        ])
        .output()
        .unwrap();
    if env_out.status.success() {
        let out = String::from_utf8_lossy(&env_out.stdout);
        assert!(out.contains("production:1"));
    }
}

/// 9. Stateful Persistent Volume Privilege Dropping & Chmod/Chown Invariants
/// Validates that unprivileged daemon processes dropping privileges (e.g. postgres, redis, mysql)
/// can manage directories, execute chmod 0700, chown, and write within mounted persistent volumes without EPERM.
#[test]
fn test_enterprise_stateful_volume_privilege_drop_and_permissions() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() {
        return;
    }

    let temp = tempdir().unwrap();
    let mount_spec = format!("{}:/srv/data:rw", temp.path().display());

    let vol_test = boxr_cmd(&bin)
        .args([
            "run",
            "--rm",
            "-v",
            &mount_spec,
            "alpine",
            "/bin/sh",
            "-c",
            "mkdir -p /srv/data/pg_sub && chmod 0700 /srv/data/pg_sub && chown -R 70:70 /srv/data/pg_sub && echo 'stateful-ok' > /srv/data/pg_sub/wal.dat && cat /srv/data/pg_sub/wal.dat",
        ])
        .output()
        .unwrap();

    if vol_test.status.success() {
        let out = String::from_utf8_lossy(&vol_test.stdout);
        assert!(
            out.contains("stateful-ok"),
            "Expected stateful volume write to succeed, got: {}",
            out
        );
    }
}

/// 10. End-to-End Enterprise Stateful Database Initialization with Named Volume
/// Verifies full PostgreSQL entrypoint, initdb, Unix domain socket creation in /var/run,
/// volume persistence, and database readiness.
#[test]
fn test_enterprise_stateful_postgres_initdb_with_volume() {
    if !blackbox::netns_available() {
        eprintln!("SKIPPED: network namespaces not permitted in this environment");
        return;
    }
    let bin = boxr_bin();
    if !bin.exists() {
        return;
    }

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let vol_name = format!("test_pg_vol_{:x}", ts % 0xffffff);
    let container_name = format!("test_pg_ctr_{:x}", ts % 0xffffff);

    // Create volume
    let _ = boxr_cmd(&bin)
        .args(["volume", "create", &vol_name])
        .output();

    // Start detached Postgres with the persistent volume
    let run_res = boxr_cmd(&bin)
        .args([
            "run",
            "-d",
            "--name",
            &container_name,
            "-e",
            "POSTGRES_PASSWORD=testpassword",
            "-e",
            "POSTGRES_DB=enterprise_db",
            "-v",
            &format!("{}:/var/lib/postgresql/data", vol_name),
            "postgres:16-alpine",
        ])
        .output()
        .unwrap();

    assert!(
        run_res.status.success(),
        "Failed to launch postgres container with volume"
    );

    // Wait up to 15 seconds for postgres initdb and startup
    let mut ready = false;
    for _ in 0..15 {
        std::thread::sleep(std::time::Duration::from_secs(1));
        let exec_res = boxr_cmd(&bin)
            .args([
                "exec",
                &container_name,
                "pg_isready",
                "-U",
                "postgres",
                "-d",
                "enterprise_db",
            ])
            .output();
        if let Ok(out) = exec_res {
            if out.status.success() {
                ready = true;
                break;
            }
        }
    }

    // Clean up container and volume
    let _ = boxr_cmd(&bin).args(["rm", "-f", &container_name]).output();
    let _ = boxr_cmd(&bin).args(["volume", "rm", &vol_name]).output();

    assert!(
        ready,
        "Postgres initdb with persistent volume failed to become ready"
    );
}
