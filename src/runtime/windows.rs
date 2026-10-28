//! # Windows OCI Container Runtime implementation
//!
//! Provides container execution on Windows using Windows Server Containers (via runhcs/HCS)
//! or native isolated process containment.

use crate::network::PortMapping;
use crate::oci::runtime::Spec;
use crate::volume::MountSpec;
use anyhow::{Result, anyhow};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Execute an OCI container bundle on Windows
pub fn execute_bundle(
    bundle_path: &Path,
    spec: &Spec,
    _mounts: &[MountSpec],
    _ports: &[PortMapping],
    detach: bool,
    _spawn_detached_watcher: bool,
) -> Result<i32> {
    let raw_rootfs = PathBuf::from(&spec.root.path);
    let rootfs_path = if raw_rootfs.is_absolute() {
        raw_rootfs
    } else {
        bundle_path.join(&spec.root.path)
    };

    if !rootfs_path.exists() {
        return Err(anyhow!("Rootfs not found at {:?}", rootfs_path));
    }

    let cmd_binary = spec
        .process
        .args
        .first()
        .ok_or_else(|| anyhow!("Process args cannot be empty"))?;

    let cmd_args = &spec.process.args[1..];

    // On Windows, if runhcs / containerd / hcsshim is installed, launch container
    let mut cmd = if which_exists("runhcs.exe") {
        let mut c = Command::new("runhcs.exe");
        c.arg("run");
        if detach {
            c.arg("-d");
        }
        c.arg("-b").arg(bundle_path);
        let id = bundle_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("boxr");
        c.arg(id);
        c
    } else {
        // Direct process invocation inside rootfs
        let clean_path = cmd_binary
            .trim_start_matches("c:\\")
            .trim_start_matches("C:\\");
        let bin_in_rootfs = rootfs_path.join(clean_path);
        let target_exe = if bin_in_rootfs.exists() {
            bin_in_rootfs
        } else {
            PathBuf::from(cmd_binary)
        };

        let mut c = Command::new(target_exe);
        for a in cmd_args {
            c.arg(a);
        }
        for env_var in &spec.process.env {
            if let Some((k, v)) = env_var.split_once('=') {
                c.env(k, v);
            }
        }
        c.current_dir(&rootfs_path);
        c
    };

    let log_path = bundle_path.join("logs.txt");
    if detach {
        let log_file = fs::File::create(&log_path)?;
        cmd.stdout(log_file.try_clone()?);
        cmd.stderr(log_file);
        let child = cmd.spawn()?;
        let pid_file = bundle_path.join("vm.pid");
        let _ = fs::write(pid_file, child.id().to_string());
        return Ok(0);
    }

    let status = cmd.status()?;
    Ok(status.code().unwrap_or(0))
}

pub fn exec_in_bundle(
    bundle_path: &Path,
    command: &[String],
    env: &[String],
    workdir: Option<&str>,
    _user: Option<&str>,
    _detach: bool,
    _attach: crate::runtime::ExecAttach,
    _exec_pid_path: Option<&Path>,
    _preserve_fds: &[u32],
) -> Result<i32> {
    let binary = &command[0];
    let args = &command[1..];
    let mut cmd = Command::new(binary);
    for a in args {
        cmd.arg(a);
    }
    for e in env {
        if let Some((k, v)) = e.split_once('=') {
            cmd.env(k, v);
        }
    }
    if let Some(wd) = workdir {
        cmd.current_dir(bundle_path.join("rootfs").join(wd.trim_start_matches('/')));
    } else {
        cmd.current_dir(bundle_path.join("rootfs"));
    }
    let status = cmd.status()?;
    Ok(status.code().unwrap_or(0))
}

fn which_exists(exe: &str) -> bool {
    Command::new("where")
        .arg(exe)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
