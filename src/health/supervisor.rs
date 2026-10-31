use super::{
    HealthCheckResult, HealthConfig, HealthOnFailureAction, HealthStatus, check_container_health,
};
use crate::storage::{ContainerStatus, ContainerStore};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HealthSupervisorSpec {
    container_id: String,
    container_name: String,
    health_cfg: HealthConfig,
    on_failure: HealthOnFailureAction,
}

fn spec_path(bundle_path: &Path) -> PathBuf {
    bundle_path.join("health-supervisor.json")
}

pub fn write_health_supervisor_spec(
    bundle_path: &Path,
    container_id: &str,
    container_name: &str,
    health_cfg: &HealthConfig,
    on_failure: HealthOnFailureAction,
) -> Result<()> {
    if health_cfg.test.is_empty() {
        return Ok(());
    }
    let spec = HealthSupervisorSpec {
        container_id: container_id.to_string(),
        container_name: container_name.to_string(),
        health_cfg: health_cfg.clone(),
        on_failure,
    };
    std::fs::write(spec_path(bundle_path), serde_json::to_string_pretty(&spec)?)?;
    Ok(())
}

pub fn spawn_detached_health_supervisor(
    bundle_path: PathBuf,
    container_id: String,
    container_name: String,
    health_cfg: HealthConfig,
    on_failure: HealthOnFailureAction,
) {
    if health_cfg.test.is_empty() {
        return;
    }
    let _ = write_health_supervisor_spec(
        &bundle_path,
        &container_id,
        &container_name,
        &health_cfg,
        on_failure,
    );
    if health_cfg.interval_secs == 0
        || std::env::var("DISABLE_HC_SYSTEMD").ok().as_deref() == Some("true")
    {
        return;
    }
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("boxr"));
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("__internal-health-supervisor")
        .arg(bundle_path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    let _ = cmd.spawn();
}

pub fn run_internal_health_supervisor(bundle_path: &Path) -> Result<()> {
    let raw =
        std::fs::read_to_string(spec_path(bundle_path)).context("read health-supervisor.json")?;
    let spec: HealthSupervisorSpec =
        serde_json::from_str(&raw).context("parse health-supervisor.json")?;
    run_supervisor_loop(
        bundle_path,
        &spec.container_id,
        &spec.container_name,
        spec.health_cfg,
        spec.on_failure,
    );
    Ok(())
}

fn run_supervisor_loop(
    bundle_path: &Path,
    container_id: &str,
    _container_name: &str,
    health_cfg: HealthConfig,
    on_failure: HealthOnFailureAction,
) {
    if health_cfg.interval_secs == 0 {
        return;
    }
    let interval = Duration::from_secs(health_cfg.interval_secs.max(1));
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .ok();
    loop {
        std::thread::sleep(interval);
        let store = ContainerStore::new();
        let cont = match store.find(container_id) {
            Some(c) => c,
            None => break,
        };
        match cont.status {
            ContainerStatus::Running => {}
            ContainerStatus::Stopping => continue,
            _ => break,
        }
        if let Some(ref rt) = rt {
            let _ = rt.block_on(crate::run_healthcheck_with_options(
                container_id,
                true,
                true,
            ));
        }
        if let Some(after) = store.find(container_id) {
            if after.health_status == HealthStatus::Unhealthy
                && matches!(
                    on_failure,
                    HealthOnFailureAction::Stop | HealthOnFailureAction::Kill
                )
            {
                break;
            }
        } else {
            break;
        }
    }
}

pub(crate) fn read_bundle_stop_timeout(bundle_path: &Path) -> Option<u64> {
    let config = bundle_path.join("config.json");
    let content = std::fs::read_to_string(config).ok()?;
    let spec: crate::oci::runtime::Spec = serde_json::from_str(&content).ok()?;
    spec.annotations
        .as_ref()
        .and_then(|a| a.get("boxr.stop_timeout"))
        .and_then(|v| v.parse::<u64>().ok())
}
