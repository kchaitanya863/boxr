use crate::runtime::exec_in_bundle;
use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthStatus {
    None,
    Starting,
    Healthy,
    Unhealthy,
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HealthStatus::None => write!(f, ""),
            HealthStatus::Starting => write!(f, "health: starting"),
            HealthStatus::Healthy => write!(f, "healthy"),
            HealthStatus::Unhealthy => write!(f, "unhealthy"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthConfig {
    pub test: Vec<String>,
    pub interval_secs: u64,
    pub timeout_secs: u64,
    pub start_period_secs: u64,
    pub retries: u32,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            test: Vec::new(),
            interval_secs: 30,
            timeout_secs: 30,
            start_period_secs: 0,
            retries: 3,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckResult {
    pub status: HealthStatus,
    pub failing_streak: u32,
    pub last_output: String,
    pub last_checked: DateTime<Utc>,
}

impl Default for HealthCheckResult {
    fn default() -> Self {
        Self {
            status: HealthStatus::Starting,
            failing_streak: 0,
            last_output: String::new(),
            last_checked: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RestartPolicy {
    No,
    Always,
    OnFailure { max_retries: u32 },
    UnlessStopped,
}

impl Default for RestartPolicy {
    fn default() -> Self {
        RestartPolicy::No
    }
}

impl std::fmt::Display for RestartPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RestartPolicy::No => write!(f, "no"),
            RestartPolicy::Always => write!(f, "always"),
            RestartPolicy::OnFailure { max_retries } => write!(f, "on-failure:{}", max_retries),
            RestartPolicy::UnlessStopped => write!(f, "unless-stopped"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum HealthOnFailureAction {
    #[default]
    None,
    Stop,
    Kill,
    Restart,
}

pub fn parse_health_on_failure(input: &str) -> Result<HealthOnFailureAction> {
    match input.trim().to_ascii_lowercase().as_str() {
        "" | "none" => Ok(HealthOnFailureAction::None),
        "stop" => Ok(HealthOnFailureAction::Stop),
        "kill" => Ok(HealthOnFailureAction::Kill),
        "restart" => Ok(HealthOnFailureAction::Restart),
        other => Err(anyhow!(
            "invalid health-on-failure action '{}': expected none, stop, kill, or restart",
            other
        )),
    }
}

pub fn parse_restart_policy(input: &str) -> Result<RestartPolicy> {
    let input = input.trim().to_lowercase();
    if input == "no" || input == "none" || input.is_empty() {
        Ok(RestartPolicy::No)
    } else if input == "always" {
        Ok(RestartPolicy::Always)
    } else if input == "unless-stopped" {
        Ok(RestartPolicy::UnlessStopped)
    } else if input == "on-failure" {
        Ok(RestartPolicy::OnFailure { max_retries: 3 })
    } else if let Some(retries_str) = input.strip_prefix("on-failure:") {
        let retries: u32 = retries_str
            .parse()
            .map_err(|_| anyhow!("Invalid retry count in on-failure: {}", retries_str))?;
        Ok(RestartPolicy::OnFailure {
            max_retries: retries,
        })
    } else {
        Err(anyhow!(
            "Invalid restart policy: '{}', expected no, always, on-failure[:max-retries], or unless-stopped",
            input
        ))
    }
}

/// Open/Closed & Dependency Inversion: Container health probe abstraction
pub trait HealthProbe: Send + Sync {
    fn check_health(
        &self,
        bundle_path: &Path,
        config: &HealthConfig,
        current: &mut HealthCheckResult,
    ) -> Result<HealthStatus>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultHealthProbe;

impl HealthProbe for DefaultHealthProbe {
    fn check_health(
        &self,
        bundle_path: &Path,
        config: &HealthConfig,
        current: &mut HealthCheckResult,
    ) -> Result<HealthStatus> {
        check_container_health(bundle_path, config, current, false)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HealthCheckLogEntry {
    #[serde(rename = "Start")]
    pub start: String,
    #[serde(rename = "End")]
    pub end: String,
    #[serde(rename = "ExitCode")]
    pub exit_code: i32,
    #[serde(rename = "Output")]
    pub output: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckResults {
    #[serde(rename = "Status")]
    pub status: String,
    #[serde(rename = "FailingStreak")]
    pub failing_streak: u32,
    #[serde(rename = "Log")]
    pub log: Vec<HealthCheckLogEntry>,
}

impl Default for HealthCheckResults {
    fn default() -> Self {
        Self {
            status: "starting".to_string(),
            failing_streak: 0,
            log: Vec::new(),
        }
    }
}

pub fn healthcheck_log_path(
    bundle_path: &Path,
    container_id: &str,
    log_destination: Option<&str>,
) -> std::path::PathBuf {
    if let Some(dest) =
        log_destination.filter(|d| !d.is_empty() && *d != "local" && *d != "events_logger")
    {
        std::path::PathBuf::from(dest).join(format!("{container_id}-healthcheck.log"))
    } else {
        bundle_path.join(format!("{container_id}-healthcheck.log"))
    }
}

pub fn read_healthcheck_results(
    bundle_path: &Path,
    container_id: &str,
    log_destination: Option<&str>,
    warn_on_corrupt: bool,
) -> (HealthCheckResults, bool) {
    let path = healthcheck_log_path(bundle_path, container_id, log_destination);
    if !path.exists() {
        return (HealthCheckResults::default(), false);
    }
    match std::fs::read_to_string(&path)
        .ok()
        .and_then(|raw| serde_json::from_str::<HealthCheckResults>(&raw).ok())
    {
        Some(res) => (res, false),
        None => {
            if warn_on_corrupt {
                eprintln!(
                    "time=\"{}\" level=warning msg=\"Failed to get healthcheck log for {}: healthcheck log corrupted\"",
                    Utc::now().to_rfc3339(),
                    container_id
                );
            }
            (
                HealthCheckResults {
                    status: "unhealthy".to_string(),
                    failing_streak: 0,
                    log: Vec::new(),
                },
                true,
            )
        }
    }
}

pub fn write_healthcheck_results(
    bundle_path: &Path,
    container_id: &str,
    log_destination: Option<&str>,
    results: &HealthCheckResults,
) -> Result<()> {
    let path = healthcheck_log_path(bundle_path, container_id, log_destination);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let json = serde_json::to_string(results)?;
    std::fs::write(&path, &json)?;
    let local_path = bundle_path.join(format!("{container_id}-healthcheck.log"));
    if local_path != path {
        let _ = std::fs::write(&local_path, &json);
    }
    Ok(())
}

/// Run a health check probe inside a container bundle
pub fn check_container_health(
    bundle_path: &Path,
    config: &HealthConfig,
    current: &mut HealthCheckResult,
    start_period_active: bool,
) -> Result<HealthStatus> {
    let (status, _, _, _, _) =
        check_container_health_with_output(bundle_path, config, current, start_period_active)?;
    Ok(status)
}

pub fn check_container_health_with_output(
    bundle_path: &Path,
    config: &HealthConfig,
    current: &mut HealthCheckResult,
    start_period_active: bool,
) -> Result<(HealthStatus, i32, String, DateTime<Utc>, DateTime<Utc>)> {
    let start_dt = Utc::now();
    if config.test.is_empty() {
        current.status = HealthStatus::None;
        return Ok((
            HealthStatus::None,
            0,
            String::new(),
            start_dt,
            Utc::now(),
        ));
    }

    let exec_cmd: Vec<String> = if config.test.first().map(|s| s.as_str()) == Some("CMD-SHELL") {
        vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            config.test[1..].join(" "),
        ]
    } else if config.test.first().map(|s| s.as_str()) == Some("CMD") {
        config.test[1..].to_vec()
    } else if config.test.len() == 1 {
        vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            config.test[0].clone(),
        ]
    } else {
        config.test.clone()
    };

    let mut env = std::fs::read_to_string(bundle_path.join("config.json"))
        .ok()
        .and_then(|s| serde_json::from_str::<crate::oci::runtime::Spec>(&s).ok())
        .map(|spec| spec.process.env)
        .unwrap_or_default();
    if !env.iter().any(|e| e.starts_with("PATH=")) {
        env.push("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string());
    }

    let cap_path = bundle_path.join(format!("hc-out-{}.tmp", std::process::id()));
    let code = match exec_in_bundle(
        bundle_path,
        &exec_cmd,
        &env,
        None,
        None,
        false,
        crate::runtime::ExecAttach {
            quiet: true,
            capture_output: Some(cap_path.clone()),
            ..Default::default()
        },
        None,
        &[],
    ) {
        Ok(c) => c,
        Err(_) => 1,
    };
    let end_dt = Utc::now();
    let output = std::fs::read_to_string(&cap_path).unwrap_or_default();
    let _ = std::fs::remove_file(&cap_path);
    current.last_checked = end_dt;
    current.last_output = output.clone();

    if code == 0 {
        current.failing_streak = 0;
        current.status = HealthStatus::Healthy;
    } else {
        current.failing_streak += 1;
        if (current.failing_streak >= config.retries || config.retries == 0) && !start_period_active
        {
            current.status = HealthStatus::Unhealthy;
        } else if current.status != HealthStatus::Healthy {
            current.status = HealthStatus::Starting;
        }
    }

    Ok((current.status.clone(), code, output, start_dt, end_dt))
}

pub mod supervisor;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_restart_policies() {
        assert_eq!(parse_restart_policy("no").unwrap(), RestartPolicy::No);
        assert_eq!(
            parse_restart_policy("always").unwrap(),
            RestartPolicy::Always
        );
        assert_eq!(
            parse_restart_policy("unless-stopped").unwrap(),
            RestartPolicy::UnlessStopped
        );
        assert_eq!(
            parse_restart_policy("on-failure").unwrap(),
            RestartPolicy::OnFailure { max_retries: 3 }
        );
        assert_eq!(
            parse_restart_policy("on-failure:5").unwrap(),
            RestartPolicy::OnFailure { max_retries: 5 }
        );
    }

    #[test]
    fn test_health_status_transitions() {
        let result = HealthCheckResult::default();
        assert_eq!(result.status, HealthStatus::Starting);
    }
}
