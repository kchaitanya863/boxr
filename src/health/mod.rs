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
    if input == "no" || input == "none" || input == "never" || input.is_empty() {
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

/// Run a health check probe inside a container bundle
pub fn check_container_health(
    bundle_path: &Path,
    config: &HealthConfig,
    current: &mut HealthCheckResult,
    start_period_active: bool,
) -> Result<HealthStatus> {
    if config.test.is_empty() {
        current.status = HealthStatus::None;
        return Ok(HealthStatus::None);
    }

    let code = match exec_in_bundle(
        bundle_path,
        &config.test,
        &[],
        None,
        None,
        false,
        crate::runtime::ExecAttach {
            quiet: true,
            ..Default::default()
        },
        None,
        &[],
    ) {
        Ok(c) => c,
        Err(_) => 1,
    };
    current.last_checked = Utc::now();

    if code == 0 {
        current.failing_streak = 0;
        current.status = HealthStatus::Healthy;
        current.last_output = "OK".to_string();
    } else {
        current.failing_streak += 1;
        current.last_output = format!("Probe exited with code {}", code);
        if current.failing_streak >= config.retries && !start_period_active {
            current.status = HealthStatus::Unhealthy;
        } else {
            current.status = HealthStatus::Starting;
        }
    }

    Ok(current.status.clone())
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
