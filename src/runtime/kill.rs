use crate::events::{ContainerEvent, EventManager};
use crate::storage::{ContainerRecord, ContainerStatus, ContainerStore};
use anyhow::{Result, anyhow};
use std::collections::HashMap;

/// Open/Closed & Dependency Inversion: Process termination contract
pub trait ProcessKiller: Send + Sync {
    fn kill(&self, container: &ContainerRecord, signal_str: Option<&str>) -> Result<()>;
}

pub struct ContainerKiller;

impl ProcessKiller for ContainerKiller {
    fn kill(&self, container: &ContainerRecord, signal_str: Option<&str>) -> Result<()> {
        Self::kill(container, signal_str)
    }
}

pub fn validate_podman_signal(sig_str: &str) -> std::result::Result<i32, String> {
    let raw = sig_str.trim();
    let stripped = raw.strip_prefix('-').unwrap_or(raw);

    if stripped.is_empty() {
        return Err("invalid signal: ".to_string());
    }

    if let Ok(num) = stripped.parse::<i64>() {
        if num == 0 {
            return Err("invalid signal: 0".to_string());
        }
        if (1..=64).contains(&num) {
            return Ok(num as i32);
        }
        return Err("valid signals are 1 through 64".to_string());
    }

    let upper = stripped.to_uppercase();
    let sig_name = upper.strip_prefix("SIG").unwrap_or(&upper);
    match sig_name {
        "HUP" => Ok(1),
        "INT" => Ok(2),
        "QUIT" => Ok(3),
        "ILL" => Ok(4),
        "TRAP" => Ok(5),
        "ABRT" | "IOT" => Ok(6),
        "BUS" => Ok(7),
        "FPE" => Ok(8),
        "KILL" => Ok(9),
        "USR1" => Ok(10),
        "SEGV" => Ok(11),
        "USR2" => Ok(12),
        "PIPE" => Ok(13),
        "ALRM" => Ok(14),
        "TERM" => Ok(15),
        "STKFLT" => Ok(16),
        "CHLD" => Ok(17),
        "CONT" => Ok(18),
        "STOP" => Ok(19),
        "TSTP" => Ok(20),
        "TTIN" => Ok(21),
        "TTOU" => Ok(22),
        "URG" => Ok(23),
        "XCPU" => Ok(24),
        "XFSZ" => Ok(25),
        "VTALRM" => Ok(26),
        "PROF" => Ok(27),
        "WINCH" => Ok(28),
        "POLL" | "IO" => Ok(29),
        "PWR" => Ok(30),
        "SYS" => Ok(31),
        _ => Err(format!("invalid signal: {}", stripped)),
    }
}

impl ContainerKiller {
    pub fn parse_signal(sig_str: &str) -> Result<i32> {
        let trimmed = sig_str.trim();
        if trimmed.starts_with('-')
            && trimmed.len() > 1
            && trimmed[1..].chars().all(|c| c.is_ascii_digit())
            && trimmed != "-1"
        {
            return Err(anyhow!("Invalid signal number: {}", trimmed));
        }
        validate_podman_signal(sig_str).map_err(|e| anyhow!(e))
    }

    pub fn kill(container: &ContainerRecord, signal_str: Option<&str>) -> Result<()> {
        let sig = signal_str.map(Self::parse_signal).transpose()?.unwrap_or(9);
        Self::kill_with_signal_num(container, Some(sig))
    }

    pub fn kill_with_signal_num(
        container: &ContainerRecord,
        signal_num: Option<i32>,
    ) -> Result<()> {
        let sig = signal_num.unwrap_or(9); // Default SIGKILL

        #[cfg(unix)]
        {
            let bundle_path = std::path::PathBuf::from(&container.bundle_path);
            let mut pids = Vec::new();
            if let Ok(pid_str) = std::fs::read_to_string(bundle_path.join("container.pid")) {
                if let Ok(pid) = pid_str.trim().parse::<i32>() {
                    if pid > 1 {
                        pids.push(pid);
                    }
                }
            }
            if pids.is_empty() || sig == 9 {
                for pid_filename in &["vm.pid", "forwarder.pid"] {
                    let pid_file = bundle_path.join(pid_filename);
                    if let Ok(pid_str) = std::fs::read_to_string(&pid_file) {
                        if let Ok(pid) = pid_str.trim().parse::<i32>() {
                            if pid > 1 {
                                pids.push(pid);
                            }
                        }
                    }
                }
            }
            #[cfg(target_os = "linux")]
            let pids = if sig == 9 {
                crate::get_process_tree_pids(&pids)
            } else {
                pids
            };

            for pid in pids {
                unsafe {
                    libc::kill(pid, sig);
                    if sig == 9 {
                        let _ = libc::kill(-pid, sig);
                    }
                }
            }
        }

        #[cfg(target_os = "linux")]
        if sig == 9 {
            let cgroup_dir = std::path::PathBuf::from("/sys/fs/cgroup/boxr").join(&container.id);
            let procs_file = cgroup_dir.join("cgroup.procs");
            if procs_file.exists() {
                if let Ok(content) = std::fs::read_to_string(procs_file) {
                    for line in content.lines() {
                        if let Ok(pid) = line.trim().parse::<i32>() {
                            unsafe {
                                libc::kill(pid, sig);
                                let _ = libc::kill(-pid, sig);
                            }
                        }
                    }
                }
            }
        }

        let is_fatal = sig == 9;
        if is_fatal {
            let store = ContainerStore::new();
            let _ = store.update_status(&container.id, ContainerStatus::Exited(128 + sig));
        }

        let mut attrs = HashMap::new();
        attrs.insert("signal".to_string(), sig.to_string());
        attrs.insert("name".to_string(), container.name.clone());
        EventManager::record(ContainerEvent::new(
            "container",
            "kill",
            &container.id,
            &container.name,
            attrs,
        ));

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_signals() {
        assert_eq!(ContainerKiller::parse_signal("SIGKILL").unwrap(), 9);
        assert_eq!(ContainerKiller::parse_signal("KILL").unwrap(), 9);
        assert_eq!(ContainerKiller::parse_signal("9").unwrap(), 9);
        assert_eq!(ContainerKiller::parse_signal("SIGTERM").unwrap(), 15);
        assert_eq!(ContainerKiller::parse_signal("TERM").unwrap(), 15);
        assert_eq!(ContainerKiller::parse_signal("SIGHUP").unwrap(), 1);
    }

    #[test]
    fn test_issue_417_process_group_termination() {
        use std::process::Command;
        use tempfile::tempdir;

        // Spawn a child process with its own process group
        let mut child = Command::new("sleep").arg("10").spawn().unwrap();

        let pid = child.id() as i32;
        let dir = tempdir().unwrap();
        let bundle_path = dir.path().to_path_buf();
        std::fs::write(bundle_path.join("vm.pid"), pid.to_string()).unwrap();

        let cont = ContainerRecord {
            id: "testcont417".to_string(),
            name: "testcont417".to_string(),
            image: "test:latest".to_string(),
            command: vec!["sleep".to_string(), "10".to_string()],
            created_at: chrono::Utc::now(),
            status: ContainerStatus::Running,
            bundle_path: bundle_path.to_string_lossy().to_string(),
            restart_policy: crate::health::RestartPolicy::No,
            health_status: crate::health::HealthStatus::None,
            restart_count: 0,
            ports: Vec::new(),
            exposed_ports: Vec::new(),
        };

        // Terminate container
        ContainerKiller::kill(&cont, Some("SIGKILL")).unwrap();

        // Wait for child to exit
        let status = child.wait().unwrap();
        assert!(!status.success());
    }
}
