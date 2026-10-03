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

impl ContainerKiller {
    pub fn parse_signal(sig_str: &str) -> Result<i32> {
        let upper = sig_str.trim().to_uppercase();
        let stripped = upper.strip_prefix("SIG").unwrap_or(&upper);

        match stripped {
            "HUP" | "1" => Ok(1),
            "INT" | "2" => Ok(2),
            "QUIT" | "3" => Ok(3),
            "KILL" | "9" => Ok(9),
            "USR1" | "10" => Ok(10),
            "USR2" | "12" => Ok(12),
            "TERM" | "15" => Ok(15),
            "CONT" | "18" => Ok(18),
            "STOP" | "19" => Ok(19),
            other => {
                if let Ok(num) = other.parse::<i32>() {
                    if num >= 1 && num <= 64 {
                        Ok(num)
                    } else {
                        Err(anyhow!("Invalid signal number: {}", num))
                    }
                } else {
                    Err(anyhow!("Unknown signal '{}'", sig_str))
                }
            }
        }
    }

    pub fn kill(container: &ContainerRecord, signal_str: Option<&str>) -> Result<()> {
        let sig = signal_str.map(Self::parse_signal).transpose()?.unwrap_or(9); // Default SIGKILL

        #[cfg(unix)]
        {
            let bundle_path = std::path::PathBuf::from(&container.bundle_path);
            let mut pids = Vec::new();
            for pid_filename in &["vm.pid", "container.pid", "forwarder.pid"] {
                let pid_file = bundle_path.join(pid_filename);
                if let Ok(pid_str) = std::fs::read_to_string(&pid_file) {
                    if let Ok(pid) = pid_str.trim().parse::<i32>() {
                        if pid > 1 {
                            pids.push(pid);
                        }
                    }
                }
            }
            #[cfg(target_os = "linux")]
            let pids = crate::get_process_tree_pids(&pids);

            for pid in pids {
                unsafe {
                    libc::kill(pid, sig);
                    let _ = libc::kill(-pid, sig);
                }
            }
        }

        #[cfg(target_os = "linux")]
        {
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

        let is_fatal = sig == 9 || sig == 15 || sig == 2 || sig == 3;
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

        println!("{}", container.id);
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
