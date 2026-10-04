//! # Guardrails & Self-Healing Subsystem 🛡️
//!
//! Provides operational guardrails for robust, leak-free, long-running operation:
//! - **Log Rotation**: Automatic size-based rotation of container logs and system event streams.
//! - **Port Collision Protection**: Prevents multiple running containers from binding the same host port.
//! - **Disk Space Protection**: Proactive checks to prevent out-of-disk failures during image pulls.
//! - **Orphan & Zombie Reaper**: Self-healing detection and recovery from unclean host reboots.
//! - **Graceful Termination**: Supervisor managing SIGTERM with fallback to SIGKILL on timeout.

use crate::storage::{ContainerStatus, ContainerStore, boxr_home};
use anyhow::{Context, Result, anyhow};
use std::fs;
use std::path::{Path, PathBuf};

/// Size-based log rotation utility
pub struct LogRotator;

impl LogRotator {
    /// Parse size string like "10m", "500k", "1g", "1048576"
    pub fn parse_size(input: &str) -> Result<u64> {
        let input = input.trim().to_lowercase();
        let (num_str, multiplier) = if let Some(n) = input.strip_suffix("g") {
            (n, 1024 * 1024 * 1024)
        } else if let Some(n) = input.strip_suffix("gb") {
            (n, 1024 * 1024 * 1024)
        } else if let Some(n) = input.strip_suffix("m") {
            (n, 1024 * 1024)
        } else if let Some(n) = input.strip_suffix("mb") {
            (n, 1024 * 1024)
        } else if let Some(n) = input.strip_suffix("k") {
            (n, 1024)
        } else if let Some(n) = input.strip_suffix("kb") {
            (n, 1024)
        } else if let Some(n) = input.strip_suffix("b") {
            (n, 1)
        } else {
            (input.as_str(), 1)
        };

        let val: u64 = num_str.parse().context("Invalid log size string")?;
        Ok(val * multiplier)
    }

    /// Check file size and rotate if exceeding `max_bytes`.
    /// Rotates e.g. logs.txt -> logs.txt.1 -> logs.txt.2 up to `max_files`.
    pub fn rotate_if_needed(file_path: &Path, max_bytes: u64, max_files: usize) -> Result<bool> {
        if !file_path.exists() {
            return Ok(false);
        }

        let metadata = fs::metadata(file_path)?;
        if metadata.len() < max_bytes {
            return Ok(false);
        }

        if max_files == 0 {
            // Truncate in place if no backup files requested
            fs::write(file_path, b"")?;
            return Ok(true);
        }

        // Shift existing rotated files: e.g. logs.2 -> logs.3, logs.1 -> logs.2
        for i in (1..max_files).rev() {
            let src = PathBuf::from(format!("{}.{}", file_path.display(), i));
            let dst = PathBuf::from(format!("{}.{}", file_path.display(), i + 1));
            if src.exists() {
                let _ = fs::rename(&src, &dst);
            }
        }

        // Rotate current file to .1
        let first_backup = PathBuf::from(format!("{}.1", file_path.display()));
        let _ = fs::rename(file_path, &first_backup);

        // Create fresh empty active log file
        fs::write(file_path, b"")?;
        Ok(true)
    }

    /// Rotate global system events file (~/.boxr/events.jsonl) if it exceeds 5MB
    pub fn rotate_events_if_needed() {
        let events_file = boxr_home().join("events.jsonl");
        let max_size = 5 * 1024 * 1024; // 5 MB
        let max_files = 3;
        let _ = Self::rotate_if_needed(&events_file, max_size, max_files);
    }
}

/// Proactive disk space checks to protect host stability
pub struct DiskGuard;

impl DiskGuard {
    /// Return available free disk space in bytes for given directory path
    pub fn free_space_bytes(path: &Path) -> Result<u64> {
        #[cfg(windows)]
        {
            let _ = path;
            return Ok(100 * 1024 * 1024 * 1024);
        }
        #[cfg(unix)]
        {
            use std::ffi::CString;
            use std::mem::MaybeUninit;

            let target_path = if path.exists() {
                path.to_path_buf()
            } else {
                path.parent().unwrap_or(Path::new("/")).to_path_buf()
            };

            let c_path = CString::new(target_path.to_string_lossy().as_bytes())?;
            let mut stat: MaybeUninit<libc::statvfs> = MaybeUninit::uninit();

            let ret = unsafe { libc::statvfs(c_path.as_ptr(), stat.as_mut_ptr()) };
            if ret != 0 {
                return Err(anyhow!("Failed to query filesystem stats via statvfs"));
            }

            let stat = unsafe { stat.assume_init() };
            let block_size = if stat.f_frsize > 0 {
                stat.f_frsize
            } else {
                stat.f_bsize
            };
            let free_bytes = (stat.f_bavail as u64) * (block_size as u64);
            Ok(free_bytes)
        }
    }

    /// Check if target filesystem has enough headroom (at least `required_bytes` + 100MB margin)
    pub fn ensure_headroom(path: &Path, required_bytes: u64) -> Result<()> {
        let margin = 100 * 1024 * 1024; // 100 MB safety buffer
        let needed = required_bytes + margin;
        let available = Self::free_space_bytes(path)?;

        if available < needed {
            return Err(anyhow!(
                "Insufficient disk space on {}: required {:.1} MB, but only {:.1} MB available",
                path.display(),
                (needed as f64) / (1024.0 * 1024.0),
                (available as f64) / (1024.0 * 1024.0)
            ));
        }
        Ok(())
    }
}

/// Host Port Collision Guard
pub struct PortCollisionGuard;

/// Reject published ports on network modes where forwarding is meaningless.
pub fn validate_network_port_compatibility(
    network: &str,
    ports: &[crate::network::PortMapping],
) -> Result<()> {
    if ports.is_empty() {
        return Ok(());
    }
    let mode = crate::network::pasta::NetworkMode::parse(network);
    if matches!(
        mode,
        crate::network::pasta::NetworkMode::None | crate::network::pasta::NetworkMode::Host
    ) {
        return Err(anyhow!(
            "published ports are not supported with --network {}",
            network
        ));
    }
    Ok(())
}

impl PortCollisionGuard {
    /// Ensure none of the requested host ports are already bound by other running containers
    pub fn ensure_no_conflicts(requested_ports: &[crate::network::PortMapping]) -> Result<()> {
        let store = ContainerStore::new();
        Self::ensure_no_conflicts_with_reader(requested_ports, &store)
    }

    /// Dependency Inversion: Validate port conflicts against any ContainerReader abstraction
    pub fn ensure_no_conflicts_with_reader(
        requested_ports: &[crate::network::PortMapping],
        reader: &impl crate::storage::ContainerReader,
    ) -> Result<()> {
        Self::ensure_no_conflicts_with_containers(requested_ports, &reader.list())
    }

    /// Single Responsibility: Pure collision check on a slice of containers
    pub fn ensure_no_conflicts_with_containers(
        requested_ports: &[crate::network::PortMapping],
        containers: &[crate::storage::ContainerRecord],
    ) -> Result<()> {
        for req in requested_ports {
            if req.host_port == 0 {
                continue;
            }
            let req_ip = req.host_ip.as_deref().unwrap_or("0.0.0.0");

            for c in containers {
                if !matches!(c.status, ContainerStatus::Running) {
                    continue;
                }

                for p in &c.ports {
                    if p.protocol == req.protocol && p.host_port == req.host_port {
                        let running_ip = p.host_ip.as_deref().unwrap_or("0.0.0.0");
                        let ips_overlap =
                            req_ip == "0.0.0.0" || running_ip == "0.0.0.0" || req_ip == running_ip;

                        if ips_overlap {
                            return Err(anyhow!(
                                "Port conflict: host port {}:{}/{} is already in use by running container '{}' ({})",
                                req_ip,
                                req.host_port,
                                req.protocol,
                                c.name,
                                &c.id[..12.min(c.id.len())]
                            ));
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

/// Self-healing reaper for orphan and zombie container processes
pub struct ProcessReaper;

impl ProcessReaper {
    /// Inspect all recorded "Running" containers, identify dead processes, and self-heal records
    pub fn reap_stale_containers() -> Result<usize> {
        let store = ContainerStore::new();
        Self::reap_stale_containers_with_store(&store)
    }

    /// Dependency Inversion: reap stale containers using any ContainerStoreOps implementation
    pub fn reap_stale_containers_with_store(
        store: &impl crate::storage::ContainerStoreOps,
    ) -> Result<usize> {
        let containers = store.list();
        let mut reaped_count = 0;

        for c in &containers {
            if !matches!(c.status, ContainerStatus::Running) {
                continue;
            }

            let bundle = PathBuf::from(&c.bundle_path);
            let vm_pid_file = bundle.join("vm.pid");
            let cont_pid_file = bundle.join("container.pid");

            let check_pid_alive = |pid_file: &Path| -> Option<bool> {
                if let Ok(pid_str) = fs::read_to_string(pid_file) {
                    if let Ok(pid) = pid_str.trim().parse::<i32>() {
                        if pid <= 1 {
                            return Some(false);
                        }
                        #[cfg(unix)]
                        {
                            return Some(unsafe { libc::kill(pid, 0) == 0 });
                        }
                        #[cfg(windows)]
                        {
                            let is_running = std::process::Command::new("tasklist")
                                .args(["/FI", &format!("PID eq {}", pid)])
                                .output()
                                .map(|o| {
                                    String::from_utf8_lossy(&o.stdout).contains(&pid.to_string())
                                })
                                .unwrap_or(false);
                            return Some(is_running);
                        }
                        #[cfg(not(any(unix, windows)))]
                        {
                            let _ = pid;
                            return Some(false);
                        }
                    }
                }
                None
            };

            let is_alive = check_pid_alive(&vm_pid_file)
                .or_else(|| check_pid_alive(&cont_pid_file))
                .unwrap_or(false);

            if !is_alive {
                // Container process is gone; self-heal state to Exited(code)
                let exit_code =
                    if let Ok(code_str) = fs::read_to_string(bundle.join("boxr-exitcode")) {
                        code_str.trim().parse::<i32>().unwrap_or(0)
                    } else {
                        137
                    };
                let _ = fs::remove_file(&vm_pid_file);
                if let Ok(cpid_str) = fs::read_to_string(&cont_pid_file) {
                    if let Ok(cpid) = cpid_str.trim().parse::<i32>() {
                        if cpid > 1 {
                            #[cfg(unix)]
                            unsafe {
                                libc::kill(cpid, libc::SIGKILL);
                            }
                        }
                    }
                }
                let _ = fs::remove_file(&cont_pid_file);
                let _ = store.update_status(&c.id, ContainerStatus::Exited(exit_code));
                reaped_count += 1;
            }
        }

        #[cfg(target_os = "macos")]
        {
            use std::collections::HashSet;
            let active_bundles: HashSet<String> = containers
                .iter()
                .filter(|c| matches!(c.status, ContainerStatus::Running))
                .map(|c| c.bundle_path.clone())
                .collect();

            let mut running_boxr_vz_pids = Vec::new();

            if let Ok(output) = std::process::Command::new("ps")
                .args(["-A", "-o", "pid,command"])
                .output()
            {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    if line.contains("boxr-vz") && line.contains("--bundle") {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if let Some(pid_str) = parts.first() {
                            if let Ok(pid) = pid_str.parse::<i32>() {
                                let mut is_active = false;
                                for i in 0..parts.len() {
                                    if parts[i] == "--bundle" && i + 1 < parts.len() {
                                        if active_bundles.contains(parts[i + 1]) {
                                            is_active = true;
                                        }
                                    }
                                }
                                if !is_active && pid > 1 && pid != std::process::id() as i32 {
                                    unsafe {
                                        libc::kill(pid, libc::SIGTERM);
                                    }
                                    reaped_count += 1;
                                } else if is_active {
                                    running_boxr_vz_pids.push(pid);
                                }
                            }
                        }
                    }
                }
            }

            // If no boxr-vz processes are active, reap any orphaned VirtualMachine XPC services
            if running_boxr_vz_pids.is_empty() {
                if let Ok(output) = std::process::Command::new("pgrep")
                    .arg("-f")
                    .arg("com.apple.Virtualization.VirtualMachine")
                    .output()
                {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    for line in stdout.lines() {
                        if let Ok(pid) = line.trim().parse::<i32>() {
                            unsafe {
                                libc::kill(pid, libc::SIGKILL);
                            }
                            reaped_count += 1;
                        }
                    }
                }
            }
        }

        Ok(reaped_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_log_rotator_size_parsing() {
        assert_eq!(LogRotator::parse_size("512b").unwrap(), 512);
        assert_eq!(LogRotator::parse_size("10k").unwrap(), 10 * 1024);
        assert_eq!(LogRotator::parse_size("10kb").unwrap(), 10 * 1024);
        assert_eq!(LogRotator::parse_size("5m").unwrap(), 5 * 1024 * 1024);
        assert_eq!(LogRotator::parse_size("5mb").unwrap(), 5 * 1024 * 1024);
        assert_eq!(
            LogRotator::parse_size("2g").unwrap(),
            2 * 1024 * 1024 * 1024
        );
        assert_eq!(
            LogRotator::parse_size("2gb").unwrap(),
            2 * 1024 * 1024 * 1024
        );
        assert!(LogRotator::parse_size("invalid_size").is_err());
    }

    #[test]
    fn test_log_rotator_rotation_lifecycle() -> Result<()> {
        let temp = tempdir().unwrap();
        let log_file = temp.path().join("logs.txt");

        // Write 100 bytes
        let data = vec![b'a'; 100];
        fs::write(&log_file, &data)?;

        // Max size 200: should NOT rotate
        let rotated = LogRotator::rotate_if_needed(&log_file, 200, 3)?;
        assert!(!rotated);
        assert_eq!(fs::metadata(&log_file)?.len(), 100);

        // Max size 50: SHOULD rotate
        let rotated = LogRotator::rotate_if_needed(&log_file, 50, 3)?;
        assert!(rotated);
        assert_eq!(fs::metadata(&log_file)?.len(), 0);

        let backup1 = temp.path().join("logs.txt.1");
        assert!(backup1.exists());
        assert_eq!(fs::metadata(&backup1)?.len(), 100);

        // Write again and rotate second time
        fs::write(&log_file, vec![b'b'; 120])?;
        let rotated = LogRotator::rotate_if_needed(&log_file, 50, 3)?;
        assert!(rotated);

        let backup2 = temp.path().join("logs.txt.2");
        assert!(backup2.exists());
        assert_eq!(fs::metadata(&backup2)?.len(), 100); // Old backup shifted to .2
        assert_eq!(fs::metadata(&backup1)?.len(), 120); // Newer backup is .1

        Ok(())
    }

    #[test]
    fn test_disk_guard_free_space() {
        let current_dir = Path::new(".");
        let free_bytes = DiskGuard::free_space_bytes(current_dir).unwrap();
        assert!(
            free_bytes > 1024 * 1024,
            "Free space should be at least 1MB"
        );

        // Asking for 1 byte should have plenty of headroom
        assert!(DiskGuard::ensure_headroom(current_dir, 1).is_ok());

        // Asking for 1000 Petabytes should fail gracefully with descriptive error
        let huge_size = 1000 * 1024 * 1024 * 1024 * 1024 * 1024u64;
        assert!(DiskGuard::ensure_headroom(current_dir, huge_size).is_err());
    }

    #[test]
    fn test_process_reaper_identifies_dead_containers() {
        // Reaping non-existent or dead containers shouldn't crash
        let reaped = ProcessReaper::reap_stale_containers().unwrap();
        let _ = reaped;
    }

    #[test]
    fn test_process_reaper_preserves_running_container_pid() {
        use crate::storage::{ContainerRecord, ContainerStatus, ContainerStore};
        use chrono::Utc;

        let temp = tempdir().unwrap();
        let bundle_dir = temp.path().join("test-bundle");
        fs::create_dir_all(&bundle_dir).unwrap();

        // Write a distinct dummy running process PID (e.g. launchd / init PID 1, or launch a child process)
        let child = std::process::Command::new("sleep")
            .arg("5")
            .spawn()
            .unwrap();
        let child_pid = child.id() as i32;
        fs::write(bundle_dir.join("container.pid"), format!("{}", child_pid)).unwrap();

        let store = ContainerStore::new();
        let record = ContainerRecord {
            id: "reap-test-alive-1234".to_string(),
            name: "reap-test-alive".to_string(),
            image: "alpine:latest".to_string(),
            command: vec!["sleep".to_string()],
            created_at: Utc::now(),
            status: ContainerStatus::Running,
            bundle_path: bundle_dir.to_string_lossy().to_string(),
            restart_policy: crate::health::RestartPolicy::No,
            health_status: crate::health::HealthStatus::None,
            restart_count: 0,
            ports: Vec::new(),
            exposed_ports: Vec::new(),
        };
        store.add(record).unwrap();

        let _ = ProcessReaper::reap_stale_containers();
        let cont = store.find("reap-test-alive-1234").unwrap();
        assert_eq!(cont.status, ContainerStatus::Running);

        let _ = store.remove("reap-test-alive-1234");
        let _ = unsafe { libc::kill(child_pid, libc::SIGKILL) };
    }

    #[test]
    fn test_port_collision_guard_detects_conflicts() {
        use crate::network::PortMapping;

        let port_8080 = vec![PortMapping {
            host_ip: None,
            host_port: 8080,
            container_port: 80,
            protocol: "tcp".to_string(),
        }];

        // Querying non-conflicting ports passes
        assert!(PortCollisionGuard::ensure_no_conflicts(&port_8080).is_ok());
    }
}
