#![allow(dead_code)]

use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Default)]
pub struct ResourceLimits {
    pub memory_max_bytes: Option<i64>,
    pub memory_swap_max_bytes: Option<i64>,
    pub memory_reservation_bytes: Option<i64>,
    pub cpu_quota_us: Option<i64>,
    pub cpu_period_us: Option<u64>,
    pub cpu_shares: Option<u64>,
    pub cpuset_cpus: Option<String>,
    pub cpuset_mems: Option<String>,
    pub memory_swappiness: Option<u64>,
    pub pids_max: Option<i64>,
    pub cgroup_conf: Vec<String>,
}

impl ResourceLimits {
    pub fn parse_memory(input: &str) -> Result<i64> {
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

        let val: i64 = num_str.parse().context("Invalid memory limit string")?;
        if val < 0 {
            return Err(anyhow::anyhow!(
                "Memory limit must be non-negative, got '{}'",
                input
            ));
        }
        if val == 0 {
            return Ok(0);
        }
        Ok(val * multiplier)
    }

    pub fn parse_cpus(input: &str) -> Result<(i64, u64)> {
        let cpus: f64 = input.parse().context("Invalid cpus limit string")?;
        if !cpus.is_finite() || cpus <= 0.0 {
            return Err(anyhow::anyhow!(
                "Invalid cpus limit: must be a positive finite number, got '{}'",
                input
            ));
        }
        let period: u64 = 100_000; // 100ms default period
        let quota = (cpus * period as f64) as i64;
        Ok((quota, period))
    }
}

/// Open/Closed & Dependency Inversion: Resource management contract
pub trait ResourceManager: Send + Sync {
    fn apply_limits(&self, limits: &ResourceLimits) -> Result<()>;
    fn add_process(&self, pid: i32) -> Result<()>;
    fn freeze(&self) -> Result<()>;
    fn unfreeze(&self) -> Result<()>;
    fn cleanup(&self) -> Result<()>;
}

pub struct CgroupV2Manager {
    cgroup_path: PathBuf,
}

impl ResourceManager for CgroupV2Manager {
    fn apply_limits(&self, limits: &ResourceLimits) -> Result<()> {
        self.apply_limits(limits)
    }

    fn add_process(&self, pid: i32) -> Result<()> {
        self.add_process(pid)
    }

    fn freeze(&self) -> Result<()> {
        self.freeze()
    }

    fn unfreeze(&self) -> Result<()> {
        self.unfreeze()
    }

    fn cleanup(&self) -> Result<()> {
        self.cleanup()
    }
}

impl CgroupV2Manager {
    /// Locate or initialize the rootless / system cgroups v2 hierarchy for a container
    pub fn new(container_id: &str) -> Result<Self> {
        let base_cgroup = Self::detect_cgroup_root();
        let boxr_cgroup = base_cgroup.join("boxr");
        let container_cgroup = boxr_cgroup.join(container_id);

        if base_cgroup.exists() {
            let _ = fs::create_dir_all(&boxr_cgroup);
            for ctl in ["+cpu", "+cpuset", "+memory", "+pids", "+io"] {
                let _ = fs::write(base_cgroup.join("cgroup.subtree_control"), ctl);
                let _ = fs::write(boxr_cgroup.join("cgroup.subtree_control"), ctl);
            }
            let _ = fs::create_dir_all(&container_cgroup);
        }

        Ok(Self {
            cgroup_path: container_cgroup,
        })
    }

    pub fn was_oom_killed(container_id: &str) -> bool {
        let base_cgroup = Self::detect_cgroup_root();
        let events_file = base_cgroup
            .join("boxr")
            .join(container_id)
            .join("memory.events");
        if let Ok(content) = fs::read_to_string(events_file) {
            for line in content.lines() {
                if let Some(rest) = line
                    .strip_prefix("oom_kill ")
                    .or_else(|| line.strip_prefix("oom "))
                {
                    if let Ok(n) = rest.trim().parse::<u64>() {
                        if n > 0 {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    fn detect_cgroup_root() -> PathBuf {
        #[cfg(target_os = "linux")]
        {
            // Check user slice first (for rootless execution)
            let uid = unsafe { libc::getuid() };
            if uid != 0 {
                let user_slice = PathBuf::from(format!(
                    "/sys/fs/cgroup/user.slice/user-{}.slice/user@{}.service",
                    uid, uid
                ));
                if user_slice.exists() {
                    return user_slice;
                }

                let unified_slice = PathBuf::from(format!(
                    "/sys/fs/cgroup/unified/user.slice/user-{}.slice/user@{}.service",
                    uid, uid
                ));
                if unified_slice.exists() {
                    return unified_slice;
                }
            }

            let sys_cgroup = PathBuf::from("/sys/fs/cgroup");
            if sys_cgroup.exists() {
                return sys_cgroup;
            }
        }

        // Mock/Fallback location for testing or platforms without cgroups
        PathBuf::from("/tmp/boxr-cgroup")
    }

    /// Apply resource constraints to the container cgroup
    pub fn apply_limits(&self, limits: &ResourceLimits) -> Result<()> {
        if !self.cgroup_path.exists() {
            return Ok(());
        }

        // Apply memory limits (cgroups v2 and v1)
        if let Some(mem) = limits.memory_max_bytes {
            if mem > 0 {
                let _ = fs::write(self.cgroup_path.join("memory.max"), mem.to_string());
                let _ = fs::write(
                    self.cgroup_path.join("memory.limit_in_bytes"),
                    mem.to_string(),
                );
            }
        }

        if let Some(swap) = limits.memory_swap_max_bytes {
            let swap_v2 = if swap < 0 {
                "max".to_string()
            } else if let Some(mem) = limits.memory_max_bytes {
                swap.saturating_sub(mem).to_string()
            } else {
                swap.to_string()
            };
            let _ = fs::write(self.cgroup_path.join("memory.swap.max"), swap_v2);
        }

        // Apply memory reservation (cgroups v2 memory.low)
        if let Some(res) = limits.memory_reservation_bytes {
            let _ = fs::write(self.cgroup_path.join("memory.low"), res.to_string());
            let _ = fs::write(
                self.cgroup_path.join("memory.soft_limit_in_bytes"),
                res.to_string(),
            );
        }

        if let Some(shares) = limits.cpu_shares {
            let weight = (1 + ((shares.saturating_sub(2)) * 9999) / 262142).clamp(1, 10000);
            let _ = fs::write(self.cgroup_path.join("cpu.weight"), weight.to_string());
        }

        // Apply CPU quota (cgroups v2 and v1)
        if let (Some(quota), Some(period)) = (limits.cpu_quota_us, limits.cpu_period_us) {
            let val = format!("{} {}", quota, period);
            let _ = fs::write(self.cgroup_path.join("cpu.max"), val);
            let _ = fs::write(self.cgroup_path.join("cpu.cfs_quota_us"), quota.to_string());
            let _ = fs::write(
                self.cgroup_path.join("cpu.cfs_period_us"),
                period.to_string(),
            );
        }

        // Apply cpuset cpus
        if let Some(cpus) = &limits.cpuset_cpus {
            let _ = fs::write(self.cgroup_path.join("cpuset.cpus"), cpus);
        }
        if let Some(mems) = &limits.cpuset_mems {
            let _ = fs::write(self.cgroup_path.join("cpuset.mems"), mems);
        }
        for kv in &limits.cgroup_conf {
            if let Some((k, v)) = kv.split_once('=') {
                let k = k.trim();
                if !k.is_empty() && !k.contains('/') && !k.contains("..") {
                    let _ = fs::write(self.cgroup_path.join(k), v.trim());
                }
            }
        }

        // Apply memory swappiness
        if let Some(swappiness) = limits.memory_swappiness {
            let _ = fs::write(
                self.cgroup_path.join("memory.swap.high"),
                swappiness.to_string(),
            );
            let _ = fs::write(
                self.cgroup_path.join("memory.swappiness"),
                swappiness.to_string(),
            );
        }

        // Apply PID limits
        if let Some(pids) = limits.pids_max {
            let val = if pids > 0 {
                pids.to_string()
            } else {
                "max".to_string()
            };
            let _ = fs::write(self.cgroup_path.join("pids.max"), val);
        }

        Ok(())
    }

    /// Attach a process ID to this cgroup
    pub fn add_process(&self, pid: i32) -> Result<()> {
        if !self.cgroup_path.exists() {
            return Ok(());
        }
        if fs::write(self.cgroup_path.join("cgroup.procs"), pid.to_string()).is_err() {
            #[cfg(target_os = "linux")]
            {
                let scope_name = format!("boxr-cg-{}-{}.scope", pid, std::process::id());
                let pid_str = pid.to_string();
                let _ = std::process::Command::new("busctl")
                    .args([
                        "--user",
                        "call",
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "StartTransientUnit",
                        "ssa(sv)a(sa(sv))",
                        &scope_name,
                        "fail",
                        "2",
                        "PIDs",
                        "au",
                        "1",
                        &pid_str,
                        "Delegate",
                        "b",
                        "1",
                        "0",
                    ])
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status();
                let _ = fs::write(self.cgroup_path.join("cgroup.procs"), pid.to_string());
            }
        }
        let _ = fs::write(self.cgroup_path.join("tasks"), pid.to_string());
        Ok(())
    }

    /// Freeze all processes in the cgroup (pause)
    pub fn freeze(&self) -> Result<()> {
        if self.cgroup_path.exists() {
            let freeze_file = self.cgroup_path.join("cgroup.freeze");
            if freeze_file.exists() {
                fs::write(freeze_file, "1")?;
            }
        }
        Ok(())
    }

    /// Thaw all processes in the cgroup (unpause)
    pub fn unfreeze(&self) -> Result<()> {
        if self.cgroup_path.exists() {
            let freeze_file = self.cgroup_path.join("cgroup.freeze");
            if freeze_file.exists() {
                fs::write(freeze_file, "0")?;
            }
        }
        Ok(())
    }

    /// Clean up the container cgroup hierarchy
    pub fn cleanup(&self) -> Result<()> {
        if self.cgroup_path.exists() {
            // In cgroups v2, cgroup.kill terminates all remaining procs
            let kill_file = self.cgroup_path.join("cgroup.kill");
            if kill_file.exists() {
                let _ = fs::write(kill_file, "1");
            }
            let _ = fs::remove_dir(&self.cgroup_path);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_memory_units() {
        assert_eq!(
            ResourceLimits::parse_memory("512m").unwrap(),
            512 * 1024 * 1024
        );
        assert_eq!(
            ResourceLimits::parse_memory("2g").unwrap(),
            2 * 1024 * 1024 * 1024
        );
        assert_eq!(ResourceLimits::parse_memory("1024k").unwrap(), 1024 * 1024);
        assert_eq!(ResourceLimits::parse_memory("1000").unwrap(), 1000);
    }

    #[test]
    fn test_parse_cpus() {
        let (quota, period) = ResourceLimits::parse_cpus("1.5").unwrap();
        assert_eq!(period, 100_000);
        assert_eq!(quota, 150_000);

        let (quota, period) = ResourceLimits::parse_cpus("0.5").unwrap();
        assert_eq!(period, 100_000);
        assert_eq!(quota, 50_000);
    }
}
