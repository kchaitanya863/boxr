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
        let (num_str, multiplier) = if let Some(n) = input.strip_suffix("ti") {
            (n, 1024_i64 * 1024 * 1024 * 1024)
        } else if let Some(n) = input.strip_suffix("tb").or_else(|| input.strip_suffix("t")) {
            (n, 1024_i64 * 1024 * 1024 * 1024)
        } else if let Some(n) = input.strip_suffix("gi") {
            (n, 1024_i64 * 1024 * 1024)
        } else if let Some(n) = input.strip_suffix("gb").or_else(|| input.strip_suffix("g")) {
            (n, 1024_i64 * 1024 * 1024)
        } else if let Some(n) = input.strip_suffix("mi") {
            (n, 1024_i64 * 1024)
        } else if let Some(n) = input.strip_suffix("mb").or_else(|| input.strip_suffix("m")) {
            (n, 1024_i64 * 1024)
        } else if let Some(n) = input.strip_suffix("ki") {
            (n, 1024_i64)
        } else if let Some(n) = input.strip_suffix("kb").or_else(|| input.strip_suffix("k")) {
            (n, 1024_i64)
        } else if let Some(n) = input.strip_suffix("b") {
            (n, 1_i64)
        } else {
            (input.as_str(), 1_i64)
        };

        if let Ok(val) = num_str.parse::<i64>() {
            if val < 0 {
                return Err(anyhow::anyhow!(
                    "Memory limit must be non-negative, got '{}'",
                    input
                ));
            }
            if val == 0 {
                return Ok(0);
            }
            return Ok(val * multiplier);
        }
        let val_f: f64 = num_str.parse().context("Invalid memory limit string")?;
        if !val_f.is_finite() || val_f < 0.0 {
            return Err(anyhow::anyhow!(
                "Memory limit must be non-negative, got '{}'",
                input
            ));
        }
        if val_f == 0.0 {
            return Ok(0);
        }
        Ok((val_f * multiplier as f64) as i64)
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
    /// locate or initialize the rootless / system cgroups v2 hierarchy for a container or pod
    pub fn new(container_id: &str) -> Result<Self> {
        Self::new_with_parent(container_id, None)
    }

    pub fn new_with_parent(container_id: &str, cgroup_parent: Option<&str>) -> Result<Self> {
        let base_cgroup = Self::detect_cgroup_root();
        let parent_cgroup =
            if let Some(parent) = cgroup_parent.map(str::trim).filter(|s| !s.is_empty()) {
                if parent.starts_with('/') {
                    PathBuf::from("/sys/fs/cgroup").join(parent.trim_start_matches('/'))
                } else {
                    base_cgroup.join("app.slice").join(parent)
                }
            } else {
                base_cgroup.join("boxr")
            };
        let container_cgroup = parent_cgroup.join(container_id);

        if base_cgroup.exists() {
            let _ = fs::create_dir_all(&parent_cgroup);
            let app_slice = base_cgroup.join("app.slice");
            for ctl in ["+cpu", "+cpuset", "+memory", "+pids", "+io"] {
                let _ = fs::write(base_cgroup.join("cgroup.subtree_control"), ctl);
                if app_slice.exists() {
                    let _ = fs::write(app_slice.join("cgroup.subtree_control"), ctl);
                }
                let _ = fs::write(parent_cgroup.join("cgroup.subtree_control"), ctl);
            }
            if fs::create_dir_all(&container_cgroup).is_err() {
                if let Ok(entries) = fs::read_dir(&parent_cgroup) {
                    for entry in entries.flatten() {
                        if entry.path().is_dir() {
                            let _ = fs::remove_dir(entry.path());
                        }
                    }
                }
                let _ = fs::create_dir_all(&container_cgroup);
            }
        }

        Ok(Self {
            cgroup_path: container_cgroup,
        })
    }

    pub fn for_bundle(bundle_path: &std::path::Path) -> Result<Self> {
        let container_id = bundle_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("");
        let mut parent_opt = None;
        if let Ok(content) = fs::read_to_string(bundle_path.join("config.json")) {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(p) = val
                    .get("annotations")
                    .and_then(|a| a.get("boxr.cgroup-parent"))
                    .and_then(|v| v.as_str())
                {
                    parent_opt = Some(p.to_string());
                } else if let Some(p) = val
                    .get("linux")
                    .and_then(|l| l.get("cgroupParent"))
                    .and_then(|v| v.as_str())
                {
                    parent_opt = Some(p.to_string());
                }
            }
        }
        Self::new_with_parent(container_id, parent_opt.as_deref())
    }

    pub fn check_oom_killed(&self) -> bool {
        let events_file = self.cgroup_path.join("memory.events");
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

    /// Return the cgroup path for an ID without creating the directory.
    pub fn path_only(container_id: &str) -> Self {
        let base_cgroup = Self::detect_cgroup_root();
        let container_cgroup = base_cgroup.join("boxr").join(container_id);
        Self {
            cgroup_path: container_cgroup,
        }
    }

    pub fn from_path(cgroup_path: PathBuf) -> Self {
        Self { cgroup_path }
    }

    pub fn cgroup_path(&self) -> &std::path::Path {
        &self.cgroup_path
    }

    pub fn relative_cgroup_path(&self) -> String {
        let s = self.cgroup_path.to_string_lossy();
        if let Some(rest) = s.strip_prefix("/sys/fs/cgroup") {
            if rest.is_empty() {
                "/".to_string()
            } else {
                rest.to_string()
            }
        } else {
            s.to_string()
        }
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

        // Apply CPU quota/period (cgroups v2 and v1)
        if limits.cpu_quota_us.is_some() || limits.cpu_period_us.is_some() {
            let quota_str = match limits.cpu_quota_us {
                Some(q) if q > 0 => q.to_string(),
                _ => "max".to_string(),
            };
            let period = limits.cpu_period_us.unwrap_or(100_000);
            let val = format!("{} {}", quota_str, period);
            let _ = fs::write(self.cgroup_path.join("cpu.max"), val);
            if let Some(quota) = limits.cpu_quota_us {
                let _ = fs::write(self.cgroup_path.join("cpu.cfs_quota_us"), quota.to_string());
            }
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
        self.add_process_with_limits(pid, None)
    }

    pub fn add_process_with_limits(&self, pid: i32, limits: Option<&ResourceLimits>) -> Result<()> {
        if let Some(parent) = self.cgroup_path.parent() {
            let _ = fs::create_dir_all(parent);
            for ctl in ["+cpu", "+cpuset", "+memory", "+pids", "+io"] {
                let _ = fs::write(parent.join("cgroup.subtree_control"), ctl);
            }
        }
        if !self.cgroup_path.exists() {
            let _ = fs::create_dir_all(&self.cgroup_path);
        }
        if let Some(lim) = limits {
            let _ = self.apply_limits(lim);
        }
        if fs::write(self.cgroup_path.join("cgroup.procs"), pid.to_string()).is_err() {
            #[cfg(target_os = "linux")]
            {
                let scope_name = format!("boxr-cg-{}-{}.scope", pid, std::process::id());
                let pid_str = pid.to_string();
                let slice_name = self
                    .cgroup_path
                    .parent()
                    .and_then(|p| p.file_name())
                    .and_then(|n| n.to_str())
                    .filter(|n| n.ends_with(".slice"))
                    .unwrap_or("app.slice");
                let mut busctl_args = vec![
                    "--user".to_string(),
                    "call".to_string(),
                    "org.freedesktop.systemd1".to_string(),
                    "/org/freedesktop/systemd1".to_string(),
                    "org.freedesktop.systemd1.Manager".to_string(),
                    "StartTransientUnit".to_string(),
                    "ssa(sv)a(sa(sv))".to_string(),
                    scope_name.clone(),
                    "fail".to_string(),
                ];
                let mut props: Vec<(String, String, String)> = Vec::new();
                if let Some(lim) = limits {
                    if let Some(mem) = lim.memory_max_bytes.filter(|&m| m > 0) {
                        props.push(("MemoryMax".to_string(), "t".to_string(), mem.to_string()));
                    }
                    if let Some(res) = lim.memory_reservation_bytes.filter(|&m| m > 0) {
                        props.push(("MemoryLow".to_string(), "t".to_string(), res.to_string()));
                    }
                    if let Some(swap) = lim.memory_swap_max_bytes {
                        let swap_val = if swap < 0 {
                            u64::MAX
                        } else if let Some(mem) = lim.memory_max_bytes {
                            swap.saturating_sub(mem) as u64
                        } else {
                            swap as u64
                        };
                        props.push((
                            "MemorySwapMax".to_string(),
                            "t".to_string(),
                            swap_val.to_string(),
                        ));
                    }
                    if let Some(shares) = lim.cpu_shares {
                        let weight =
                            (1 + ((shares.saturating_sub(2)) * 9999) / 262142).clamp(1, 10000);
                        props.push(("CPUWeight".to_string(), "t".to_string(), weight.to_string()));
                    }
                    if let Some(pids) = lim.pids_max.filter(|&p| p > 0) {
                        props.push(("TasksMax".to_string(), "t".to_string(), pids.to_string()));
                    }
                }
                let prop_count = 3 + props.len();
                busctl_args.push(prop_count.to_string());
                busctl_args.extend([
                    "PIDs".to_string(),
                    "au".to_string(),
                    "1".to_string(),
                    pid_str.clone(),
                    "Delegate".to_string(),
                    "b".to_string(),
                    "1".to_string(),
                    "Slice".to_string(),
                    "s".to_string(),
                    slice_name.to_string(),
                ]);
                for (k, t, v) in props {
                    busctl_args.push(k);
                    busctl_args.push(t);
                    busctl_args.push(v);
                }
                busctl_args.push("0".to_string());
                let _ = std::process::Command::new("busctl")
                    .args(&busctl_args)
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status();
                let is_default_boxr_parent = self
                    .cgroup_path
                    .parent()
                    .and_then(|p| p.file_name())
                    .and_then(|n| n.to_str())
                    == Some("boxr");
                let proc_cg_file = format!("/proc/{}/cgroup", pid);
                for _ in 0..40 {
                    if let Ok(cg_txt) = fs::read_to_string(&proc_cg_file) {
                        if let Some(rel) = cg_txt.lines().find_map(|l| l.strip_prefix("0::")) {
                            let rel_trimmed = rel.trim();
                            if rel_trimmed.contains("user@") || rel_trimmed.contains(&scope_name) {
                                let cur_cg = PathBuf::from("/sys/fs/cgroup")
                                    .join(rel_trimmed.trim_start_matches('/'));
                                if cur_cg.exists() {
                                    if let Some(lim) = limits {
                                        let tmp_mgr = Self {
                                            cgroup_path: cur_cg.clone(),
                                        };
                                        let _ = tmp_mgr.apply_limits(lim);
                                    }
                                }
                                if !is_default_boxr_parent {
                                    if let Some(parent) = self.cgroup_path.parent() {
                                        let _ = fs::create_dir_all(parent);
                                        for ctl in ["+cpu", "+cpuset", "+memory", "+pids", "+io"] {
                                            let _ = fs::write(
                                                parent.join("cgroup.subtree_control"),
                                                ctl,
                                            );
                                        }
                                    }
                                    let _ = fs::create_dir_all(&self.cgroup_path);
                                    if let Some(lim) = limits {
                                        let _ = self.apply_limits(lim);
                                    }
                                    let _ =
                                        fs::write(self.cgroup_path.join("cgroup.procs"), &pid_str);
                                }
                                break;
                            }
                        }
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
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

    pub fn freeze_pid(pid: i32) {
        if let Ok(cg) = fs::read_to_string(format!("/proc/{pid}/cgroup")) {
            for line in cg.lines() {
                if let Some((_, rel)) = line.rsplit_once("::") {
                    let rel = rel.trim().trim_start_matches('/');
                    if !rel.is_empty() {
                        let p = PathBuf::from("/sys/fs/cgroup")
                            .join(rel)
                            .join("cgroup.freeze");
                        if p.exists() {
                            let _ = fs::write(p, "1");
                        }
                    }
                }
            }
        }
    }

    pub fn unfreeze_pid(pid: i32) {
        if let Ok(cg) = fs::read_to_string(format!("/proc/{pid}/cgroup")) {
            for line in cg.lines() {
                if let Some((_, rel)) = line.rsplit_once("::") {
                    let rel = rel.trim().trim_start_matches('/');
                    if !rel.is_empty() {
                        let p = PathBuf::from("/sys/fs/cgroup")
                            .join(rel)
                            .join("cgroup.freeze");
                        if p.exists() {
                            let _ = fs::write(p, "0");
                        }
                    }
                }
            }
        }
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
