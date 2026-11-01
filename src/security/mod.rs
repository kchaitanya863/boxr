#![allow(dead_code, unused_imports)]

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdMapping {
    pub container_id: u32,
    pub host_id: u32,
    pub size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootlessUserConfig {
    pub enabled: bool,
    pub uid_mappings: Vec<IdMapping>,
    pub gid_mappings: Vec<IdMapping>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UsernsMappingMode {
    pub keep_id: bool,
    pub keep_id_uid: Option<u32>,
    pub keep_id_gid: Option<u32>,
    pub nomap: bool,
    pub keep_id_uid: Option<u32>,
    pub keep_id_gid: Option<u32>,
    pub max_size: Option<u32>,
}

impl Default for RootlessUserConfig {
    fn default() -> Self {
        #[cfg(unix)]
        let (uid, gid) = {
            let u = unsafe { libc::getuid() };
            let g = unsafe { libc::getgid() };
            (u, g)
        };
        #[cfg(not(unix))]
        let (uid, gid) = (1000, 1000);

        Self {
            enabled: uid != 0,
            uid_mappings: vec![IdMapping {
                container_id: 0,
                host_id: uid,
                size: 1,
            }],
            gid_mappings: vec![IdMapping {
                container_id: 0,
                host_id: gid,
                size: 1,
            }],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubordinateRange {
    pub start: u32,
    pub count: u32,
}

impl RootlessUserConfig {
    /// Parse /etc/subuid or /etc/subgid file content for a matching username or UID
    pub fn parse_subid_content(
        content: &str,
        user_id: u32,
        username: Option<&str>,
    ) -> Option<SubordinateRange> {
        let uid_str = user_id.to_string();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 3 {
                let name_or_id = parts[0].trim();
                let matches_name = username.map(|u| u == name_or_id).unwrap_or(false);
                let matches_id = name_or_id == uid_str;
                if matches_name || matches_id {
                    if let (Ok(start), Ok(count)) = (
                        parts[1].trim().parse::<u32>(),
                        parts[2].trim().parse::<u32>(),
                    ) {
                        return Some(SubordinateRange { start, count });
                    }
                }
            }
        }
        None
    }

    /// Read all subordinate ranges from /etc/subuid or /etc/subgid for the current user.
    pub fn read_subordinate_ranges(is_gid: bool) -> Vec<SubordinateRange> {
        #[cfg(unix)]
        let (id, user_name) = {
            let u = if is_gid {
                unsafe { libc::getgid() }
            } else {
                unsafe { libc::getuid() }
            };
            let name = std::env::var("USER").ok();
            (u, name)
        };
        #[cfg(not(unix))]
        let (id, user_name): (u32, Option<String>) = (1000, None);

        let file_path = if is_gid { "/etc/subgid" } else { "/etc/subuid" };
        let Ok(content) = fs::read_to_string(file_path) else {
            return Vec::new();
        };
        let uid_str = id.to_string();
        let mut ranges = Vec::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() < 3 {
                continue;
            }
            let name_or_id = parts[0].trim();
            let matches_name = user_name
                .as_deref()
                .map(|u| u == name_or_id)
                .unwrap_or(false);
            let matches_id = name_or_id == uid_str;
            if !matches_name && !matches_id {
                continue;
            }
            if let (Ok(start), Ok(count)) = (
                parts[1].trim().parse::<u32>(),
                parts[2].trim().parse::<u32>(),
            ) {
                ranges.push(SubordinateRange { start, count });
            }
        }
        ranges
    }

    /// Read the first subordinate range from /etc/subuid or /etc/subgid on Linux
    pub fn read_subordinate_range(is_gid: bool) -> Option<SubordinateRange> {
        Self::read_subordinate_ranges(is_gid).into_iter().next()
    }

    /// Check if newuidmap and newgidmap helper binaries are installed on the system
    pub fn has_newidmap_binaries() -> bool {
        let has_uidmap = Path::new("/usr/bin/newuidmap").exists()
            || Path::new("/bin/newuidmap").exists()
            || std::process::Command::new("which")
                .arg("newuidmap")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
        let has_gidmap = Path::new("/usr/bin/newgidmap").exists()
            || Path::new("/bin/newgidmap").exists()
            || std::process::Command::new("which")
                .arg("newgidmap")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
        has_uidmap && has_gidmap
    }

    /// Configure UID and GID mapping for a target child PID in a new user namespace
    #[cfg(target_os = "linux")]
    pub fn setup_child_mappings(pid: i32) -> Result<()> {
        Self::setup_child_mappings_with_mode(pid, UsernsMappingMode::default())
    }

    /// Podman-compatible maps for `--userns=keep-id` / `nomap`, with default-map fallback.
    #[cfg(target_os = "linux")]
    pub fn setup_child_mappings_with_mode(pid: i32, mode: UsernsMappingMode) -> Result<()> {
        let (host_uid, host_gid) = unsafe { (libc::getuid(), libc::getgid()) };
        let sub_uid = Self::read_subordinate_ranges(false);
        let sub_gid = Self::read_subordinate_ranges(true);
        let sub_uid_first = sub_uid.first().copied();
        let sub_gid_first = sub_gid.first().copied();

        if mode.keep_id {
            let target_uid = mode.keep_id_uid.unwrap_or(host_uid);
            let target_gid = mode.keep_id_gid.unwrap_or(host_gid);
            let uid_maps =
                Self::keep_id_uid_mappings_ext(target_uid, host_uid, &sub_uid, mode.max_size);
            let gid_maps =
                Self::keep_id_uid_mappings_ext(target_gid, host_gid, &sub_gid, mode.max_size);
            if Self::apply_id_mappings(pid, &uid_maps, &gid_maps).is_ok() {
                return Ok(());
            }
        } else if mode.nomap {
            let uid_maps = Self::nomap_uid_mappings(sub_uid_first.as_ref());
            let gid_maps = Self::nomap_uid_mappings(sub_gid_first.as_ref());
            if Self::apply_id_mappings(pid, &uid_maps, &gid_maps).is_ok() {
                return Ok(());
            }
        }

        let mut uid_mappings = vec![IdMapping {
            container_id: 0,
            host_id: host_uid,
            size: 1,
        }];
        let mut gid_mappings = vec![IdMapping {
            container_id: 0,
            host_id: host_gid,
            size: 1,
        }];
        if let Some(u_range) = sub_uid_first {
            uid_mappings.push(IdMapping {
                container_id: 1,
                host_id: u_range.start,
                size: u_range.count,
            });
        }
        if let Some(g_range) = sub_gid_first {
            gid_mappings.push(IdMapping {
                container_id: 1,
                host_id: g_range.start,
                size: g_range.count,
            });
        }
        if Self::apply_id_mappings(pid, &uid_mappings, &gid_mappings).is_ok() {
            return Ok(());
        }

        if sub_uid_first.is_some() && sub_gid_first.is_some() && !Self::has_newidmap_binaries() {
            eprintln!(
                "boxr: install the 'uidmap' package (newuidmap/newgidmap) for full rootless UID/GID ranges; \
using single-ID mapping only (images requiring chown/--user may fail)"
            );
        }

        let cfg = RootlessUserConfig {
            enabled: true,
            uid_mappings,
            gid_mappings,
        };
        cfg.write_proc_mappings(pid)?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn keep_id_uid_mappings(host_id: u32, sub_ranges: &[SubordinateRange]) -> Vec<IdMapping> {
        Self::keep_id_uid_mappings_ext(host_id, host_id, sub_ranges, None)
    }

    #[cfg(target_os = "linux")]
    fn keep_id_uid_mappings_ext(
        target_id: u32,
        host_id: u32,
        sub_ranges: &[SubordinateRange],
        max_size: Option<u32>,
    ) -> Vec<IdMapping> {
        let mut maps = Vec::new();
        if let Some(r) = sub_ranges.first() {
            if let Some(sz) = max_size {
                if sz <= 1 {
                    maps.push(IdMapping {
                        container_id: target_id,
                        host_id,
                        size: 1,
                    });
                } else if target_id >= sz {
                    maps.push(IdMapping {
                        container_id: 0,
                        host_id: r.start,
                        size: sz - 1,
                    });
                    maps.push(IdMapping {
                        container_id: target_id,
                        host_id,
                        size: 1,
                    });
                } else {
                    if target_id > 0 {
                        maps.push(IdMapping {
                            container_id: 0,
                            host_id: r.start,
                            size: target_id,
                        });
                    }
                    maps.push(IdMapping {
                        container_id: target_id,
                        host_id,
                        size: 1,
                    });
                    let rem = sz - target_id - 1;
                    if rem > 0 {
                        maps.push(IdMapping {
                            container_id: target_id + 1,
                            host_id: r.start + target_id,
                            size: rem,
                        });
                    }
                }
                return maps;
            }
            if target_id > 0 {
                let first_size = target_id.min(r.count);
                if first_size > 0 {
                    maps.push(IdMapping {
                        container_id: 0,
                        host_id: r.start,
                        size: first_size,
                    });
                }
            }
            maps.push(IdMapping {
                container_id: target_id,
                host_id,
                size: 1,
            });
            if r.count > target_id {
                maps.push(IdMapping {
                    container_id: target_id + 1,
                    host_id: r.start + target_id,
                    size: r.count - target_id,
                });
            }
        } else {
            maps.push(IdMapping {
                container_id: target_id,
                host_id,
                size: 1,
            });
        }
        maps
    }

    #[cfg(target_os = "linux")]
    fn nomap_uid_mappings(sub: Option<&SubordinateRange>) -> Vec<IdMapping> {
        if let Some(r) = sub {
            vec![IdMapping {
                container_id: 0,
                host_id: r.start,
                size: r.count,
            }]
        } else {
            vec![IdMapping {
                container_id: 0,
                host_id: 0,
                size: 1,
            }]
        }
    }

    #[cfg(target_os = "linux")]
    fn apply_newidmap_mappings(pid: i32, uid_maps: &[IdMapping], gid_maps: &[IdMapping]) -> bool {
        if !Self::has_newidmap_binaries() {
            return false;
        }
        let mut uid_args = vec![pid.to_string()];
        for m in uid_maps {
            uid_args.push(m.container_id.to_string());
            uid_args.push(m.host_id.to_string());
            uid_args.push(m.size.to_string());
        }
        let mut gid_args = vec![pid.to_string()];
        for m in gid_maps {
            gid_args.push(m.container_id.to_string());
            gid_args.push(m.host_id.to_string());
            gid_args.push(m.size.to_string());
        }
        let uid_status = std::process::Command::new("newuidmap")
            .args(&uid_args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        let gid_status = std::process::Command::new("newgidmap")
            .args(&gid_args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        matches!(
            (uid_status, gid_status),
            (Ok(u_st), Ok(g_st)) if u_st.success() && g_st.success()
        )
    }

    #[cfg(target_os = "linux")]
    pub fn apply_id_mappings(
        pid: i32,
        uid_maps: &[IdMapping],
        gid_maps: &[IdMapping],
    ) -> Result<()> {
        let cfg = RootlessUserConfig {
            enabled: true,
            uid_mappings: uid_maps.to_vec(),
            gid_mappings: gid_maps.to_vec(),
        };
        // Prefer newuidmap/newgidmap first: direct procfs mapping leaves setgroups at "deny"
        // on some hosts when allow cannot be restored (075-exec supplementary groups).
        if Self::apply_newidmap_mappings(pid, uid_maps, gid_maps) {
            Self::reenable_setgroups_for_pid(pid);
            return Ok(());
        }
        if cfg.write_proc_mappings(pid).is_ok() {
            return Ok(());
        }
        if Self::apply_newidmap_mappings(pid, uid_maps, gid_maps) {
            Self::reenable_setgroups_for_pid(pid);
            return Ok(());
        }
        cfg.write_proc_mappings(pid)
    }

    #[cfg(unix)]
    pub fn augment_maps_for_rootfs_setup(
        uid_maps: &[IdMapping],
        gid_maps: &[IdMapping],
    ) -> (Vec<IdMapping>, Vec<IdMapping>, bool) {
        let host_uid = unsafe { libc::getuid() };
        let host_gid = unsafe { libc::getgid() };
        const SETUP_ID: u32 = 65534;

        fn container_to_host(maps: &[IdMapping], cid: u32) -> Option<u32> {
            for m in maps {
                let end = m.container_id.saturating_add(m.size);
                if cid >= m.container_id && cid < end {
                    return Some(m.host_id + (cid - m.container_id));
                }
            }
            None
        }

        let uid_has_host = container_to_host(uid_maps, 0) == Some(host_uid);
        let gid_has_host = container_to_host(gid_maps, 0) == Some(host_gid);
        if uid_has_host && gid_has_host {
            return (uid_maps.to_vec(), gid_maps.to_vec(), false);
        }

        let mut u = uid_maps.to_vec();
        if !uid_has_host && container_to_host(&u, SETUP_ID).is_none() {
            u.push(IdMapping {
                container_id: SETUP_ID,
                host_id: host_uid,
                size: 1,
            });
        }
        let mut g = gid_maps.to_vec();
        if !gid_has_host && container_to_host(&g, SETUP_ID).is_none() {
            g.push(IdMapping {
                container_id: SETUP_ID,
                host_id: host_gid,
                size: 1,
            });
        }
        (u, g, !uid_has_host)
    }

    #[cfg(not(unix))]
    pub fn augment_maps_for_rootfs_setup(
        uid_maps: &[IdMapping],
        gid_maps: &[IdMapping],
    ) -> (Vec<IdMapping>, Vec<IdMapping>, bool) {
        (uid_maps.to_vec(), gid_maps.to_vec(), false)
    }

    /// Shift a host path to container uid/gid 0 on disk using the same ID maps as the container.
    #[cfg(target_os = "linux")]
    pub fn chown_path_as_mapped_root(
        path: &Path,
        uid_maps: &[IdMapping],
        gid_maps: &[IdMapping],
    ) -> Result<()> {
        use nix::sched::{CloneFlags, unshare};
        use nix::sys::wait::{WaitStatus, waitpid};
        use nix::unistd::{ForkResult, Gid, Uid, fork, setresgid, setresuid};
        use std::ffi::CString;
        use std::io::{Read, Write};
        use std::os::unix::net::UnixStream;

        fn chown_visit(path: &Path) -> Result<()> {
            let cstr = CString::new(path.to_string_lossy().as_ref())
                .with_context(|| format!("invalid path {:?}", path))?;
            let rc = unsafe { libc::chown(cstr.as_ptr(), 0, 0) };
            if rc != 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() != Some(libc::ENOENT) {
                    return Err(anyhow::anyhow!("chown {:?}: {}", path, err));
                }
            }
            if path.is_dir() {
                for entry in fs::read_dir(path).with_context(|| format!("read_dir {:?}", path))? {
                    let entry = entry?;
                    chown_visit(&entry.path())?;
                }
            }
            Ok(())
        }

        let (mut parent_sock, mut child_sock) = UnixStream::pair()?;
        match unsafe { fork() }? {
            ForkResult::Parent { child } => {
                drop(child_sock);
                let mut sync_buf = [0u8; 5];
                parent_sock.read_exact(&mut sync_buf)?;
                Self::apply_id_mappings(child.as_raw(), uid_maps, gid_maps)?;
                parent_sock.write_all(b"done")?;
                drop(parent_sock);
                match waitpid(child, None)? {
                    WaitStatus::Exited(_, 0) => Ok(()),
                    WaitStatus::Exited(_, code) => Err(anyhow::anyhow!(
                        "chown_path_as_mapped_root helper exited with {}",
                        code
                    )),
                    WaitStatus::Signaled(_, sig, _) => Err(anyhow::anyhow!(
                        "chown_path_as_mapped_root helper signaled with {}",
                        sig
                    )),
                    _ => Err(anyhow::anyhow!(
                        "chown_path_as_mapped_root helper wait failed"
                    )),
                }
            }
            ForkResult::Child => {
                drop(parent_sock);
                unshare(CloneFlags::CLONE_NEWUSER)?;
                let _ = fs::write("/proc/self/setgroups", "deny");
                child_sock.write_all(b"ready")?;
                let mut done = [0u8; 4];
                child_sock.read_exact(&mut done)?;
                drop(child_sock);
                let root_gid = Gid::from_raw(0);
                let root_uid = Uid::from_raw(0);
                setresgid(root_gid, root_gid, root_gid).context("setresgid in chown helper")?;
                setresuid(root_uid, root_uid, root_uid).context("setresuid in chown helper")?;
                if chown_visit(path).is_err() {
                    std::process::exit(1);
                }
                std::process::exit(0);
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn chown_path_as_mapped_root(
        _path: &Path,
        _uid_maps: &[IdMapping],
        _gid_maps: &[IdMapping],
    ) -> Result<()> {
        Ok(())
    }

    /// Configure UID and GID mapping for a target PID in Linux /proc/<pid>
    #[cfg(target_os = "linux")]
    pub fn write_proc_mappings(&self, pid: i32) -> Result<()> {
        let pid_str = pid.to_string();
        let proc_dir = Path::new("/proc").join(&pid_str);

        // In Linux unprivileged user namespaces, writing to gid_map requires first disabling setgroups
        let setgroups_path = proc_dir.join("setgroups");
        if setgroups_path.exists() {
            let _ = fs::write(&setgroups_path, "deny");
        }

        // Write uid_map: "<container_uid> <host_uid> <count>\n"
        let mut uid_content = String::new();
        for m in &self.uid_mappings {
            uid_content.push_str(&format!("{} {} {}\n", m.container_id, m.host_id, m.size));
        }
        fs::write(proc_dir.join("uid_map"), uid_content)
            .context("Failed to write uid_map in /proc")?;

        // Write gid_map: "<container_gid> <host_gid> <count>\n"
        let mut gid_content = String::new();
        for m in &self.gid_mappings {
            gid_content.push_str(&format!("{} {} {}\n", m.container_id, m.host_id, m.size));
        }
        fs::write(proc_dir.join("gid_map"), gid_content)
            .context("Failed to write gid_map in /proc")?;

        Self::enable_setgroups_for_pid(pid).context("Failed to enable setgroups after gid_map")?;

        Ok(())
    }

    /// Write `allow` to `/proc/<pid>/setgroups`, falling back to a user-ns helper when direct writes fail.
    #[cfg(target_os = "linux")]
    fn enable_setgroups_for_pid(pid: i32) -> Result<()> {
        if Self::write_setgroups_allow(pid).is_ok() {
            return Ok(());
        }
        Self::allow_setgroups_from_userns(pid, pid)
    }

    #[cfg(target_os = "linux")]
    fn write_setgroups_allow(pid: i32) -> Result<()> {
        let setgroups_path = Path::new("/proc").join(pid.to_string()).join("setgroups");
        if !setgroups_path.exists() {
            return Ok(());
        }
        fs::write(&setgroups_path, "allow").context("write /proc setgroups allow")?;
        let mode = fs::read_to_string(&setgroups_path).unwrap_or_default();
        if mode.trim() != "allow" {
            return Err(anyhow::anyhow!(
                "setgroups stuck at {} after writing allow",
                mode.trim()
            ));
        }
        Ok(())
    }

    /// Re-enable supplementary groups for a process in a rootless user namespace (075-exec parity).
    #[cfg(target_os = "linux")]
    pub fn reenable_setgroups_for_pid(pid: i32) {
        let _ = Self::enable_setgroups_for_pid(pid);
    }

    /// Join `anchor_pid`'s user namespace as namespaced root and write `allow` for `target_pid`.
    /// Required when the caller lives in the initial user namespace (host `boxr exec` parent).
    #[cfg(target_os = "linux")]
    pub fn allow_setgroups_from_userns(anchor_pid: i32, target_pid: i32) -> Result<()> {
        use nix::sched::{CloneFlags, setns};
        use nix::sys::wait::waitpid;
        use nix::unistd::{ForkResult, Gid, Uid, fork};

        match unsafe { fork() }? {
            ForkResult::Parent { child } => {
                waitpid(child, None).context("setgroups userns helper wait")?;
                Ok(())
            }
            ForkResult::Child => {
                if let Ok(f) = std::fs::File::open(format!("/proc/{anchor_pid}/ns/user")) {
                    let _ = setns(&f, CloneFlags::CLONE_NEWUSER);
                }
                let root_gid = Gid::from_raw(0);
                let root_uid = Uid::from_raw(0);
                let _ = nix::unistd::setresgid(root_gid, root_gid, root_gid);
                let _ = nix::unistd::setresuid(root_uid, root_uid, root_uid);
                let _ = fs::write("/proc/self/setgroups", "allow");
                let _ = Self::write_setgroups_allow(target_pid);
                std::process::exit(0);
            }
        }
    }

    /// After the parent finishes `uid_map` / `gid_map`, re-enable supplementary groups inside
    /// the user namespace. Rootless children write `deny` before mapping; without `allow`,
    /// entrypoints that call `setgroups` (e.g. official `postgres` images) fail with EPERM.
    #[cfg(target_os = "linux")]
    pub fn try_enable_setgroups_after_mapping() {
        let path = Path::new("/proc/self/setgroups");
        if !path.exists() {
            return;
        }
        if let Err(e) = fs::write(path, "allow") {
            static WARN_ONCE: std::sync::Once = std::sync::Once::new();
            WARN_ONCE.call_once(|| {
                let _ = e;
                // Intentionally quiet: stderr from this path is often captured in container logs.
            });
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn try_enable_setgroups_after_mapping() {}
}

pub mod caps;
pub mod seccomp;

#[cfg(test)]
mod tests;

pub use caps::*;
pub use seccomp::*;
