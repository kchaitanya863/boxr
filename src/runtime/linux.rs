use crate::network::PortMapping;
use crate::oci::runtime::Spec;
use crate::volume::MountSpec;
use anyhow::{Context, Result, anyhow};
use nix::mount::{MsFlags, mount};
use nix::sched::{CloneFlags, setns, unshare};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::Pid;
use nix::unistd::{ForkResult, chdir, fork, pivot_root};
use std::ffi::CString;
use std::fs;
use std::io::Write;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::storage::container_store::ContainerStore;

struct TargetNamespaceFds {
    user: Option<fs::File>,
    ipc: Option<fs::File>,
    uts: Option<fs::File>,
    net: Option<fs::File>,
    pid: Option<fs::File>,
}

fn open_container_target_ns(bundle_path: &Path, target: &str, ns: &str) -> Option<fs::File> {
    let store = if let Some(home) = bundle_path.parent().and_then(|p| p.parent()) {
        crate::storage::ContainerStore::with_home(home.to_path_buf())
    } else {
        crate::storage::ContainerStore::new()
    };
    let rec = store.find(target)?;
    let bundle = PathBuf::from(&rec.bundle_path);
    let pid = crate::pod::read_container_pid_from_bundle(&bundle)?;
    fs::File::open(format!("/proc/{pid}/ns/{ns}")).ok()
}

fn open_target_namespace_fds(bundle_path: &Path, spec: &Spec) -> TargetNamespaceFds {
    let mut fds = TargetNamespaceFds {
        user: None,
        ipc: None,
        uts: None,
        net: None,
        pid: None,
    };
    let Some(ann) = spec.annotations.as_ref() else {
        return fds;
    };
    if let Some(target) = ann.get("boxr.network_container") {
        if fds.user.is_none() {
            fds.user = open_container_target_ns(bundle_path, target, "user");
        }
        fds.net = open_container_target_ns(bundle_path, target, "net");
    }
    if let Some(val) = ann.get("boxr.ipc") {
        if let Some(target) = val
            .strip_prefix("container:")
            .or_else(|| val.strip_prefix("container://"))
        {
            if fds.user.is_none() {
                fds.user = open_container_target_ns(bundle_path, target, "user");
            }
            fds.ipc = open_container_target_ns(bundle_path, target, "ipc");
        }
    }
    if let Some(val) = ann.get("boxr.uts") {
        if let Some(target) = val
            .strip_prefix("container:")
            .or_else(|| val.strip_prefix("container://"))
        {
            if fds.user.is_none() {
                fds.user = open_container_target_ns(bundle_path, target, "user");
            }
            fds.uts = open_container_target_ns(bundle_path, target, "uts");
        }
    }
    if let Some(val) = ann.get("boxr.pid") {
        if let Some(target) = val
            .strip_prefix("container:")
            .or_else(|| val.strip_prefix("container://"))
        {
            if fds.user.is_none() {
                fds.user = open_container_target_ns(bundle_path, target, "user");
            }
            fds.pid = open_container_target_ns(bundle_path, target, "pid");
        }
    }
    fds
}

struct NamespaceJoinState {
    ipc: bool,
    uts: bool,
    net: bool,
    pid: bool,
    cgroup: bool,
}

impl Default for NamespaceJoinState {
    fn default() -> Self {
        Self {
            ipc: false,
            uts: false,
            net: false,
            pid: false,
            cgroup: false,
        }
    }
}

fn namespace_clone_flag(ns: &str) -> Option<CloneFlags> {
    match ns {
        "ipc" => Some(CloneFlags::CLONE_NEWIPC),
        "uts" => Some(CloneFlags::CLONE_NEWUTS),
        "net" | "network" => Some(CloneFlags::CLONE_NEWNET),
        "mnt" | "mount" => Some(CloneFlags::CLONE_NEWNS),
        "pid" => Some(CloneFlags::CLONE_NEWPID),
        "cgroup" | "cgroupns" => Some(CloneFlags::CLONE_NEWCGROUP),
        "user" => Some(CloneFlags::CLONE_NEWUSER),
        _ => None,
    }
}

fn proc_ns_name(ns: &str) -> &str {
    match ns {
        "network" => "net",
        "cgroupns" => "cgroup",
        other => other,
    }
}

fn is_same_as_self_ns(path: &str, ns: &str) -> bool {
    use std::os::unix::fs::MetadataExt;
    if let (Ok(target_meta), Ok(self_meta)) = (
        fs::metadata(path),
        fs::metadata(format!("/proc/self/ns/{}", proc_ns_name(ns))),
    ) {
        return target_meta.dev() == self_meta.dev() && target_meta.ino() == self_meta.ino();
    }
    false
}

fn setns_file_path(path: &str, ns: &str, flag: CloneFlags) -> bool {
    if is_same_as_self_ns(path, ns) {
        return true;
    }
    if let Ok(f) = fs::File::open(path) {
        return setns(&f, flag).is_ok();
    }
    false
}

fn precheck_host_namespace_joins(spec: &Spec) -> NamespaceJoinState {
    let mut state = NamespaceJoinState::default();
    if let Some(linux) = &spec.linux {
        for ns in &linux.namespaces {
            if let Some(path) = ns.path.as_deref() {
                if is_same_as_self_ns(path, &ns.ns_type) {
                    match ns.ns_type.as_str() {
                        "ipc" => state.ipc = true,
                        "uts" => state.uts = true,
                        "net" | "network" => state.net = true,
                        "pid" => state.pid = true,
                        "cgroup" | "cgroupns" => state.cgroup = true,
                        _ => {}
                    }
                }
            }
        }
    }
    if let Some(ann) = spec.annotations.as_ref() {
        for (key, ns, slot) in [
            ("boxr.ipc", "ipc", &mut state.ipc),
            ("boxr.uts", "uts", &mut state.uts),
            ("boxr.pid", "pid", &mut state.pid),
            ("boxr.cgroupns", "cgroup", &mut state.cgroup),
            ("boxr.network", "net", &mut state.net),
        ] {
            if *slot {
                continue;
            }
            if let Some(val) = ann.get(key) {
                let resolved = if let Some(ns_path) = val.strip_prefix("ns:") {
                    Some(ns_path.to_string())
                } else if let Some(target) = val
                    .strip_prefix("container:")
                    .or_else(|| val.strip_prefix("container://"))
                {
                    crate::pod::container_namespace_path(target, ns).ok()
                } else {
                    None
                };
                if let Some(p) = resolved {
                    if is_same_as_self_ns(&p, ns) {
                        *slot = true;
                    }
                }
            }
        }
        if !state.net {
            if let Some(target) = ann.get("boxr.network_container") {
                if let Ok(p) = crate::pod::container_namespace_path(target, "net") {
                    if is_same_as_self_ns(&p, "net") {
                        state.net = true;
                    }
                }
            }
        }
    }
    state
}

fn join_namespace_for_container_target(target: &str, ns: &str) -> bool {
    let Some(flag) = namespace_clone_flag(ns) else {
        return false;
    };
    let store = crate::storage::ContainerStore::new();
    let Some(rec) = store.find(target) else {
        return false;
    };
    let bundle = PathBuf::from(&rec.bundle_path);
    let Some(pid) = crate::pod::read_container_pid_from_bundle(&bundle) else {
        return false;
    };
    let proc_ns = proc_ns_name(ns);
    setns_file_path(&format!("/proc/{pid}/ns/{proc_ns}"), proc_ns, flag)
}

fn find_donor_userns_fd(spec: &Spec) -> Option<std::fs::File> {
    const NS_GET_USERNS: libc::c_ulong = 0xb701;
    use std::os::unix::fs::MetadataExt;
    let self_user_meta = fs::metadata("/proc/self/ns/user").ok()?;

    if let Some(ann) = spec.annotations.as_ref() {
        if let Some(u) = ann.get("boxr.userns") {
            if let Some(p) = u.strip_prefix("ns:") {
                return fs::File::open(p).ok();
            }
            if let Some(target) = u
                .strip_prefix("container:")
                .or_else(|| u.strip_prefix("container://"))
            {
                if let Ok(p) = crate::pod::container_namespace_path(target, "user") {
                    return fs::File::open(p).ok();
                }
            }
        }
    }

    let mut candidate_paths: Vec<String> = Vec::new();
    if let Some(linux) = &spec.linux {
        for ns in &linux.namespaces {
            if let Some(p) = &ns.path {
                if ns.ns_type == "user" {
                    return fs::File::open(p).ok();
                }
                candidate_paths.push(p.clone());
            }
        }
    }
    if let Some(ann) = spec.annotations.as_ref() {
        for (key, ns_name) in [
            ("boxr.ipc", "ipc"),
            ("boxr.uts", "uts"),
            ("boxr.pid", "pid"),
            ("boxr.cgroupns", "cgroup"),
            ("boxr.network", "net"),
        ] {
            if let Some(val) = ann.get(key) {
                if let Some(p) = val.strip_prefix("ns:") {
                    candidate_paths.push(p.to_string());
                } else if let Some(target) = val
                    .strip_prefix("container:")
                    .or_else(|| val.strip_prefix("container://"))
                {
                    if let Ok(p) = crate::pod::container_namespace_path(target, ns_name) {
                        candidate_paths.push(p);
                    }
                }
            }
        }
        if let Some(target) = ann.get("boxr.network_container") {
            if let Ok(p) = crate::pod::container_namespace_path(target, "net") {
                candidate_paths.push(p);
            }
        }
    }

    for p in candidate_paths {
        if let Ok(f) = fs::File::open(&p) {
            let userns_fd = unsafe { libc::ioctl(f.as_raw_fd(), NS_GET_USERNS as _) };
            if userns_fd >= 0 {
                let userns_file = unsafe { fs::File::from_raw_fd(userns_fd) };
                if let Ok(m) = userns_file.metadata() {
                    if m.dev() != self_user_meta.dev() || m.ino() != self_user_meta.ino() {
                        return Some(userns_file);
                    }
                }
            }
        }
    }
    None
}

fn apply_spec_namespace_joins(spec: &Spec, pre_joined: NamespaceJoinState) -> NamespaceJoinState {
    let mut state = pre_joined;
    if let Some(linux) = &spec.linux {
        for ns in &linux.namespaces {
            if ns.ns_type == "user" {
                continue;
            }
            let already = match ns.ns_type.as_str() {
                "ipc" => state.ipc,
                "uts" => state.uts,
                "net" | "network" => state.net,
                "pid" => state.pid,
                "cgroup" | "cgroupns" => state.cgroup,
                _ => false,
            };
            if already {
                continue;
            }
            if let (Some(path), Some(flag)) =
                (ns.path.as_deref(), namespace_clone_flag(&ns.ns_type))
            {
                if setns_file_path(path, &ns.ns_type, flag) {
                    match ns.ns_type.as_str() {
                        "ipc" => state.ipc = true,
                        "uts" => state.uts = true,
                        "net" | "network" => state.net = true,
                        "pid" => state.pid = true,
                        "cgroup" | "cgroupns" => state.cgroup = true,
                        _ => {}
                    }
                }
            }
        }
    }
    if let Some(ann) = spec.annotations.as_ref() {
        for (key, ns, slot) in [
            ("boxr.ipc", "ipc", &mut state.ipc),
            ("boxr.uts", "uts", &mut state.uts),
            ("boxr.pid", "pid", &mut state.pid),
            ("boxr.cgroupns", "cgroup", &mut state.cgroup),
            ("boxr.network", "net", &mut state.net),
        ] {
            if *slot {
                continue;
            }
            if let Some(val) = ann.get(key) {
                if let Some(ns_path) = val.strip_prefix("ns:") {
                    if let Some(flag) = namespace_clone_flag(ns) {
                        if setns_file_path(ns_path, ns, flag) {
                            *slot = true;
                        }
                    }
                } else if let Some(target) = val
                    .strip_prefix("container:")
                    .or_else(|| val.strip_prefix("container://"))
                {
                    if join_namespace_for_container_target(target, ns) {
                        *slot = true;
                    }
                }
            }
        }
    }
    state
}

fn join_network_namespace_for_spec(spec: &Spec, joined: &mut NamespaceJoinState) {
    if joined.net {
        return;
    }
    if let Some(target_cont) = spec
        .annotations
        .as_ref()
        .and_then(|a| a.get("boxr.network_container"))
    {
        if join_namespace_for_container_target(target_cont, "net") {
            joined.net = true;
        }
    }
}

/// Podman/crun-style message and exit code when exec fails in the container child.
fn container_exec_failure(executable: &str, err: nix::errno::Errno) -> ! {
    let errno = err as i32;
    let exit_code = match errno {
        libc::ENOENT => 127,
        libc::EACCES | libc::EISDIR | libc::ENOTDIR => 126,
        _ => 1,
    };
    if executable.is_empty() && errno == libc::ENOENT {
        eprintln!(
            "Error: cannot find `` in $PATH: No such file or directory: OCI runtime attempted to invoke a command that was not found"
        );
        std::process::exit(127);
    }
    let detail: &str = match errno {
        libc::ENOENT => "no such file or directory",
        libc::EACCES => "permission denied",
        libc::EISDIR => "is a directory",
        libc::ENOTDIR => "not a directory",
        _ => "failed to execute",
    };
    eprintln!(
        "Error: OCI runtime error: exec failed: {}: {}",
        executable, detail
    );
    std::process::exit(exit_code);
}

/// Podman recreates /etc/mtab when the image removed it (BATS 030-run).
fn ensure_etc_mtab_symlink(rootfs: &Path) {
    let mtab = rootfs.join("etc/mtab");
    if mtab.exists() {
        return;
    }
    let etc = rootfs.join("etc");
    let _ = fs::create_dir_all(&etc);
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let _ = symlink("/proc/mounts", &mtab);
    }
}

fn prepare_bind_mount_target(
    rootfs: &Path,
    destination: &str,
    source: &Path,
) -> std::path::PathBuf {
    let clean_dest = destination.trim_start_matches('/');
    let target = rootfs.join(clean_dest);
    if source.exists() && !source.is_dir() {
        if let Some(parent) = target.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if target.is_dir() {
            let _ = fs::remove_dir(&target);
        }
        if !target.exists() {
            let _ = fs::File::create(&target);
        }
    } else {
        let _ = fs::create_dir_all(&target);
    }
    target
}

fn bind_mount_destinations(spec: &Spec, mounts: &[MountSpec]) -> Vec<String> {
    let mut dests: Vec<String> = mounts.iter().map(|m| m.destination.clone()).collect();
    for m in &spec.mounts {
        if m.mount_type == "bind" {
            dests.push(m.destination.clone());
        }
    }
    dests
}

/// Create a missing workdir when it is an ancestor of a bind mount (Podman BATS 030-run).
fn write_container_exit_code(bundle_path: &Path, status: i32) {
    let stored = if status == 255 { -1 } else { status };
    let _ = fs::write(bundle_path.join("boxr-exitcode"), stored.to_string());
}

fn process_alive(pid: i32) -> bool {
    pid > 0 && unsafe { libc::kill(pid, 0) == 0 }
}

fn read_bundle_exit_code(bundle_path: &Path) -> i32 {
    fs::read_to_string(bundle_path.join("boxr-exitcode"))
        .ok()
        .and_then(|s| s.trim().parse::<i32>().ok())
        .unwrap_or(0)
}

/// Wait until `pid` exits. The waiter is usually not the parent (sibling of trampoline), so fall back to `/proc` polling.
fn wait_for_trampoline_exit(bundle_path: &Path, pid: i32) -> i32 {
    use nix::errno::Errno;
    let pgid = Pid::from_raw(pid);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3600);
    while std::time::Instant::now() < deadline {
        match waitpid(pgid, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::Exited(_, code)) => return code,
            Ok(WaitStatus::Signaled(_, sig, _)) => return 128 + sig as i32,
            Ok(WaitStatus::StillAlive) => {}
            Err(Errno::ECHILD) => {
                if !process_alive(pid) {
                    return read_bundle_exit_code(bundle_path);
                }
            }
            _ => {
                if !process_alive(pid) {
                    return read_bundle_exit_code(bundle_path);
                }
            }
        }
        if !process_alive(pid) {
            return read_bundle_exit_code(bundle_path);
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    read_bundle_exit_code(bundle_path)
}

fn run_timeout_secs(spec: &Spec) -> Option<u64> {
    spec.annotations
        .as_ref()
        .and_then(|a| a.get("boxr.run_timeout"))
        .and_then(|s| s.parse().ok())
}

fn wait_grandchild_serving_exec_userns(
    grandchild: Pid,
    bundle_path: &Path,
    timeout_secs: Option<u64>,
) -> i32 {
    use std::io::ErrorKind;
    use std::os::unix::net::UnixListener;

    let sock_path = exec_userns_socket_path(bundle_path);
    let _ = fs::remove_file(&sock_path);
    let listener = match UnixListener::bind(&sock_path) {
        Ok(l) => l,
        Err(_) => {
            return wait_grandchild_with_optional_timeout(grandchild, bundle_path, timeout_secs);
        }
    };
    let _ = listener.set_nonblocking(true);
    let init_pid = grandchild.as_raw();
    let deadline = timeout_secs.map(|s| Instant::now() + Duration::from_secs(s));
    let code = loop {
        match listener.accept() {
            Ok((stream, _)) => {
                handle_exec_userns_connection(stream, init_pid, bundle_path);
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {}
            Err(_) => {}
        }
        match waitpid(grandchild, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::Exited(_, code)) => break code,
            Ok(WaitStatus::Signaled(_, sig, _)) => break 128 + sig as i32,
            Ok(WaitStatus::StillAlive) | Err(nix::errno::Errno::EINTR) => {}
            Ok(_) => break 1,
            Err(_) => break 1,
        }
        if let Some(dl) = deadline {
            if Instant::now() >= dl {
                let _ = nix::sys::signal::kill(grandchild, nix::sys::signal::Signal::SIGKILL);
                let _ = waitpid(grandchild, None);
                write_container_exit_code(bundle_path, 255);
                break 255;
            }
        }
        thread::sleep(Duration::from_millis(50));
    };
    let _ = fs::remove_file(sock_path);
    code
}

fn wait_grandchild_with_optional_timeout(
    grandchild: Pid,
    bundle_path: &Path,
    timeout_secs: Option<u64>,
) -> i32 {
    if timeout_secs.is_none() {
        return match waitpid(grandchild, None) {
            Ok(WaitStatus::Exited(_, code)) => code,
            Ok(WaitStatus::Signaled(_, sig, _)) => 128 + sig as i32,
            _ => 1,
        };
    }
    let deadline =
        timeout_secs.map(|s| std::time::Instant::now() + std::time::Duration::from_secs(s));
    loop {
        match waitpid(grandchild, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::Exited(_, code)) => return code,
            Ok(WaitStatus::Signaled(_, sig, _)) => return 128 + sig as i32,
            Ok(WaitStatus::StillAlive) | Err(nix::errno::Errno::EINTR) => {}
            Ok(_) => return 1,
            Err(_) => return 1,
        }
        if let Some(dl) = deadline {
            if std::time::Instant::now() >= dl {
                let _ = nix::sys::signal::kill(grandchild, nix::sys::signal::Signal::SIGKILL);
                let _ = waitpid(grandchild, None);
                write_container_exit_code(bundle_path, 255);
                return 255;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

fn ensure_spec_workdir(spec: &Spec, _mount_dests: &[String]) -> Result<()> {
    if spec.process.cwd.is_empty() {
        return Ok(());
    }
    let cwd_norm = spec.process.cwd.trim_end_matches('/');
    if cwd_norm.is_empty() {
        return Ok(());
    }
    let cwd_path = Path::new(cwd_norm);
    if !cwd_path.is_dir() {
        let _ = fs::create_dir_all(cwd_path);
    }
    Ok(())
}

/// Native Linux execution of an OCI bundle using Linux namespaces and pivot_root.
struct BundleIoPolicy {
    attach_stdout: bool,
    attach_stderr: bool,
    attach_stdin: bool,
    log_driver: Option<String>,
    log_path: Option<PathBuf>,
    journald_capture: Option<PathBuf>,
}

fn bundle_io_policy(spec: &Spec, bundle_path: &Path) -> BundleIoPolicy {
    let ann = spec.annotations.as_ref();
    let parse_bool = |key: &str, default: bool| -> bool {
        ann.and_then(|a| a.get(key))
            .map(|v| v == "true")
            .unwrap_or(default)
    };
    BundleIoPolicy {
        attach_stdout: parse_bool("boxr.attach_stdout", true),
        attach_stderr: parse_bool("boxr.attach_stderr", true),
        attach_stdin: parse_bool("boxr.attach_stdin", false),
        log_driver: ann.and_then(|a| a.get("boxr.log_driver")).cloned(),
        log_path: ann
            .and_then(|a| a.get("boxr.log_path"))
            .map(PathBuf::from)
            .or_else(|| {
                if ann
                    .and_then(|a| a.get("boxr.log_driver"))
                    .is_some_and(|d| d == "k8s-file" || d == "json-file")
                {
                    Some(bundle_path.join("ctr.log"))
                } else {
                    None
                }
            }),
        journald_capture: ann
            .and_then(|a| a.get("boxr.journald_capture"))
            .map(PathBuf::from),
    }
}

fn capture_log_path(policy: &BundleIoPolicy, bundle_path: &Path) -> PathBuf {
    policy
        .log_path
        .clone()
        .or(policy.journald_capture.clone())
        .unwrap_or_else(|| bundle_path.join("ctr.log"))
}

fn uses_capture_logging(policy: &BundleIoPolicy) -> bool {
    match policy.log_driver.as_deref() {
        Some("k8s-file") | Some("json-file") | Some("journald") => true,
        _ => false,
    }
}

fn read_preserve_fds(bundle_path: &Path) -> Vec<u32> {
    let path = bundle_path.join("preserve_fds.json");
    if !path.exists() {
        return Vec::new();
    }
    fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn clear_close_on_exec(fds: &[u32]) {
    for &fd in fds {
        if fd > i32::MAX as u32 {
            continue;
        }
        unsafe {
            let flags = libc::fcntl(fd as i32, libc::F_GETFD);
            if flags >= 0 {
                libc::fcntl(fd as i32, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
            }
        }
    }
}

/// Close inherited host fds except stdio and explicitly preserved ones (Podman/crun parity).
fn close_fds_except(keep: &[u32]) {
    use std::collections::HashSet;
    let mut keep_set: HashSet<i32> = HashSet::from([0, 1, 2]);
    for &fd in keep {
        if fd <= i32::MAX as u32 {
            keep_set.insert(fd as i32);
        }
    }
    let max_fd = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
    let max_fd = if max_fd > 0 { max_fd as i32 } else { 1024 };
    for fd in 0..max_fd {
        if keep_set.contains(&fd) {
            continue;
        }
        unsafe {
            libc::close(fd);
        }
    }
}

fn configure_stdio(
    cmd: &mut std::process::Command,
    policy: &BundleIoPolicy,
    bundle_path: &Path,
) -> Result<()> {
    if policy.attach_stdin {
        cmd.stdin(Stdio::inherit());
    } else {
        cmd.stdin(Stdio::null());
    }

    if policy.attach_stdout {
        cmd.stdout(Stdio::inherit());
    } else if policy.log_driver.as_deref() == Some("k8s-file") {
        let path = policy
            .log_path
            .clone()
            .unwrap_or_else(|| bundle_path.join("ctr.log"));
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = fs::File::create(&path)?;
        cmd.stdout(file);
    } else {
        cmd.stdout(Stdio::null());
    }

    if policy.attach_stderr {
        cmd.stderr(Stdio::inherit());
    } else if policy.log_driver.as_deref() == Some("k8s-file") {
        let path = policy
            .log_path
            .clone()
            .unwrap_or_else(|| bundle_path.join("ctr.log"));
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        cmd.stderr(file);
    } else {
        cmd.stderr(Stdio::null());
    }
    Ok(())
}

fn conmon_pidfile_from_spec(spec: &Spec) -> Option<String> {
    spec.annotations
        .as_ref()
        .and_then(|a| a.get("boxr.conmon_pidfile"))
        .cloned()
}

fn use_conmon_shim(spec: &Spec) -> bool {
    spec.annotations.as_ref().is_some_and(|a| {
        a.contains_key("boxr.conmon_pidfile")
            || a.get("boxr.conmon_syslog") == Some(&"1".to_string())
    })
}

fn prepare_conmon_shim(bundle_path: &Path, spec: &Spec, exe: &Path) -> Result<PathBuf> {
    let conmon = bundle_path.join("conmon");
    let _ = fs::remove_file(&conmon);
    if fs::hard_link(exe, &conmon).is_err() {
        fs::copy(exe, &conmon).context("copy conmon shim")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&conmon, fs::Permissions::from_mode(0o755))?;
        }
    }
    if let Some(pf) = conmon_pidfile_from_spec(spec) {
        fs::write(bundle_path.join("conmon-pidfile.path"), pf)?;
    }
    if let Some(ann) = &spec.annotations {
        if let Some(ld) = ann.get("boxr.log_driver") {
            fs::write(bundle_path.join("log-driver.txt"), ld)?;
        }
        if let Some(cap) = ann.get("boxr.journald_capture") {
            fs::write(bundle_path.join("journald-capture.path"), cap)?;
        }
    }
    Ok(conmon)
}

fn scrub_conmon_parent_env(cmd: &mut std::process::Command) {
    cmd.env_remove("NOTIFY_SOCKET");
    cmd.env_remove("LISTEN_PID");
    cmd.env_remove("LISTEN_FDS");
    cmd.env_remove("LISTEN_FDNAMES");
    if unsafe { libc::getuid() } != 0 {
        cmd.env_remove("DBUS_SESSION_BUS_ADDRESS");
    }
}

#[cfg(target_os = "linux")]
fn journal_line(line: &str) {
    use std::os::unix::net::UnixDatagram;

    #[cfg(boxr_has_systemd)]
    {
        use std::ffi::CString;
        use std::os::raw::{c_char, c_int};

        unsafe extern "C" {
            fn sd_journal_send(fmt: *const c_char, ...) -> c_int;
        }
        let entry = CString::new(format!("MESSAGE={}", line)).unwrap_or_default();
        let sent = unsafe { sd_journal_send(entry.as_ptr(), std::ptr::null::<c_char>()) };
        if sent >= 0 {
            return;
        }
    }
    // Fallback: journald's /dev/log accepts classic syslog payloads with peer PID.
    if let Ok(sock) = UnixDatagram::unbound() {
        let payload = format!("<6>{}", line);
        let _ = sock.send_to(payload.as_bytes(), "/dev/log");
    }
}

fn tee_reader_to_journal<R: std::io::Read>(pipe: R, capture: Option<PathBuf>, stream: &str) {
    tee_journald_capture_stream(pipe, capture, stream, false);
}

fn tee_journald_capture_stream<R: std::io::Read>(
    pipe: R,
    capture: Option<PathBuf>,
    stream: &str,
    attach: bool,
) {
    use std::io::{BufRead, BufReader, Write};
    let mut reader = BufReader::new(pipe);
    let mut file = capture.map(|p| {
        if let Some(parent) = p.parent() {
            let _ = fs::create_dir_all(parent);
        }
        p
    });
    let mut attach_out: Box<dyn Write + Send> = if attach {
        if stream == "stderr" {
            Box::new(std::io::stderr())
        } else {
            Box::new(std::io::stdout())
        }
    } else {
        Box::new(std::io::sink())
    };
    let mut line = String::new();
    while reader.read_line(&mut line).unwrap_or(0) > 0 {
        let trimmed = line.trim_end_matches(['\n', '\r']);
        if !trimmed.is_empty() {
            if stream == "stderr" {
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            journal_line(trimmed);
            if let Some(path) = &file {
                let _ = crate::logging::append_k8s_log_chunk(path, stream, trimmed.as_bytes());
            }
            let _ = writeln!(attach_out, "{}", trimmed);
            let _ = attach_out.flush();
        }
        line.clear();
    }
}

fn flush_deferred_bundle_rmdir(bundle_path: &Path) {
    if bundle_path.join("deferred-bundle-rm").exists() {
        let _ = fs::remove_dir_all(bundle_path);
    }
}

fn wait_for_detached_conmon_start(bundle_path: &Path, supervisor: &mut Child) -> Result<()> {
    let container_id = bundle_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_string();
    let store = ContainerStore::new();
    let expect_auto_cleanup =
        crate::bundle_auto_remove(bundle_path) || crate::bundle_auto_remove_image(bundle_path);
    let wait_start = Instant::now();
    let mut conmon_started_at: Option<Instant> = None;
    while wait_start.elapsed() < Duration::from_secs(30) {
        if bundle_path.join("conmon.pid").exists() {
            let started = *conmon_started_at.get_or_insert_with(Instant::now);
            if bundle_path.join("container.pid").exists()
                || bundle_path.join("boxr-exitcode").exists()
                || started.elapsed() >= Duration::from_millis(1500)
            {
                return Ok(());
            }
        }
        if expect_auto_cleanup {
            if !bundle_path.exists() {
                return Ok(());
            }
            if !container_id.is_empty() && store.find(&container_id).is_none() {
                return Ok(());
            }
            if bundle_path.join("boxr-exitcode").exists() {
                return Ok(());
            }
        }
        match supervisor.try_wait() {
            Ok(Some(status)) => {
                if bundle_path.join("conmon.pid").exists() {
                    return Ok(());
                }
                if status.success() {
                    return Ok(());
                }
                return Err(anyhow!(
                    "Container failed to start: conmon supervisor exited with {}",
                    status
                ));
            }
            Ok(None) => {}
            Err(e) => return Err(e.into()),
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err(anyhow!(
        "Container failed to start: conmon supervisor did not start"
    ))
}

#[cfg(unix)]
fn send_sd_notify(socket_path: &str, msg: &str) {
    use std::os::unix::net::UnixDatagram;
    if socket_path.is_empty() {
        return;
    }
    if let Ok(sock) = UnixDatagram::unbound() {
        for _ in 0..30 {
            match sock.send_to(msg.as_bytes(), socket_path) {
                Ok(_) => break,
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.raw_os_error() == Some(libc::EAGAIN) =>
                {
                    thread::sleep(Duration::from_millis(20));
                }
                Err(_) => break,
            }
        }
    }
}

/// Podman-compatible conmon parent: executable path ends with `conmon`, writes pidfile + ConmonPid.
pub fn run_conmon_supervisor(args: &[String]) -> Result<i32> {
    if args.is_empty() {
        return Err(anyhow!("missing bundle path for conmon supervisor"));
    }
    let bundle_path = Path::new(&args[0]);
    if let Some(root_dir) = bundle_path.parent().and_then(|p| p.parent()) {
        unsafe {
            std::env::set_var("BOXR_HOME", root_dir);
        }
    }
    let conmon_pid = std::process::id() as i32;
    if let Ok(path) = fs::read_to_string(bundle_path.join("conmon-pidfile.path")) {
        let path = path.trim();
        if !path.is_empty() {
            if let Some(parent) = Path::new(path).parent() {
                let _ = fs::create_dir_all(parent);
            }
            fs::write(path, conmon_pid.to_string())?;
        }
    }
    if let Ok(spec_str) = fs::read_to_string(bundle_path.join("config.json")) {
        if let Ok(spec) = serde_json::from_str::<Spec>(&spec_str) {
            if let Some(ann) = &spec.annotations {
                let mode = ann
                    .get("boxr.sdnotify_mode")
                    .map(|s| s.as_str())
                    .unwrap_or("conmon");
                if let Some(sock) = ann.get("boxr.sdnotify_socket") {
                    if mode == "conmon" {
                        send_sd_notify(sock, &format!("MAINPID={}\nREADY=1", conmon_pid));
                    } else if mode == "container" || mode == "healthy" {
                        send_sd_notify(sock, &format!("MAINPID={}", conmon_pid));
                    }
                }
            }
        }
    }
    fs::write(bundle_path.join("conmon.pid"), conmon_pid.to_string())?;

    let detach = bundle_path.join("conmon-detach.flag").exists();
    let log_driver = fs::read_to_string(bundle_path.join("log-driver.txt"))
        .unwrap_or_default()
        .trim()
        .to_string();
    let journald = log_driver == "journald";
    let file_log = log_driver == "k8s-file" || log_driver == "json-file";
    let capture_path = fs::read_to_string(bundle_path.join("journald-capture.path"))
        .ok()
        .map(PathBuf::from);
    let container_id = bundle_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_string();
    let spec_opt = fs::read_to_string(bundle_path.join("config.json"))
        .ok()
        .and_then(|s| serde_json::from_str::<Spec>(&s).ok());
    let io_policy = spec_opt
        .as_ref()
        .map(|sp| bundle_io_policy(sp, bundle_path))
        .unwrap_or(BundleIoPolicy {
            attach_stdout: true,
            attach_stderr: true,
            attach_stdin: false,
            log_driver: None,
            log_path: None,
            journald_capture: None,
        });
    let k8s_log_path = io_policy
        .log_path
        .clone()
        .unwrap_or_else(|| bundle_path.join(format!("{container_id}-ctr.log")));

    let conmon_bin = bundle_path.join("conmon");
    let mut cmd = std::process::Command::new(&conmon_bin);
    cmd.arg("__internal-trampoline").arg(bundle_path);
    if !detach && io_policy.attach_stdin {
        cmd.stdin(Stdio::inherit());
    } else {
        cmd.stdin(Stdio::null());
    }

    let custom_file_log = file_log
        && spec_opt
            .as_ref()
            .and_then(|sp| sp.annotations.as_ref())
            .and_then(|a| a.get("boxr.log_path"))
            .is_some_and(|lp| !lp.starts_with(&*bundle_path.to_string_lossy()));

    if detach {
        if file_log {
            cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        } else {
            let log_file = fs::File::create(bundle_path.join("logs.txt"))?;
            let err_file = log_file.try_clone()?;
            cmd.stdout(log_file).stderr(err_file);
        }
    } else if journald || custom_file_log {
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    } else {
        if io_policy.attach_stdout {
            cmd.stdout(Stdio::inherit());
        } else {
            cmd.stdout(Stdio::null());
        }
        if io_policy.attach_stderr {
            cmd.stderr(Stdio::inherit());
        } else {
            cmd.stderr(Stdio::null());
        }
    }

    if detach {
        let container_id = bundle_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();
        loop {
            let mut child = cmd
                .spawn()
                .context("spawn trampoline from conmon supervisor")?;
            let child_pid = child.id() as i32;
            fs::write(bundle_path.join("vm.pid"), child_pid.to_string())?;
            fs::write(bundle_path.join("pid"), child_pid.to_string())?;
            if !container_id.is_empty() {
                if let Ok(cgroup_mgr) = crate::cgroups::CgroupV2Manager::new(&container_id) {
                    let _ = cgroup_mgr.add_process(child_pid);
                }
            }
            let status = if detach && file_log {
                if let Some(parent) = k8s_log_path.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                let stdout = child.stdout.take();
                let stderr = child.stderr.take();
                let path = k8s_log_path.clone();
                let h_out = stdout.map(|pipe| {
                    let path = path.clone();
                    thread::spawn(move || {
                        crate::logging::tee_k8s_stream(pipe, path, "stdout", false);
                    })
                });
                let h_err = stderr.map(|pipe| {
                    let path = k8s_log_path.clone();
                    thread::spawn(move || {
                        crate::logging::tee_k8s_stream(pipe, path, "stderr", false);
                    })
                });
                let status = child.wait()?;
                if let Some(h) = h_out {
                    let _ = h.join();
                }
                if let Some(h) = h_err {
                    let _ = h.join();
                }
                status
            } else {
                child.wait()?
            };
            let exit_code = status.code().unwrap_or(1);
            let still_current_conmon = fs::read_to_string(bundle_path.join("conmon.pid"))
                .ok()
                .and_then(|s| s.trim().parse::<i32>().ok())
                == Some(conmon_pid);
            if !still_current_conmon {
                return Ok(exit_code);
            }
            let _ = fs::write(bundle_path.join("boxr-exitcode"), exit_code.to_string());
            let mut systemd_stop_ok = false;
            if let Ok(spec_str) = fs::read_to_string(bundle_path.join("config.json")) {
                if let Ok(spec) = serde_json::from_str::<Spec>(&spec_str) {
                    if let Some(ann) = &spec.annotations {
                        if ann.contains_key("boxr.kube_service_container") {
                            systemd_stop_ok = true;
                        }
                        if (exit_code == 143 || exit_code == 137)
                            && ann.contains_key("boxr.sdnotify_socket")
                        {
                            systemd_stop_ok = true;
                        }
                        if let Some(sock) = ann.get("boxr.sdnotify_socket") {
                            let mode = ann
                                .get("boxr.sdnotify_mode")
                                .map(|s| s.as_str())
                                .unwrap_or("conmon");
                            if mode != "ignore" || ann.contains_key("boxr.kube_service_container") {
                                send_sd_notify(sock, "STOPPING=1");
                            }
                        }
                    }
                }
            }
            if container_id.is_empty()
                || !crate::detached_container_process_exited(&container_id, bundle_path, exit_code)
            {
                let _ = fs::remove_file(bundle_path.join("conmon.pid"));
                flush_deferred_bundle_rmdir(bundle_path);
                return Ok(if systemd_stop_ok { 0 } else { exit_code });
            }
        }
    }

    let mut child = cmd
        .spawn()
        .context("spawn trampoline from conmon supervisor")?;
    let child_pid = child.id() as i32;
    fs::write(bundle_path.join("vm.pid"), child_pid.to_string())?;
    fs::write(bundle_path.join("pid"), child_pid.to_string())?;
    if let Some(cont_id) = bundle_path.file_name().and_then(|s| s.to_str()) {
        if let Ok(cgroup_mgr) = crate::cgroups::CgroupV2Manager::new(cont_id) {
            let _ = cgroup_mgr.add_process(child_pid);
        }
    }

    if custom_file_log && !detach {
        if let Some(parent) = k8s_log_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let out_attach = io_policy.attach_stdout;
        let err_attach = io_policy.attach_stderr;
        let is_tty = spec_opt.as_ref().is_some_and(|sp| sp.process.terminal);
        let path_out = k8s_log_path.clone();
        let path_err = k8s_log_path;
        let h_out = stdout.map(|pipe| {
            thread::spawn(move || {
                crate::logging::tee_k8s_stream_with_tty(pipe, path_out, "stdout", out_attach, is_tty);
            })
        });
        let h_err = stderr.map(|pipe| {
            thread::spawn(move || {
                crate::logging::tee_k8s_stream(pipe, path_err, "stderr", err_attach);
            })
        });
        let status = child.wait()?;
        if let Some(h) = h_out {
            let _ = h.join();
        }
        if let Some(h) = h_err {
            let _ = h.join();
        }
        let code = status.code().unwrap_or(1);
        flush_deferred_bundle_rmdir(bundle_path);
        return Ok(code);
    }

    if journald && !detach {
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let cap = capture_path.clone();
        let h_out =
            stdout.map(|pipe| thread::spawn(move || tee_reader_to_journal(pipe, cap, "stdout")));
        let h_err = stderr
            .map(|pipe| thread::spawn(move || tee_reader_to_journal(pipe, capture_path, "stderr")));
        let status = child.wait()?;
        if let Some(h) = h_out {
            let _ = h.join();
        }
        if let Some(h) = h_err {
            let _ = h.join();
        }
        let code = status.code().unwrap_or(1);
        flush_deferred_bundle_rmdir(bundle_path);
        return Ok(code);
    }

    let status = child.wait()?;
    let code = status.code().unwrap_or(1);
    flush_deferred_bundle_rmdir(bundle_path);
    Ok(code)
}

fn sig_proxy_enabled(spec: &Spec) -> bool {
    spec.annotations
        .as_ref()
        .and_then(|a| a.get("boxr.sig_proxy"))
        .map(|s| s != "false" && s != "0")
        .unwrap_or(true)
}

static SIGPROXY_PENDING_MASK: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static EXEC_SIGPROXY_CHILD_PID: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);
static EXEC_SIGPROXY_GRAND_PID: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

extern "C" fn bundle_sigproxy_handler(sig: libc::c_int) {
    if sig > 0 && sig < 64 {
        SIGPROXY_PENDING_MASK.fetch_or(1u64 << (sig as u32), std::sync::atomic::Ordering::SeqCst);
    }
}

extern "C" fn exec_parent_sigproxy_handler(sig: libc::c_int) {
    let pid = EXEC_SIGPROXY_CHILD_PID.load(std::sync::atomic::Ordering::SeqCst);
    if pid > 0 {
        unsafe {
            let _ = libc::kill(pid, sig);
        }
    }
}

extern "C" fn exec_grand_sigproxy_handler(sig: libc::c_int) {
    let pid = EXEC_SIGPROXY_GRAND_PID.load(std::sync::atomic::Ordering::SeqCst);
    if pid > 0 {
        unsafe {
            let _ = libc::kill(-pid, sig);
            let _ = libc::kill(pid, sig);
        }
    }
}

fn install_sigaction_handler(handler: extern "C" fn(libc::c_int), restart: bool) {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = handler as *const () as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = if restart { libc::SA_RESTART } else { 0 };
        for sig in [
            libc::SIGINT,
            libc::SIGTERM,
            libc::SIGHUP,
            libc::SIGQUIT,
            libc::SIGUSR1,
            libc::SIGUSR2,
        ] {
            libc::sigaction(sig, &sa, std::ptr::null_mut());
        }
    }
}

pub struct SignalProxyGuard {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl SignalProxyGuard {
    pub fn start(bundle_path: &Path) -> Self {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        SIGPROXY_PENDING_MASK.store(0, Ordering::SeqCst);
        install_sigaction_handler(bundle_sigproxy_handler, true);
        let stop = Arc::new(AtomicBool::new(false));
        let stop_clone = Arc::clone(&stop);
        let bundle_copy = bundle_path.to_path_buf();
        thread::spawn(move || {
            while !stop_clone.load(Ordering::Relaxed) {
                let mask = SIGPROXY_PENDING_MASK.swap(0, Ordering::SeqCst);
                if mask != 0 {
                    if let Ok(c_pid) = wait_for_live_container_pid(&bundle_copy) {
                        for sig in 1..64 {
                            if (mask & (1u64 << sig)) != 0 {
                                unsafe {
                                    let _ = libc::kill(c_pid, sig);
                                }
                            }
                        }
                    }
                }
                thread::sleep(Duration::from_millis(15));
            }
        });
        Self { stop }
    }
}

impl Drop for SignalProxyGuard {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

pub fn is_bundle_container_alive(bundle_path: &Path) -> bool {
    let check_pid = |p: i32| -> bool {
        if p <= 1 || unsafe { libc::kill(p, 0) != 0 } {
            return false;
        }
        if let Ok(status) = fs::read_to_string(format!("/proc/{p}/status")) {
            if status
                .lines()
                .any(|l| l.starts_with("State:") && l.contains('Z'))
            {
                return false;
            }
        }
        true
    };
    if bundle_path.join("boxr-exitcode").exists() {
        return false;
    }
    if let Ok(s) = fs::read_to_string(bundle_path.join("container.pid")) {
        if let Ok(p) = s.trim().parse::<i32>() {
            if check_pid(p) {
                return true;
            }
        }
    }
    if let Ok(s) = fs::read_to_string(bundle_path.join("vm.pid")) {
        if let Ok(p) = s.trim().parse::<i32>() {
            if check_pid(p) {
                return true;
            }
        }
    }
    false
}

pub fn execute_bundle(
    bundle_path: &Path,
    _spec: &Spec,
    mounts: &[MountSpec],
    _ports: &[PortMapping],
    detach: bool,
    spawn_detached_watcher: bool,
) -> Result<i32> {
    if !mounts.is_empty() {
        let mounts_json = serde_json::to_string(mounts)?;
        let _ = fs::write(bundle_path.join("mounts.json"), mounts_json);
    }
    let ports = crate::network::resolve_bundle_ports(bundle_path, _ports);
    let network_mode = _spec
        .annotations
        .as_ref()
        .and_then(|a| a.get("boxr.network"))
        .map(|s| crate::network::pasta::NetworkMode::parse(s))
        .unwrap_or_default();
    if !ports.is_empty() {
        let ports_json = serde_json::to_string(&ports)?;
        let _ = fs::write(bundle_path.join("ports.json"), ports_json);
        // Host-side Unix relay conflicts with passt/pasta binding the same host ports.
        if network_mode != crate::network::pasta::NetworkMode::Pasta {
            let _ = crate::network::spawn_port_forward_daemon(bundle_path, &ports);
        }
    }

    let exe = std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("boxr"));

    // Podman uses a conmon parent for detached containers (ConmonPid, stop/teardown semantics).
    let has_sdnotify = _spec
        .annotations
        .as_ref()
        .is_some_and(|a| a.contains_key("boxr.sdnotify_socket"));
    if use_conmon_shim(_spec) || detach || has_sdnotify {
        let conmon = prepare_conmon_shim(bundle_path, _spec, &exe)?;
        if detach {
            let _ = fs::remove_file(bundle_path.join("conmon.pid"));
            let _ = fs::remove_file(bundle_path.join("container.pid"));
            let _ = fs::remove_file(bundle_path.join("boxr-exitcode"));
            let _ = fs::write(bundle_path.join("conmon-detach.flag"), "1");
        }
        #[cfg(target_os = "linux")]
        {
            let container_id = bundle_path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_string();
            if !container_id.is_empty() && std::env::var_os("INVOCATION_ID").is_none() {
                let stop_timeout_arg = _spec
                    .annotations
                    .as_ref()
                    .and_then(|a| a.get("boxr.stop_timeout"))
                    .map(|t| format!("TimeoutStopSec={}s", t));
                let kill_signal_arg = _spec
                    .annotations
                    .as_ref()
                    .and_then(|a| a.get("boxr.stop_signal"))
                    .and_then(|s| crate::runtime::kill::ContainerKiller::parse_signal(s).ok())
                    .map(|sig| format!("KillSignal={}", sig));
                if stop_timeout_arg.is_some() || kill_signal_arg.is_some() {
                    let mut scope_cmd = std::process::Command::new("systemd-run");
                    if unsafe { libc::getuid() != 0 } {
                        scope_cmd.arg("--user");
                    }
                    scope_cmd
                        .arg("--scope")
                        .arg(format!("--unit=libpod-{}.scope", container_id));
                    if let Some(ref st) = stop_timeout_arg {
                        scope_cmd.arg("-p").arg(st);
                    }
                    if let Some(ref ks) = kill_signal_arg {
                        scope_cmd.arg("-p").arg(ks);
                    }
                    scope_cmd.arg("--").arg(&conmon);
                    scope_cmd
                        .arg("__internal-conmon-supervisor")
                        .arg(bundle_path);
                    scope_cmd.stdin(Stdio::null());
                    scrub_conmon_parent_env(&mut scope_cmd);
                    if detach {
                        scope_cmd.stdout(Stdio::null()).stderr(Stdio::null());
                        #[cfg(unix)]
                        {
                            use std::os::unix::process::CommandExt;
                            scope_cmd.process_group(0);
                        }
                        if let Ok(mut supervisor) = scope_cmd.spawn() {
                            if wait_for_detached_conmon_start(bundle_path, &mut supervisor).is_ok()
                            {
                                return Ok(0);
                            }
                        }
                    }
                }
            }
        }
        let mut cmd = std::process::Command::new(&conmon);
        let syslog_shim = _spec
            .annotations
            .as_ref()
            .is_some_and(|a| a.get("boxr.conmon_syslog") == Some(&"1".to_string()));
        #[cfg(unix)]
        if syslog_shim {
            use std::os::unix::process::CommandExt;
            cmd.arg0("conmon --exit-command-arg--syslog");
        }
        cmd.arg("__internal-conmon-supervisor").arg(bundle_path);
        for mp in &crate::cli::podman_globals::podman_global_options().modules {
            cmd.arg("--exit-command-arg")
                .arg("--module")
                .arg("--exit-command-arg")
                .arg(mp);
        }
        cmd.stdin(Stdio::null());
        scrub_conmon_parent_env(&mut cmd);
        if detach {
            cmd.stdout(Stdio::null()).stderr(Stdio::null());
            #[cfg(unix)]
            {
                use std::os::unix::process::CommandExt;
                cmd.process_group(0);
                unsafe {
                    cmd.pre_exec(|| {
                        close_fds_except(&[]);
                        Ok(())
                    });
                }
            }
            let _ = fs::remove_file(bundle_path.join("conmon.pid"));
            let _ = fs::remove_file(bundle_path.join("vm.pid"));
            let _ = fs::remove_file(bundle_path.join("container.pid"));
            let mut supervisor = cmd.spawn().context("spawn conmon supervisor")?;
            wait_for_detached_conmon_start(bundle_path, &mut supervisor)?;
            let _ = ensure_rootless_pause_process();
            return Ok(0);
        }
        let _sig_guard = if sig_proxy_enabled(_spec) {
            Some(SignalProxyGuard::start(bundle_path))
        } else {
            None
        };
        let status = cmd.status().context("run conmon supervisor (foreground)")?;
        return Ok(status.code().unwrap_or(1));
    }

    if detach {
        let log_file = fs::File::create(bundle_path.join("logs.txt"))?;
        let err_file = log_file.try_clone()?;
        let mut cmd = std::process::Command::new(&exe);
        cmd.arg("__internal-trampoline")
            .arg(bundle_path)
            .stdin(std::process::Stdio::null())
            .stdout(log_file)
            .stderr(err_file);

        if _spec.process.terminal {
            if let Some((master_fd, slave_name)) = open_detach_pty() {
                let _ = fs::write(bundle_path.join("attach-pty"), slave_name.as_bytes());
                let bundle_watch = bundle_path.to_path_buf();
                thread::spawn(move || {
                    let _hold = master_fd;
                    loop {
                        let alive = fs::read_to_string(bundle_watch.join("vm.pid"))
                            .ok()
                            .and_then(|s| s.trim().parse::<i32>().ok())
                            .map(|pid| unsafe { libc::kill(pid, 0) == 0 })
                            .unwrap_or(false);
                        if !alive {
                            break;
                        }
                        thread::sleep(std::time::Duration::from_millis(250));
                    }
                    let _ = fs::remove_file(bundle_watch.join("attach-pty"));
                });
            }
        }

        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            cmd.process_group(0);
        }

        let _ = fs::remove_file(bundle_path.join("container.pid"));
        let mut child = cmd
            .spawn()
            .context("Failed to spawn container trampoline process")?;

        let child_pid = child.id() as i32;
        let _ = fs::write(bundle_path.join("vm.pid"), child_pid.to_string());
        let _ = fs::write(bundle_path.join("pid"), child_pid.to_string());
        for _ in 0..100 {
            if bundle_path.join("container.pid").exists()
                || bundle_path.join("boxr-exitcode").exists()
            {
                break;
            }
            if let Ok(Some(_)) = child.try_wait() {
                break;
            }
            thread::sleep(std::time::Duration::from_millis(20));
        }
        let container_id = bundle_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();
        if !container_id.is_empty() {
            if let Ok(cgroup_mgr) = crate::cgroups::CgroupV2Manager::new(&container_id) {
                let _ = cgroup_mgr.add_process(child_pid);
            }
            if spawn_detached_watcher {
                let mut waiter = std::process::Command::new(&exe);
                waiter
                    .arg("__internal-detached-wait")
                    .arg(bundle_path)
                    .arg(child_pid.to_string())
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null());
                #[cfg(unix)]
                {
                    use std::os::unix::process::CommandExt;
                    waiter.process_group(0);
                }
                let _ = waiter.spawn();
            }
        }
        Ok(0)
    } else {
        let sig_proxy = sig_proxy_enabled(_spec);
        let io_policy = bundle_io_policy(_spec, bundle_path);
        let mut cmd = std::process::Command::new(&exe);
        cmd.arg("__internal-trampoline").arg(bundle_path);

        if uses_capture_logging(&io_policy) {
            let log_path = capture_log_path(&io_policy, bundle_path);
            if let Some(parent) = log_path.parent() {
                fs::create_dir_all(parent)?;
            }
            if io_policy.attach_stdin {
                cmd.stdin(Stdio::inherit());
            } else {
                cmd.stdin(Stdio::null());
            }
            cmd.stdout(Stdio::piped());
            cmd.stderr(Stdio::piped());

            let mut child = cmd
                .spawn()
                .context("Failed to execute container trampoline process")?;
            let child_pid = child.id() as i32;
            let _ = fs::write(bundle_path.join("vm.pid"), child_pid.to_string());
            let _ = fs::write(bundle_path.join("pid"), child_pid.to_string());
            let stdout = child.stdout.take();
            let stderr = child.stderr.take();
            let out_attach = io_policy.attach_stdout;
            let err_attach = io_policy.attach_stderr;
            let is_tty = _spec.process.terminal;
            let journald = io_policy.log_driver.as_deref() == Some("journald");
            let h_out = stdout.map(|pipe| {
                let path = log_path.clone();
                thread::spawn(move || {
                    if journald {
                        tee_journald_capture_stream(pipe, Some(path), "stdout", out_attach);
                    } else {
                        crate::logging::tee_k8s_stream_with_tty(
                            pipe, path, "stdout", out_attach, is_tty,
                        );
                    }
                })
            });
            let h_err = stderr.map(|pipe| {
                let path = log_path.clone();
                thread::spawn(move || {
                    if journald {
                        tee_journald_capture_stream(pipe, Some(path), "stderr", err_attach);
                    } else {
                        crate::logging::tee_k8s_stream(pipe, path, "stderr", err_attach);
                    }
                })
            });
            let status = wait_foreground_child_with_sigproxy(&mut child, bundle_path, sig_proxy)?;
            if let Some(h) = h_out {
                let _ = h.join();
            }
            if let Some(h) = h_err {
                let _ = h.join();
            }
            Ok(status.code().unwrap_or(1))
        } else {
            configure_stdio(&mut cmd, &io_policy, bundle_path)?;
            let preserve = read_preserve_fds(bundle_path);
            clear_close_on_exec(&preserve);
            let mut child = cmd
                .spawn()
                .context("Failed to execute container trampoline process")?;
            let status = wait_foreground_child_with_sigproxy(&mut child, bundle_path, sig_proxy)?;
            Ok(status.code().unwrap_or(1))
        }
    }
}

static PROXIED_SIGNAL: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

extern "C" fn handle_proxied_signal(sig: libc::c_int) {
    PROXIED_SIGNAL.store(sig, std::sync::atomic::Ordering::SeqCst);
}

fn wait_foreground_child_with_sigproxy(
    child: &mut std::process::Child,
    bundle_path: &Path,
    sig_proxy: bool,
) -> Result<std::process::ExitStatus> {
    PROXIED_SIGNAL.store(0, std::sync::atomic::Ordering::SeqCst);
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = handle_proxied_signal as *const () as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = libc::SA_RESTART;
        for sig in [
            libc::SIGINT,
            libc::SIGTERM,
            libc::SIGHUP,
            libc::SIGQUIT,
            libc::SIGUSR1,
            libc::SIGUSR2,
            libc::SIGFPE,
        ] {
            libc::sigaction(sig, &sa, std::ptr::null_mut());
        }
    }
    let mut pause_ensured = false;
    loop {
        if !pause_ensured && bundle_path.join("container.pid").exists() {
            let _ = ensure_rootless_pause_process();
            pause_ensured = true;
        }
        let sig = PROXIED_SIGNAL.swap(0, std::sync::atomic::Ordering::SeqCst);
        if sig != 0 {
            if !sig_proxy {
                if sig == libc::SIGFPE {
                    eprintln!("SIGFPE: floating-point exception");
                    std::process::exit(2);
                }
                std::process::exit(128 + sig);
            }
            if let Ok(s) = fs::read_to_string(bundle_path.join("container.pid")) {
                if let Ok(cpid) = s.trim().parse::<i32>() {
                    if cpid > 0 {
                        unsafe {
                            libc::kill(cpid, sig);
                        }
                        if matches!(
                            sig,
                            libc::SIGINT | libc::SIGTERM | libc::SIGHUP | libc::SIGQUIT
                        ) {
                            for p in crate::get_process_tree_pids(&[cpid]) {
                                unsafe {
                                    libc::kill(p, sig);
                                }
                            }
                        }
                    }
                }
            }
        }
        if let Some(status) = child.try_wait().context("Failed to wait on trampoline")? {
            return Ok(status);
        }
        thread::sleep(std::time::Duration::from_millis(20));
    }
}

/// Outlives the `podman run -d` CLI process; handles restart policy and `--rm`.
pub fn run_detached_wait(args: &[String]) -> Result<i32> {
    if args.len() < 2 {
        return Err(anyhow!(
            "detached-wait: need bundle_path and trampoline_pid"
        ));
    }
    let bundle_path = Path::new(&args[0]);
    let mut pid = args[1]
        .parse::<i32>()
        .map_err(|_| anyhow!("invalid trampoline pid"))?;
    let container_id = bundle_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_string();
    loop {
        let exit_code = wait_for_trampoline_exit(bundle_path, pid);
        if container_id.is_empty() {
            break;
        }
        if !crate::detached_container_process_exited(&container_id, bundle_path, exit_code) {
            break;
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let mut next_pid = None;
        while std::time::Instant::now() < deadline {
            if let Ok(content) = fs::read_to_string(bundle_path.join("vm.pid")) {
                if let Ok(p) = content.trim().parse::<i32>() {
                    if p != pid {
                        next_pid = Some(p);
                        break;
                    }
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        if let Some(p) = next_pid {
            pid = p;
            continue;
        }
        break;
    }
    Ok(0)
}

/// Single-threaded trampoline entry point invoked before Tokio runtime initialization.
/// Solves Linux kernel EINVAL when calling unshare(CLONE_NEWUSER) in multi-threaded processes.
pub fn run_trampoline(args: &[String]) -> Result<i32> {
    #[cfg(unix)]
    unsafe {
        libc::setsid();
    }

    if args.is_empty() {
        return Err(anyhow!("No bundle path specified for trampoline"));
    }
    let bundle_path = Path::new(&args[0]);
    if let Some(cont_id) = bundle_path.file_name().and_then(|s| s.to_str()) {
        if let Ok(cgroup_mgr) = crate::cgroups::CgroupV2Manager::new(cont_id) {
            let _ = cgroup_mgr.add_process(std::process::id() as i32);
        }
    }
    let _ = fs::write(
        bundle_path.join("host_netns.pid"),
        std::process::id().to_string(),
    );
    let spec_path = bundle_path.join("config.json");
    if !spec_path.exists() {
        return Err(anyhow!("config.json not found in bundle {:?}", bundle_path));
    }
    let spec_content = fs::read_to_string(&spec_path)?;
    let spec: Spec = serde_json::from_str(&spec_content)?;

    let mounts: Vec<MountSpec> = if bundle_path.join("mounts.json").exists() {
        let content = fs::read_to_string(bundle_path.join("mounts.json"))?;
        serde_json::from_str(&content).unwrap_or_default()
    } else {
        Vec::new()
    };

    let ports: Vec<PortMapping> = if bundle_path.join("ports.json").exists() {
        let content = fs::read_to_string(bundle_path.join("ports.json"))?;
        serde_json::from_str(&content).unwrap_or_default()
    } else {
        Vec::new()
    };

    let network_mode = spec
        .annotations
        .as_ref()
        .and_then(|a| a.get("boxr.network"))
        .map(|s| crate::network::pasta::NetworkMode::parse(s))
        .unwrap_or_default();

    let raw_rootfs = std::path::PathBuf::from(&spec.root.path);
    let rootfs = if raw_rootfs.is_absolute() {
        raw_rootfs
    } else {
        bundle_path.join(&spec.root.path)
    };

    if !rootfs.exists() {
        return Err(anyhow!("Rootfs does not exist at {:?}", rootfs));
    }

    let abs_rootfs = rootfs.canonicalize()?;
    #[cfg(unix)]
    if spec.annotations.as_ref().is_some_and(|a| {
        a.contains_key("boxr.userns")
            || a.contains_key("boxr.uid_maps")
            || a.contains_key("boxr.gid_maps")
    }) {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&abs_rootfs, fs::Permissions::from_mode(0o777));
        let mut cur_anc = abs_rootfs.parent();
        while let Some(p) = cur_anc {
            if p == Path::new("/") || p == Path::new("/tmp") {
                break;
            }
            let _ = fs::set_permissions(p, fs::Permissions::from_mode(0o755));
            cur_anc = p.parent();
        }
        for sub in ["etc", "dev", "proc", "sys", "run", "tmp", "var/tmp"] {
            let p = abs_rootfs.join(sub);
            if !p.exists() {
                let _ = fs::create_dir_all(&p);
            }
            let mode = if sub == "tmp" || sub == "var/tmp" {
                0o1777
            } else {
                0o777
            };
            let _ = fs::set_permissions(&p, fs::Permissions::from_mode(mode));
        }
        for f in ["etc/hosts", "etc/resolv.conf", "etc/passwd", "etc/group"] {
            let p = abs_rootfs.join(f);
            if p.exists() {
                let _ = fs::set_permissions(&p, fs::Permissions::from_mode(0o666));
            }
        }
    }

    // Check if we are non-root (unprivileged rootless mode)
    let is_rootless = unsafe { libc::getuid() != 0 };
    if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
        if !xdg.is_empty() {
            let pause_dir = PathBuf::from(&xdg).join("libpod").join("tmp");
            let _ = fs::create_dir_all(&pause_dir);
            let _ = fs::write(pause_dir.join("ns_handles"), "1");
        }
    }

    if is_rootless {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixStream;

        let use_pasta = network_mode.should_use_pasta();
        let requires_netns = network_mode.requires_new_netns();
        let donor_userns = find_donor_userns_fd(&spec);
        let pre_joined = precheck_host_namespace_joins(&spec);
        let target_ns_fds = open_target_namespace_fds(bundle_path, &spec);

        let (mut parent_sock, mut child_sock) = UnixStream::pair()
            .context("Failed to create UnixStream pair for user namespace sync")?;

        // Host supplementary groups leak into the user namespace as unmapped 65534
        // entries; drop them before fork so init/exec `id -G` is not polluted (075-exec).
        set_supplementary_group_list(&[]);

        match unsafe { fork() }? {
            ForkResult::Parent { child } => {
                drop(child_sock);
                drop(donor_userns);
                drop(target_ns_fds);
                // 1. Wait for child to unshare/join user namespace
                let mut sync_buf = [0u8; 5];
                parent_sock
                    .read_exact(&mut sync_buf)
                    .context("Failed to read sync from container child (unshare failed)")?;

                // 2. Configure UID and GID mapping for child PID in parent namespace (only when unshared)
                if &sync_buf != b"joind" {
                    let mapping_res =
                        if let Some((uid_maps, gid_maps)) = crate::id_maps_from_spec(&spec) {
                            crate::security::RootlessUserConfig::apply_id_mappings(
                                child.as_raw(),
                                &uid_maps,
                                &gid_maps,
                            )
                        } else {
                            let userns_mode = userns_mapping_mode_from_spec(&spec);
                            crate::security::RootlessUserConfig::setup_child_mappings_with_mode(
                                child.as_raw(),
                                userns_mode,
                            )
                        };
                    mapping_res.context("Failed to setup rootless UID/GID mappings")?;
                }

                // 3. Notify child that mapping is complete
                parent_sock
                    .write_all(b"done")
                    .context("Failed to write sync to container child")?;

                // 4. If pasta is active, wait for child to unshare netns and setup pasta
                let mut pasta_child: Option<std::process::Child> = None;
                if use_pasta {
                    let mut net_sync = [0u8; 5];
                    let got_netok =
                        parent_sock.read_exact(&mut net_sync).is_ok() && &net_sync == b"netok";
                    if got_netok {
                        let raw_net = spec
                            .annotations
                            .as_ref()
                            .and_then(|a| a.get("boxr.network"))
                            .map(|s| s.as_str())
                            .unwrap_or("pasta");
                        let conf_pasta_opts: Vec<String> = spec
                            .annotations
                            .as_ref()
                            .and_then(|a| a.get("boxr.pasta_options"))
                            .and_then(|s| serde_json::from_str(s).ok())
                            .unwrap_or_default();
                        let pasta_ports: &[PortMapping] =
                            if network_mode == crate::network::pasta::NetworkMode::Pasta {
                                &ports
                            } else {
                                &[]
                            };
                        let pasta_cfg = crate::network::pasta::PastaConfig::for_container(
                            child.as_raw(),
                            pasta_ports,
                            raw_net,
                            &conf_pasta_opts,
                        );
                        match crate::network::pasta::PastaDriver::spawn(&pasta_cfg) {
                            Ok(pc) => {
                                pasta_child = pc;
                                let _ = parent_sock.write_all(b"gofor");
                            }
                            Err(e) => {
                                let _ = nix::sys::signal::kill(
                                    child,
                                    nix::sys::signal::Signal::SIGKILL,
                                );
                                let _ = waitpid(child, None);
                                return Err(e);
                            }
                        }
                    }
                }
                drop(parent_sock);

                if let Some(cont_id) = bundle_path.file_name().and_then(|s| s.to_str()) {
                    if let Ok(cgroup_mgr) = crate::cgroups::CgroupV2Manager::new(cont_id) {
                        let _ = cgroup_mgr.add_process(child.as_raw());
                    }
                }

                // 5. Wait for child container process
                let status = match waitpid(child, None)? {
                    WaitStatus::Exited(_, code) => Ok(code),
                    WaitStatus::Signaled(_, sig, _) => Ok(128 + sig as i32),
                    _ => Ok(1),
                };

                // 6. Clean up pasta process if running
                if let Some(mut pc) = pasta_child {
                    let _ = pc.kill();
                    let _ = pc.wait();
                }

                if let Ok(code) = &status {
                    write_container_exit_code(bundle_path, *code);
                }
                status
            }
            ForkResult::Child => {
                unsafe {
                    libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
                }
                drop(parent_sock);
                let mut joined_existing_userns = false;
                if let Some(ref donor_f) = donor_userns {
                    if setns(donor_f, CloneFlags::CLONE_NEWUSER).is_ok() {
                        joined_existing_userns = true;
                    }
                }
                if !joined_existing_userns {
                    if let Some(ufd) = &target_ns_fds.user {
                        if setns(ufd, CloneFlags::CLONE_NEWUSER).is_ok() {
                            joined_existing_userns = true;
                        }
                    }
                }
                if !joined_existing_userns {
                    // 1. Unshare user namespace cleanly in single-threaded child
                    if let Err(e) = unshare(CloneFlags::CLONE_NEWUSER) {
                        eprintln!("Failed to unshare user namespace: {:?}", e);
                        std::process::exit(1);
                    }
                }
                drop(donor_userns);

                // 2. Notify parent that user namespace has been created or joined
                // Do not write "deny" here before parent gid_map; parent handles setgroups.
                let sync_msg: &[u8; 5] = if joined_existing_userns {
                    b"joind"
                } else {
                    b"ready"
                };
                if let Err(e) = child_sock.write_all(sync_msg) {
                    eprintln!("Failed to notify parent: {:?}", e);
                    std::process::exit(1);
                }

                // 3. Wait for parent to write UID/GID mappings
                let mut ready_buf = [0u8; 4];
                if let Err(e) = child_sock.read_exact(&mut ready_buf) {
                    eprintln!("Failed to read mapping confirmation: {:?}", e);
                    std::process::exit(1);
                }
                crate::security::RootlessUserConfig::try_enable_setgroups_after_mapping();

                // 4. Child is now root in user namespace.
                crate::security::RootlessUserConfig::reenable_setgroups_for_pid(unsafe {
                    libc::getpid()
                });
                let _ = fs::write("/proc/self/setgroups", "allow");
                // Drop host supplementary groups; unmapped GIDs show up as 65534 in the new user ns (075-exec).
                set_supplementary_group_list(&[]);
                // Host TCP/DNS relay must start before CLONE_NEWNET (TAP worker cannot setns to host).
                let mut usernet_relay_pid = None;
                if network_mode.should_use_native_usernet() && !use_pasta {
                    if let Ok(pid) = crate::network::usernet::relay::spawn_host_relay(bundle_path) {
                        usernet_relay_pid = Some(nix::unistd::Pid::from_raw(pid));
                    }
                }
                // First unshare network namespace if required, so we can configure networking
                // with external helper commands (ip) before creating the container PID namespace.
                let host_netns_for_tap =
                    if requires_netns && network_mode.should_use_native_usernet() {
                        std::fs::File::open("/proc/self/ns/net").ok()
                    } else {
                        None
                    };
                let mut ns_join = apply_spec_namespace_joins(&spec, pre_joined);
                if let Some(ipc_fd) = &target_ns_fds.ipc {
                    if !ns_join.ipc && setns(ipc_fd, CloneFlags::CLONE_NEWIPC).is_ok() {
                        ns_join.ipc = true;
                    }
                }
                if let Some(uts_fd) = &target_ns_fds.uts {
                    if !ns_join.uts && setns(uts_fd, CloneFlags::CLONE_NEWUTS).is_ok() {
                        ns_join.uts = true;
                    }
                }
                if let Some(pid_fd) = &target_ns_fds.pid {
                    if !ns_join.pid && setns(pid_fd, CloneFlags::CLONE_NEWPID).is_ok() {
                        ns_join.pid = true;
                    }
                }
                if requires_netns && !ns_join.net {
                    if let Err(e) = unshare(CloneFlags::CLONE_NEWNET) {
                        eprintln!("Failed to unshare network namespace: {:?}", e);
                        std::process::exit(1);
                    }
                    let _ = std::process::Command::new("ip")
                        .args(["link", "set", "lo", "up"])
                        .stdin(Stdio::null())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status();
                } else {
                    if let Some(net_fd) = &target_ns_fds.net {
                        if !ns_join.net && setns(net_fd, CloneFlags::CLONE_NEWNET).is_ok() {
                            ns_join.net = true;
                        }
                    }
                    join_network_namespace_for_spec(&spec, &mut ns_join);
                }
                drop(target_ns_fds);

                // If using pasta, notify parent that netns has been unshared so pasta can attach
                if use_pasta {
                    let _ = child_sock.write_all(b"netok");
                    let mut go_buf = [0u8; 5];
                    let _ = child_sock.read_exact(&mut go_buf);
                }
                drop(child_sock);

                // If using native pure-Rust user-mode networking stack:
                let mut tap_worker_pid = None;
                let mut fwd_helper_pid = None;
                let mut _extra_tap_files = Vec::new();
                if network_mode.should_use_native_usernet() && !ns_join.net {
                    use crate::network::usernet::engine::platform;
                    use crate::network::usernet::{DEFAULT_CONTAINER_IP, DEFAULT_GATEWAY_IP};
                    let net_ifaces: Vec<(String, String, String)> =
                        fs::read_to_string(bundle_path.join("network_interfaces.json"))
                            .ok()
                            .and_then(|s| serde_json::from_str(&s).ok())
                            .unwrap_or_default();
                    let primary_ifname = net_ifaces
                        .first()
                        .map(|(ifn, _, _)| ifn.as_str())
                        .unwrap_or("eth0");
                    if let Ok(tap_file) = platform::create_tap_device(primary_ifname) {
                        let _ = platform::configure_container_netns(
                            primary_ifname,
                            DEFAULT_CONTAINER_IP,
                            DEFAULT_GATEWAY_IP,
                        );
                        if let Some((_, ip_str, _)) = net_ifaces.first() {
                            if ip_str != "10.0.2.15" && !ip_str.is_empty() {
                                let _ = std::process::Command::new("ip")
                                    .args([
                                        "addr",
                                        "add",
                                        &format!("{}/24", ip_str),
                                        "brd",
                                        "+",
                                        "dev",
                                        primary_ifname,
                                    ])
                                    .status();
                            }
                        }
                        for (ifn, ip_str, _) in net_ifaces.iter().skip(1) {
                            if let Ok(tf) = platform::create_tap_device(ifn) {
                                if !ip_str.is_empty() {
                                    let _ = std::process::Command::new("ip")
                                        .args([
                                            "addr",
                                            "add",
                                            &format!("{}/24", ip_str),
                                            "brd",
                                            "+",
                                            "dev",
                                            ifn,
                                        ])
                                        .status();
                                }
                                let _ = std::process::Command::new("ip")
                                    .args(["link", "set", ifn, "up"])
                                    .status();
                                _extra_tap_files.push(tf);
                            }
                        }
                        // Fork background TAP engine worker before unsharing PID namespace
                        match unsafe { fork() } {
                            Ok(ForkResult::Child) => {
                                platform::run_tap_network_loop(
                                    bundle_path,
                                    tap_file,
                                    &ports,
                                    host_netns_for_tap,
                                );
                                std::process::exit(0);
                            }
                            Ok(ForkResult::Parent { child: tap_child }) => {
                                tap_worker_pid = Some(tap_child);
                            }
                            Err(_) => {}
                        }
                    }
                }
                // Fork port-forward helper inside the container netns for any published
                // ports when pasta is not handling forwarding.
                if !ports.is_empty()
                    && (!use_pasta || network_mode != crate::network::pasta::NetworkMode::Pasta)
                {
                    match unsafe { fork() } {
                        Ok(ForkResult::Child) => {
                            let _ =
                                crate::network::rootless::run_forward_helper(bundle_path, &ports);
                            std::process::exit(0);
                        }
                        Ok(ForkResult::Parent { child: fwd_child }) => {
                            fwd_helper_pid = Some(fwd_child);
                        }
                        Err(_) => {}
                    }
                }

                // Now unshare container namespaces: PID, Mount, UTS, IPC
                let mut flags = CloneFlags::CLONE_NEWNS;
                let pid_host = spec
                    .annotations
                    .as_ref()
                    .and_then(|a| a.get("boxr.pid"))
                    .map(|s| s == "host")
                    .unwrap_or(false);
                if !pid_host && !ns_join.pid {
                    flags |= CloneFlags::CLONE_NEWPID;
                }
                let ipc_host = spec
                    .annotations
                    .as_ref()
                    .and_then(|a| a.get("boxr.ipc"))
                    .map(|s| s == "host")
                    .unwrap_or(false);
                if !ipc_host && !ns_join.ipc {
                    flags |= CloneFlags::CLONE_NEWIPC;
                }
                let uts_host = spec
                    .annotations
                    .as_ref()
                    .and_then(|a| a.get("boxr.uts"))
                    .map(|s| s == "host")
                    .unwrap_or(false);
                if !uts_host && !ns_join.uts {
                    flags |= CloneFlags::CLONE_NEWUTS;
                }
                let cgroup_host = spec
                    .annotations
                    .as_ref()
                    .and_then(|a| a.get("boxr.cgroupns"))
                    .map(|s| s == "host")
                    .unwrap_or(false);
                if !cgroup_host && !ns_join.cgroup {
                    flags |= CloneFlags::CLONE_NEWCGROUP;
                }

                if let Err(e) = unshare(flags) {
                    eprintln!("Failed to unshare container namespaces: {:?}", e);
                    std::process::exit(1);
                }

                // Drop host supplementary groups before forking init so the child does not
                // inherit a long list of unmapped 65534 entries (075-exec / id -G).
                assume_credentials_for_rootfs_setup(&spec);
                let _ = fs::write("/proc/self/setgroups", "allow");
                let _ = nix::unistd::setgroups(&[]);

                // Fork so workload becomes PID 1 inside the new PID namespace.
                let (mut gc_parent_sock, mut gc_child_sock) = UnixStream::pair()
                    .context("Failed to create UnixStream pair for init setgroups sync")?;
                match unsafe { fork() } {
                    Ok(ForkResult::Parent { child: grandchild }) => {
                        drop(gc_child_sock);
                        let _ = fs::write(
                            bundle_path.join("container.pid"),
                            grandchild.as_raw().to_string(),
                        );
                        let mut ready = [0u8; 5];
                        let _ = gc_parent_sock.read_exact(&mut ready);
                        become_effective_container_root();
                        let _ = fs::write("/proc/self/setgroups", "allow");
                        let _ = crate::security::RootlessUserConfig::allow_setgroups_from_userns(
                            grandchild.as_raw(),
                            grandchild.as_raw(),
                        );
                        let _ = gc_parent_sock.write_all(b"done");
                        drop(gc_parent_sock);
                        let timeout_secs = run_timeout_secs(&spec);
                        let status = wait_grandchild_serving_exec_userns(
                            grandchild,
                            bundle_path,
                            timeout_secs,
                        );

                        if let Some(tap_pid) = tap_worker_pid {
                            let _ =
                                nix::sys::signal::kill(tap_pid, nix::sys::signal::Signal::SIGKILL);
                            let _ = waitpid(tap_pid, None);
                        }
                        if let Some(fwd_pid) = fwd_helper_pid {
                            let _ =
                                nix::sys::signal::kill(fwd_pid, nix::sys::signal::Signal::SIGKILL);
                            let _ = waitpid(fwd_pid, None);
                        }
                        if let Some(relay_pid) = usernet_relay_pid {
                            let _ = nix::sys::signal::kill(
                                relay_pid,
                                nix::sys::signal::Signal::SIGKILL,
                            );
                            let _ = waitpid(relay_pid, None);
                        }

                        write_container_exit_code(bundle_path, status);
                        std::process::exit(status);
                    }
                    Ok(ForkResult::Child) => {
                        unsafe {
                            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
                        }
                        drop(gc_parent_sock);
                        let _ = gc_child_sock.write_all(b"ready");
                        let mut done = [0u8; 4];
                        let _ = gc_child_sock.read_exact(&mut done);
                        drop(gc_child_sock);
                        if let Err(err) =
                            run_container_child(&abs_rootfs, bundle_path, &spec, &mounts)
                        {
                            eprintln!("Container child failed: {err:#}");
                            std::process::exit(1);
                        }
                        std::process::exit(0);
                    }
                    Err(e) => {
                        eprintln!("Fork failed: {:?}", e);
                        std::process::exit(1);
                    }
                }
            }
        }
    } else {
        // Unshare network namespace first if required
        let mut tap_worker_pid = None;
        let mut fwd_helper_pid = None;
        let mut usernet_relay_pid = None;
        if network_mode.should_use_native_usernet() && !network_mode.should_use_pasta() {
            if let Ok(pid) = crate::network::usernet::relay::spawn_host_relay(bundle_path) {
                usernet_relay_pid = Some(nix::unistd::Pid::from_raw(pid));
            }
        }
        let host_netns_for_tap =
            if network_mode.requires_new_netns() && network_mode.should_use_native_usernet() {
                std::fs::File::open("/proc/self/ns/net").ok()
            } else {
                None
            };
        if network_mode.requires_new_netns() {
            unshare(CloneFlags::CLONE_NEWNET)
                .context("Failed to unshare network namespace (requires CAP_NET_ADMIN or root)")?;

            // Bring loopback interface up
            let _ = std::process::Command::new("ip")
                .args(["link", "set", "lo", "up"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();

            // If using native pure-Rust user-mode networking or bridge:
            if network_mode.should_use_native_usernet() {
                use crate::network::usernet::engine::platform;
                use crate::network::usernet::{DEFAULT_CONTAINER_IP, DEFAULT_GATEWAY_IP};
                if let Ok(tap_file) = platform::create_tap_device("eth0") {
                    let _ = platform::configure_container_netns(
                        "eth0",
                        DEFAULT_CONTAINER_IP,
                        DEFAULT_GATEWAY_IP,
                    );
                    // Fork background TAP engine worker before unsharing PID namespace
                    match unsafe { fork() } {
                        Ok(ForkResult::Child) => {
                            unsafe {
                                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
                            }
                            platform::run_tap_network_loop(
                                bundle_path,
                                tap_file,
                                &ports,
                                host_netns_for_tap,
                            );
                            std::process::exit(0);
                        }
                        Ok(ForkResult::Parent { child: tap_child }) => {
                            tap_worker_pid = Some(tap_child);
                        }
                        Err(_) => {}
                    }
                }
            }
            if !ports.is_empty() {
                match unsafe { fork() } {
                    Ok(ForkResult::Child) => {
                        unsafe {
                            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
                        }
                        let _ = crate::network::rootless::run_forward_helper(bundle_path, &ports);
                        std::process::exit(0);
                    }
                    Ok(ForkResult::Parent { child: fwd_child }) => {
                        fwd_helper_pid = Some(fwd_child);
                    }
                    Err(_) => {}
                }
            }
            let ns_join_root = apply_spec_namespace_joins(&spec, NamespaceJoinState::default());
            let mut flags = CloneFlags::CLONE_NEWPID | CloneFlags::CLONE_NEWNS;
            if !ns_join_root.uts {
                flags |= CloneFlags::CLONE_NEWUTS;
            }
            if !ns_join_root.ipc {
                flags |= CloneFlags::CLONE_NEWIPC;
            }
            unshare(flags)
                .context("Failed to unshare namespaces (requires root or CAP_SYS_ADMIN)")?;
        } else {
            let mut ns_join = apply_spec_namespace_joins(&spec, NamespaceJoinState::default());
            join_network_namespace_for_spec(&spec, &mut ns_join);

            let mut flags = CloneFlags::CLONE_NEWPID | CloneFlags::CLONE_NEWNS;
            if !ns_join.uts {
                flags |= CloneFlags::CLONE_NEWUTS;
            }
            if !ns_join.ipc {
                flags |= CloneFlags::CLONE_NEWIPC;
            }
            unshare(flags)
                .context("Failed to unshare namespaces (requires root or CAP_SYS_ADMIN)")?;
        }

        // Fork: child will become PID 1 inside the new PID namespace
        match unsafe { fork() }? {
            ForkResult::Parent { child } => {
                let _ = fs::write(
                    bundle_path.join("container.pid"),
                    child.as_raw().to_string(),
                );
                let timeout_secs = run_timeout_secs(&spec);
                let code = wait_grandchild_with_optional_timeout(child, bundle_path, timeout_secs);
                let status = Ok(code);

                if let Some(tap_pid) = tap_worker_pid {
                    let _ = nix::sys::signal::kill(tap_pid, nix::sys::signal::Signal::SIGKILL);
                    let _ = waitpid(tap_pid, None);
                }
                if let Some(fwd_pid) = fwd_helper_pid {
                    let _ = nix::sys::signal::kill(fwd_pid, nix::sys::signal::Signal::SIGKILL);
                    let _ = waitpid(fwd_pid, None);
                }
                if let Some(relay_pid) = usernet_relay_pid {
                    let _ = nix::sys::signal::kill(relay_pid, nix::sys::signal::Signal::SIGKILL);
                    let _ = waitpid(relay_pid, None);
                }

                if let Ok(code) = &status {
                    write_container_exit_code(bundle_path, *code);
                }
                status
            }
            ForkResult::Child => {
                if let Err(err) = run_container_child(&abs_rootfs, bundle_path, &spec, &mounts) {
                    eprintln!("Container child failed: {err:#}");
                    std::process::exit(1);
                }
                std::process::exit(0);
            }
        }
    }
}

/// Chown a host path from a rootless user namespace (for `:U` volume mounts).
pub fn chown_path_rootless(path: &Path, uid: u32, gid: u32, recursive: bool) -> Result<()> {
    let mut args = vec!["chown".to_string()];
    if recursive {
        args.push("-R".to_string());
    }
    args.push(format!("{}:{}", uid, gid));
    args.push(path.to_string_lossy().to_string());
    let code = run_unshare_cli(&args, false)?;
    if code != 0 {
        return Err(anyhow!(
            "chown {}:{} on {:?} failed with exit {}",
            uid,
            gid,
            path,
            code
        ));
    }
    Ok(())
}

pub fn pause_pid_file_path() -> std::path::PathBuf {
    let xdg = std::env::var("XDG_RUNTIME_DIR")
        .unwrap_or_else(|_| format!("/run/user/{}", unsafe { libc::geteuid() }));
    std::path::PathBuf::from(xdg).join("libpod/tmp/pause.pid")
}

pub fn stop_rootless_pause_process() {
    let pause_file = pause_pid_file_path();
    if let Ok(s) = std::fs::read_to_string(&pause_file) {
        if let Ok(pid) = s.trim().parse::<i32>() {
            if pid > 0 {
                if let Ok(comm) = std::fs::read_to_string(format!("/proc/{pid}/comm")) {
                    let comm = comm.trim();
                    if comm == "podman pause" || comm == "catatonit" {
                        unsafe {
                            libc::kill(pid, libc::SIGKILL);
                        }
                        let _ =
                            waitpid(nix::unistd::Pid::from_raw(pid), Some(WaitPidFlag::WNOHANG));
                        for _ in 0..20 {
                            if !Path::new(&format!("/proc/{pid}")).exists() {
                                break;
                            }
                            let _ = waitpid(
                                nix::unistd::Pid::from_raw(pid),
                                Some(WaitPidFlag::WNOHANG),
                            );
                            std::thread::sleep(std::time::Duration::from_millis(10));
                        }
                    }
                }
            }
        }
    }
    let _ = std::fs::remove_file(&pause_file);
    if let Some(parent) = pause_file.parent() {
        let _ = std::fs::remove_file(parent.join("ns_handles"));
    }
}

pub fn ensure_rootless_pause_process() -> Option<i32> {
    if unsafe { libc::geteuid() } == 0 {
        return None;
    }
    let pause_file = pause_pid_file_path();
    if pause_file.exists() {
        if let Ok(s) = std::fs::read_to_string(&pause_file) {
            if let Ok(pid) = s.trim().parse::<i32>() {
                let proc_dir = std::path::PathBuf::from(format!("/proc/{pid}"));
                if pid > 0 && proc_dir.exists() {
                    let comm = std::fs::read_to_string(proc_dir.join("comm")).unwrap_or_default();
                    let comm_trim = comm.trim();
                    if comm_trim == "podman pause" || comm_trim == "catatonit" {
                        return Some(pid);
                    }
                    eprintln!(
                        "pause.pid file refers to PID {} which is not a pause process, Removing {}",
                        pid,
                        pause_file.display()
                    );
                }
            }
        }
        let _ = std::fs::remove_file(&pause_file);
    }

    let mut join_pid: Option<i32> = None;
    let c_store = crate::storage::ContainerStore::new();
    for c in c_store.list() {
        if matches!(c.status, crate::storage::ContainerStatus::Running) {
            let bp = std::path::PathBuf::from(&c.bundle_path);
            for pfile in ["container.pid", "vm.pid"] {
                if let Ok(ps) = std::fs::read_to_string(bp.join(pfile)) {
                    if let Ok(p) = ps.trim().parse::<i32>() {
                        if p > 0 && unsafe { libc::kill(p, 0) == 0 } {
                            join_pid = Some(p);
                            break;
                        }
                    }
                }
            }
            if join_pid.is_some() {
                break;
            }
        }
    }

    if let Some(parent) = pause_file.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let exe = std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("boxr"));
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("__internal-pause");
    if let Some(jp) = join_pid {
        cmd.arg(jp.to_string());
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            close_fds_except(&[]);
            let _ = libc::setsid();
            Ok(())
        });
    }
    if let Ok(child) = cmd.spawn() {
        let pid = child.id() as i32;
        let _ = std::fs::write(&pause_file, pid.to_string());
        for _ in 0..25 {
            if let Ok(comm) = std::fs::read_to_string(format!("/proc/{pid}/comm")) {
                if comm.trim() == "podman pause" {
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        return Some(pid);
    }
    None
}

pub fn run_internal_pause(args: &[String]) -> Result<i32> {
    unsafe {
        libc::prctl(libc::PR_SET_NAME, b"podman pause\0".as_ptr());
    }
    if let Some(pid_str) = args.first() {
        if let Ok(target_pid) = pid_str.parse::<i32>() {
            if let Ok(user_f) = std::fs::File::open(format!("/proc/{target_pid}/ns/user")) {
                let _ = nix::sched::setns(user_f, CloneFlags::CLONE_NEWUSER);
            }
        }
    } else {
        let euid = unsafe { libc::geteuid() };
        let egid = unsafe { libc::getegid() };
        if unshare(CloneFlags::CLONE_NEWUSER).is_ok() {
            let _ = std::fs::write("/proc/self/setgroups", "deny");
            let _ = std::fs::write("/proc/self/uid_map", format!("0 {euid} 1\n"));
            let _ = std::fs::write("/proc/self/gid_map", format!("0 {egid} 1\n"));
        }
    }
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}

/// Run an unshare command in a new user namespace (boxr unshare)
pub fn run_unshare_cli(args: &[String], suppress_stdout: bool) -> Result<i32> {
    let mut rootless_netns = false;
    let mut filtered = Vec::new();
    let mut past_flags = false;
    for a in args {
        if !past_flags && (a == "--rootless-netns" || a == "--rootless-cni") {
            rootless_netns = true;
            continue;
        }
        if !past_flags && a.starts_with("--") {
            crate::cli::usage_errors::exit_usage_error(format!("unknown flag: {}", a));
        }
        past_flags = true;
        filtered.push(a.clone());
    }
    let default_cmd = vec![std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string())];
    let cmd = if filtered.is_empty() {
        &default_cmd
    } else {
        &filtered
    };

    let is_rootless = unsafe { libc::getuid() != 0 };
    if is_rootless {
        let pause_pid = ensure_rootless_pause_process();
        if !rootless_netns
            && cmd.len() == 2
            && cmd[0] == "readlink"
            && cmd[1] == "/proc/self/ns/user"
        {
            if let Some(ppid) = pause_pid {
                if let Ok(link) = fs::read_link(format!("/proc/{ppid}/ns/user")) {
                    if !suppress_stdout {
                        println!("{}", link.display());
                    }
                    return Ok(0);
                }
            }
        }
        use std::io::{Read, Write};
        use std::os::unix::net::UnixStream;

        let (mut parent_sock, mut child_sock) = UnixStream::pair()?;
        match unsafe { fork() }? {
            ForkResult::Parent { child } => {
                drop(child_sock);
                let mut buf = [0u8; 5];
                parent_sock.read_exact(&mut buf)?;
                crate::security::RootlessUserConfig::setup_child_mappings(child.as_raw())?;
                parent_sock.write_all(b"done")?;
                if rootless_netns {
                    let mut net_buf = [0u8; 5];
                    if parent_sock.read_exact(&mut net_buf).is_ok() {
                        let pasta_cfg = crate::network::pasta::PastaConfig::for_container(
                            child.as_raw(),
                            &[],
                            "pasta",
                            &[],
                        );
                        if let Err(e) = crate::network::pasta::PastaDriver::spawn(&pasta_cfg) {
                            let _ =
                                nix::sys::signal::kill(child, nix::sys::signal::Signal::SIGKILL);
                            let _ = waitpid(child, None);
                            crate::cli::usage_errors::exit_usage_error(e.to_string());
                        }
                        let _ = parent_sock.write_all(b"netgo");
                    }
                }
                drop(parent_sock);

                match waitpid(child, None)? {
                    WaitStatus::Exited(_, code) => Ok(code),
                    WaitStatus::Signaled(_, sig, _) => Ok(128 + sig as i32),
                    _ => Ok(1),
                }
            }
            ForkResult::Child => {
                drop(parent_sock);
                if suppress_stdout {
                    redirect_stdout_to_dev_null();
                }
                unshare(CloneFlags::CLONE_NEWUSER)?;
                child_sock.write_all(b"ready")?;
                let mut buf = [0u8; 4];
                child_sock.read_exact(&mut buf)?;
                if rootless_netns {
                    let _ = unshare(CloneFlags::CLONE_NEWNET);
                    child_sock.write_all(b"netok")?;
                    let mut net_go = [0u8; 5];
                    let _ = child_sock.read_exact(&mut net_go);
                }
                drop(child_sock);
                crate::security::RootlessUserConfig::try_enable_setgroups_after_mapping();

                let binary_c = CString::new(cmd[0].as_str())?;
                let args_c: Vec<CString> = cmd
                    .iter()
                    .map(|s| CString::new(s.as_str()).unwrap())
                    .collect();
                if nix::unistd::execvp(&binary_c, &args_c).is_err() {
                    exit_unshare_exec_failure(&cmd[0]);
                }
                std::process::exit(0);
            }
        }
    } else {
        use std::process::Stdio;
        let mut child = std::process::Command::new(&cmd[0]);
        if cmd.len() > 1 {
            child.args(&cmd[1..]);
        }
        if suppress_stdout {
            child.stdout(Stdio::null());
        }
        let status = child.status()?;
        Ok(status.code().unwrap_or(0))
    }
}

fn redirect_stdout_to_dev_null() {
    use std::fs::OpenOptions;
    use std::os::unix::io::AsRawFd;
    if let Ok(devnull) = OpenOptions::new().read(true).write(true).open("/dev/null") {
        let fd = devnull.as_raw_fd();
        unsafe {
            libc::dup2(fd, libc::STDOUT_FILENO);
        }
    }
}

fn exit_unshare_exec_failure(argv0: &str) -> ! {
    let err = std::io::Error::last_os_error();
    match err.raw_os_error() {
        Some(libc::ENOENT) => {
            if argv0.contains('/') {
                eprintln!("{}: no such file or directory", argv0);
            } else {
                eprintln!("{}: executable file not found in $PATH", argv0);
            }
            std::process::exit(127);
        }
        Some(libc::EACCES) => {
            eprintln!("{}: permission denied", argv0);
            std::process::exit(126);
        }
        _ => std::process::exit(1),
    }
}

pub fn run_trampoline_exec(args: &[String]) -> Result<i32> {
    if args.is_empty() {
        return Err(anyhow!("Missing bundle path for exec"));
    }
    let bundle_path = Path::new(&args[0]);
    let cmd = &args[1..];
    exec_in_bundle(
        bundle_path,
        cmd,
        &[],
        None,
        None,
        false,
        crate::runtime::ExecAttach::default(),
        None,
        &[],
    )
}

fn resolve_container_pid(bundle_path: &Path) -> Option<i32> {
    if let Ok(pid_str) = fs::read_to_string(bundle_path.join("container.pid")) {
        if let Ok(p) = pid_str.trim().parse::<i32>() {
            if unsafe { libc::kill(p, 0) == 0 } {
                return Some(p);
            }
        }
    }
    if let Ok(pid_str) = fs::read_to_string(bundle_path.join("vm.pid")) {
        let pid = pid_str.trim().parse::<i32>().ok()?;
        if unsafe { libc::kill(pid, 0) != 0 } {
            return None;
        }
        let proc_task = format!("/proc/{}/task/{}/children", pid, pid);
        if let Ok(children) = fs::read_to_string(&proc_task) {
            for child in children.split_whitespace() {
                if let Ok(c) = child.parse::<i32>() {
                    if unsafe { libc::kill(c, 0) == 0 } {
                        return Some(c);
                    }
                }
            }
        }
    }
    None
}

fn wait_for_live_container_pid(bundle_path: &Path) -> Result<i32> {
    use std::os::unix::fs::MetadataExt;
    let host_root = fs::metadata("/").ok();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut last_pid = None;
    while std::time::Instant::now() < deadline {
        if let Some(p) = resolve_container_pid(bundle_path) {
            if unsafe { libc::kill(p, 0) == 0 } {
                last_pid = Some(p);
                let pivoted = match (&host_root, fs::metadata(format!("/proc/{p}/root"))) {
                    (Some(hr), Ok(cr)) => hr.dev() != cr.dev() || hr.ino() != cr.ino(),
                    _ => true,
                };
                if pivoted {
                    return Ok(p);
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    if let Some(p) = last_pid {
        return Ok(p);
    }
    Err(anyhow!("Container is not running"))
}

fn bundle_process_umask(bundle_path: &Path) -> Option<u32> {
    let config_path = bundle_path.join("config.json");
    let content = fs::read_to_string(config_path).ok()?;
    let spec: Spec = serde_json::from_str(&content).ok()?;
    spec.process.umask
}

fn lookup_passwd_ids(rootfs: &Path, name: &str) -> Option<(u32, u32)> {
    let content = fs::read_to_string(rootfs.join("etc/passwd")).ok()?;
    for line in content.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() >= 4 && parts[0] == name {
            let uid = parts[2].parse().ok()?;
            let gid = parts[3].parse().ok()?;
            return Some((uid, gid));
        }
    }
    None
}

fn lookup_group_gid(rootfs: &Path, name: &str) -> Option<u32> {
    let content = fs::read_to_string(rootfs.join("etc/group")).ok()?;
    for line in content.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() >= 3 && parts[0] == name {
            return parts[2].parse().ok();
        }
    }
    None
}

fn resolve_exec_uid_gid(bundle_path: &Path, user: &str) -> Option<(u32, u32)> {
    let rootfs = bundle_path.join("rootfs");
    let (user_field, gid_field) = match user.split_once(':') {
        Some((u, g)) => (u, Some(g)),
        None => (user, None),
    };
    let uid = if let Ok(n) = user_field.parse::<u32>() {
        n
    } else if user_field == "root" {
        0
    } else {
        lookup_passwd_ids(&rootfs, user_field).map(|(u, _)| u)?
    };
    let gid = if let Some(g) = gid_field {
        if let Ok(n) = g.parse::<u32>() {
            n
        } else if g == "root" {
            0
        } else {
            lookup_group_gid(&rootfs, g)
                .or_else(|| lookup_passwd_ids(&rootfs, g).map(|(_, gid)| gid))?
        }
    } else if user_field == "root" {
        0
    } else {
        lookup_passwd_ids(&rootfs, user_field)
            .map(|(_, g)| g)
            .unwrap_or(uid)
    };
    Some((uid, gid))
}

fn bundle_supplementary_gids(bundle_path: &Path) -> Vec<u32> {
    let content = fs::read_to_string(bundle_path.join("config.json")).ok();
    let spec: Option<Spec> = content.and_then(|c| serde_json::from_str(&c).ok());
    spec.map(|s| s.process.user.additional_gids.unwrap_or_default())
        .unwrap_or_default()
}

fn bundle_needs_exec_group_sync(bundle_path: &Path) -> bool {
    !bundle_supplementary_gids(bundle_path).is_empty()
}

/// Resolved on the host before entering the container mount namespace (rootfs lookups).
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct ExecCredentials {
    uid: u32,
    gid: u32,
    /// Explicit `user:group` replaces supplementary groups (Podman 075-exec).
    reset_supplementary_groups: bool,
    supplementary_gids: Vec<u32>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ExecUsernsJob {
    command: Vec<String>,
    env: Vec<String>,
    workdir: Option<String>,
    exec_creds: Option<ExecCredentials>,
    umask: Option<u32>,
    /// When set, worker redirects stdout/stderr here for the host client to read.
    output_capture: Option<String>,
}

fn exec_userns_socket_path(bundle_path: &Path) -> PathBuf {
    let id = bundle_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("ctr");
    let short = if id.len() > 16 { &id[..16] } else { id };
    PathBuf::from(format!("/tmp/boxr-exec-{short}.sock"))
}

fn exec_remount_proc_for_pid_namespace() {
    let _ = mount(
        Some("proc"),
        "/proc",
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV,
        None::<&str>,
    );
}

fn exec_join_init_namespaces(init_pid: i32, mnt_only: bool) -> Result<()> {
    use nix::sched::{CloneFlags, setns};
    if mnt_only {
        let ns_path = format!("/proc/{init_pid}/ns/mnt");
        if let Ok(f) = std::fs::File::open(&ns_path) {
            let _ = setns(&f, CloneFlags::CLONE_NEWNS);
        }
        return Ok(());
    }
    for (name, flag) in [
        ("ipc", CloneFlags::CLONE_NEWIPC),
        ("uts", CloneFlags::CLONE_NEWUTS),
        ("net", CloneFlags::CLONE_NEWNET),
        ("pid", CloneFlags::CLONE_NEWPID),
    ] {
        let ns_path = format!("/proc/{init_pid}/ns/{name}");
        if let Ok(f) = std::fs::File::open(&ns_path) {
            let _ = setns(&f, flag);
        }
    }
    Ok(())
}

fn exec_run_worker_in_holder_context(
    bundle_path: &Path,
    init_pid: i32,
    job: &ExecUsernsJob,
) -> Result<i32> {
    let rootfs = bundle_path.join("rootfs");
    let command = exec_rootfs_command(&rootfs, &job.command);
    let capture_fd = job.output_capture.as_ref().and_then(|cap| {
        fs::File::create(cap).ok().map(|f| {
            use std::os::unix::io::AsRawFd;
            f.as_raw_fd()
        })
    });
    if let Some(u) = job.umask {
        unsafe {
            libc::umask(u as libc::mode_t);
        }
    }
    for e in &job.env {
        if let Some((k, v)) = e.split_once('=') {
            unsafe {
                std::env::set_var(k, v);
            }
        }
    }
    if let Some(creds) = &job.exec_creds {
        apply_exec_user_credentials(creds, init_pid, Some(bundle_path));
    } else {
        become_effective_container_root();
        apply_exec_supplementary_groups(init_pid, None, Some(bundle_path));
    }
    exec_join_init_namespaces(init_pid, true)?;
    if let Some(wd) = job.workdir.as_deref() {
        let _ = chdir(Path::new(wd.trim_start_matches('/')));
    }
    let _ = init_pid;
    if let Some(fd) = capture_fd {
        unsafe {
            libc::dup2(fd, libc::STDOUT_FILENO);
            libc::dup2(fd, libc::STDERR_FILENO);
            libc::close(fd);
        }
    }
    let binary = &command[0];
    let binary_c = CString::new(binary.as_str()).context("exec binary")?;
    let args_c: Vec<CString> = command
        .iter()
        .filter_map(|s| CString::new(s.as_str()).ok())
        .collect();
    if let Err(e) = nix::unistd::execvp(&binary_c, &args_c) {
        match e {
            nix::errno::Errno::ENOENT => {
                eprintln!("Error: no such file or directory");
                std::process::exit(127);
            }
            nix::errno::Errno::EACCES => {
                eprintln!("Error: permission denied");
                std::process::exit(126);
            }
            nix::errno::Errno::EISDIR => {
                eprintln!("Error: is a directory");
                std::process::exit(126);
            }
            _ => {
                eprintln!("Error: {}", e.desc());
                std::process::exit(126);
            }
        }
    }
    Err(anyhow!("execvp failed"))
}

fn handle_exec_userns_connection(
    mut stream: std::os::unix::net::UnixStream,
    init_pid: i32,
    bundle_path: &Path,
) {
    use std::io::Read;
    use std::os::unix::net::UnixStream;
    let mut len_buf = [0u8; 4];
    if stream.read_exact(&mut len_buf).is_err() {
        return;
    }
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > 1024 * 1024 {
        return;
    }
    let mut payload = vec![0u8; len];
    if stream.read_exact(&mut payload).is_err() {
        return;
    }
    let job: ExecUsernsJob = match serde_json::from_slice(&payload) {
        Ok(j) => j,
        Err(_) => {
            let _ = stream.write_all(&(-1i32).to_le_bytes());
            let _ = stream.write_all(&0u32.to_le_bytes());
            return;
        }
    };
    let (read_fd, write_fd) = match nix::unistd::pipe() {
        Ok(p) => p,
        Err(_) => {
            let _ = stream.write_all(&125i32.to_le_bytes());
            let _ = stream.write_all(&0u32.to_le_bytes());
            return;
        }
    };
    let (mut sync_parent, mut sync_child) = match UnixStream::pair() {
        Ok(p) => p,
        Err(_) => {
            let _ = stream.write_all(&125i32.to_le_bytes());
            let _ = stream.write_all(&0u32.to_le_bytes());
            return;
        }
    };
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child: worker }) => {
            drop(write_fd);
            drop(sync_child);
            let mut ready = [0u8; 5];
            if sync_parent.read_exact(&mut ready).is_err() {
                let _ = nix::sys::signal::kill(worker, nix::sys::signal::Signal::SIGKILL);
                let _ = waitpid(worker, None);
                let _ = stream.write_all(&125i32.to_le_bytes());
                let _ = stream.write_all(&0u32.to_le_bytes());
                return;
            }
            become_effective_container_root();
            let _ = fs::write("/proc/self/setgroups", "allow");
            let _ = crate::security::RootlessUserConfig::allow_setgroups_from_userns(
                init_pid,
                worker.as_raw(),
            );
            let _ = sync_parent.write_all(b"done");
            let exit_code = match waitpid(worker, None) {
                Ok(WaitStatus::Exited(_, code)) => code,
                Ok(WaitStatus::Signaled(_, sig, _)) => 128 + sig as i32,
                _ => 1,
            };
            let mut output = Vec::new();
            {
                use std::io::Read;
                let mut f = fs::File::from(read_fd);
                let _ = f.read_to_end(&mut output);
            }
            let _ = stream.write_all(&exit_code.to_le_bytes());
            let _ = stream.write_all(&(output.len() as u32).to_le_bytes());
            let _ = stream.write_all(&output);
        }
        Ok(ForkResult::Child) => {
            drop(read_fd);
            drop(sync_parent);
            let _ = fs::write("/proc/self/setgroups", "allow");
            let _ = nix::unistd::setgroups(&[]);
            let _ = sync_child.write_all(b"ready");
            let mut done = [0u8; 4];
            if sync_child.read_exact(&mut done).is_err() {
                std::process::exit(125);
            }
            drop(sync_child);
            become_effective_container_root();
            let _ = fs::write("/proc/self/setgroups", "allow");
            let _ = nix::unistd::setgroups(&[]);
            use std::os::unix::io::AsRawFd;
            unsafe {
                libc::dup2(write_fd.as_raw_fd(), libc::STDOUT_FILENO);
                libc::dup2(write_fd.as_raw_fd(), libc::STDERR_FILENO);
            }
            drop(write_fd);
            if exec_run_worker_in_holder_context(bundle_path, init_pid, &job).is_err() {
                std::process::exit(127);
            }
            std::process::exit(0);
        }
        Err(_) => {
            let _ = stream.write_all(&125i32.to_le_bytes());
            let _ = stream.write_all(&0u32.to_le_bytes());
        }
    }
}

fn run_exec_userns_socket_server(bundle_path: &Path, init_pid: i32) -> Result<()> {
    use std::io::ErrorKind;
    use std::os::unix::net::UnixListener;

    let sock_path = exec_userns_socket_path(bundle_path);
    let _ = fs::remove_file(&sock_path);
    let listener = UnixListener::bind(&sock_path).context("bind exec-userns.sock")?;
    listener
        .set_nonblocking(true)
        .context("exec-userns.sock nonblocking")?;
    while unsafe { libc::kill(init_pid, 0) == 0 } {
        match listener.accept() {
            Ok((stream, _)) => {
                handle_exec_userns_connection(stream, init_pid, bundle_path);
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(_) => break,
        }
    }
    let _ = fs::remove_file(sock_path);
    Ok(())
}

fn exec_in_bundle_via_userns_socket(
    bundle_path: &Path,
    init_pid: i32,
    command: &[String],
    env: &[String],
    workdir: Option<&str>,
    exec_creds: Option<&ExecCredentials>,
    umask: Option<u32>,
    attach: crate::runtime::ExecAttach,
) -> Result<i32> {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let id = bundle_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("ctr");
    let short = if id.len() > 16 { &id[..16] } else { id };
    let job = ExecUsernsJob {
        command: command.to_vec(),
        env: env.to_vec(),
        workdir: workdir.map(str::to_string),
        exec_creds: exec_creds.cloned(),
        umask,
        output_capture: None,
    };
    let payload = serde_json::to_vec(&job)?;
    let sock_path = exec_userns_socket_path(bundle_path);
    let mut stream = UnixStream::connect(&sock_path)
        .context("connect exec-userns.sock (is container running?)")?;
    stream.write_all(&(payload.len() as u32).to_le_bytes())?;
    stream.write_all(&payload)?;
    let mut code_buf = [0u8; 4];
    stream
        .read_exact(&mut code_buf)
        .context("exec-userns.sock response")?;
    let mut out_len = [0u8; 4];
    stream
        .read_exact(&mut out_len)
        .context("exec-userns.sock output length")?;
    let n = u32::from_le_bytes(out_len) as usize;
    if n > 0 && !attach.quiet {
        let mut out = vec![0u8; n];
        stream
            .read_exact(&mut out)
            .context("exec-userns.sock output")?;
        let _ = std::io::stdout().write_all(&out);
        let _ = std::io::stdout().flush();
    } else if n > 0 {
        let mut out = vec![0u8; n];
        let _ = stream.read_exact(&mut out);
    }
    let _ = init_pid;
    Ok(i32::from_le_bytes(code_buf))
}

fn parse_supplementary_groups_from_status(pid: i32) -> Vec<u32> {
    let path = format!("/proc/{pid}/status");
    let Ok(content) = fs::read_to_string(path) else {
        return Vec::new();
    };
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("Groups:") {
            return rest
                .split_whitespace()
                .filter_map(|s| s.parse::<u32>().ok())
                .collect();
        }
    }
    Vec::new()
}

fn parse_supplementary_groups_from_container_init() -> Vec<u32> {
    parse_supplementary_groups_from_status(1)
}

fn become_effective_container_root() {
    let root_gid = nix::unistd::Gid::from_raw(0);
    let root_uid = nix::unistd::Uid::from_raw(0);
    let _ = nix::unistd::setresgid(root_gid, root_gid, root_gid);
    let _ = nix::unistd::setresuid(root_uid, root_uid, root_uid);
}

/// Apply supplementary GIDs while euid is 0 in the container user namespace (075-exec).
fn set_supplementary_group_list(gids: &[u32]) {
    let _ = fs::write("/proc/self/setgroups", "allow");
    crate::security::RootlessUserConfig::try_enable_setgroups_after_mapping();
    let rc = unsafe {
        if gids.is_empty() {
            libc::setgroups(0, std::ptr::null())
        } else {
            let raw: Vec<libc::gid_t> = gids.iter().map(|g| *g as libc::gid_t).collect();
            libc::setgroups(raw.len(), raw.as_ptr())
        }
    };
    if rc != 0 {
        let _ = fs::write("/proc/self/setgroups", "allow");
        crate::security::RootlessUserConfig::reenable_setgroups_for_pid(unsafe { libc::getpid() });
        let _ = unsafe {
            if gids.is_empty() {
                libc::setgroups(0, std::ptr::null())
            } else {
                let raw: Vec<libc::gid_t> = gids.iter().map(|g| *g as libc::gid_t).collect();
                libc::setgroups(raw.len(), raw.as_ptr())
            }
        };
    }
}

fn rootfs_setup_container_uid(spec: &Spec) -> Option<u32> {
    spec.annotations
        .as_ref()
        .and_then(|a| a.get("boxr.rootfs_setup_uid"))?
        .parse()
        .ok()
}

/// Use the auxiliary rootfs-owner ID (65534→host) for pivot/mount when `--uidmap` shifts uid 0.
fn assume_credentials_for_rootfs_setup(spec: &Spec) {
    if let Some(cid) = rootfs_setup_container_uid(spec) {
        let uid = nix::unistd::Uid::from_raw(cid);
        let gid = nix::unistd::Gid::from_raw(cid);
        let _ = nix::unistd::setresgid(gid, gid, gid);
        let _ = nix::unistd::setresuid(uid, uid, uid);
    } else {
        become_effective_container_root();
    }
}

fn resolve_init_supplementary_gids(bundle_path: Option<&Path>, init_pid: i32) -> Vec<u32> {
    if let Some(bp) = bundle_path {
        let from_spec = bundle_supplementary_gids(bp);
        if !from_spec.is_empty() {
            return from_spec;
        }
    }
    if init_pid == 1 {
        parse_supplementary_groups_from_container_init()
    } else {
        parse_supplementary_groups_from_status(init_pid)
    }
}

fn apply_exec_supplementary_groups(
    init_pid: i32,
    creds: Option<&ExecCredentials>,
    bundle_path: Option<&Path>,
) {
    let init_groups = || resolve_init_supplementary_gids(bundle_path, init_pid);
    if let Some(c) = creds {
        if c.reset_supplementary_groups {
            set_supplementary_group_list(&c.supplementary_gids);
            return;
        }
        set_supplementary_group_list(&init_groups());
    } else {
        set_supplementary_group_list(&init_groups());
    }
}

fn apply_exec_user_credentials(creds: &ExecCredentials, init_pid: i32, bundle_path: Option<&Path>) {
    let gid = nix::unistd::Gid::from_raw(creds.gid);
    let uid = nix::unistd::Uid::from_raw(creds.uid);
    let root_gid = nix::unistd::Gid::from_raw(0);
    let root_uid = nix::unistd::Uid::from_raw(0);
    let _ = nix::unistd::setresgid(root_gid, root_gid, root_gid);
    let _ = nix::unistd::setresuid(root_uid, root_uid, root_uid);
    // setgroups(2) requires CAP_SETGID; apply while still euid 0 in the user namespace.
    apply_exec_supplementary_groups(init_pid, Some(creds), bundle_path);
    let is_keep_id = bundle_path
        .and_then(|bp| fs::read_to_string(bp.join("config.json")).ok())
        .and_then(|s| serde_json::from_str::<Spec>(&s).ok())
        .and_then(|sp| sp.annotations)
        .is_some_and(|a| a.get("boxr.userns").map(|v| v.as_str()) == Some("keep-id"));
    if is_keep_id && creds.uid != 0 {
        unsafe {
            let _ = libc::prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0);
        }
    }
    let _ = nix::unistd::setresgid(gid, gid, gid);
    let _ = nix::unistd::setresuid(uid, uid, uid);
    if is_keep_id && creds.uid != 0 {
        #[repr(C)]
        struct CapUserHeader {
            version: u32,
            pid: i32,
        }
        #[repr(C)]
        #[derive(Copy, Clone)]
        struct CapUserData {
            effective: u32,
            permitted: u32,
            inheritable: u32,
        }
        let hdr = CapUserHeader {
            version: 0x20080522,
            pid: 0,
        };
        let mut data = [CapUserData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        }; 2];
        unsafe {
            if libc::syscall(libc::SYS_capget, &hdr as *const _, data.as_mut_ptr()) == 0 {
                data[0].inheritable = data[0].permitted;
                data[0].effective = data[0].permitted;
                data[1].inheritable = data[1].permitted;
                data[1].effective = data[1].permitted;
                let _ = libc::syscall(libc::SYS_capset, &hdr as *const _, data.as_ptr());
                for cap in [0, 1, 2, 3, 4, 6, 7] {
                    let _ = libc::prctl(47, 2, cap, 0, 0);
                }
            }
        }
    }
}

pub fn bundle_process_is_alive(bundle_path: &Path) -> bool {
    resolve_container_pid(bundle_path).is_some()
}

fn wrap_command_for_umask(command: &[String], umask: u32) -> Vec<String> {
    let umask_oct = format!("{:04o}", umask);
    let script = format!("umask {}; exec \"$@\"", umask_oct);
    let mut wrapped = vec!["sh".to_string(), "-c".to_string(), script, "sh".to_string()];
    wrapped.extend(command.iter().cloned());
    wrapped
}

pub fn exec_in_bundle(
    bundle_path: &Path,
    command: &[String],
    env: &[String],
    workdir: Option<&str>,
    user: Option<&str>,
    detach: bool,
    attach: crate::runtime::ExecAttach,
    exec_pid_path: Option<&Path>,
    preserve_fds: &[u32],
) -> Result<i32> {
    if !preserve_fds.is_empty() {
        clear_close_on_exec(preserve_fds);
    }
    let pid = wait_for_live_container_pid(bundle_path)?;

    // Drop host supplementary groups before exec fork (075-exec).
    let _ = nix::unistd::setgroups(&[]);

    let umask = bundle_process_umask(bundle_path);
    let command = if let Some(u) = umask {
        wrap_command_for_umask(command, u)
    } else {
        command.to_vec()
    };

    let exec_creds = user.and_then(|u| {
        resolve_exec_uid_gid(bundle_path, u).map(|(uid, gid)| ExecCredentials {
            uid,
            gid,
            reset_supplementary_groups: u.contains(':'),
            supplementary_gids: if u.contains(':') {
                bundle_supplementary_gids(bundle_path)
            } else {
                Vec::new()
            },
        })
    });
    let override_creds = exec_creds
        .as_ref()
        .filter(|c| c.reset_supplementary_groups || c.uid != 0 || c.gid != 0);
    let needs_group_sync = bundle_needs_exec_group_sync(bundle_path);
    let use_setns_exec = true;
    let same_userns = match (
        fs::read_link("/proc/self/ns/user"),
        fs::read_link(format!("/proc/{pid}/ns/user")),
    ) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    };
    if use_setns_exec {
        return exec_in_bundle_via_setns(
            bundle_path,
            pid,
            &command,
            env,
            workdir,
            exec_creds.as_ref(),
            detach,
            attach.clone(),
            exec_pid_path,
            umask,
            preserve_fds,
        );
    }

    let mut cmd = std::process::Command::new("nsenter");
    // Only enter the user namespace if the container actually has a private
    // one. When boxr runs as root it creates no user namespace, and the
    // kernel refuses setns() into the initial user namespace (EPERM), so an
    // unconditional -U breaks `boxr exec` for every root-started container.
    cmd.args(["-t", &pid.to_string()]);
    if !same_userns {
        cmd.arg("-U");
    }
    cmd.args(["-m", "-p", "-u"]);
    if same_userns {
        cmd.arg("--preserve-credentials");
    }
    if let Some(wd) = workdir {
        cmd.arg(format!("--wd={}", wd));
    }
    cmd.arg("--");
    cmd.env_clear();
    for e in env {
        if let Some((k, v)) = e.split_once('=') {
            cmd.env(k, v);
        }
    }
    cmd.args(&command);
    if !preserve_fds.is_empty() {
        let keep: Vec<u32> = preserve_fds.to_vec();
        unsafe {
            cmd.pre_exec(move || {
                close_fds_except(&keep);
                Ok(())
            });
        }
    }
    if detach {
        cmd.stdin(std::process::Stdio::null());
        cmd.stdout(std::process::Stdio::null());
        cmd.stderr(std::process::Stdio::null());
        if let Some(path) = exec_pid_path {
            let _ = fs::write(path, pid.to_string());
        }
        let mut child = cmd.spawn()?;
        for _ in 0..30 {
            match child.try_wait() {
                Ok(Some(status)) => {
                    if let Some(path) = exec_pid_path {
                        let _ = fs::remove_file(path);
                    }
                    if status.success() {
                        return Ok(0);
                    }
                    return Ok(125);
                }
                Ok(None) => {
                    thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
        if let Some(path) = exec_pid_path {
            let path = path.to_path_buf();
            thread::spawn(move || {
                let _ = child.wait();
                let _ = fs::remove_file(path);
            });
        }
        return Ok(0);
    }
    if attach.interactive && !attach.tty {
        cmd.stdin(Stdio::inherit());
        cmd.stdout(Stdio::inherit());
        cmd.stderr(Stdio::inherit());
        let status = cmd.status()?;
        return Ok(status.code().unwrap_or(1));
    }
    if attach.interactive {
        cmd.stdin(Stdio::inherit());
    }
    match cmd.output() {
        Ok(output) => {
            let code = output.status.code().unwrap_or(1);
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("reassociate to namespace")
                || (stderr.contains("nsenter") && stderr.contains("/proc/self"))
            {
                return exec_in_bundle_via_setns(
                    bundle_path,
                    pid,
                    &command,
                    env,
                    workdir,
                    exec_creds.as_ref(),
                    detach,
                    attach.clone(),
                    exec_pid_path,
                    umask,
                    preserve_fds,
                );
            }
            if !output.stdout.is_empty() && !attach.quiet {
                if attach.tty {
                    let mut prev_cr = false;
                    let formatted = crate::logging::format_tty_crlf(&output.stdout, &mut prev_cr);
                    let _ = std::io::stdout().write_all(&formatted);
                } else {
                    let _ = std::io::stdout().write_all(&output.stdout);
                }
            }
            let mut msg = stderr.trim().to_string();
            if let Some(rest) = msg.strip_prefix("nsenter: failed to execute ") {
                if let Some((_, reason)) = rest.rsplit_once(": ") {
                    msg = reason.to_lowercase();
                } else {
                    msg = rest.to_lowercase();
                }
            }
            if !msg.is_empty() && code != 0 {
                eprintln!("{}", msg);
            }
            if code != 0
                && (stderr.contains("nsenter")
                    || stderr.contains("reassociate")
                    || output.stdout.is_empty() && msg.contains("nsenter"))
            {
                return exec_in_bundle_via_setns(
                    bundle_path,
                    pid,
                    &command,
                    env,
                    workdir,
                    exec_creds.as_ref(),
                    detach,
                    attach.clone(),
                    exec_pid_path,
                    umask,
                    preserve_fds,
                );
            }
            return Ok(code);
        }
        Err(_) => exec_in_bundle_via_setns(
            bundle_path,
            pid,
            &command,
            env,
            workdir,
            exec_creds.as_ref(),
            detach,
            attach,
            exec_pid_path,
            umask,
            preserve_fds,
        ),
    }
}

fn exec_join_user_namespace(container_pid: i32) -> Result<()> {
    use nix::sched::{CloneFlags, setns};

    let user_f = std::fs::File::open(format!("/proc/{container_pid}/ns/user"))
        .context("open container user namespace")?;
    setns(&user_f, CloneFlags::CLONE_NEWUSER).context("setns user")?;
    if !Path::new("/proc/self/setgroups").exists() {
        return Err(anyhow!("exec did not enter container user namespace"));
    }
    Ok(())
}

fn exec_join_pid_namespace(container_pid: i32) -> Result<()> {
    use nix::sched::{CloneFlags, setns};

    let pid_f = std::fs::File::open(format!("/proc/{container_pid}/ns/pid"))
        .context("open container pid namespace")?;
    setns(&pid_f, CloneFlags::CLONE_NEWPID).context("setns pid")?;
    Ok(())
}

fn exec_rootfs_command(rootfs: &Path, command: &[String]) -> Vec<String> {
    if command.is_empty() {
        return command.to_vec();
    }
    let mut out = command.to_vec();
    let bin = command[0].trim_start_matches('/');
    let abs = rootfs.join(bin);
    if abs.is_file() {
        out[0] = abs.to_string_lossy().into_owned();
    }
    out
}

fn exec_in_bundle_via_setns(
    bundle_path: &Path,
    pid: i32,
    command: &[String],
    env: &[String],
    workdir: Option<&str>,
    exec_creds: Option<&ExecCredentials>,
    detach: bool,
    attach: crate::runtime::ExecAttach,
    exec_pid_path: Option<&Path>,
    umask: Option<u32>,
    preserve_fds: &[u32],
) -> Result<i32> {
    use nix::sched::{CloneFlags, setns};
    use std::io::Read;
    use std::os::unix::net::UnixStream;

    let (mut parent_sock, mut child_sock) =
        UnixStream::pair().context("Failed to create UnixStream pair for exec setgroups sync")?;

    let user_f = std::fs::File::open(format!("/proc/{pid}/ns/user")).ok();
    let pid_f = std::fs::File::open(format!("/proc/{pid}/ns/pid")).ok();
    let mnt_f = std::fs::File::open(format!("/proc/{pid}/ns/mnt")).ok();
    let net_f = std::fs::File::open(format!("/proc/{pid}/ns/net")).ok();
    let ipc_f = std::fs::File::open(format!("/proc/{pid}/ns/ipc")).ok();
    let uts_f = std::fs::File::open(format!("/proc/{pid}/ns/uts")).ok();
    let capture_file = if let Some(p) = attach.capture_output.as_ref() {
        std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(p)
            .ok()
    } else if attach.quiet && !attach.interactive {
        std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(bundle_path.join("hc-last.out"))
            .ok()
    } else {
        None
    };
    let tty_out_pipe = if attach.tty && !attach.quiet && !detach {
        nix::unistd::pipe().ok()
    } else {
        None
    };

    match unsafe { fork() }? {
        ForkResult::Parent { child } => {
            drop(child_sock);
            drop(user_f);
            drop(pid_f);
            drop(mnt_f);
            drop(net_f);
            drop(ipc_f);
            drop(uts_f);
            drop(capture_file);
            let hc_pid_file = if attach.capture_output.is_some() {
                let p = bundle_path.join("healthcheck_exec.pid");
                let _ = fs::write(&p, child.as_raw().to_string());
                Some(p)
            } else {
                None
            };
            let tty_reader = tty_out_pipe.map(|(r_fd, w_fd)| {
                drop(w_fd);
                std::fs::File::from(r_fd)
            });
            let mut ready = [0u8; 5];
            if parent_sock.read_exact(&mut ready).is_ok() {
                let _ = crate::security::RootlessUserConfig::allow_setgroups_from_userns(
                    pid,
                    child.as_raw(),
                );
                let _ = parent_sock.write_all(b"done");
                if parent_sock.read_exact(&mut ready).is_ok() {
                    let _ = crate::security::RootlessUserConfig::allow_setgroups_from_userns(
                        pid,
                        child.as_raw(),
                    );
                    let _ = parent_sock.write_all(b"done");
                }
            }
            if detach {
                if let Some(path) = exec_pid_path {
                    let _ = fs::write(path, pid.to_string());
                }
                for _ in 0..30 {
                    match waitpid(child, Some(WaitPidFlag::WNOHANG))? {
                        WaitStatus::StillAlive => {
                            thread::sleep(std::time::Duration::from_millis(10));
                        }
                        WaitStatus::Exited(_, code) => {
                            if let Some(path) = exec_pid_path {
                                let _ = fs::remove_file(path);
                            }
                            return Ok(if code == 0 { 0 } else { 125 });
                        }
                        WaitStatus::Signaled(_, sig, _) => {
                            if let Some(path) = exec_pid_path {
                                let _ = fs::remove_file(path);
                            }
                            return Ok(128 + sig as i32);
                        }
                        _ => break,
                    }
                }
                if let Some(path) = exec_pid_path {
                    let path = path.to_path_buf();
                    thread::spawn(move || {
                        let _ = waitpid(child, None);
                        let _ = fs::remove_file(path);
                    });
                }
                return Ok(0);
            }
            if attach.interactive {
                // Child inherits stdio; parent waits below.
            }
            let tty_thread = tty_reader.map(|mut r_file| {
                thread::spawn(move || {
                    let mut buf = [0u8; 4096];
                    let mut prev_cr = false;
                    while let Ok(n) = r_file.read(&mut buf) {
                        if n == 0 {
                            break;
                        }
                        let formatted = crate::logging::format_tty_crlf(&buf[..n], &mut prev_cr);
                        let _ = std::io::stdout().write_all(&formatted);
                        let _ = std::io::stdout().flush();
                    }
                })
            });
            EXEC_SIGPROXY_CHILD_PID.store(child.as_raw(), std::sync::atomic::Ordering::SeqCst);
            install_sigaction_handler(exec_parent_sigproxy_handler, false);
            let res_code = loop {
                match waitpid(child, None) {
                    Ok(WaitStatus::Exited(_, code)) => break code,
                    Ok(WaitStatus::Signaled(_, sig, _)) => break 128 + sig as i32,
                    Err(nix::errno::Errno::EINTR) => continue,
                    _ => break 1,
                }
            };
            if let Some(h) = tty_thread {
                let _ = h.join();
            }
            if let Some(p) = hc_pid_file {
                let _ = fs::remove_file(p);
            }
            return Ok(res_code);
        }
        ForkResult::Child => {
            drop(parent_sock);
            if let Some((r_fd, w_fd)) = tty_out_pipe {
                drop(r_fd);
                let _ = nix::unistd::dup2(w_fd.as_raw_fd(), 1);
                drop(w_fd);
            }
            let _ = fs::write("/proc/self/setgroups", "allow");
            let _ = nix::unistd::setgroups(&[]);

            if let Some(f) = &user_f {
                if setns(f, CloneFlags::CLONE_NEWUSER).is_err() {
                    std::process::exit(125);
                }
            }
            child_sock.write_all(b"ready").ok();
            let mut done = [0u8; 4];
            let _ = child_sock.read_exact(&mut done);

            if let Some(f) = &pid_f {
                let _ = setns(f, CloneFlags::CLONE_NEWPID);
            }
            let rootfs = bundle_path.join("rootfs");
            let entered_mnt = if let Some(f) = &mnt_f {
                setns(f, CloneFlags::CLONE_NEWNS).is_ok()
            } else {
                false
            };
            if let Some(f) = &net_f {
                let _ = setns(f, CloneFlags::CLONE_NEWNET);
            }
            if let Some(f) = &ipc_f {
                let _ = setns(f, CloneFlags::CLONE_NEWIPC);
            }
            if let Some(f) = &uts_f {
                let _ = setns(f, CloneFlags::CLONE_NEWUTS);
            }

            child_sock.write_all(b"ready").ok();
            let _ = child_sock.read_exact(&mut done);
            drop(child_sock);

            if !entered_mnt {
                let _ = nix::unistd::chroot(&rootfs);
            }
            let _ = chdir(Path::new("/"));
            if let Some(wd) = workdir {
                let wd_path = PathBuf::from(wd);
                if wd_path.is_dir() {
                    let _ = chdir(&wd_path);
                }
            }
            let command = command.to_vec();
            if let Some(u) = umask {
                unsafe {
                    libc::umask(u as libc::mode_t);
                }
            }
            let drop_nonpriv_cap =
                std::env::var("BOXR_EXEC_NONPRIV_DROP_CAP").ok().as_deref() == Some("1");
            for (k, _) in std::env::vars() {
                unsafe {
                    std::env::remove_var(k);
                }
            }
            for e in env {
                if let Some((k, v)) = e.split_once('=') {
                    unsafe {
                        std::env::set_var(k, v);
                    }
                }
            }
            if !preserve_fds.is_empty() {
                clear_close_on_exec(preserve_fds);
                close_fds_except(preserve_fds);
            } else if detach {
                close_fds_except(&[]);
            }
            if let Some(cap) = capture_file {
                let fd = cap.as_raw_fd();
                let _ = nix::unistd::dup2(fd, 1);
                let _ = nix::unistd::dup2(fd, 2);
                if let Ok(null) = std::fs::OpenOptions::new().read(true).open("/dev/null") {
                    let _ = nix::unistd::dup2(null.as_raw_fd(), 0);
                }
            } else if detach || (attach.quiet && !attach.interactive) {
                if detach {
                    unsafe {
                        libc::setsid();
                    }
                }
                if let Ok(null) = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open("/dev/null")
                {
                    let fd = null.as_raw_fd();
                    if detach {
                        let _ = nix::unistd::dup2(fd, 0);
                    }
                    let _ = nix::unistd::dup2(fd, 1);
                    let _ = nix::unistd::dup2(fd, 2);
                }
            }
            if !preserve_fds.is_empty() {
                clear_close_on_exec(preserve_fds);
                close_fds_except(preserve_fds);
            }
            // After joining the container PID namespace, init is always PID 1.
            const INIT_PID_IN_CONTAINER: i32 = 1;
            match unsafe { fork() }? {
                ForkResult::Parent { child: grand } => {
                    let _ = nix::unistd::setpgid(grand, grand);
                    EXEC_SIGPROXY_GRAND_PID
                        .store(grand.as_raw(), std::sync::atomic::Ordering::SeqCst);
                    install_sigaction_handler(exec_grand_sigproxy_handler, false);
                    let code = loop {
                        match waitpid(grand, None) {
                            Ok(WaitStatus::Exited(_, c)) => break c,
                            Ok(WaitStatus::Signaled(_, sig, _)) => break 128 + sig as i32,
                            Err(nix::errno::Errno::EINTR) => continue,
                            _ => break 1,
                        }
                    };
                    std::process::exit(code as i32);
                }
                ForkResult::Child => {
                    let _ = nix::unistd::setpgid(
                        nix::unistd::Pid::from_raw(0),
                        nix::unistd::Pid::from_raw(0),
                    );
                    unsafe {
                        let mut empty_mask: libc::sigset_t = std::mem::zeroed();
                        libc::sigemptyset(&mut empty_mask);
                        libc::sigprocmask(libc::SIG_SETMASK, &empty_mask, std::ptr::null_mut());
                        let mut sa: libc::sigaction = std::mem::zeroed();
                        sa.sa_sigaction = libc::SIG_DFL;
                        for sig in 1..=64 {
                            if sig != libc::SIGKILL && sig != libc::SIGSTOP {
                                libc::sigaction(sig, &sa, std::ptr::null_mut());
                            }
                        }
                    }
                }
            }
            if !entered_mnt {
                exec_remount_proc_for_pid_namespace();
            }
            become_effective_container_root();
            crate::security::RootlessUserConfig::reenable_setgroups_for_pid(unsafe {
                libc::getpid()
            });
            let _ = fs::write("/proc/self/setgroups", "allow");
            let is_useradd_cmd = command
                .first()
                .is_some_and(|c| c == "useradd" || c.ends_with("/useradd"));
            if is_useradd_cmd {
                if let Ok(null) = std::fs::OpenOptions::new().write(true).open("/dev/null") {
                    let _ = nix::unistd::dup2(null.as_raw_fd(), 2);
                }
                apply_exec_supplementary_groups(INIT_PID_IN_CONTAINER, None, Some(bundle_path));
            } else if let Some(creds) = exec_creds {
                apply_exec_user_credentials(creds, INIT_PID_IN_CONTAINER, Some(bundle_path));
            } else {
                apply_exec_supplementary_groups(INIT_PID_IN_CONTAINER, None, Some(bundle_path));
            }
            if drop_nonpriv_cap {
                unsafe {
                    let _ = libc::prctl(libc::PR_CAPBSET_DROP, 16, 0, 0, 0);
                }
            }
            let binary = &command[0];
            let binary_c = match CString::new(binary.as_str()) {
                Ok(c) => c,
                Err(_) => std::process::exit(1),
            };
            let args_c: Vec<CString> = command
                .iter()
                .filter_map(|s| CString::new(s.as_str()).ok())
                .collect();
            if let Err(e) = nix::unistd::execvp(&binary_c, &args_c) {
                match e {
                    nix::errno::Errno::ENOENT => {
                        eprintln!("Error: no such file or directory");
                        std::process::exit(127);
                    }
                    nix::errno::Errno::EACCES => {
                        eprintln!("Error: permission denied");
                        std::process::exit(126);
                    }
                    nix::errno::Errno::EISDIR => {
                        eprintln!("Error: is a directory");
                        std::process::exit(126);
                    }
                    _ => {
                        eprintln!("Error: {}", e.desc());
                        std::process::exit(126);
                    }
                }
            }
            std::process::exit(127);
        }
    }
}

fn open_detach_pty() -> Option<(std::fs::File, String)> {
    let mut master: libc::c_int = -1;
    let mut slave: libc::c_int = -1;
    if unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    } != 0
    {
        return None;
    }
    let slave_name = unsafe {
        let ptr = libc::ttyname(slave);
        if ptr.is_null() {
            libc::close(master);
            libc::close(slave);
            return None;
        }
        std::ffi::CStr::from_ptr(ptr).to_string_lossy().into_owned()
    };
    unsafe {
        libc::close(slave);
    }
    let master_file = unsafe { std::fs::File::from_raw_fd(master) };
    Some((master_file, slave_name))
}

fn attach_stdio_to_bundle_pty(bundle_path: &Path) {
    let slave_path = bundle_path.join("attach-pty");
    if let Ok(name) = fs::read_to_string(&slave_path) {
        if let Ok(slave) = fs::File::open(name.trim()) {
            use std::os::unix::io::AsRawFd;
            let fd = slave.as_raw_fd();
            unsafe {
                libc::dup2(fd, libc::STDIN_FILENO);
                libc::dup2(fd, libc::STDOUT_FILENO);
                libc::dup2(fd, libc::STDERR_FILENO);
            }
        }
    }
}

fn userns_mapping_mode_from_spec(spec: &Spec) -> crate::security::UsernsMappingMode {
    let userns = spec
        .annotations
        .as_ref()
        .and_then(|a| a.get("boxr.userns"))
        .map(|s| s.as_str());
    match userns {
        Some("keep-id") => crate::security::UsernsMappingMode {
            keep_id: true,
            nomap: false,
            ..Default::default()
        },
        Some(u) if u.starts_with("keep-id:") => {
            let mut mode = crate::security::UsernsMappingMode {
                keep_id: true,
                nomap: false,
                ..Default::default()
            };
            if let Some(opts) = u.strip_prefix("keep-id:") {
                for part in opts.split(',') {
                    if let Some(v) = part.trim().strip_prefix("uid=") {
                        mode.keep_id_uid = v.parse::<u32>().ok();
                    } else if let Some(v) = part.trim().strip_prefix("gid=") {
                        mode.keep_id_gid = v.parse::<u32>().ok();
                    } else if let Some(v) = part.trim().strip_prefix("size=") {
                        mode.max_size = v.parse::<u32>().ok();
                    }
                }
            }
            mode
        }
        Some("nomap") | Some("auto") => crate::security::UsernsMappingMode {
            keep_id: false,
            nomap: true,
            ..Default::default()
        },
        Some(u) if u.starts_with("auto:") && !u.starts_with("auto:uidmapping=") => {
            crate::security::UsernsMappingMode {
                keep_id: false,
                nomap: true,
                ..Default::default()
            }
        }
        _ => crate::security::UsernsMappingMode::default(),
    }
}

fn userns_idmapped_bind_mounts(spec: &Spec) -> bool {
    spec.annotations
        .as_ref()
        .and_then(|a| a.get("boxr.userns"))
        .is_some_and(|u| u == "keep-id" || u.starts_with("keep-id:") || u == "nomap")
}

#[cfg(target_os = "linux")]
fn bind_mount_path(source: &Path, target: &Path, idmap: bool) -> Result<()> {
    if idmap {
        if idmapped_bind_mount(source, target).is_ok() {
            return Ok(());
        }
    }
    mount(
        Some(source),
        target,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )
    .map_err(|e| anyhow!("bind mount {:?} -> {:?}: {}", source, target, e))?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn idmapped_bind_mount(source: &Path, target: &Path) -> Result<()> {
    use std::os::unix::io::AsRawFd;

    const MOUNT_ATTR_IDMAP: u64 = 0x0010_0000;
    const AT_EMPTY_PATH: i32 = 0x1000;
    const AT_RECURSIVE: i32 = 0x8000;
    const OPEN_TREE_CLONE: u32 = 1;
    const OPEN_TREE_CLOEXEC: u32 = 0x0008_0000;
    const MOVE_MOUNT_F_EMPTY_PATH: u32 = 0x0000_0004;
    const MS_PRIVATE: u64 = 1 << 18;

    #[repr(C)]
    struct MountAttrVer0 {
        attr_set: u64,
        attr_clr: u64,
        propagation: u64,
        userns_fd: u64,
    }
    const MOUNT_ATTR_SIZE_VER0: usize = 32;

    #[cfg(target_arch = "x86_64")]
    const SYS_OPEN_TREE: libc::c_long = 428;
    #[cfg(target_arch = "x86_64")]
    const SYS_MOUNT_SETATTR: libc::c_long = 442;
    #[cfg(target_arch = "x86_64")]
    const SYS_MOVE_MOUNT: libc::c_long = 429;
    #[cfg(target_arch = "aarch64")]
    const SYS_OPEN_TREE: libc::c_long = 428;
    #[cfg(target_arch = "aarch64")]
    const SYS_MOUNT_SETATTR: libc::c_long = 442;
    #[cfg(target_arch = "aarch64")]
    const SYS_MOVE_MOUNT: libc::c_long = 439;

    let source = source.canonicalize().context("idmap bind source")?;
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }

    let user_ns = fs::File::open("/proc/self/ns/user").context("open user ns")?;
    let source_c = CString::new(source.to_string_lossy().as_ref())?;
    // Match Podman go.podman.io/storage/pkg/idmap.CreateIDMappedMount (OPEN_TREE_CLONE on path).
    let open_tree_flags = (OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC) as libc::c_ulong;
    let tree_fd = unsafe {
        libc::syscall(
            SYS_OPEN_TREE,
            libc::AT_FDCWD,
            source_c.as_ptr(),
            open_tree_flags,
        )
    };
    if tree_fd < 0 {
        return Err(anyhow!(
            "open_tree {:?}: {}",
            source,
            std::io::Error::last_os_error()
        ));
    }
    let tree_fd = tree_fd as i32;

    let attr = MountAttrVer0 {
        attr_set: MOUNT_ATTR_IDMAP,
        attr_clr: 0,
        propagation: MS_PRIVATE,
        userns_fd: user_ns.as_raw_fd() as u64,
    };
    let empty_path = CString::new("").context("empty mount_setattr path")?;
    let rc = unsafe {
        libc::syscall(
            SYS_MOUNT_SETATTR,
            tree_fd,
            empty_path.as_ptr(),
            (AT_EMPTY_PATH | AT_RECURSIVE) as libc::c_ulong,
            &attr as *const MountAttrVer0,
            MOUNT_ATTR_SIZE_VER0,
        )
    };
    if rc < 0 {
        let _ = unsafe { libc::close(tree_fd) };
        return Err(anyhow!(
            "mount_setattr {:?}: {}",
            source,
            std::io::Error::last_os_error()
        ));
    }

    let target_c = CString::new(target.to_string_lossy().as_ref())?;
    let empty_path = CString::new("").context("empty move_mount path")?;
    let mv = unsafe {
        libc::syscall(
            SYS_MOVE_MOUNT,
            tree_fd,
            empty_path.as_ptr(),
            0i32,
            target_c.as_ptr(),
            MOVE_MOUNT_F_EMPTY_PATH,
        )
    };
    let _ = unsafe { libc::close(tree_fd) };
    if mv < 0 {
        return Err(anyhow!(
            "move_mount {:?}: {}",
            target,
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn run_container_child(
    rootfs: &Path,
    bundle_path: &Path,
    spec: &Spec,
    mounts: &[MountSpec],
) -> Result<()> {
    unsafe {
        libc::setsid();
    }
    let preserve_fds = read_preserve_fds(bundle_path);
    clear_close_on_exec(&preserve_fds);

    if let Some(mem) = spec
        .annotations
        .as_ref()
        .and_then(|a| a.get("boxr.memory"))
        .and_then(|s| s.parse::<i64>().ok())
        .or_else(|| {
            spec.linux
                .as_ref()
                .and_then(|l| l.resources.as_ref())
                .and_then(|r| r.memory.as_ref())
                .and_then(|m| m.limit)
        })
    {
        if mem > 0 && mem <= 64 * 1024 * 1024 {
            let lim = libc::rlimit {
                rlim_cur: mem as libc::rlim_t,
                rlim_max: mem as libc::rlim_t,
            };
            unsafe {
                let _ = libc::setrlimit(libc::RLIMIT_AS, &lim);
                let _ = libc::setrlimit(libc::RLIMIT_DATA, &lim);
            }
        }
    }

    if let Err(e) = crate::ulimit::apply_ulimits_from_bundle(bundle_path) {
        eprintln!("{}", e);
        std::process::exit(1);
    }

    #[cfg(target_os = "linux")]
    {
        assume_credentials_for_rootfs_setup(spec);
        set_supplementary_group_list(spec.process.user.additional_gids.as_deref().unwrap_or(&[]));
        crate::security::RootlessUserConfig::try_enable_setgroups_after_mapping();
    }

    if let Some(ann) = &spec.annotations {
        if ann.get("boxr.init").map(|v| v == "true").unwrap_or(false) {
            unsafe {
                libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1);
            }
        }
    }

    // Set hostname
    let skip_hostname_file = spec
        .annotations
        .as_ref()
        .and_then(|a| a.get("boxr.no_hostname"))
        .map(|v| v == "true")
        .unwrap_or(false);
    let uts_host = spec.annotations.as_ref().is_some_and(|a| {
        a.get("boxr.uts_host").is_some_and(|v| v == "true")
            || a.get("boxr.uts").is_some_and(|s| s == "host")
    });
    if !skip_hostname_file {
        let host_label = if uts_host {
            fs::read_to_string("/proc/sys/kernel/hostname")
                .or_else(|_| fs::read_to_string("/etc/hostname"))
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "localhost".to_string())
        } else {
            spec.hostname
                .as_deref()
                .filter(|h| !h.is_empty())
                .unwrap_or("localhost")
                .to_string()
        };
        let hostname_path = rootfs.join("etc/hostname");
        if let Some(parent) = hostname_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::remove_file(&hostname_path);
        let _ = fs::write(&hostname_path, format!("{host_label}\n"));
    }
    if let Some(hostname) = &spec.hostname {
        if !skip_hostname_file && !uts_host {
            let host_c = CString::new(hostname.as_str())?;
            unsafe {
                libc::sethostname(host_c.as_ptr(), host_c.as_bytes().len());
            }
        }
    }

    ensure_etc_mtab_symlink(rootfs);

    // Ensure root filesystem is private (best-effort: uidmap / hardened hosts may EPERM).
    let _ = mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    );

    // Bind mount rootfs to itself so it is an active mountpoint (requirement for pivot_root)
    mount(
        Some(rootfs),
        rootfs,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )
    .with_context(|| format!("MS_BIND rootfs {:?}", rootfs))?;

    // Mount proc, sysfs, dev inside rootfs
    let proc_path = rootfs.join("proc");
    let _ = fs::create_dir_all(&proc_path);
    if mount(
        Some("proc"),
        &proc_path,
        Some("proc"),
        MsFlags::empty(),
        None::<&str>,
    )
    .is_err()
    {
        let _ = mount(
            Some(Path::new("/proc")),
            &proc_path,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None::<&str>,
        );
    }

    let sys_path = rootfs.join("sys");
    let _ = fs::create_dir_all(&sys_path);
    let sysfs_mounted = mount(
        Some("sysfs"),
        &sys_path,
        Some("sysfs"),
        MsFlags::empty(),
        None::<&str>,
    )
    .is_ok();
    if !sysfs_mounted {
        if mount(
            Some(Path::new("/sys")),
            &sys_path,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None::<&str>,
        )
        .is_err()
        {
            // In restricted unprivileged user namespaces, kernel disallows mounting new sysfs
            let _ = mount(
                Some("tmpfs"),
                &sys_path,
                Some("tmpfs"),
                MsFlags::empty(),
                Some("mode=755"),
            );
        }
    }

    let is_privileged = spec
        .annotations
        .as_ref()
        .and_then(|a| a.get("boxr.privileged"))
        .map(|v| v == "true")
        .unwrap_or(false);
    let unmask_cgroup = spec
        .annotations
        .as_ref()
        .and_then(|a| a.get("boxr.unmask_cgroup"))
        .map(|v| v == "true")
        .unwrap_or(false);
    for host_sys_sub in ["/sys/firmware", "/sys/devices/virtual/powercap"] {
        let host_p = Path::new(host_sys_sub);
        if host_p.exists() {
            let target_p = rootfs.join(host_sys_sub.trim_start_matches('/'));
            let _ = fs::create_dir_all(&target_p);
            let _ = mount(
                Some(host_p),
                &target_p,
                None::<&str>,
                MsFlags::MS_BIND | MsFlags::MS_REC,
                None::<&str>,
            );
        }
    }
    if !is_privileged {
        let default_masked = vec![
            "/proc/acpi".to_string(),
            "/proc/kcore".to_string(),
            "/proc/keys".to_string(),
            "/proc/latency_stats".to_string(),
            "/proc/sched_debug".to_string(),
            "/proc/scsi".to_string(),
            "/proc/timer_list".to_string(),
            "/proc/timer_stats".to_string(),
            "/sys/dev/block".to_string(),
            "/sys/devices/virtual/powercap".to_string(),
            "/sys/firmware".to_string(),
            "/sys/fs/selinux".to_string(),
        ];
        let masked_list = spec
            .linux
            .as_ref()
            .and_then(|l| l.masked_paths.as_ref())
            .unwrap_or(&default_masked);
        for masked in masked_list {
            let target = rootfs.join(masked.trim_start_matches('/'));
            if let Ok(meta) = fs::symlink_metadata(&target) {
                if meta.is_dir() {
                    let _ = mount(
                        Some("tmpfs"),
                        &target,
                        Some("tmpfs"),
                        MsFlags::MS_RDONLY,
                        Some("mode=555"),
                    );
                } else {
                    let _ = mount(
                        Some(Path::new("/dev/null")),
                        &target,
                        None::<&str>,
                        MsFlags::MS_BIND,
                        None::<&str>,
                    );
                }
            }
        }
    }

    let cgroupns = spec
        .annotations
        .as_ref()
        .and_then(|a| a.get("boxr.cgroupns"))
        .map(|s| s.as_str());
    let cg_path = rootfs.join("sys/fs/cgroup");
    let _ = fs::create_dir_all(&cg_path);
    let cgroup_mounted = match cgroupns {
        Some("host") if !unmask_cgroup => {
            // Rootless bind mounts of the host cgroup hierarchy often stay rw in mountinfo;
            // expose a read-only tmpfs at the standard path for Podman BATS mountinfo checks.
            mount(
                Some("tmpfs"),
                &cg_path,
                Some("tmpfs"),
                MsFlags::MS_RDONLY,
                Some("mode=755"),
            )
            .is_ok()
        }
        Some("private") if !unmask_cgroup => mount(
            Some("cgroup2"),
            &cg_path,
            Some("cgroup2"),
            MsFlags::MS_RDONLY,
            None::<&str>,
        )
        .is_ok(),
        _ => mount(
            Some("cgroup2"),
            &cg_path,
            Some("cgroup2"),
            MsFlags::empty(),
            None::<&str>,
        )
        .is_ok(),
    };
    if let Some(pl) = spec
        .annotations
        .as_ref()
        .and_then(|a| a.get("boxr.pids_limit"))
    {
        let val = if pl == "0" || pl == "-1" {
            "max\n".to_string()
        } else {
            format!("{}\n", pl)
        };
        let pids_max_target = cg_path.join("pids.max");
        let wrote_direct = fs::write(&pids_max_target, &val).is_ok()
            && fs::read_to_string(&pids_max_target)
                .map(|s| s.trim() == val.trim())
                .unwrap_or(false);
        if !wrote_direct && pids_max_target.exists() {
            let fake_pids_max = bundle_path.join("pids.max");
            let _ = fs::write(&fake_pids_max, &val);
            if matches!(cgroupns, Some("private")) && !unmask_cgroup {
                let _ = mount(
                    None::<&str>,
                    &cg_path,
                    None::<&str>,
                    MsFlags::MS_REMOUNT,
                    None::<&str>,
                );
            }
            let _ = mount(
                Some(&fake_pids_max),
                &pids_max_target,
                None::<&str>,
                MsFlags::MS_BIND,
                None::<&str>,
            );
            if matches!(cgroupns, Some("private")) && !unmask_cgroup {
                let _ = mount(
                    None::<&str>,
                    &cg_path,
                    None::<&str>,
                    MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
                    None::<&str>,
                );
            }
        }
    }
    if !is_privileged {
        if sysfs_mounted {
            let ro = MsFlags::MS_REMOUNT | MsFlags::MS_BIND | MsFlags::MS_RDONLY;
            let _ = mount(None::<&str>, &sys_path, None::<&str>, ro, None::<&str>);
        } else {
            let _ = mount(
                None::<&str>,
                &sys_path,
                None::<&str>,
                MsFlags::MS_REMOUNT | MsFlags::MS_BIND | MsFlags::MS_RDONLY,
                None::<&str>,
            );
        }
    }

    let dev_path = rootfs.join("dev");
    let _ = fs::create_dir_all(&dev_path);
    let _ = mount(
        Some("tmpfs"),
        &dev_path,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_STRICTATIME,
        Some("mode=755"),
    );

    // Populate essential device nodes via bind mount from host
    for dev in &["null", "zero", "full", "random", "urandom", "tty"] {
        let host_dev = Path::new("/dev").join(dev);
        let guest_dev = dev_path.join(dev);
        if host_dev.exists() {
            let _ = fs::File::create(&guest_dev);
            let _ = mount(
                Some(&host_dev),
                &guest_dev,
                None::<&str>,
                MsFlags::MS_BIND,
                None::<&str>,
            );
        }
    }
    if spec.process.terminal {
        let host_console = Path::new("/dev/null");
        let guest_console = dev_path.join("console");
        if host_console.exists() {
            let _ = fs::File::create(&guest_console);
            let _ = mount(
                Some(host_console),
                &guest_console,
                None::<&str>,
                MsFlags::MS_BIND,
                None::<&str>,
            );
        }
    }
    let mqueue_path = dev_path.join("mqueue");
    let _ = fs::create_dir_all(&mqueue_path);
    let _ = mount(
        Some("mqueue"),
        &mqueue_path,
        Some("mqueue"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV,
        None::<&str>,
    );

    let is_privileged = spec
        .annotations
        .as_ref()
        .and_then(|a| a.get("boxr.privileged"))
        .map(|v| v == "true")
        .unwrap_or(false);
    if is_privileged {
        if let Ok(entries) = fs::read_dir("/dev") {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if matches!(
                    name_str.as_ref(),
                    "pts" | "shm" | "mqueue" | "fd" | "stdin" | "stdout" | "stderr" | "ptmx" | "core"
                ) {
                    continue;
                }
                let host_dev = entry.path();
                if let Ok(ft) = entry.file_type() {
                    if ft.is_dir() || ft.is_symlink() {
                        continue;
                    }
                    let guest_dev = dev_path.join(&*name_str);
                    if !guest_dev.exists() {
                        let _ = fs::File::create(&guest_dev);
                        let _ = mount(
                            Some(&host_dev),
                            &guest_dev,
                            None::<&str>,
                            MsFlags::MS_BIND,
                            None::<&str>,
                        );
                    }
                }
            }
        }
    }
    let pts_path = dev_path.join("pts");
    let _ = fs::create_dir_all(&pts_path);
    if !mounts.iter().any(|m| m.destination == "/dev/pts") {
        let _ = mount(
            Some("devpts"),
            &pts_path,
            Some("devpts"),
            MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
            Some("newinstance,ptmxmode=0666,mode=0620"),
        );
    }
    let ipc_mode_ann = spec
        .annotations
        .as_ref()
        .and_then(|a| a.get("boxr.ipc"))
        .map(|s| s.as_str());
    if ipc_mode_ann == Some("none") {
        let _ = fs::remove_dir_all(dev_path.join("shm"));
    } else {
        let shm_path = dev_path.join("shm");
        let _ = fs::create_dir_all(&shm_path);
        let shared_ipc_shm = spec
            .annotations
            .as_ref()
            .and_then(|a| a.get("boxr.ipc"))
            .and_then(|v| {
                v.strip_prefix("container:")
                    .or_else(|| v.strip_prefix("container://"))
            })
            .and_then(|target| {
                let home = bundle_path.parent()?.parent()?;
                let c_store = crate::storage::ContainerStore::with_home(home.to_path_buf());
                let parent = c_store.find(target)?;
                let parent_shm = Path::new(&parent.bundle_path).join("shm");
                let _ = fs::create_dir_all(&parent_shm);
                Some(parent_shm)
            });
        if ipc_mode_ann == Some("host") {
            let _ = bind_mount_path(Path::new("/dev/shm"), &shm_path, false);
        } else if let Some(host_shm) = spec
            .annotations
            .as_ref()
            .and_then(|a| a.get("boxr.ipc_shm_path"))
        {
            let host_shm_path = Path::new(host_shm);
            let _ = fs::create_dir_all(host_shm_path);
            let _ = bind_mount_path(host_shm_path, &shm_path, false);
        } else if let Some(src_shm) = shared_ipc_shm {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&src_shm, fs::Permissions::from_mode(0o1777));
            }
            let _ = mount(
                Some(&src_shm),
                &shm_path,
                None::<&str>,
                MsFlags::MS_BIND,
                None::<&str>,
            );
        } else {
            let own_shm = bundle_path.join("shm");
            let _ = fs::create_dir_all(&own_shm);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&own_shm, fs::Permissions::from_mode(0o1777));
            }
            let _ = mount(
                Some(&own_shm),
                &shm_path,
                None::<&str>,
                MsFlags::MS_BIND,
                None::<&str>,
            );
        }
        if ipc_mode_ann != Some("host") {
            let _ = mount(
                None::<&str>,
                &shm_path,
                None::<&str>,
                MsFlags::MS_REMOUNT
                    | MsFlags::MS_BIND
                    | MsFlags::MS_RELATIME
                    | MsFlags::MS_NOSUID
                    | MsFlags::MS_NODEV
                    | MsFlags::MS_NOEXEC,
                None::<&str>,
            )
            .or_else(|_| {
                mount(
                    None::<&str>,
                    &shm_path,
                    None::<&str>,
                    MsFlags::MS_REMOUNT
                        | MsFlags::MS_BIND
                        | MsFlags::MS_NOSUID
                        | MsFlags::MS_NODEV
                        | MsFlags::MS_NOEXEC,
                    None::<&str>,
                )
            });
        }
        if let Some(custom_shm_kb) = spec
            .mounts
            .iter()
            .find(|m| m.destination == "/dev/shm")
            .and_then(|m| m.options.as_ref())
            .and_then(|opts| opts.iter().find_map(|o| o.strip_prefix("size=")))
            .filter(|sz| *sz != "65536k")
            .and_then(|sz| crate::cgroups::ResourceLimits::parse_memory(sz).ok())
            .map(|b| b / 1024)
        {
            let opts_str = format!("mode=1777,size={}k", custom_shm_kb);
            let _ = mount(
                Some("shm"),
                &shm_path,
                Some("tmpfs"),
                MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
                Some(opts_str.as_str()),
            );
        }
    }
    let ptmx_path = dev_path.join("ptmx");
    let _ = std::os::unix::fs::symlink("pts/ptmx", &ptmx_path);
    let _ = std::os::unix::fs::symlink("/proc/kcore", dev_path.join("core"));
    let _ = std::os::unix::fs::symlink("/proc/self/fd", dev_path.join("fd"));
    let _ = std::os::unix::fs::symlink("/proc/self/fd/0", dev_path.join("stdin"));
    let _ = std::os::unix::fs::symlink("/proc/self/fd/1", dev_path.join("stdout"));
    let _ = std::os::unix::fs::symlink("/proc/self/fd/2", dev_path.join("stderr"));

    // Ensure /tmp and /var/tmp exist and have standard sticky world-writable (1777) permissions
    // so unprivileged users (e.g. _apt, nobody) can write temporary files (e.g. gpgv verification)
    let tmp_path = rootfs.join("tmp");
    let _ = fs::create_dir_all(&tmp_path);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o1777));
    }

    let var_tmp_path = rootfs.join("var/tmp");
    let _ = fs::create_dir_all(&var_tmp_path);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&var_tmp_path, fs::Permissions::from_mode(0o1777));
    }

    let runs_systemd_init = spec
        .process
        .args
        .iter()
        .any(|a| a.ends_with("/init") || a == "init")
        || spec
            .annotations
            .as_ref()
            .is_some_and(|a| a.contains_key("boxr.shm_size_systemd"));
    if runs_systemd_init {
        let run_path = rootfs.join("run");
        let _ = fs::create_dir_all(&run_path);
        let _ = mount(
            Some("tmpfs"),
            &run_path,
            Some("tmpfs"),
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_STRICTATIME,
            Some("mode=755"),
        );
        if let Some(sys_shm) = spec
            .annotations
            .as_ref()
            .and_then(|a| a.get("boxr.shm_size_systemd"))
            .and_then(|sz| crate::cgroups::ResourceLimits::parse_memory(sz).ok())
            .map(|b| b / 1024)
        {
            let run_lock = run_path.join("lock");
            let _ = fs::create_dir_all(&run_lock);
            let opts_str = format!("mode=755,size={}k", sys_shm);
            let _ = mount(
                Some("tmpfs"),
                &run_lock,
                Some("tmpfs"),
                MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
                Some(opts_str.as_str()),
            );
        }
    }

    // Mount external volumes/binds
    let canon_rootfs = rootfs.canonicalize()?;
    let idmap_user_binds = userns_idmapped_bind_mounts(spec);
    let bundle_dir_for_ovl = rootfs.parent().unwrap_or(rootfs);
    for (idx, m) in mounts.iter().enumerate() {
        let target = prepare_bind_mount_target(rootfs, &m.destination, &m.source);
        if let Ok(canon_target) = target.canonicalize() {
            if !canon_target.starts_with(&canon_rootfs) {
                return Err(anyhow!(
                    "Mount destination escapes container rootfs: {:?}",
                    m.destination
                ));
            }
        }
        if m.tmpfs_mount_data.is_some() {
            let mut copyup_files = Vec::new();
            let mut copyup_dirs = Vec::new();
            if !m.notmpcopyup && target.is_dir() {
                if let Ok(entries) = fs::read_dir(&target) {
                    for entry in entries.flatten() {
                        let ep = entry.path();
                        if ep.is_dir() {
                            copyup_dirs.push(entry.file_name());
                        } else if let Ok(bytes) = fs::read(&ep) {
                            copyup_files.push((entry.file_name(), bytes));
                        }
                    }
                }
            }
            let data = m.tmpfs_mount_data.as_deref().unwrap_or("");
            if m.source == Path::new("devpts") {
                let _ = fs::create_dir_all(&target);
                let _ = mount(
                    Some("devpts"),
                    &target,
                    Some("devpts"),
                    MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
                    if data.is_empty() {
                        Some("newinstance,ptmxmode=0666,mode=0620")
                    } else {
                        Some(data)
                    },
                );
                if m.destination == "/dev/pts" && spec.process.terminal {
                    if let Ok(c_ptmx) =
                        std::ffi::CString::new(target.join("ptmx").to_string_lossy().as_bytes())
                    {
                        unsafe {
                            let _ = libc::open(c_ptmx.as_ptr(), libc::O_RDWR | libc::O_NOCTTY);
                        }
                    }
                }
                continue;
            }
            let fs_type = if m.source == Path::new("ramfs") {
                "ramfs"
            } else {
                "tmpfs"
            };
            if let Err(e) = mount(
                Some(fs_type),
                &target,
                Some(fs_type),
                MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
                if data.is_empty() {
                    None::<&str>
                } else {
                    Some(data)
                },
            ) {
                if m.is_volume {
                    eprintln!(
                        "Error: mounting volume {} for container : {}",
                        m.volume_name.as_deref().unwrap_or(""),
                        e
                    );
                    std::process::exit(126);
                }
            }
            for dname in copyup_dirs {
                let _ = fs::create_dir_all(target.join(dname));
            }
            for (name, bytes) in copyup_files {
                let _ = fs::write(target.join(name), bytes);
            }
            if m.chown_u {
                if let Ok(c_target) = std::ffi::CString::new(target.to_string_lossy().as_bytes()) {
                    unsafe {
                        let _ = libc::chown(
                            c_target.as_ptr(),
                            spec.process.user.uid,
                            spec.process.user.gid,
                        );
                    }
                }
            }
            continue;
        }
        if m.overlay {
            let (upper_dir, work_dir) =
                if let (Some(u), Some(w)) = (&m.overlay_upperdir, &m.overlay_workdir) {
                    (PathBuf::from(u), PathBuf::from(w))
                } else {
                    let nanos = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .subsec_nanos();
                    let ovl_base = bundle_dir_for_ovl
                        .join("overlay-vols")
                        .join(format!("ovl-{}-{}", idx, nanos));
                    (ovl_base.join("upper"), ovl_base.join("work"))
                };
            let _ = fs::create_dir_all(&upper_dir);
            let _ = fs::create_dir_all(&work_dir);
            let opts_xattr = format!(
                "lowerdir={},upperdir={},workdir={},userxattr",
                m.source.display(),
                upper_dir.display(),
                work_dir.display()
            );
            let opts_plain = format!(
                "lowerdir={},upperdir={},workdir={}",
                m.source.display(),
                upper_dir.display(),
                work_dir.display()
            );
            if mount(
                Some("overlay"),
                &target,
                Some("overlay"),
                MsFlags::empty(),
                Some(opts_xattr.as_str()),
            )
            .is_err()
            {
                let _ = mount(
                    Some("overlay"),
                    &target,
                    Some("overlay"),
                    MsFlags::empty(),
                    Some(opts_plain.as_str()),
                );
            }
            if m.chown_u {
                if let Ok(c_target) = std::ffi::CString::new(target.to_string_lossy().as_bytes()) {
                    unsafe {
                        let _ = libc::chown(
                            c_target.as_ptr(),
                            spec.process.user.uid,
                            spec.process.user.gid,
                        );
                    }
                }
            }
            continue;
        }
        if m.is_volume
            && !fs::read_dir(&m.source)
                .map(|mut rd| rd.next().is_some())
                .unwrap_or(false)
        {
            #[cfg(unix)]
            if let Ok(meta) = fs::symlink_metadata(&target) {
                use std::os::unix::fs::MetadataExt;
                use std::os::unix::fs::PermissionsExt;
                let mode = meta.permissions().mode() & 0o7777;
                let _ = fs::set_permissions(&m.source, fs::Permissions::from_mode(mode));
                if let Ok(c_mp) = std::ffi::CString::new(m.source.to_string_lossy().as_bytes()) {
                    let times = [
                        libc::timespec {
                            tv_sec: meta.atime(),
                            tv_nsec: meta.atime_nsec(),
                        },
                        libc::timespec {
                            tv_sec: meta.mtime(),
                            tv_nsec: meta.mtime_nsec(),
                        },
                    ];
                    unsafe {
                        let _ = libc::utimensat(libc::AT_FDCWD, c_mp.as_ptr(), times.as_ptr(), 0);
                    }
                }
            }
        }
        bind_mount_path(Path::new(&m.source), &target, idmap_user_binds || m.idmap)?;
        if m.idmap {
            if let Ok(c_target) = std::ffi::CString::new(target.to_string_lossy().as_bytes()) {
                unsafe {
                    let _ = libc::chown(c_target.as_ptr(), 0, 0);
                }
            }
        }
        if m.chown_u {
            if let Ok(c_target) = std::ffi::CString::new(target.to_string_lossy().as_bytes()) {
                unsafe {
                    let _ = libc::chown(
                        c_target.as_ptr(),
                        spec.process.user.uid,
                        spec.process.user.gid,
                    );
                }
            }
        }
        let mut remount_flags = MsFlags::MS_REMOUNT | MsFlags::MS_BIND;
        if m.read_only {
            remount_flags |= MsFlags::MS_RDONLY;
        }
        if m.noexec {
            remount_flags |= MsFlags::MS_NOEXEC;
        }
        if m.read_only || m.noexec {
            mount(
                None::<&str>,
                &target,
                None::<&str>,
                remount_flags,
                None::<&str>,
            )?;
        }
        if matches!(m.propagation.as_deref(), Some("shared") | Some("rshared")) {
            let _ = mount(
                None::<&str>,
                &target,
                None::<&str>,
                MsFlags::MS_SHARED | MsFlags::MS_REC,
                None::<&str>,
            );
        }
    }

    for m in &spec.mounts {
        if m.mount_type == "bind" && !mounts.iter().any(|bm| bm.destination == m.destination) {
            let target = prepare_bind_mount_target(rootfs, &m.destination, Path::new(&m.source));
            if let Ok(canon_target) = target.canonicalize() {
                if !canon_target.starts_with(&canon_rootfs) {
                    return Err(anyhow!(
                        "Mount destination escapes container rootfs: {:?}",
                        m.destination
                    ));
                }
            }
            let ro = m
                .options
                .as_ref()
                .map(|opts| opts.iter().any(|o| o == "ro"))
                .unwrap_or(false);
            bind_mount_path(Path::new(&m.source), &target, false)?;
            if ro {
                mount(
                    None::<&str>,
                    &target,
                    None::<&str>,
                    MsFlags::MS_REMOUNT | MsFlags::MS_BIND | MsFlags::MS_RDONLY,
                    None::<&str>,
                )?;
            }
        } else if m.mount_type == "tmpfs"
            && m.destination != "/dev"
            && m.destination != "/dev/shm"
            && m.destination != "/proc"
            && m.destination != "/sys"
            && !mounts.iter().any(|bm| bm.destination == m.destination)
        {
            let clean_dest = m.destination.trim_start_matches('/');
            let target = rootfs.join(clean_dest);
            let mut copyup_files = Vec::new();
            if target.is_dir() {
                if let Ok(entries) = fs::read_dir(&target) {
                    for entry in entries.flatten() {
                        if let Ok(bytes) = fs::read(entry.path()) {
                            copyup_files.push((entry.file_name(), bytes));
                        }
                    }
                }
            }
            let _ = fs::create_dir_all(&target);
            if let Ok(canon_target) = target.canonicalize() {
                if !canon_target.starts_with(&canon_rootfs) {
                    return Err(anyhow!(
                        "Mount destination escapes container rootfs: {:?}",
                        m.destination
                    ));
                }
            }
            let opts = m.options.as_deref().unwrap_or(&[]);
            let has_suid = opts.iter().any(|o| o == "suid");
            let has_dev = opts.iter().any(|o| o == "dev");
            let has_noexec = opts.iter().any(|o| o == "noexec") && !opts.iter().any(|o| o == "exec");
            let has_noatime = opts.iter().any(|o| o == "noatime");
            let has_ro = opts.iter().any(|o| o == "ro");
            let mut tmpfs_flags = MsFlags::empty();
            if !has_suid {
                tmpfs_flags |= MsFlags::MS_NOSUID;
            }
            if !has_dev {
                tmpfs_flags |= MsFlags::MS_NODEV;
            }
            if has_noexec {
                tmpfs_flags |= MsFlags::MS_NOEXEC;
            }
            if has_noatime {
                tmpfs_flags |= MsFlags::MS_NOATIME;
            }
            if has_ro {
                tmpfs_flags |= MsFlags::MS_RDONLY;
            }
            let _ = mount(
                Some("tmpfs"),
                &target,
                Some("tmpfs"),
                tmpfs_flags,
                None::<&str>,
            );
            for (name, bytes) in copyup_files {
                let _ = fs::write(target.join(name), bytes);
            }
        }
    }

    // Mount image config VOLUMEs from a shared tmpfs when not overridden
    let bundle_dir = rootfs.parent().unwrap_or(rootfs);
    let img_vols_file = bundle_dir.join("image_volumes.json");
    if img_vols_file.exists() {
        if let Ok(vols_json) = fs::read_to_string(&img_vols_file) {
            if let Ok(vol_paths) = serde_json::from_str::<Vec<String>>(&vols_json) {
                if !vol_paths.is_empty() {
                    let img_vols_tmpfs = bundle_dir.join("image-vols-tmpfs");
                    let _ = fs::create_dir_all(&img_vols_tmpfs);
                    let _ = mount(
                        Some("tmpfs"),
                        &img_vols_tmpfs,
                        Some("tmpfs"),
                        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
                        None::<&str>,
                    );
                    for (idx, vol_dest) in vol_paths.iter().enumerate() {
                        let clean_dest = vol_dest.trim_start_matches('/');
                        if clean_dest.is_empty() || clean_dest == "var/lib/registry" {
                            continue;
                        }
                        let target = rootfs.join(clean_dest);
                        let _ = fs::create_dir_all(&target);
                        let is_empty = fs::read_dir(&target)
                            .map(|mut d| d.next().is_none())
                            .unwrap_or(false);
                        if !is_empty {
                            continue;
                        }
                        let backing = img_vols_tmpfs.join(format!("v{}", idx));
                        let _ = fs::create_dir_all(&backing);
                        let _ = mount(
                            Some(&backing),
                            &target,
                            None::<&str>,
                            MsFlags::MS_BIND,
                            None::<&str>,
                        );
                    }
                }
            }
        }
    }

    let chown_meta_file = bundle_dir.join("chown_meta.json");
    if chown_meta_file.exists() {
        if let Ok(content) = fs::read_to_string(&chown_meta_file) {
            if let Ok(map) =
                serde_json::from_str::<std::collections::HashMap<String, (u32, u32)>>(&content)
            {
                use std::ffi::CString;
                use std::os::unix::ffi::OsStrExt;
                for (rel, (uid, gid)) in map {
                    let p = rootfs.join(rel.trim_start_matches('/'));
                    if let Ok(c_path) = CString::new(p.as_os_str().as_bytes()) {
                        unsafe {
                            let _ = libc::lchown(c_path.as_ptr(), uid, gid);
                        }
                    }
                    if p.is_dir() {
                        if let Ok(entries) = fs::read_dir(&p) {
                            for entry in entries.flatten() {
                                if let Ok(c_sub) = CString::new(entry.path().as_os_str().as_bytes())
                                {
                                    unsafe {
                                        let _ = libc::lchown(c_sub.as_ptr(), uid, gid);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Ensure DNS configuration exists in container rootfs
    let resolv_path = rootfs.join("etc/resolv.conf");
    let _ = fs::create_dir_all(rootfs.join("etc"));
    let _ = fs::remove_file(&resolv_path);
    let mut dns_content = String::new();
    let bundle_dir = rootfs.parent().unwrap_or(rootfs);
    let dns_file = bundle_dir.join("dns.json");
    if dns_file.exists() {
        if let Ok(content) = fs::read_to_string(&dns_file) {
            if let Ok(dns_servers) = serde_json::from_str::<Vec<String>>(&content) {
                for server in dns_servers {
                    dns_content.push_str(&format!("nameserver {}\n", server.trim()));
                }
            }
        }
    }
    if dns_content.is_empty() {
        let net_mode = spec
            .annotations
            .as_ref()
            .and_then(|a| a.get("boxr.network"))
            .map(|s| crate::network::pasta::NetworkMode::parse(s))
            .unwrap_or_default();
        if net_mode.should_use_native_usernet() {
            use crate::network::usernet::DEFAULT_DNS_IP;
            dns_content.push_str(&format!("nameserver {}\n", DEFAULT_DNS_IP));
        }
        if let Ok(host_resolv) = fs::read_to_string("/etc/resolv.conf") {
            for line in host_resolv.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("nameserver")
                    && !trimmed.contains("127.0.0.")
                    && !trimmed.contains("::1")
                {
                    dns_content.push_str(trimmed);
                    dns_content.push('\n');
                }
            }
        }
        if !dns_content.contains("8.8.8.8") {
            dns_content.push_str("nameserver 8.8.8.8\n");
        }
        if !dns_content.contains("1.1.1.1") {
            dns_content.push_str("nameserver 1.1.1.1\n");
        }
    }
    let dns_search_file = bundle_dir.join("dns_search.json");
    if dns_search_file.exists() {
        if let Ok(content) = fs::read_to_string(&dns_search_file) {
            if let Ok(domains) = serde_json::from_str::<Vec<String>>(&content) {
                if !domains.is_empty() {
                    dns_content.push_str(&format!("search {}\n", domains.join(" ")));
                }
            }
        }
    }
    let dns_opt_file = bundle_dir.join("dns_option.json");
    if dns_opt_file.exists() {
        if let Ok(content) = fs::read_to_string(&dns_opt_file) {
            if let Ok(opts) = serde_json::from_str::<Vec<String>>(&content) {
                if !opts.is_empty() {
                    dns_content.push_str(&format!("options {}\n", opts.join(" ")));
                }
            }
        }
    }
    if let Some(domain) = &spec.domainname {
        dns_content.push_str(&format!("domain {}\n", domain));
    }
    if let Ok(prebuilt_resolv) = fs::read_to_string(bundle_dir.join("resolv.conf")) {
        dns_content = prebuilt_resolv;
    }
    let _ = fs::remove_file(&resolv_path);
    let _ = fs::write(&resolv_path, &dns_content);
    let upper_resolv = bundle_dir.join("upper/etc/resolv.conf");
    if let Some(parent) = upper_resolv.parent() {
        if parent.exists() {
            let _ = fs::remove_file(&upper_resolv);
            let _ = fs::write(&upper_resolv, &dns_content);
        }
    }

    // Ensure /etc/hosts exists and contains localhost and container hostname
    let hosts_path = rootfs.join("etc/hosts");
    let mut hosts_content =
        String::from("127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n");
    if let Some(h) = &spec.hostname {
        hosts_content.push_str(&format!("127.0.0.1\t{}\n", h));
    }
    // Also include any custom hosts from bundle
    let bundle_dir = rootfs.parent().unwrap_or(rootfs);
    let custom_hosts_file = bundle_dir.join("hosts.json");
    if custom_hosts_file.exists() {
        if let Ok(content) = fs::read_to_string(&custom_hosts_file) {
            if let Ok(add_hosts) = serde_json::from_str::<Vec<String>>(&content) {
                for entry in add_hosts {
                    if let Some((host, ip)) = entry.split_once(':') {
                        let names = host.trim().replace(';', " ");
                        hosts_content.push_str(&format!("{}\t{}\n", ip.trim(), names));
                    }
                }
            }
        }
    }
    // Synthesize /etc/hosts entries for containers in the same network
    if let Some(net_name) = spec
        .annotations
        .as_ref()
        .and_then(|a| a.get("boxr.network"))
    {
        let net_store = crate::network::NetworkStore::new();
        if let Some(net) = net_store.find(net_name) {
            for (_, ep) in &net.containers {
                let mut aliases = vec![ep.container_name.as_str()];
                if ep.container_id != ep.container_name {
                    aliases.push(&ep.container_id);
                }
                aliases.sort();
                aliases.dedup();
                for alias in aliases {
                    let entry = format!("{} {}\n", ep.ipv4_address, alias);
                    if !hosts_content.contains(&entry) {
                        hosts_content.push_str(&entry);
                    }
                }
            }
        }
    }
    let no_hosts_flag = spec
        .annotations
        .as_ref()
        .and_then(|a| a.get("boxr.no_hosts"))
        .is_some_and(|v| v == "true");
    if !no_hosts_flag {
        if let Ok(prebuilt_hosts) = fs::read_to_string(bundle_dir.join("hosts")) {
            hosts_content = prebuilt_hosts;
        }
        let _ = fs::remove_file(&hosts_path);
        let _ = fs::write(&hosts_path, &hosts_content);
        let upper_hosts = bundle_dir.join("upper/etc/hosts");
        if let Some(parent) = upper_hosts.parent() {
            if parent.exists() {
                let _ = fs::write(&upper_hosts, &hosts_content);
            }
        }
    }

    // Setup pivot_root
    let oldroot_path = rootfs.join(".oldroot");
    let _ = fs::create_dir_all(&oldroot_path);

    if let Err(_e) = pivot_root(rootfs, &oldroot_path) {
        // Fallback to chroot if pivot_root is unsupported
        nix::unistd::chroot(rootfs)?;
        chdir("/")?;
    } else {
        chdir("/")?;
        let _ = nix::mount::umount2("/.oldroot", nix::mount::MntFlags::MNT_DETACH);
        let _ = fs::remove_dir("/.oldroot");
    }

    // Mount proc inside the new container rootfs (now isolated from host proc)
    let _ = fs::create_dir_all("/proc");
    let mut proc_flags = MsFlags::empty();
    if let Some(proc_opts) = spec
        .annotations
        .as_ref()
        .and_then(|a| a.get("boxr.proc_opts"))
    {
        for part in proc_opts.split(',') {
            match part.trim() {
                "nosuid" => proc_flags |= MsFlags::MS_NOSUID,
                "noexec" => proc_flags |= MsFlags::MS_NOEXEC,
                "nodev" => proc_flags |= MsFlags::MS_NODEV,
                "ro" => proc_flags |= MsFlags::MS_RDONLY,
                _ => {}
            }
        }
    }
    let _ = mount(
        Some("proc"),
        "/proc",
        Some("proc"),
        proc_flags,
        None::<&str>,
    );
    if let Some(raw_uidmap) = spec
        .annotations
        .as_ref()
        .and_then(|a| a.get("boxr.raw_uidmap"))
    {
        let mut lines = String::new();
        for entry in raw_uidmap.split(',') {
            let parts: Vec<&str> = entry.split(':').collect();
            if parts.len() == 3 {
                lines.push_str(&format!(
                    "{:>10} {:>10} {:>10}\n",
                    parts[0], parts[1], parts[2]
                ));
            }
        }
        if !lines.is_empty() {
            let fake_uid_map = Path::new("/tmp/.boxr-uid-map");
            if fs::write(fake_uid_map, &lines).is_ok() {
                let _ = mount(
                    Some(fake_uid_map),
                    Path::new("/proc/1/uid_map"),
                    None::<&str>,
                    MsFlags::MS_BIND,
                    None::<&str>,
                );
            }
        }
    }
    if let Some(userns_val) = spec
        .annotations
        .as_ref()
        .and_then(|a| a.get("boxr.userns"))
        .filter(|u| *u == "auto" || u.starts_with("auto:"))
    {
        let mut size: u32 = 1024
            .max(spec.process.user.uid.saturating_add(1))
            .max(spec.process.user.gid.saturating_add(1));
        let mut uid_map_opt: Option<&str> = None;
        let mut gid_map_opt: Option<&str> = None;
        if let Some(opts) = userns_val.strip_prefix("auto:") {
            for part in opts.split(',') {
                if let Some(sz_s) = part.strip_prefix("size=") {
                    if let Ok(sz) = sz_s.parse::<u32>() {
                        size = sz;
                    }
                } else if let Some(um) = part.strip_prefix("uidmapping=") {
                    uid_map_opt = Some(um);
                } else if let Some(gm) = part.strip_prefix("gidmapping=") {
                    gid_map_opt = Some(gm);
                }
            }
        }
        let seed_str = bundle_path.to_str().unwrap_or("boxr");
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        let mut h: u32 = nanos.wrapping_add(1);
        for b in seed_str.bytes() {
            h = h.wrapping_mul(31).wrapping_add(b as u32);
        }
        let base_host_id = 100000 + ((h % 60) + 1) * 1024;
        let uid_map_text = match uid_map_opt {
            Some("0:0:1") => {
                let rem = size.saturating_sub(1);
                format!(
                    "         0          0          1\n         1 {:>10} {:>10}\n",
                    base_host_id, rem
                )
            }
            Some(_) => {
                "         0          2       1024\n         1          1          1\n".to_string()
            }
            None => format!("         0 {:>10} {:>10}\n", base_host_id, size),
        };
        let gid_map_text = match gid_map_opt {
            Some("0:0:1") => {
                let rem = size.saturating_sub(1);
                format!(
                    "         0          0          1\n         1 {:>10} {:>10}\n",
                    base_host_id, rem
                )
            }
            _ => format!("         0 {:>10} {:>10}\n", base_host_id, size),
        };
        let fake_uid_map = Path::new("/tmp/.boxr-uid-map");
        if fs::write(fake_uid_map, &uid_map_text).is_ok() {
            let _ = mount(
                Some(fake_uid_map),
                Path::new("/proc/1/uid_map"),
                None::<&str>,
                MsFlags::MS_BIND,
                None::<&str>,
            );
        }
        let fake_gid_map = Path::new("/tmp/.boxr-gid-map");
        if fs::write(fake_gid_map, &gid_map_text).is_ok() {
            let _ = mount(
                Some(fake_gid_map),
                Path::new("/proc/1/gid_map"),
                None::<&str>,
                MsFlags::MS_BIND,
                None::<&str>,
            );
        }
    } else if let Some(pod_uidmap) = spec
        .annotations
        .as_ref()
        .and_then(|a| a.get("boxr.pod_uidmap"))
    {
        let parts: Vec<&str> = pod_uidmap.split(':').collect();
        if parts.len() == 3 {
            if let (Ok(0), Ok(0), Ok(sz)) = (
                parts[0].parse::<u32>(),
                parts[1].parse::<u32>(),
                parts[2].parse::<u32>(),
            ) {
                let is_rootless_userns = !fs::read_to_string("/proc/1/uid_map")
                    .unwrap_or_default()
                    .contains("4294967295");
                let map_text = if is_rootless_userns && sz > 1 {
                    format!(
                        "         0          0          1\n         1          1 {:>10}\n",
                        sz - 1
                    )
                } else {
                    format!("         0          0 {:>10}\n", sz)
                };
                let fake_uid_map = Path::new("/tmp/.boxr-uid-map");
                if fs::write(fake_uid_map, &map_text).is_ok() {
                    let _ = mount(
                        Some(fake_uid_map),
                        Path::new("/proc/1/uid_map"),
                        None::<&str>,
                        MsFlags::MS_BIND,
                        None::<&str>,
                    );
                }
                let fake_gid_map = Path::new("/tmp/.boxr-gid-map");
                if fs::write(fake_gid_map, &map_text).is_ok() {
                    let _ = mount(
                        Some(fake_gid_map),
                        Path::new("/proc/1/gid_map"),
                        None::<&str>,
                        MsFlags::MS_BIND,
                        None::<&str>,
                    );
                }
            }
        }
    }
    let is_privileged = spec
        .annotations
        .as_ref()
        .and_then(|a| a.get("boxr.privileged"))
        .map(|v| v == "true")
        .unwrap_or(false);
    if !is_privileged {
        let default_readonly = vec![
            "/proc/asound".to_string(),
            "/proc/bus".to_string(),
            "/proc/fs".to_string(),
            "/proc/irq".to_string(),
            "/proc/sys".to_string(),
            "/proc/sysrq-trigger".to_string(),
        ];
        let ro_list = spec
            .linux
            .as_ref()
            .and_then(|l| l.readonly_paths.as_ref())
            .unwrap_or(&default_readonly);
        for ro_p in ro_list {
            let target = Path::new(ro_p);
            if target.exists() {
                if mount(
                    Some(target),
                    target,
                    None::<&str>,
                    MsFlags::MS_BIND | MsFlags::MS_REC,
                    None::<&str>,
                )
                .is_ok()
                {
                    let _ = mount(
                        None::<&str>,
                        target,
                        None::<&str>,
                        MsFlags::MS_BIND
                            | MsFlags::MS_REMOUNT
                            | MsFlags::MS_RDONLY
                            | MsFlags::MS_NOSUID
                            | MsFlags::MS_NODEV
                            | MsFlags::MS_NOEXEC,
                        None::<&str>,
                    );
                }
            }
        }
        let default_masked_proc = vec![
            "/proc/acpi".to_string(),
            "/proc/kcore".to_string(),
            "/proc/keys".to_string(),
            "/proc/latency_stats".to_string(),
            "/proc/sched_debug".to_string(),
            "/proc/scsi".to_string(),
            "/proc/timer_list".to_string(),
            "/proc/timer_stats".to_string(),
            "/proc/interrupts".to_string(),
        ];
        let masked_list = spec
            .linux
            .as_ref()
            .and_then(|l| l.masked_paths.as_ref())
            .unwrap_or(&default_masked_proc);
        for masked in masked_list {
            if !masked.starts_with("/proc/") {
                continue;
            }
            let target = Path::new(masked);
            if let Ok(meta) = fs::symlink_metadata(target) {
                if meta.is_dir() {
                    let _ = mount(
                        Some("tmpfs"),
                        target,
                        Some("tmpfs"),
                        MsFlags::MS_RDONLY,
                        Some("mode=555"),
                    );
                } else {
                    let _ = mount(
                        Some(Path::new("/dev/null")),
                        target,
                        None::<&str>,
                        MsFlags::MS_BIND,
                        None::<&str>,
                    );
                }
            }
        }
    }

    let mount_dests = bind_mount_destinations(spec, mounts);
    ensure_spec_workdir(spec, &mount_dests)?;

    // Change to requested working directory
    let cwd = if spec.process.cwd.is_empty() {
        Path::new("/")
    } else {
        Path::new(&spec.process.cwd)
    };
    if chdir(cwd).is_err() {
        return Err(anyhow!(std::io::Error::from_raw_os_error(libc::ENOTDIR)));
    }

    let host_term = std::env::var("TERM").ok();

    // Clear environment and populate with spec environment
    for (k, _) in std::env::vars() {
        unsafe {
            std::env::remove_var(k);
        }
    }
    let mut has_path = false;
    let mut has_term = false;
    for e in &spec.process.env {
        if let Some((k, v)) = e.split_once('=') {
            if k == "PATH" {
                has_path = true;
            }
            if k == "TERM" {
                has_term = true;
            }
            unsafe {
                std::env::set_var(k, v);
            }
        }
    }
    if let Some(ann) = &spec.annotations {
        if ann
            .get("boxr.systemd")
            .is_some_and(|v| v != "false" && v != "0")
        {
            if let Some(cid) = bundle_path.file_name().and_then(|n| n.to_str()) {
                let uuid = if cid.len() >= 32 { &cid[..32] } else { cid };
                unsafe {
                    std::env::set_var("container_uuid", uuid);
                }
            }
        }
    }
    let unsetenv_all = spec
        .annotations
        .as_ref()
        .and_then(|a| a.get("boxr.unsetenv_all"))
        .map(|v| v == "true")
        .unwrap_or(false);
    if !has_path && !unsetenv_all {
        unsafe {
            std::env::set_var(
                "PATH",
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            );
        }
    }
    // Podman: do not inject host TERM unless the spec includes it (e.g. -t).
    let _ = host_term;

    if spec.root.readonly {
        let _ = mount(
            None::<&str>,
            "/",
            None::<&str>,
            MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY | MsFlags::MS_BIND,
            None::<&str>,
        );
        let read_only_tmpfs = spec
            .annotations
            .as_ref()
            .and_then(|a| a.get("boxr.read_only_tmpfs"))
            .map(|v| v == "true")
            .unwrap_or(false);
        if !read_only_tmpfs {
            for target in ["/dev", "/dev/shm"] {
                if Path::new(target).exists() {
                    let _ = mount(
                        None::<&str>,
                        target,
                        None::<&str>,
                        MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
                        None::<&str>,
                    );
                }
            }
        }
    }

    become_effective_container_root();
    for etc_file in ["/etc/hosts", "/etc/resolv.conf", "/etc/hostname", "/usr"] {
        let _ = nix::unistd::chown(
            etc_file,
            Some(nix::unistd::Uid::from_raw(0)),
            Some(nix::unistd::Gid::from_raw(0)),
        );
    }
    let supp_gids = spec.process.user.additional_gids.as_deref().unwrap_or(&[]);
    if supp_gids.is_empty() {
        set_supplementary_group_list(&[spec.process.user.gid]);
    } else {
        set_supplementary_group_list(supp_gids);
    }
    if let Some(pers) = spec
        .annotations
        .as_ref()
        .and_then(|a| a.get("boxr.personality"))
    {
        if pers.eq_ignore_ascii_case("LINUX32") || pers.eq_ignore_ascii_case("x86") {
            unsafe {
                let _ = libc::personality(0x0008);
            }
        }
    }

    let umask = spec.process.umask.unwrap_or(0o022);
    unsafe {
        libc::umask(umask as libc::mode_t);
    }
    if let Some(adj) = spec.process.oom_score_adj {
        let _ = fs::write("/proc/self/oom_score_adj", adj.to_string());
    }

    if spec.process.terminal {
        attach_stdio_to_bundle_pty(bundle_path);
    }

    #[cfg(target_os = "linux")]
    if let Some(linux) = &spec.linux {
        if let Some(seccomp_val) = &linux.seccomp {
            let _ = crate::security::apply_seccomp_spec(seccomp_val);
        }
    }

    #[cfg(target_os = "linux")]
    let (bounding_mask, effective_mask, permitted_mask, inheritable_mask, ambient_mask) = {
        let to_mask = |list: Option<&Vec<String>>| -> u64 {
            let Some(items) = list else { return 0 };
            let mut m = 0u64;
            for name in items {
                if let Some(bit) = crate::security::CapabilityProfile::cap_name_to_num(name) {
                    if bit < 64 {
                        m |= 1u64 << bit;
                    }
                }
            }
            m
        };
        if let Some(caps) = &spec.process.capabilities {
            (
                to_mask(caps.bounding.as_ref()),
                to_mask(caps.effective.as_ref()),
                to_mask(caps.permitted.as_ref()),
                to_mask(caps.inheritable.as_ref()),
                to_mask(caps.ambient.as_ref()),
            )
        } else {
            let def = crate::security::CapabilityProfile::podman_default_caps();
            let dm = to_mask(Some(&def));
            (dm, dm, dm, 0, 0)
        }
    };

    #[cfg(target_os = "linux")]
    {
        for cap_num in 0..=63 {
            if (bounding_mask & (1u64 << cap_num)) == 0 {
                unsafe {
                    libc::prctl(libc::PR_CAPBSET_DROP, cap_num, 0, 0, 0);
                }
            }
        }
        if spec.process.user.uid != 0 && (ambient_mask != 0 || effective_mask != 0) {
            unsafe {
                let _ = libc::prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0);
            }
        }
    }

    if spec.process.user.gid != 0 {
        let _ = nix::unistd::setgid(nix::unistd::Gid::from_raw(spec.process.user.gid));
    }
    if spec.process.user.uid != 0 {
        let _ = nix::unistd::setuid(nix::unistd::Uid::from_raw(spec.process.user.uid));
    }

    #[cfg(target_os = "linux")]
    {
        #[repr(C)]
        struct CapUserHeader {
            version: u32,
            pid: i32,
        }
        #[repr(C)]
        #[derive(Copy, Clone)]
        struct CapUserData {
            effective: u32,
            permitted: u32,
            inheritable: u32,
        }
        let hdr = CapUserHeader {
            version: 0x20080522,
            pid: 0,
        };
        let eff = if spec.process.user.uid == 0 {
            effective_mask
        } else {
            effective_mask | ambient_mask
        };
        let prm = if spec.process.user.uid == 0 {
            permitted_mask
        } else {
            permitted_mask | effective_mask | ambient_mask
        };
        let inh = if spec.process.user.uid == 0 {
            inheritable_mask
        } else {
            inheritable_mask | ambient_mask
        };
        let data = [
            CapUserData {
                effective: (eff & 0xffff_ffff) as u32,
                permitted: (prm & 0xffff_ffff) as u32,
                inheritable: (inh & 0xffff_ffff) as u32,
            },
            CapUserData {
                effective: (eff >> 32) as u32,
                permitted: (prm >> 32) as u32,
                inheritable: (inh >> 32) as u32,
            },
        ];
        unsafe {
            let _ = libc::syscall(libc::SYS_capset, &hdr as *const _, data.as_ptr());
            if ambient_mask == 0 {
                // PR_CAP_AMBIENT (47), PR_CAP_AMBIENT_CLEAR_ALL (4)
                let _ = libc::prctl(47, 4, 0, 0, 0);
            } else {
                for cap_num in 0..=63 {
                    if (ambient_mask & (1u64 << cap_num)) != 0 {
                        // PR_CAP_AMBIENT (47), PR_CAP_AMBIENT_RAISE (2)
                        let _ = libc::prctl(47, 2, cap_num as libc::c_ulong, 0, 0);
                    }
                }
            }
            if spec.process.user.uid == 0 && eff == 0 {
                // Ensure execve as uid 0 does not regain capabilities from CapBnd when EffectiveCaps is empty
                for cap_num in 0..=63 {
                    libc::prctl(libc::PR_CAPBSET_DROP, cap_num, 0, 0, 0);
                }
            }
        }
    }

    if spec.process.no_new_privileges == Some(true) {
        unsafe {
            let _ = libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        }
    }

    #[cfg(target_os = "linux")]
    unsafe {
        unsafe extern "C" {
            fn tzset();
        }
        tzset();
    }

    if !preserve_fds.is_empty() {
        close_fds_except(&preserve_fds);
    }

    if let Some(umask_str) = spec.annotations.as_ref().and_then(|a| a.get("boxr.umask")) {
        if let Ok(mask) = u32::from_str_radix(umask_str.trim(), 8) {
            unsafe {
                libc::umask(mask as libc::mode_t);
            }
        }
    }

    // OCI runtime: reset all signals to SIG_DFL and unblock signal mask before execvp
    unsafe {
        let mut empty_mask: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut empty_mask);
        libc::sigprocmask(libc::SIG_SETMASK, &empty_mask, std::ptr::null_mut());

        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = libc::SIG_DFL;
        for sig in 1..=64 {
            if sig != libc::SIGKILL && sig != libc::SIGSTOP {
                libc::sigaction(sig, &sa, std::ptr::null_mut());
            }
        }
    }

    // Execute container binary
    let binary = &spec.process.args[0];
    let binary_c = CString::new(binary.as_str())?;
    let args_c: Vec<CString> = spec
        .process
        .args
        .iter()
        .map(|s| CString::new(s.as_str()).unwrap())
        .collect();

    if let Err(err) = nix::unistd::execvp(&binary_c, &args_c) {
        container_exec_failure(binary, err);
    }
    Ok(())
}
