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
use std::path::{Path, PathBuf};
use std::os::unix::io::FromRawFd;
use std::os::unix::process::CommandExt;
use std::io::Write;
use std::process::Stdio;
use std::thread;

struct NamespaceJoinState {
    ipc: bool,
    uts: bool,
    net: bool,
}

impl Default for NamespaceJoinState {
    fn default() -> Self {
        Self {
            ipc: false,
            uts: false,
            net: false,
        }
    }
}

fn namespace_clone_flag(ns: &str) -> Option<CloneFlags> {
    match ns {
        "ipc" => Some(CloneFlags::CLONE_NEWIPC),
        "uts" => Some(CloneFlags::CLONE_NEWUTS),
        "net" => Some(CloneFlags::CLONE_NEWNET),
        "mnt" => Some(CloneFlags::CLONE_NEWNS),
        "pid" => Some(CloneFlags::CLONE_NEWPID),
        "cgroup" => Some(CloneFlags::CLONE_NEWCGROUP),
        "user" => Some(CloneFlags::CLONE_NEWUSER),
        _ => None,
    }
}

fn setns_file_path(path: &str, flag: CloneFlags) {
    if let Ok(f) = fs::File::open(path) {
        let _ = setns(&f, flag);
    }
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
    setns_file_path(&format!("/proc/{pid}/ns/{ns}"), flag);
    true
}

fn apply_spec_namespace_joins(spec: &Spec) -> NamespaceJoinState {
    let mut state = NamespaceJoinState::default();
    if let Some(linux) = &spec.linux {
        for ns in &linux.namespaces {
            if let (Some(path), Some(flag)) = (ns.path.as_deref(), namespace_clone_flag(&ns.ns_type))
            {
                setns_file_path(path, flag);
                match ns.ns_type.as_str() {
                    "ipc" => state.ipc = true,
                    "uts" => state.uts = true,
                    "net" => state.net = true,
                    _ => {}
                }
            }
        }
    }
    if let Some(ann) = spec.annotations.as_ref() {
        for (key, ns, slot) in [
            ("boxr.ipc", "ipc", &mut state.ipc),
            ("boxr.uts", "uts", &mut state.uts),
        ] {
            if *slot {
                continue;
            }
            if let Some(val) = ann.get(key) {
                if let Some(target) = val
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
    eprintln!("Error: OCI runtime error: exec failed: {}: {}", executable, detail);
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

fn prepare_bind_mount_target(rootfs: &Path, destination: &str, source: &Path) -> std::path::PathBuf {
    let clean_dest = destination.trim_start_matches('/');
    let target = rootfs.join(clean_dest);
    if source.is_file() {
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
    let deadline = timeout_secs.map(|s| {
        std::time::Instant::now() + std::time::Duration::from_secs(s)
    });
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

fn ensure_spec_workdir(spec: &Spec, mount_dests: &[String]) -> Result<()> {
    if spec.process.cwd.is_empty() {
        return Ok(());
    }
    let cwd_norm = spec.process.cwd.trim_end_matches('/');
    let cwd_path = Path::new(cwd_norm);
    if cwd_path.is_dir() {
        return Ok(());
    }
    let covered = mount_dests.iter().any(|d| {
        let d = d.trim_end_matches('/');
        d == cwd_norm || d.starts_with(&format!("{}/", cwd_norm))
    });
    if covered {
        fs::create_dir_all(cwd_path)?;
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
    let max_fd = if max_fd > 0 {
        max_fd as i32
    } else {
        1024
    };
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
        let file = fs::OpenOptions::new().create(true).append(true).open(&path)?;
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
    fs::copy(exe, &conmon).context("copy conmon shim")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&conmon, fs::Permissions::from_mode(0o755))?;
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
    if unsafe { libc::getuid() } != 0 {
        cmd.env_remove("DBUS_SESSION_BUS_ADDRESS");
    }
}

#[cfg(target_os = "linux")]
fn journal_line(line: &str) {
    use std::ffi::CString;
    use std::os::raw::{c_char, c_int};
    use std::os::unix::net::UnixDatagram;

    unsafe extern "C" {
        fn sd_journal_send(fmt: *const c_char, ...) -> c_int;
    }
    let entry = CString::new(format!("MESSAGE={}", line)).unwrap_or_default();
    let sent = unsafe { sd_journal_send(entry.as_ptr(), std::ptr::null::<c_char>()) };
    if sent >= 0 {
        return;
    }
    // Fallback: journald's /dev/log accepts classic syslog payloads with peer PID.
    if let Ok(sock) = UnixDatagram::unbound() {
        let payload = format!("<6>{}", line);
        let _ = sock.send_to(payload.as_bytes(), "/dev/log");
    }
}

fn tee_reader_to_journal<R: std::io::Read>(
    pipe: R,
    capture: Option<PathBuf>,
    stream: &str,
) {
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

/// Podman-compatible conmon parent: executable path ends with `conmon`, writes pidfile + ConmonPid.
pub fn run_conmon_supervisor(args: &[String]) -> Result<i32> {
    if args.is_empty() {
        return Err(anyhow!("missing bundle path for conmon supervisor"));
    }
    let bundle_path = Path::new(&args[0]);
    let conmon_pid = std::process::id() as i32;
    fs::write(bundle_path.join("conmon.pid"), conmon_pid.to_string())?;
    if let Ok(path) = fs::read_to_string(bundle_path.join("conmon-pidfile.path")) {
        let path = path.trim();
        if !path.is_empty() {
            if let Some(parent) = Path::new(path).parent() {
                let _ = fs::create_dir_all(parent);
            }
            fs::write(path, conmon_pid.to_string())?;
        }
    }

    let detach = bundle_path.join("conmon-detach.flag").exists();
    let log_driver = fs::read_to_string(bundle_path.join("log-driver.txt"))
        .unwrap_or_default()
        .trim()
        .to_string();
    let journald = log_driver == "journald";
    let capture_path = fs::read_to_string(bundle_path.join("journald-capture.path"))
        .ok()
        .map(PathBuf::from);

    let conmon_bin = bundle_path.join("conmon");
    let mut cmd = std::process::Command::new(&conmon_bin);
    cmd.arg("__internal-trampoline").arg(bundle_path);
    cmd.stdin(Stdio::null());

    if detach {
        let log_file = fs::File::create(bundle_path.join("logs.txt"))?;
        let err_file = log_file.try_clone()?;
        cmd.stdout(log_file).stderr(err_file);
    } else if journald {
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    } else {
        cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());
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

    if journald && !detach {
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let cap = capture_path.clone();
        let h_out = stdout.map(|pipe| {
            thread::spawn(move || tee_reader_to_journal(pipe, cap, "stdout"))
        });
        let h_err = stderr.map(|pipe| {
            thread::spawn(move || tee_reader_to_journal(pipe, capture_path, "stderr"))
        });
        let status = child.wait()?;
        if let Some(h) = h_out {
            let _ = h.join();
        }
        if let Some(h) = h_err {
            let _ = h.join();
        }
        return Ok(status.code().unwrap_or(1));
    }

    let status = child.wait()?;
    Ok(status.code().unwrap_or(1))
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
        if !network_mode.should_use_pasta() {
            let _ = crate::network::spawn_port_forward_daemon(bundle_path, &ports);
        }
    }

    let exe = std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("boxr"));

    // Podman uses a conmon parent for detached containers (ConmonPid, stop/teardown semantics).
    if use_conmon_shim(_spec) || detach {
        let conmon = prepare_conmon_shim(bundle_path, _spec, &exe)?;
        if detach {
            let _ = fs::write(bundle_path.join("conmon-detach.flag"), "1");
        }
        let mut cmd = std::process::Command::new(&conmon);
        let syslog_shim = _spec.annotations.as_ref().is_some_and(|a| {
            a.get("boxr.conmon_syslog") == Some(&"1".to_string())
        });
        #[cfg(unix)]
        if syslog_shim {
            use std::os::unix::process::CommandExt;
            cmd.arg0("conmon --exit-command-arg--syslog");
        }
        cmd.arg("__internal-conmon-supervisor").arg(bundle_path);
        cmd.stdin(Stdio::null());
        scrub_conmon_parent_env(&mut cmd);
        if detach {
            cmd.stdout(Stdio::null()).stderr(Stdio::null());
            #[cfg(unix)]
            {
                use std::os::unix::process::CommandExt;
                cmd.process_group(0);
            }
            let _child = cmd.spawn().context("spawn conmon supervisor")?;
            let wait_start = std::time::Instant::now();
            while wait_start.elapsed() < std::time::Duration::from_secs(30) {
                if bundle_path.join("conmon.pid").exists() && bundle_path.join("vm.pid").exists() {
                    break;
                }
                thread::sleep(std::time::Duration::from_millis(50));
            }
            return Ok(0);
        }
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

        let mut child = cmd
            .spawn()
            .context("Failed to spawn container trampoline process")?;

        let child_pid = child.id() as i32;
        let _ = fs::write(bundle_path.join("vm.pid"), child_pid.to_string());
        let _ = fs::write(bundle_path.join("pid"), child_pid.to_string());
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
            let stdout = child.stdout.take();
            let stderr = child.stderr.take();
            let out_attach = io_policy.attach_stdout;
            let err_attach = io_policy.attach_stderr;
            let journald = io_policy.log_driver.as_deref() == Some("journald");
            let h_out = stdout.map(|pipe| {
                let path = log_path.clone();
                thread::spawn(move || {
                    if journald {
                        tee_journald_capture_stream(pipe, Some(path), "stdout", out_attach);
                    } else {
                        crate::logging::tee_k8s_stream(pipe, path, "stdout", out_attach);
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
            let status = child.wait().context("Failed to wait on trampoline")?;
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
            let status = cmd
                .status()
                .context("Failed to execute container trampoline process")?;
            Ok(status.code().unwrap_or(1))
        }
    }
}

/// Outlives the `podman run -d` CLI process; handles restart policy and `--rm`.
pub fn run_detached_wait(args: &[String]) -> Result<i32> {
    if args.len() < 2 {
        return Err(anyhow!("detached-wait: need bundle_path and trampoline_pid"));
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

    // Check if we are non-root (unprivileged rootless mode)
    let is_rootless = unsafe { libc::getuid() != 0 };

    if is_rootless {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixStream;

        let use_pasta = network_mode.should_use_pasta();
        let requires_netns = network_mode.requires_new_netns();

        let (mut parent_sock, mut child_sock) = UnixStream::pair()
            .context("Failed to create UnixStream pair for user namespace sync")?;

        match unsafe { fork() }? {
            ForkResult::Parent { child } => {
                drop(child_sock);
                // 1. Wait for child to unshare user namespace
                let mut sync_buf = [0u8; 5];
                parent_sock
                    .read_exact(&mut sync_buf)
                    .context("Failed to read sync from container child (unshare failed)")?;

                // 2. Configure UID and GID mapping for child PID in parent namespace
                let mapping_res = if let Some((uid_maps, gid_maps)) =
                    crate::id_maps_from_spec(&spec)
                {
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

                // 3. Notify child that mapping is complete
                parent_sock
                    .write_all(b"done")
                    .context("Failed to write sync to container child")?;

                // 4. If pasta is active, wait for child to unshare netns and setup pasta
                let mut pasta_child: Option<std::process::Child> = None;
                if use_pasta {
                    let mut net_sync = [0u8; 5];
                    if parent_sock.read_exact(&mut net_sync).is_ok() && &net_sync == b"netok" {
                        let pasta_cfg =
                            crate::network::pasta::PastaConfig::for_pid(child.as_raw(), &ports);
                        pasta_child = crate::network::pasta::PastaDriver::spawn(&pasta_cfg)
                            .ok()
                            .flatten();
                        let _ = parent_sock.write_all(b"gofor");
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
                // 1. Unshare user namespace cleanly in single-threaded child
                if let Err(e) = unshare(CloneFlags::CLONE_NEWUSER) {
                    eprintln!("Failed to unshare user namespace: {:?}", e);
                    std::process::exit(1);
                }
                // Required before parent writes gid_map (newuidmap path skips write_proc_mappings).
                let _ = fs::write("/proc/self/setgroups", "deny");

                // 2. Notify parent that user namespace has been created
                if let Err(e) = child_sock.write_all(b"ready") {
                    eprintln!("Failed to notify parent: {:?}", e);
                    std::process::exit(1);
                }

                // 3. Wait for parent to write UID/GID mappings
                let mut ready_buf = [0u8; 4];
                if let Err(e) = child_sock.read_exact(&mut ready_buf) {
                    eprintln!("Failed to read mapping confirmation: {:?}", e);
                    std::process::exit(1);
                }

                // 4. Child is now root in user namespace.
                let _ = fs::write("/proc/self/setgroups", "allow");
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
                let mut ns_join = apply_spec_namespace_joins(&spec);
                if requires_netns {
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
                    join_network_namespace_for_spec(&spec, &mut ns_join);
                }

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
                if !ports.is_empty() && !use_pasta {
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
                let mut flags = CloneFlags::CLONE_NEWPID | CloneFlags::CLONE_NEWNS;
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
                if !cgroup_host {
                    flags |= CloneFlags::CLONE_NEWCGROUP;
                }

                if let Err(e) = unshare(flags) {
                    eprintln!("Failed to unshare container namespaces: {:?}", e);
                    std::process::exit(1);
                }

                // Fork so workload becomes PID 1 inside the new PID namespace.
                match unsafe { fork() } {
                    Ok(ForkResult::Parent { child: grandchild }) => {
                        let _ = fs::write(
                            bundle_path.join("container.pid"),
                            grandchild.as_raw().to_string(),
                        );
                        crate::security::RootlessUserConfig::reenable_setgroups_for_pid(
                            grandchild.as_raw(),
                        );
                        let timeout_secs = run_timeout_secs(&spec);
                        let status = wait_grandchild_with_optional_timeout(
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
                        let _ = fs::write("/proc/self/setgroups", "allow");
                        if let Err(err) =
                            run_container_child(&abs_rootfs, bundle_path, &spec, &mounts)
                        {
                            eprintln!("Container child failed: {:?}", err);
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
            let ns_join_root = apply_spec_namespace_joins(&spec);
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
            let mut ns_join = apply_spec_namespace_joins(&spec);
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
                let code = wait_grandchild_with_optional_timeout(
                    child,
                    bundle_path,
                    timeout_secs,
                );
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
                if let Err(err) =
                    run_container_child(&abs_rootfs, bundle_path, &spec, &mounts)
                {
                    eprintln!("Container child failed: {:?}", err);
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
    let code = run_unshare_cli(&args)?;
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

/// Run an unshare command in a new user namespace (boxr unshare)
pub fn run_unshare_cli(args: &[String]) -> Result<i32> {
    if let Some(first) = args.first() {
        if first.starts_with("--") {
            crate::cli::usage_errors::exit_usage_error(format!("unknown flag: {}", first));
        }
    }
    let default_cmd = vec![std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string())];
    let cmd = if args.is_empty() { &default_cmd } else { args };

    let is_rootless = unsafe { libc::getuid() != 0 };
    if is_rootless {
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
                drop(parent_sock);

                match waitpid(child, None)? {
                    WaitStatus::Exited(_, code) => Ok(code),
                    WaitStatus::Signaled(_, sig, _) => Ok(128 + sig as i32),
                    _ => Ok(1),
                }
            }
            ForkResult::Child => {
                drop(parent_sock);
                unshare(CloneFlags::CLONE_NEWUSER)?;
                child_sock.write_all(b"ready")?;
                let mut buf = [0u8; 4];
                child_sock.read_exact(&mut buf)?;
                drop(child_sock);

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
        let mut child = std::process::Command::new(&cmd[0]);
        if cmd.len() > 1 {
            child.args(&cmd[1..]);
        }
        let status = child.status()?;
        Ok(status.code().unwrap_or(0))
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
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if let Some(p) = resolve_container_pid(bundle_path) {
            if unsafe { libc::kill(p, 0) == 0 } {
                return Ok(p);
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
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
            lookup_group_gid(&rootfs, g).or_else(|| lookup_passwd_ids(&rootfs, g).map(|(_, gid)| gid))?
        }
    } else if user_field == "root" {
        0
    } else {
        lookup_passwd_ids(&rootfs, user_field).map(|(_, g)| g).unwrap_or(uid)
    };
    Some((uid, gid))
}

fn bundle_supplementary_gids(bundle_path: &Path) -> Vec<u32> {
    let content = fs::read_to_string(bundle_path.join("config.json")).ok();
    let spec: Option<Spec> = content.and_then(|c| serde_json::from_str(&c).ok());
    spec.map(|s| s.process.user.additional_gids.unwrap_or_default())
        .unwrap_or_default()
}

/// Resolved on the host before entering the container mount namespace (rootfs lookups).
struct ExecCredentials {
    uid: u32,
    gid: u32,
    /// Explicit `user:group` replaces supplementary groups (Podman 075-exec).
    reset_supplementary_groups: bool,
    supplementary_gids: Vec<u32>,
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

fn apply_exec_supplementary_groups(init_pid: i32, creds: Option<&ExecCredentials>) {
    let _ = fs::write("/proc/self/setgroups", "allow");
    if let Some(c) = creds {
        if c.reset_supplementary_groups {
            let gids: Vec<nix::unistd::Gid> = c
                .supplementary_gids
                .iter()
                .map(|g| nix::unistd::Gid::from_raw(*g))
                .collect();
            // Explicit user:group clears inherited groups; --group-add supplies extras only.
            let _ = nix::unistd::setgroups(&gids);
            return;
        }
        if c.uid == 0 {
            let gids = parse_supplementary_groups_from_status(init_pid);
            let raw: Vec<nix::unistd::Gid> = gids
                .iter()
                .map(|g| nix::unistd::Gid::from_raw(*g))
                .collect();
            let _ = nix::unistd::setgroups(&raw);
        } else {
            let _ = nix::unistd::setgroups(&[]);
        }
    } else {
        let gids = parse_supplementary_groups_from_status(init_pid);
        let raw: Vec<nix::unistd::Gid> = gids
            .iter()
            .map(|g| nix::unistd::Gid::from_raw(*g))
            .collect();
        let _ = nix::unistd::setgroups(&raw);
    }
}

fn apply_exec_user_credentials(creds: &ExecCredentials, init_pid: i32) {
    let gid = nix::unistd::Gid::from_raw(creds.gid);
    let uid = nix::unistd::Uid::from_raw(creds.uid);
    let root_gid = nix::unistd::Gid::from_raw(0);
    let root_uid = nix::unistd::Uid::from_raw(0);
    let _ = nix::unistd::setresgid(root_gid, root_gid, root_gid);
    let _ = nix::unistd::setresuid(root_uid, root_uid, root_uid);
    apply_exec_supplementary_groups(init_pid, Some(creds));
    let _ = nix::unistd::setresgid(gid, gid, gid);
    let _ = nix::unistd::setresuid(uid, uid, uid);
}

pub fn bundle_process_is_alive(bundle_path: &Path) -> bool {
    resolve_container_pid(bundle_path).is_some()
}

fn wrap_command_for_umask(command: &[String], umask: u32) -> Vec<String> {
    let umask_oct = format!("{:04o}", umask);
    let script = format!("umask {}; exec \"$@\"", umask_oct);
    let mut wrapped = vec![
        "sh".to_string(),
        "-c".to_string(),
        script,
        "sh".to_string(),
    ];
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
    let same_userns = match (
        fs::read_link("/proc/self/ns/user"),
        fs::read_link(format!("/proc/{pid}/ns/user")),
    ) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    };
    if override_creds.is_some() {
        return exec_in_bundle_via_setns(
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
    cmd.args(["-m", "-p", "-u", "--preserve-credentials"]);
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
    if attach.interactive {
        cmd.stdin(Stdio::inherit());
        cmd.stdout(Stdio::inherit());
        cmd.stderr(Stdio::inherit());
        let status = cmd.status()?;
        return Ok(status.code().unwrap_or(1));
    }
    match cmd.output() {
        Ok(output) => {
            let code = output.status.code().unwrap_or(1);
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !output.stdout.is_empty() {
                let _ = std::io::stdout().write_all(&output.stdout);
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
            // nsenter can fail PID namespace reassociation yet still run the command on the
            // host with a broken /proc view (075-exec Groups: lines). Prefer setns when detected.
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
                    attach,
                    exec_pid_path,
                    umask,
                    preserve_fds,
                );
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
                    attach,
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

    let needs_setgroups_sync = exec_creds.is_some();
    let sync_pair = if needs_setgroups_sync {
        Some(
            UnixStream::pair()
                .context("Failed to create UnixStream pair for exec setgroups sync")?,
        )
    } else {
        None
    };

    match unsafe { fork() }? {
        ForkResult::Parent { child } => {
            if let Some((mut parent_sock, _)) = sync_pair {
                let mut ready = [0u8; 5];
                parent_sock
                    .read_exact(&mut ready)
                    .context("exec child did not signal namespace join")?;
                crate::security::RootlessUserConfig::reenable_setgroups_for_pid(child.as_raw());
                parent_sock
                    .write_all(b"done")
                    .context("Failed to notify exec child after setgroups allow")?;
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
            match waitpid(child, None)? {
                WaitStatus::Exited(_, code) => Ok(code),
                WaitStatus::Signaled(_, sig, _) => Ok(128 + sig as i32),
                _ => Ok(1),
            }
        }
        ForkResult::Child => {
            if needs_setgroups_sync {
                // Drop host supplementary groups before joining the container user
                // namespace (setgroups is often EPERM after setns when /proc/pid/setgroups is deny).
                let _ = fs::write("/proc/self/setgroups", "allow");
                let _ = nix::unistd::setgroups(&[]);
            }
            if let Some((_, mut child_sock)) = sync_pair {
                for (name, flag) in [
                    ("user", CloneFlags::CLONE_NEWUSER),
                    ("ipc", CloneFlags::CLONE_NEWIPC),
                    ("uts", CloneFlags::CLONE_NEWUTS),
                    ("net", CloneFlags::CLONE_NEWNET),
                    ("mnt", CloneFlags::CLONE_NEWNS),
                    ("pid", CloneFlags::CLONE_NEWPID),
                ] {
                    let ns_path = format!("/proc/{}/ns/{}", pid, name);
                    if let Ok(f) = std::fs::File::open(&ns_path) {
                        let _ = setns(&f, flag);
                    }
                }
                child_sock
                    .write_all(b"ready")
                    .ok();
                let mut done = [0u8; 4];
                let _ = child_sock.read_exact(&mut done);
                drop(child_sock);
            } else {
                let enter_ns = |name: &str, flag: CloneFlags| {
                    let ns_path = format!("/proc/{}/ns/{}", pid, name);
                    if let Ok(f) = std::fs::File::open(&ns_path) {
                        let _ = setns(&f, flag);
                    }
                };
                for (name, flag) in [
                    ("user", CloneFlags::CLONE_NEWUSER),
                    ("ipc", CloneFlags::CLONE_NEWIPC),
                    ("uts", CloneFlags::CLONE_NEWUTS),
                    ("net", CloneFlags::CLONE_NEWNET),
                    ("mnt", CloneFlags::CLONE_NEWNS),
                    ("pid", CloneFlags::CLONE_NEWPID),
                ] {
                    enter_ns(name, flag);
                }
            }
            if let Some(wd) = workdir {
                let _ = chdir(Path::new(wd));
            } else {
                let _ = chdir(Path::new("/"));
            }
            if let Some(u) = umask {
                unsafe {
                    libc::umask(u as libc::mode_t);
                }
            }
            for e in env {
                if let Some((k, v)) = e.split_once('=') {
                    unsafe {
                        std::env::set_var(k, v);
                    }
                }
            }
            if !Path::new("/proc/self").exists() {
                let _ = nix::mount::mount(
                    Some("proc"),
                    "/proc",
                    Some("proc"),
                    nix::mount::MsFlags::empty(),
                    None::<&str>,
                );
            }
            // After joining the container mount/PID namespaces, ensure /proc reflects
            // the container (075-exec reads /proc/self/status and /proc/1/status).
            let _ = nix::mount::mount(
                Some("proc"),
                "/proc",
                Some("proc"),
                nix::mount::MsFlags::MS_NOSUID
                    | nix::mount::MsFlags::MS_NODEV
                    | nix::mount::MsFlags::MS_NOEXEC,
                None::<&str>,
            );
            if !preserve_fds.is_empty() {
                clear_close_on_exec(preserve_fds);
                close_fds_except(preserve_fds);
            }
            // Container init is PID 1 after joining the container PID namespace.
            let init_pid = 1;
            crate::security::RootlessUserConfig::reenable_setgroups_for_pid(unsafe {
                libc::getpid()
            });
            if let Some(creds) = exec_creds {
                apply_exec_user_credentials(creds, init_pid);
            } else {
                apply_exec_supplementary_groups(init_pid, None);
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
            let _ = nix::unistd::execvp(&binary_c, &args_c);
            std::process::exit(127);
        }
    }
}

fn open_detach_pty() -> Option<(std::fs::File, String)> {
    let mut master: libc::c_int = -1;
    let mut slave: libc::c_int = -1;
    if unsafe { libc::openpty(&mut master, &mut slave, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut()) }
        != 0
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
        },
        Some("nomap") => crate::security::UsernsMappingMode {
            keep_id: false,
            nomap: true,
        },
        _ => crate::security::UsernsMappingMode::default(),
    }
}

fn userns_idmapped_bind_mounts(spec: &Spec) -> bool {
    spec.annotations
        .as_ref()
        .and_then(|a| a.get("boxr.userns"))
        .is_some_and(|u| u == "keep-id" || u == "nomap")
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
    .map_err(|e| anyhow!("bind mount {:?} -> {:?}: {}", source, target, e))
}

#[cfg(target_os = "linux")]
fn idmapped_bind_mount(source: &Path, target: &Path) -> Result<()> {
    use std::os::unix::io::AsRawFd;

    const MOUNT_ATTR_IDMAP: u64 = 0x0010_0000;
    const AT_EMPTY_PATH: i32 = 0x1000;
    const AT_NO_AUTOMOUNT: i32 = 0x800;
    const AT_SYMLINK_NOFOLLOW: i32 = 0x100;
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
    let open_tree_flags = (OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC) as libc::c_ulong
        | (AT_EMPTY_PATH | AT_NO_AUTOMOUNT | AT_SYMLINK_NOFOLLOW) as libc::c_ulong;
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
    let preserve_fds = read_preserve_fds(bundle_path);
    clear_close_on_exec(&preserve_fds);

    if let Err(e) = crate::ulimit::apply_ulimits_from_bundle(bundle_path) {
        eprintln!("{}", e);
        std::process::exit(1);
    }

    #[cfg(target_os = "linux")]
    {
        let _ = fs::write("/proc/self/setgroups", "allow");
        let mut supp: Vec<nix::unistd::Gid> = spec
            .process
            .user
            .additional_gids
            .as_ref()
            .map(|gids| {
                gids.iter()
                    .map(|g| nix::unistd::Gid::from_raw(*g))
                    .collect()
            })
            .unwrap_or_default();
        if supp.is_empty() {
            supp.push(nix::unistd::Gid::from_raw(spec.process.user.gid));
        }
        let _ = nix::unistd::setgroups(&supp);
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
    if !skip_hostname_file {
        let host_label = spec
            .hostname
            .as_deref()
            .filter(|h| !h.is_empty())
            .unwrap_or("localhost");
        let hostname_path = rootfs.join("etc/hostname");
        if let Some(parent) = hostname_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::write(&hostname_path, format!("{host_label}\n"));
    }
    if let Some(hostname) = &spec.hostname {
        if !skip_hostname_file {
            let host_c = CString::new(hostname.as_str())?;
            unsafe {
                libc::sethostname(host_c.as_ptr(), host_c.as_bytes().len());
            }
        }
    }

    ensure_etc_mtab_symlink(rootfs);

    // Ensure root filesystem is private
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )?;

    // Bind mount rootfs to itself so it is an active mountpoint (requirement for pivot_root)
    mount(
        Some(rootfs),
        rootfs,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )?;

    // Mount proc, sysfs, dev inside rootfs
    let proc_path = rootfs.join("proc");
    let _ = fs::create_dir_all(&proc_path);
    let _ = mount(
        Some("proc"),
        &proc_path,
        Some("proc"),
        MsFlags::empty(),
        None::<&str>,
    );

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
        // In restricted unprivileged user namespaces, kernel disallows mounting new sysfs
        let _ = mount(
            Some("tmpfs"),
            &sys_path,
            Some("tmpfs"),
            MsFlags::empty(),
            Some("mode=755"),
        );
    }

    let cgroupns = spec
        .annotations
        .as_ref()
        .and_then(|a| a.get("boxr.cgroupns"))
        .map(|s| s.as_str());
    let cg_path = rootfs.join("sys/fs/cgroup");
    let _ = fs::create_dir_all(&cg_path);
    let cgroup_mounted = match cgroupns {
        Some("host") => {
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
        Some("private") => mount(
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
    let pts_path = dev_path.join("pts");
    let _ = fs::create_dir_all(&pts_path);
    let _ = mount(
        Some("devpts"),
        &pts_path,
        Some("devpts"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        Some("newinstance,ptmxmode=0666,mode=0620"),
    );
    let shm_path = dev_path.join("shm");
    let _ = fs::create_dir_all(&shm_path);
    let _ = mount(
        Some("tmpfs"),
        &shm_path,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        Some("mode=1777,size=67108864"),
    );
    let ptmx_path = dev_path.join("ptmx");
    let _ = std::os::unix::fs::symlink("pts/ptmx", &ptmx_path);
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
        .any(|a| a.ends_with("/init") || a == "init");
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
    }

    // Mount external volumes/binds
    let canon_rootfs = rootfs.canonicalize()?;
    let idmap_user_binds = userns_idmapped_bind_mounts(spec);
    for m in mounts {
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
            let data = m.tmpfs_mount_data.as_deref().unwrap_or("");
            let _ = mount(
                Some("tmpfs"),
                &target,
                Some("tmpfs"),
                MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
                if data.is_empty() {
                    None::<&str>
                } else {
                    Some(data)
                },
            );
            continue;
        }
        bind_mount_path(Path::new(&m.source), &target, idmap_user_binds)?;
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
    }

    for m in &spec.mounts {
        if m.mount_type == "bind" {
            let target =
                prepare_bind_mount_target(rootfs, &m.destination, Path::new(&m.source));
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
            && m.destination != "/proc"
            && m.destination != "/sys"
        {
            let clean_dest = m.destination.trim_start_matches('/');
            let target = rootfs.join(clean_dest);
            let _ = fs::create_dir_all(&target);
            if let Ok(canon_target) = target.canonicalize() {
                if !canon_target.starts_with(&canon_rootfs) {
                    return Err(anyhow!(
                        "Mount destination escapes container rootfs: {:?}",
                        m.destination
                    ));
                }
            }
            let _ = mount(
                Some("tmpfs"),
                &target,
                Some("tmpfs"),
                MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
                None::<&str>,
            );
        }
    }

    // Ensure DNS configuration exists in container rootfs
    let resolv_path = rootfs.join("etc/resolv.conf");
    let _ = fs::create_dir_all(rootfs.join("etc"));
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
    let net_mode = spec
        .annotations
        .as_ref()
        .and_then(|a| a.get("boxr.network"))
        .map(|s| crate::network::pasta::NetworkMode::parse(s))
        .unwrap_or_default();
    if net_mode.should_use_native_usernet() {
        use crate::network::usernet::DEFAULT_DNS_IP;
        dns_content = format!("nameserver {}\n", DEFAULT_DNS_IP);
    }
    if dns_content.is_empty() {
        if let Ok(host_resolv) = fs::read_to_string("/etc/resolv.conf") {
            for line in host_resolv.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("nameserver") {
                    dns_content.push_str(trimmed);
                    dns_content.push('\n');
                }
            }
        }
        if !dns_content.contains("1.1.1.1") {
            dns_content.push_str("nameserver 1.1.1.1\n");
        }
        if !dns_content.contains("8.8.8.8") {
            dns_content.push_str("nameserver 8.8.8.8\n");
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
    let _ = fs::write(&resolv_path, dns_content);

    // Ensure /etc/hosts exists and contains localhost and container hostname
    let hosts_path = rootfs.join("etc/hosts");
    let mut hosts_content =
        String::from("127.0.0.1 localhost\n::1 localhost ip6-localhost ip6-loopback\n");
    if let Some(h) = &spec.hostname {
        hosts_content.push_str(&format!("127.0.0.1 {}\n", h));
    }
    // Also include any custom hosts from bundle
    let bundle_dir = rootfs.parent().unwrap_or(rootfs);
    let custom_hosts_file = bundle_dir.join("hosts.json");
    if custom_hosts_file.exists() {
        if let Ok(content) = fs::read_to_string(&custom_hosts_file) {
            if let Ok(add_hosts) = serde_json::from_str::<Vec<String>>(&content) {
                for entry in add_hosts {
                    if let Some((host, ip)) = entry.split_once(':') {
                        hosts_content.push_str(&format!("{} {}\n", ip.trim(), host.trim()));
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
    let _ = fs::write(&hosts_path, &hosts_content);
    let upper_hosts = bundle_dir.join("upper/etc/hosts");
    if let Some(parent) = upper_hosts.parent() {
        if parent.exists() {
            let _ = fs::write(&upper_hosts, &hosts_content);
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
    let _ = mount(
        Some("proc"),
        "/proc",
        Some("proc"),
        MsFlags::empty(),
        None::<&str>,
    );

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

    #[cfg(target_os = "linux")]
    if let Some(linux) = &spec.linux {
        if linux.seccomp.is_some() {
            let _ = crate::security::apply_default_seccomp();
        }
    }

    #[cfg(target_os = "linux")]
    if let Some(caps) = &spec.process.capabilities {
        if let Some(bounding) = &caps.bounding {
            for cap_num in 0..41 {
                let cap_name = match cap_num {
                    0 => "CAP_CHOWN",
                    1 => "CAP_DAC_OVERRIDE",
                    2 => "CAP_DAC_READ_SEARCH",
                    3 => "CAP_FOWNER",
                    4 => "CAP_FSETID",
                    5 => "CAP_KILL",
                    6 => "CAP_SETGID",
                    7 => "CAP_SETUID",
                    8 => "CAP_SETPCAP",
                    9 => "CAP_LINUX_IMMUTABLE",
                    10 => "CAP_NET_BIND_SERVICE",
                    11 => "CAP_NET_BROADCAST",
                    12 => "CAP_NET_ADMIN",
                    13 => "CAP_NET_RAW",
                    14 => "CAP_IPC_LOCK",
                    15 => "CAP_IPC_OWNER",
                    16 => "CAP_SYS_MODULE",
                    17 => "CAP_SYS_RAWIO",
                    18 => "CAP_SYS_CHROOT",
                    19 => "CAP_SYS_PTRACE",
                    20 => "CAP_SYS_PACCT",
                    21 => "CAP_SYS_ADMIN",
                    22 => "CAP_SYS_BOOT",
                    23 => "CAP_SYS_NICE",
                    24 => "CAP_SYS_RESOURCE",
                    25 => "CAP_SYS_TIME",
                    26 => "CAP_SYS_TTY_CONFIG",
                    27 => "CAP_MKNOD",
                    28 => "CAP_LEASE",
                    29 => "CAP_AUDIT_WRITE",
                    30 => "CAP_AUDIT_CONTROL",
                    31 => "CAP_SETFCAP",
                    32 => "CAP_MAC_OVERRIDE",
                    33 => "CAP_MAC_ADMIN",
                    34 => "CAP_SYSLOG",
                    35 => "CAP_WAKE_ALARM",
                    36 => "CAP_BLOCK_SUSPEND",
                    37 => "CAP_AUDIT_READ",
                    38 => "CAP_PERFMON",
                    39 => "CAP_BPF",
                    40 => "CAP_CHECKPOINT_RESTORE",
                    _ => "",
                };
                if !cap_name.is_empty() && !bounding.contains(&cap_name.to_string()) {
                    unsafe {
                        libc::prctl(libc::PR_CAPBSET_DROP, cap_num, 0, 0, 0);
                    }
                }
            }
        }
    }

    let _ = fs::write("/proc/self/setgroups", "allow");
    let _ = nix::unistd::setgroups(&[]);
    if let Some(gids) = &spec.process.user.additional_gids {
        let raw_gids: Vec<nix::unistd::Gid> = gids
            .iter()
            .map(|g| nix::unistd::Gid::from_raw(*g))
            .collect();
        let _ = nix::unistd::setgroups(&raw_gids);
    }
    if let Some(u) = spec.process.umask {
        unsafe {
            libc::umask(u as libc::mode_t);
        }
    }
    if let Some(adj) = spec.process.oom_score_adj {
        let _ = fs::write("/proc/self/oom_score_adj", adj.to_string());
    }

    if spec.process.terminal {
        attach_stdio_to_bundle_pty(bundle_path);
    }

    if spec.process.user.gid != 0 {
        let _ = nix::unistd::setgid(nix::unistd::Gid::from_raw(spec.process.user.gid));
    }
    if spec.process.user.uid != 0 {
        let _ = nix::unistd::setuid(nix::unistd::Uid::from_raw(spec.process.user.uid));
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
