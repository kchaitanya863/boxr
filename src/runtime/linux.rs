use crate::network::PortMapping;
use crate::oci::runtime::Spec;
use crate::volume::MountSpec;
use anyhow::{Context, Result, anyhow};
use nix::mount::{MsFlags, mount};
use nix::sched::{CloneFlags, unshare};
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{ForkResult, chdir, fork, pivot_root};
use std::ffi::CString;
use std::fs;
use std::path::Path;

/// Native Linux execution of an OCI bundle using Linux namespaces and pivot_root.
pub fn execute_bundle(
    bundle_path: &Path,
    _spec: &Spec,
    mounts: &[MountSpec],
    _ports: &[PortMapping],
    detach: bool,
) -> Result<i32> {
    if !mounts.is_empty() {
        let mounts_json = serde_json::to_string(mounts)?;
        let _ = fs::write(bundle_path.join("mounts.json"), mounts_json);
    }
    let ports = crate::network::resolve_bundle_ports(bundle_path, _ports);
    let _ = crate::network::spawn_port_forward_daemon(bundle_path, &ports);

    let exe = std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("boxr"));

    if detach {
        let log_file = fs::File::create(bundle_path.join("logs.txt"))?;
        let err_file = log_file.try_clone()?;
        let mut cmd = std::process::Command::new(&exe);
        cmd.arg("__internal-trampoline")
            .arg(bundle_path)
            .stdin(std::process::Stdio::null())
            .stdout(log_file)
            .stderr(err_file);

        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            cmd.process_group(0);
        }

        let child = cmd
            .spawn()
            .context("Failed to spawn container trampoline process")?;

        let child_pid = child.id() as i32;
        let _ = fs::write(bundle_path.join("vm.pid"), child_pid.to_string());
        let _ = fs::write(bundle_path.join("pid"), child_pid.to_string());
        if let Some(cont_id) = bundle_path.file_name().and_then(|s| s.to_str()) {
            if let Ok(cgroup_mgr) = crate::cgroups::CgroupV2Manager::new(cont_id) {
                let _ = cgroup_mgr.add_process(child_pid);
            }
        }
        Ok(0)
    } else {
        let status = std::process::Command::new(&exe)
            .arg("__internal-trampoline")
            .arg(bundle_path)
            .stdin(std::process::Stdio::inherit())
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .status()
            .context("Failed to execute container trampoline process")?;

        Ok(status.code().unwrap_or(1))
    }
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
                let _ = fs::write(
                    bundle_path.join("container.pid"),
                    child.as_raw().to_string(),
                );
                drop(child_sock);
                // 1. Wait for child to unshare user namespace
                let mut sync_buf = [0u8; 5];
                parent_sock
                    .read_exact(&mut sync_buf)
                    .context("Failed to read sync from container child (unshare failed)")?;

                // 2. Configure UID and GID mapping for child PID in parent namespace
                crate::security::RootlessUserConfig::setup_child_mappings(child.as_raw())
                    .context("Failed to setup rootless UID/GID mappings")?;

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

                let _ = fs::write(
                    bundle_path.join("container.pid"),
                    child.as_raw().to_string(),
                );
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
                // First unshare network namespace if required, so we can configure networking
                // with external helper commands (ip) before creating the container PID namespace.
                if requires_netns {
                    if let Err(e) = unshare(CloneFlags::CLONE_NEWNET) {
                        eprintln!("Failed to unshare network namespace: {:?}", e);
                        std::process::exit(1);
                    }
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
                                platform::run_tap_network_loop(tap_file, &ports);
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
                if !ipc_host {
                    flags |= CloneFlags::CLONE_NEWIPC;
                }
                let uts_host = spec
                    .annotations
                    .as_ref()
                    .and_then(|a| a.get("boxr.uts"))
                    .map(|s| s == "host")
                    .unwrap_or(false);
                if !uts_host {
                    flags |= CloneFlags::CLONE_NEWUTS;
                }
                let cgroup_private = spec
                    .annotations
                    .as_ref()
                    .and_then(|a| a.get("boxr.cgroupns"))
                    .map(|s| s == "private")
                    .unwrap_or(false);
                if cgroup_private {
                    flags |= CloneFlags::CLONE_NEWCGROUP;
                }

                if let Err(e) = unshare(flags) {
                    eprintln!("Failed to unshare container namespaces: {:?}", e);
                    std::process::exit(1);
                }

                // 5. Fork so grandchild becomes PID 1 inside new PID namespace
                match unsafe { fork() } {
                    Ok(ForkResult::Parent { child: grandchild }) => {
                        let _ = fs::write(
                            bundle_path.join("container.pid"),
                            grandchild.as_raw().to_string(),
                        );
                        let status = match waitpid(grandchild, None) {
                            Ok(WaitStatus::Exited(_, code)) => code,
                            Ok(WaitStatus::Signaled(_, sig, _)) => 128 + sig as i32,
                            _ => 1,
                        };

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

                        let _ = fs::write(bundle_path.join("boxr-exitcode"), status.to_string());
                        std::process::exit(status);
                    }
                    Ok(ForkResult::Child) => {
                        unsafe {
                            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
                        }
                        if let Err(err) = run_container_child(&abs_rootfs, &spec, &mounts) {
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
        if network_mode.requires_new_netns() {
            unshare(CloneFlags::CLONE_NEWNET)
                .context("Failed to unshare network namespace (requires CAP_NET_ADMIN or root)")?;

            // Bring loopback interface up
            let _ = std::process::Command::new("ip")
                .args(["link", "set", "lo", "up"])
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
                            platform::run_tap_network_loop(tap_file, &ports);
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
                        let _ = crate::network::rootless::run_forward_helper(bundle_path, &ports);
                        std::process::exit(0);
                    }
                    Ok(ForkResult::Parent { child: fwd_child }) => {
                        fwd_helper_pid = Some(fwd_child);
                    }
                    Err(_) => {}
                }
            }
        }

        // Unshare remaining namespaces: PID, Mount, UTS, IPC
        let mut flags = CloneFlags::CLONE_NEWPID
            | CloneFlags::CLONE_NEWNS
            | CloneFlags::CLONE_NEWUTS
            | CloneFlags::CLONE_NEWIPC;

        unshare(flags).context("Failed to unshare namespaces (requires root or CAP_SYS_ADMIN)")?;

        // Fork: child will become PID 1 inside the new PID namespace
        match unsafe { fork() }? {
            ForkResult::Parent { child } => {
                let _ = fs::write(
                    bundle_path.join("container.pid"),
                    child.as_raw().to_string(),
                );
                let status = match waitpid(child, None)? {
                    WaitStatus::Exited(_, code) => Ok(code),
                    WaitStatus::Signaled(_, sig, _) => Ok(128 + sig as i32),
                    _ => Ok(1),
                };

                if let Some(tap_pid) = tap_worker_pid {
                    let _ = nix::sys::signal::kill(tap_pid, nix::sys::signal::Signal::SIGKILL);
                    let _ = waitpid(tap_pid, None);
                }
                if let Some(fwd_pid) = fwd_helper_pid {
                    let _ = nix::sys::signal::kill(fwd_pid, nix::sys::signal::Signal::SIGKILL);
                    let _ = waitpid(fwd_pid, None);
                }

                status
            }
            ForkResult::Child => {
                if let Err(err) = run_container_child(&abs_rootfs, &spec, &mounts) {
                    eprintln!("Container child failed: {:?}", err);
                    std::process::exit(1);
                }
                std::process::exit(0);
            }
        }
    }
}

/// Run an unshare command in a new user namespace (boxr unshare)
pub fn run_unshare_cli(args: &[String]) -> Result<i32> {
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
                nix::unistd::execvp(&binary_c, &args_c)?;
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

pub fn run_trampoline_exec(args: &[String]) -> Result<i32> {
    if args.is_empty() {
        return Err(anyhow!("Missing bundle path for exec"));
    }
    let bundle_path = Path::new(&args[0]);
    let cmd = &args[1..];
    exec_in_bundle(bundle_path, cmd, &[], None, None, false)
}

pub fn exec_in_bundle(
    bundle_path: &Path,
    command: &[String],
    env: &[String],
    workdir: Option<&str>,
    user: Option<&str>,
    detach: bool,
) -> Result<i32> {
    let target_pid = if let Ok(pid_str) = fs::read_to_string(bundle_path.join("container.pid")) {
        pid_str.trim().parse::<i32>().ok()
    } else {
        None
    };

    let target_pid = target_pid.or_else(|| {
        if let Ok(pid_str) = fs::read_to_string(bundle_path.join("vm.pid")) {
            let pid = pid_str.trim().parse::<i32>().ok()?;
            let proc_task = format!("/proc/{}/task/{}/children", pid, pid);
            if let Ok(children) = fs::read_to_string(&proc_task) {
                if let Some(first_child) = children.split_whitespace().next() {
                    return first_child.parse::<i32>().ok();
                }
            }
            Some(pid)
        } else {
            None
        }
    });

    let pid = match target_pid {
        Some(p) if unsafe { libc::kill(p, 0) == 0 } => p,
        _ => return Err(anyhow!("Container is not running")),
    };

    let mut cmd = std::process::Command::new("nsenter");
    // Only enter the user namespace if the container actually has a private
    // one. When boxr runs as root it creates no user namespace, and the
    // kernel refuses setns() into the initial user namespace (EPERM), so an
    // unconditional -U breaks `boxr exec` for every root-started container.
    let same_userns = match (
        fs::read_link("/proc/self/ns/user"),
        fs::read_link(format!("/proc/{pid}/ns/user")),
    ) {
        (Ok(a), Ok(b)) => a == b,
        _ => false, // unknown: keep historical behavior (pass -U)
    };
    cmd.args(["-t", &pid.to_string()]);
    if !same_userns {
        cmd.arg("-U");
    }
    cmd.args(["-m", "-p", "-u", "--preserve-credentials"]);
    if let Some(wd) = workdir {
        cmd.arg(format!("--wd={}", wd));
    }
    if let Some(u) = user {
        if let Ok(uid) = u.parse::<u32>() {
            cmd.args(["--setuid", &uid.to_string(), "--setgid", &uid.to_string()]);
        }
    }
    cmd.arg("--");
    for e in env {
        if let Some((k, v)) = e.split_once('=') {
            cmd.env(k, v);
        }
    }
    cmd.args(command);
    if detach {
        cmd.stdin(std::process::Stdio::null());
        cmd.stdout(std::process::Stdio::null());
        cmd.stderr(std::process::Stdio::null());
        let _ = cmd.spawn()?;
        return Ok(0);
    }
    match cmd.status() {
        Ok(status) => Ok(status.code().unwrap_or(0)),
        Err(_) => {
            // Fallback: enter namespaces via /proc/<pid>/ns using setns if nsenter command is not installed
            use nix::sched::{CloneFlags, setns};

            let ns_types = [
                ("user", CloneFlags::CLONE_NEWUSER),
                ("ipc", CloneFlags::CLONE_NEWIPC),
                ("uts", CloneFlags::CLONE_NEWUTS),
                ("net", CloneFlags::CLONE_NEWNET),
                ("pid", CloneFlags::CLONE_NEWPID),
                ("mnt", CloneFlags::CLONE_NEWNS),
            ];
            for (name, flag) in ns_types {
                let ns_path = format!("/proc/{}/ns/{}", pid, name);
                if let Ok(f) = std::fs::File::open(&ns_path) {
                    let _ = setns(&f, flag);
                }
            }

            match unsafe { fork() }? {
                ForkResult::Parent { child } => match waitpid(child, None)? {
                    WaitStatus::Exited(_, code) => Ok(code),
                    WaitStatus::Signaled(_, sig, _) => Ok(128 + sig as i32),
                    _ => Ok(1),
                },
                ForkResult::Child => {
                    if let Some(wd) = workdir {
                        let _ = chdir(Path::new(wd));
                    } else {
                        let _ = chdir(Path::new("/"));
                    }
                    for e in env {
                        if let Some((k, v)) = e.split_once('=') {
                            unsafe {
                                std::env::set_var(k, v);
                            }
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
                    let _ = nix::unistd::execvp(&binary_c, &args_c);
                    std::process::exit(127);
                }
            }
        }
    }
}

fn run_container_child(rootfs: &Path, spec: &Spec, mounts: &[MountSpec]) -> Result<()> {
    if let Some(ann) = &spec.annotations {
        if ann.get("boxr.init").map(|v| v == "true").unwrap_or(false) {
            unsafe {
                libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1);
            }
        }
    }

    // Set hostname
    if let Some(hostname) = &spec.hostname {
        let host_c = CString::new(hostname.as_str())?;
        unsafe {
            libc::sethostname(host_c.as_ptr(), host_c.as_bytes().len());
        }
    }

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
    if mount(
        Some("sysfs"),
        &sys_path,
        Some("sysfs"),
        MsFlags::MS_RDONLY,
        None::<&str>,
    )
    .is_err()
    {
        // In restricted unprivileged user namespaces, kernel disallows mounting new sysfs
        // Fallback: mount tmpfs on /sys
        let _ = mount(
            Some("tmpfs"),
            &sys_path,
            Some("tmpfs"),
            MsFlags::MS_RDONLY,
            Some("mode=755"),
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

    // Mount external volumes/binds
    let canon_rootfs = rootfs.canonicalize()?;
    for m in mounts {
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
        let mut flags = MsFlags::MS_BIND | MsFlags::MS_REC;
        if m.read_only {
            flags |= MsFlags::MS_RDONLY;
        }
        let _ = mount(Some(&m.source), &target, None::<&str>, flags, None::<&str>);
    }

    for m in &spec.mounts {
        if m.mount_type == "bind" {
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
            let mut flags = MsFlags::MS_BIND | MsFlags::MS_REC;
            if m.options
                .as_ref()
                .map(|opts| opts.iter().any(|o| o == "ro"))
                .unwrap_or(false)
            {
                flags |= MsFlags::MS_RDONLY;
            }
            let _ = mount(
                Some(Path::new(&m.source)),
                &target,
                None::<&str>,
                flags,
                None::<&str>,
            );
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

    // Change to requested working directory
    let cwd = if spec.process.cwd.is_empty() {
        Path::new("/")
    } else {
        Path::new(&spec.process.cwd)
    };
    let _ = chdir(cwd);

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
    if !has_path {
        unsafe {
            std::env::set_var(
                "PATH",
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            );
        }
    }
    if !has_term {
        if let Some(t) = host_term {
            unsafe {
                std::env::set_var("TERM", t);
            }
        }
    }

    if spec.root.readonly {
        let _ = mount(
            None::<&str>,
            "/",
            None::<&str>,
            MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY | MsFlags::MS_BIND,
            None::<&str>,
        );
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

    if spec.process.user.gid != 0 {
        let _ = nix::unistd::setgid(nix::unistd::Gid::from_raw(spec.process.user.gid));
    }
    if spec.process.user.uid != 0 {
        let _ = nix::unistd::setuid(nix::unistd::Uid::from_raw(spec.process.user.uid));
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

    nix::unistd::execvp(&binary_c, &args_c)?;
    Ok(())
}
