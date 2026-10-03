use crate::network::PortMapping;
use crate::oci::runtime::Spec;
use crate::storage::boxr_home;
use crate::volume::MountSpec;
use anyhow::{Context, Result, anyhow};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const PERM_SO_ARM64: &[u8] = include_bytes!("libboxr_perm.so");
const PERM_SO_X86_64: &[u8] = include_bytes!("libboxr_perm_x86_64.so");

fn apply_vm_resource_args(cmd: &mut Command, spec: Option<&Spec>) {
    let mut mem_set = false;
    let mut cpu_set = false;
    if let Some(ann) = spec.and_then(|s| s.annotations.as_ref()) {
        if let Some(m) = ann.get("boxr.memory") {
            cmd.arg("--memory").arg(m);
            mem_set = true;
        }
        if let Some(c) = ann.get("boxr.cpus") {
            if let Ok(cpus_f) = c.parse::<f64>() {
                let cpu_count = (cpus_f.ceil() as u64).max(1);
                cmd.arg("--cpus").arg(cpu_count.to_string());
                cpu_set = true;
            }
        }
    }
    if !mem_set {
        if let Ok(mb) = std::env::var("BOXR_VM_MEMORY_MB") {
            if let Ok(n) = mb.parse::<u64>() {
                cmd.arg("--memory").arg((n * 1024 * 1024).to_string());
            }
        }
    }
    if !cpu_set {
        if let Ok(cpus) = std::env::var("BOXR_VM_CPUS") {
            if let Ok(n) = cpus.parse::<u64>() {
                cmd.arg("--cpus").arg(n.max(1).to_string());
            }
        }
    }
}

/// Ensure native Apple Virtualization runner binary is compiled and codesigned
pub fn ensure_vz_runner() -> Result<PathBuf> {
    let home = boxr_home();
    let bin_dir = home.join("bin");
    let runner_bin = bin_dir.join("boxr-vz");

    let vz_source = include_str!("boxr-vz.m");
    let entitlements = include_str!("boxr-vz.entitlements");

    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(vz_source.as_bytes());
    hasher.update(entitlements.as_bytes());
    let current_hash = format!("{:x}", hasher.finalize());

    let hash_file = bin_dir.join("boxr-vz.hash");
    if runner_bin.exists() && hash_file.exists() {
        if let Ok(saved_hash) = fs::read_to_string(&hash_file) {
            if saved_hash.trim() == current_hash {
                return Ok(runner_bin);
            }
        }
    }

    fs::create_dir_all(&bin_dir)?;

    let temp_dir = tempfile::tempdir()?;
    let m_file = temp_dir.path().join("boxr-vz.m");
    let ent_file = temp_dir.path().join("boxr-vz.entitlements");

    fs::write(&m_file, vz_source)?;
    fs::write(&ent_file, entitlements)?;

    let status = Command::new("clang")
        .args([
            "-O3",
            "-fobjc-arc",
            "-framework",
            "Foundation",
            "-framework",
            "Virtualization",
            m_file.to_str().unwrap(),
            "-o",
            runner_bin.to_str().unwrap(),
        ])
        .status()
        .context("Failed to compile native Apple Virtualization runner (clang required)")?;

    if !status.success() {
        return Err(anyhow!("clang failed to compile native boxr-vz runner"));
    }

    let sign_status = Command::new("codesign")
        .args([
            "-s",
            "-",
            "--entitlements",
            ent_file.to_str().unwrap(),
            "-f",
            runner_bin.to_str().unwrap(),
        ])
        .status()
        .context("Failed to codesign boxr-vz with virtualization entitlement")?;

    if !sign_status.success() {
        return Err(anyhow!("codesign failed for boxr-vz"));
    }

    let _ = fs::write(&hash_file, current_hash);

    Ok(runner_bin)
}

/// Ensure Linux kernel and initrd exist in ~/.boxr/vm/
pub fn ensure_vm_assets() -> Result<(PathBuf, PathBuf)> {
    let vm_dir = boxr_home().join("vm");
    let kernel_path = vm_dir.join("vmlinux");
    let initrd_path = vm_dir.join("initrd.cpio.gz");

    if kernel_path.exists() && initrd_path.exists() {
        return Ok((kernel_path, initrd_path));
    }

    fs::create_dir_all(&vm_dir)?;

    println!(
        "Initializing native Apple Silicon Linux kernel and micro-VM initrd in ~/.boxr/vm/..."
    );

    let kernel_url =
        "https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/aarch64/netboot/vmlinuz-virt";
    let initrd_url =
        "https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/aarch64/netboot/initramfs-virt";

    let temp_kernel = vm_dir.join("vmlinuz-virt.tmp");
    let status_k = Command::new("curl")
        .args(["-fsSL", kernel_url, "-o", temp_kernel.to_str().unwrap()])
        .status()
        .context("Failed to download Linux kernel via curl")?;

    if !status_k.success() {
        return Err(anyhow!("curl failed downloading Linux kernel"));
    }

    let k_bytes = fs::read(&temp_kernel)?;
    let _ = fs::remove_file(&temp_kernel);

    // Decompress zimg payload (gzip starting at offset 51568 or search for gzip magic)
    let gz_magic = [0x1fu8, 0x8bu8];
    let gz_offset = k_bytes
        .windows(2)
        .position(|w| w == gz_magic)
        .ok_or_else(|| anyhow!("Could not find gzip payload in kernel"))?;

    use flate2::read::GzDecoder;
    use std::io::Read;
    let mut decoder = GzDecoder::new(&k_bytes[gz_offset..]);
    let mut decompressed_kernel = Vec::new();
    decoder.read_to_end(&mut decompressed_kernel)?;
    fs::write(&kernel_path, decompressed_kernel)?;

    let status_i = Command::new("curl")
        .args(["-fsSL", initrd_url, "-o", initrd_path.to_str().unwrap()])
        .status()
        .context("Failed to download initramfs via curl")?;

    if !status_i.success() {
        return Err(anyhow!("curl failed downloading initramfs"));
    }

    println!("✓ Native Linux micro-VM assets successfully installed.");
    Ok((kernel_path, initrd_path))
}

/// Safely quote a string for POSIX shell execution, preventing command injection or variable expansion.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Execute an OCI container bundle on macOS using Apple's native Virtualization.framework.
pub fn execute_bundle(
    bundle_path: &Path,
    spec: &Spec,
    mounts: &[MountSpec],
    ports: &[PortMapping],
    detach: bool,
) -> Result<i32> {
    let raw_rootfs = PathBuf::from(&spec.root.path);
    let rootfs_path = if raw_rootfs.is_absolute() {
        raw_rootfs
    } else {
        bundle_path.join(&spec.root.path)
    };

    if !rootfs_path.exists() {
        return Err(anyhow!("Rootfs not found at {:?}", rootfs_path));
    }

    let abs_rootfs = rootfs_path
        .canonicalize()
        .context("Failed to canonicalize rootfs path")?;

    let cmd_binary = spec
        .process
        .args
        .first()
        .ok_or_else(|| anyhow!("Process args cannot be empty"))?;

    let cmd_args = &spec.process.args[1..];

    if let Some(ann) = &spec.annotations {
        if let Some(platform) = ann.get("boxr.platform") {
            if platform.starts_with("windows") {
                return Err(anyhow!(
                    "Windows container execution requires a native Windows host (Windows Server or Windows 10/11 with Containers feature enabled). The OCI image was successfully downloaded and stored locally."
                ));
            }
            #[cfg(target_arch = "aarch64")]
            if platform.contains("amd64") || platform.contains("x86_64") {
                return Err(anyhow!(
                    "Running linux/amd64 containers on Apple Silicon requires Rosetta 2 for Linux"
                ));
            }
        }
    }

    let runner_bin = ensure_vz_runner()?;
    let (kernel_path, initrd_path) = ensure_vm_assets()?;

    let mut cmd = Command::new(&runner_bin);
    cmd.arg("--bundle").arg(bundle_path);
    cmd.arg("--rootfs").arg(&abs_rootfs);
    cmd.arg("--kernel").arg(&kernel_path);
    cmd.arg("--initrd").arg(&initrd_path);

    for p in ports {
        let host_ip_str = p.host_ip.as_deref().unwrap_or("0.0.0.0");
        cmd.arg("--port").arg(format!(
            "{}:{}:{}",
            host_ip_str, p.host_port, p.container_port
        ));
    }

    apply_vm_resource_args(&mut cmd, Some(spec));

    // Build the runner script inside the container's rootfs
    let mut run_script = String::new();
    run_script.push_str("#!/bin/sh\n");
    run_script.push_str("mount -t proc proc /proc 2>/dev/null || true\n");
    run_script.push_str("mount -t sysfs sysfs /sys 2>/dev/null || true\n");
    run_script.push_str("mount -t devtmpfs devtmpfs /dev 2>/dev/null || true\n");
    run_script.push_str("ln -s /proc/self/fd /dev/fd 2>/dev/null || true\n");
    run_script.push_str("ln -s /proc/self/fd/0 /dev/stdin 2>/dev/null || true\n");
    run_script.push_str("ln -s /proc/self/fd/1 /dev/stdout 2>/dev/null || true\n");
    run_script.push_str("ln -s /proc/self/fd/2 /dev/stderr 2>/dev/null || true\n");
    run_script.push_str("ip link set lo up 2>/dev/null || ifconfig lo up 2>/dev/null || true\n");
    let mut dns_str = String::new();
    let dns_file = bundle_path.join("dns.json");
    if dns_file.exists() {
        if let Ok(content) = fs::read_to_string(&dns_file) {
            if let Ok(dns_servers) = serde_json::from_str::<Vec<String>>(&content) {
                for server in dns_servers {
                    dns_str.push_str(&format!("nameserver {}\\n", server.trim()));
                }
            }
        }
    }
    let dns_search_file = bundle_path.join("dns_search.json");
    if dns_search_file.exists() {
        if let Ok(content) = fs::read_to_string(&dns_search_file) {
            if let Ok(domains) = serde_json::from_str::<Vec<String>>(&content) {
                if !domains.is_empty() {
                    dns_str.push_str(&format!("search {}\\n", domains.join(" ")));
                }
            }
        }
    }
    let dns_opt_file = bundle_path.join("dns_option.json");
    if dns_opt_file.exists() {
        if let Ok(content) = fs::read_to_string(&dns_opt_file) {
            if let Ok(opts) = serde_json::from_str::<Vec<String>>(&content) {
                if !opts.is_empty() {
                    dns_str.push_str(&format!("options {}\\n", opts.join(" ")));
                }
            }
        }
    }
    if let Some(domain) = &spec.domainname {
        dns_str.push_str(&format!("domain {}\\n", domain));
    }
    if dns_str.is_empty() {
        dns_str =
            "nameserver 192.168.64.1\\nnameserver 1.1.1.1\\nnameserver 8.8.8.8\\n".to_string();
    }
    run_script.push_str(&format!(
        "printf '{}' > /etc/resolv.conf 2>/dev/null || true\n",
        dns_str
    ));
    if let Some(umask_val) = spec.process.umask {
        run_script.push_str(&format!("umask {:04o} 2>/dev/null || true\n", umask_val));
    }
    run_script.push_str("mkdir -p /tmp /run 2>/dev/null; chmod 1777 /tmp 2>/dev/null || true\n");
    run_script
        .push_str("mount -t tmpfs -o mode=0777,nodev,nosuid tmpfs /run 2>/dev/null || true\n");
    run_script.push_str("if [ ! -L /var/run ]; then mkdir -p /var/run 2>/dev/null; mount -t tmpfs -o mode=0777,nodev,nosuid tmpfs /var/run 2>/dev/null || true; fi\n");
    run_script.push_str("mkdir -p /usr/local/bin 2>/dev/null; printf '#!/bin/sh\\n/bin/busybox chown \"$@\" 2>/dev/null || /bin/chown \"$@\" 2>/dev/null || true\\nexit 0\\n' > /usr/local/bin/chown 2>/dev/null; chmod +x /usr/local/bin/chown 2>/dev/null || true\n");
    let is_x86_64 = if let Some(ann) = &spec.annotations {
        ann.get("boxr.platform")
            .map(|p| p.contains("amd64") || p.contains("x86_64"))
            .unwrap_or(false)
    } else {
        false
    };
    let perm_bytes = if is_x86_64 {
        PERM_SO_X86_64
    } else {
        PERM_SO_ARM64
    };
    let perm_so_path = rootfs_path.join("libboxr_perm.so");
    let _ = fs::write(&perm_so_path, perm_bytes);
    run_script.push_str("echo /libboxr_perm.so > /etc/ld.so.preload 2>/dev/null || true\n");
    run_script.push_str("export LD_PRELOAD=\"/libboxr_perm.so${LD_PRELOAD:+:$LD_PRELOAD}\"\n");

    // Volume mounts
    let mut all_mounts = mounts.to_vec();
    for m in &spec.mounts {
        if m.mount_type == "bind" {
            let src = PathBuf::from(&m.source);
            if src.exists() {
                all_mounts.push(MountSpec {
                    source: src,
                    destination: m.destination.clone(),
                    read_only: m
                        .options
                        .as_ref()
                        .map(|opts| opts.iter().any(|o| o == "ro"))
                        .unwrap_or(false),
                    is_volume: false,
                });
            }
        } else if m.mount_type == "tmpfs"
            && m.destination != "/dev"
            && m.destination != "/proc"
            && m.destination != "/sys"
        {
            let opts_str = m
                .options
                .as_ref()
                .map(|o| o.join(","))
                .unwrap_or_else(|| "rw".to_string());
            run_script.push_str(&format!(
                "mkdir -p \"{}\" 2>/dev/null; mount -t tmpfs -o {} tmpfs \"{}\" 2>/dev/null || true\n",
                m.destination, opts_str, m.destination
            ));
        }
    }

    for (idx, m) in all_mounts.iter().enumerate() {
        let tag = format!("m{}", idx);
        cmd.arg("--mount")
            .arg(format!("{}={}", tag, m.source.display()));
        let mount_opts = if m.read_only { " -o ro" } else { "" };
        run_script.push_str(&format!(
            "mkdir -p \"{}\" 2>/dev/null; mount -t virtiofs{} \"{}\" \"{}\" 2>/dev/null || true\n",
            m.destination, mount_opts, tag, m.destination
        ));
    }

    let readonly_teardown = if spec.root.readonly {
        run_script.push_str(
            "mount -o remount,ro,bind / 2>/dev/null || mount -o remount,ro / 2>/dev/null || true\n",
        );
        "mount -o remount,rw,bind / 2>/dev/null || mount -o remount,rw / 2>/dev/null || true\n"
    } else {
        ""
    };

    // Environment variables
    for env_var in &spec.process.env {
        if let Some((k, v)) = env_var.split_once('=') {
            run_script.push_str(&format!(
                "export {}=\"{}\"\n",
                k,
                v.replace('\\', "\\\\").replace('"', "\\\"")
            ));
        }
    }

    if let Some(hostname) = &spec.hostname {
        run_script.push_str(&format!("hostname \"{}\" 2>/dev/null || true\n", hostname));
    }

    // Working directory
    let cwd = if spec.process.cwd.is_empty() {
        "/"
    } else {
        &spec.process.cwd
    };
    run_script.push_str(&format!("cd \"{}\" 2>/dev/null || cd /\n", cwd));

    fs::create_dir_all(bundle_path)?;

    // Construct command invocation using safe POSIX shell quoting
    let mut cmd_parts = vec![shell_quote(cmd_binary)];
    for arg in cmd_args {
        cmd_parts.push(shell_quote(arg));
    }
    let cmd_line = cmd_parts.join(" ");

    let final_cmd = if spec.process.user.uid != 0 {
        let u = spec.process.user.uid;
        format!(
            "UNAME=$(grep -E ':[0-9]*:{u}:' /etc/passwd 2>/dev/null | cut -d: -f1 | head -n 1); if [ -z \"$UNAME\" ]; then UNAME=$(grep -E ':{u}:' /etc/passwd 2>/dev/null | cut -d: -f1 | head -n 1); fi; if [ -z \"$UNAME\" ]; then adduser -D -u {u} -s /bin/sh \"u{u}\" 2>/dev/null || useradd -u {u} -s /bin/sh \"u{u}\" 2>/dev/null || true; UNAME=\"u{u}\"; fi; sed -i \"s|:${{u}}:.*$|:${{u}}:${{u}}::/:/bin/sh|\" /etc/passwd 2>/dev/null || true; su -s /bin/sh \"$UNAME\" -c {}",
            shell_quote(&cmd_line),
            u = u
        )
    } else {
        cmd_line
    };

    // Ensure /etc/hosts exists and contains localhost, container hostname, and custom add-hosts
    let hosts_path = rootfs_path.join("etc/hosts");
    let _ = fs::create_dir_all(rootfs_path.join("etc"));
    let mut hosts_content =
        String::from("127.0.0.1 localhost\n::1 localhost ip6-localhost ip6-loopback\n");
    if let Some(h) = &spec.hostname {
        hosts_content.push_str(&format!("127.0.0.1 {}\n", h));
    }
    let custom_hosts_file = bundle_path.join("hosts.json");
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
    if let Some(net_name) = spec.annotations.as_ref().and_then(|a| a.get("boxr.network")) {
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
    let upper_hosts = bundle_path.join("upper/etc/hosts");
    if let Some(parent) = upper_hosts.parent() {
        if parent.exists() {
            let _ = fs::write(&upper_hosts, &hosts_content);
        }
    }

    if detach {
        run_script.push_str(&format!("{} 2>&1 | tee /logs.txt &\n", final_cmd));
        run_script.push_str("sleep 0.1\n");
        run_script.push_str("MAIN_PID=$!\n");
        run_script.push_str("while kill -0 $MAIN_PID 2>/dev/null; do\n");
        run_script.push_str("  for f in /boxr-exec-*.sh; do\n");
        run_script.push_str("    [ -f \"$f\" ] || continue\n");
        run_script.push_str("    ID=$(echo \"$f\" | sed 's/.*boxr-exec-//; s/\\.sh//')\n");
        run_script.push_str(readonly_teardown);
        run_script.push_str("    /bin/sh \"$f\" > \"/boxr-exec-${ID}.log\" 2>&1\n");
        run_script.push_str("    echo $? > \"/boxr-exec-${ID}.done\"\n");
        run_script.push_str("    rm -f \"$f\"\n");
        run_script.push_str("  done\n");
        run_script.push_str("  sleep 0.05 2>/dev/null || sleep 1\n");
        run_script.push_str("done\n");
        run_script.push_str("wait $MAIN_PID 2>/dev/null\n");
        run_script.push_str("EXIT_CODE=$?\n");
        run_script.push_str(readonly_teardown);
        run_script.push_str("echo $EXIT_CODE > /boxr-exitcode\n");
        run_script.push_str("sync 2>/dev/null || true\n");
        run_script.push_str("echo 1 > /proc/sys/kernel/sysrq 2>/dev/null; echo o > /proc/sysrq-trigger 2>/dev/null || /bin/busybox poweroff -f 2>/dev/null || poweroff -f 2>/dev/null || halt -f -p 2>/dev/null\n");
    } else {
        run_script.push_str(&format!("{}\n", final_cmd));
        run_script.push_str("EXIT_CODE=$?\n");
        run_script.push_str(readonly_teardown);
        run_script.push_str("echo $EXIT_CODE > /boxr-exitcode\n");
        run_script.push_str("sync 2>/dev/null || true\n");
        run_script.push_str("echo 1 > /proc/sys/kernel/sysrq 2>/dev/null; echo o > /proc/sysrq-trigger 2>/dev/null || /bin/busybox poweroff -f 2>/dev/null || poweroff -f 2>/dev/null || halt -f -p 2>/dev/null\n");
    }

    let run_script_path = rootfs_path.join("boxr-run.sh");
    fs::write(&run_script_path, run_script)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&run_script_path, fs::Permissions::from_mode(0o777));
    }

    if detach {
        cmd.arg("--detach");
        cmd.stdin(std::process::Stdio::null());
        cmd.stdout(std::process::Stdio::null());
        cmd.stderr(std::process::Stdio::null());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            cmd.process_group(0);
        }
        let _child = cmd.spawn()?;
        // Give background VM a brief moment to create vm.pid and bind published ports
        std::thread::sleep(std::time::Duration::from_millis(1500));
        return Ok(0);
    }

    let status = cmd.status()?;
    Ok(status.code().unwrap_or(0))
}

/// Execute a command in an existing container bundle
pub fn exec_in_bundle(
    bundle_path: &Path,
    command: &[String],
    env: &[String],
    workdir: Option<&str>,
    user: Option<&str>,
    detach: bool,
) -> Result<i32> {
    let rootfs_path = bundle_path.join("rootfs");
    let pid_file = bundle_path.join("vm.pid");

    let is_running = if let Ok(pid_str) = fs::read_to_string(&pid_file) {
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            unsafe { libc::kill(pid, 0) == 0 }
        } else {
            false
        }
    } else {
        false
    };

    if is_running {
        let mut exec_script = String::new();
        exec_script.push_str("#!/bin/sh\n");
        exec_script.push_str(
            "export PATH=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH\"\n",
        );
        for e in env {
            if let Some((k, v)) = e.split_once('=') {
                exec_script.push_str(&format!(
                    "export {}=\"{}\"\n",
                    k,
                    v.replace('\\', "\\\\").replace('"', "\\\"")
                ));
            }
        }
        if let Some(wd) = workdir {
            exec_script.push_str(&format!("cd \"{}\" 2>/dev/null || cd /\n", wd));
        }
        let binary = &command[0];
        let args = &command[1..];
        let mut cmd_parts = vec![shell_quote(binary)];
        for a in args {
            cmd_parts.push(shell_quote(a));
        }
        let cmd_line = cmd_parts.join(" ");

        let final_cmd = if let Some(u) = user {
            format!(
                "UNAME=$(id -un {u} 2>/dev/null); if [ -z \"$UNAME\" ]; then adduser -D -u {u} -s /bin/sh \"u{u}\" 2>/dev/null || true; UNAME=\"u{u}\"; fi; su -s /bin/sh \"$UNAME\" -c {}",
                shell_quote(&cmd_line),
                u = u
            )
        } else {
            format!("exec {}", cmd_line)
        };
        exec_script.push_str(&format!("{}\n", final_cmd));

        let exec_id = hex::encode(crate::storage::container_store::rand_id());
        let exec_script_path = rootfs_path.join(format!("boxr-exec-{}.sh", exec_id));
        let exec_done_path = rootfs_path.join(format!("boxr-exec-{}.done", exec_id));
        let exec_log_path = rootfs_path.join(format!("boxr-exec-{}.log", exec_id));

        let _ = fs::remove_file(&exec_done_path);
        let _ = fs::remove_file(&exec_log_path);
        fs::write(&exec_script_path, &exec_script)?;

        if detach {
            return Ok(0);
        }

        let start = std::time::Instant::now();
        while !exec_done_path.exists() {
            if start.elapsed() > std::time::Duration::from_secs(30) {
                let _ = fs::remove_file(&exec_script_path);
                return Err(anyhow!("Exec timed out after 30 seconds"));
            }
            std::thread::sleep(std::time::Duration::from_millis(30));
        }

        if exec_log_path.exists() {
            let out = fs::read_to_string(&exec_log_path)?;
            print!("{}", out);
            let _ = fs::remove_file(&exec_log_path);
        }

        let exit_code = if let Ok(c) = fs::read_to_string(&exec_done_path) {
            c.trim().parse::<i32>().unwrap_or(0)
        } else {
            0
        };
        let _ = fs::remove_file(&exec_done_path);
        return Ok(exit_code);
    }

    let runner_bin = ensure_vz_runner()?;
    let (kernel_path, initrd_path) = ensure_vm_assets()?;

    let binary = &command[0];
    let args = &command[1..];

    let mut run_script = String::new();
    run_script.push_str("#!/bin/sh\n");
    run_script.push_str("mount -t proc proc /proc 2>/dev/null || true\n");
    run_script.push_str("mount -t sysfs sysfs /sys 2>/dev/null || true\n");
    run_script.push_str("mount -t devtmpfs devtmpfs /dev 2>/dev/null || true\n");

    for e in env {
        if let Some((k, v)) = e.split_once('=') {
            run_script.push_str(&format!(
                "export {}=\"{}\"\n",
                k,
                v.replace('\\', "\\\\").replace('"', "\\\"")
            ));
        }
    }

    let mut cmd_line = format!("exec {}", binary);
    for a in args {
        let cleaned = a.trim_matches('"');
        cmd_line.push_str(&format!(
            " \"{}\"",
            cleaned.replace('\\', "\\\\").replace('"', "\\\"")
        ));
    }
    run_script.push_str(&format!("{}\n", cmd_line));

    let run_script_path = rootfs_path.join("boxr-run.sh");
    fs::write(&run_script_path, run_script)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&run_script_path, fs::Permissions::from_mode(0o777));
    }

    let mut cmd = Command::new(&runner_bin);
    cmd.arg("--bundle")
        .arg(bundle_path)
        .arg("--rootfs")
        .arg(&rootfs_path)
        .arg("--kernel")
        .arg(&kernel_path)
        .arg("--initrd")
        .arg(&initrd_path);
    apply_vm_resource_args(&mut cmd, None);
    let status = cmd.status()?;

    Ok(status.code().unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shell_quote_escaping() {
        assert_eq!(shell_quote("hello"), "'hello'");
        assert_eq!(shell_quote("hello world"), "'hello world'");
        assert_eq!(shell_quote("$HOME"), "'$HOME'");
        assert_eq!(shell_quote("`whoami`"), "'`whoami`'");
        assert_eq!(shell_quote("$(id -u)"), "'$(id -u)'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
        assert_eq!(shell_quote("\"quoted\""), "'\"quoted\"'");
    }
}
