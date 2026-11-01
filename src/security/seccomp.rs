use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeccompRule {
    pub default_action: String,
    pub architectures: Vec<String>,
    pub syscalls: Vec<SeccompSyscall>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeccompSyscall {
    pub names: Vec<String>,
    pub action: String,
}

/// Apply a custom seccomp JSON profile if present, or the default seccomp BPF filter.
#[cfg(target_os = "linux")]
pub fn apply_seccomp_from_profile(profile_path: Option<&str>) -> anyhow::Result<()> {
    if let Some(p) = profile_path {
        if p == "unconfined" {
            return Ok(());
        }
        let raw_opt = if p.trim_start().starts_with('{') {
            Some(p.to_string())
        } else {
            std::fs::read_to_string(p).ok()
        };
        if let Some(raw) = raw_opt {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) {
                return apply_seccomp_spec(&val);
            }
        }
    }
    let val = serde_json::to_value(SeccompRule::default_filter())?;
    apply_seccomp_spec(&val)
}

#[cfg(target_os = "linux")]
pub fn apply_seccomp_spec(seccomp_val: &serde_json::Value) -> anyhow::Result<()> {
    use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, TargetArch};
    use std::collections::BTreeMap;
    use std::convert::TryInto;

    let default_action_str = seccomp_val
        .get("defaultAction")
        .or_else(|| seccomp_val.get("default_action"))
        .and_then(|v| v.as_str())
        .unwrap_or("SCMP_ACT_ALLOW");

    let parse_action = |act: &str| -> SeccompAction {
        match act {
            "SCMP_ACT_ALLOW" => SeccompAction::Allow,
            "SCMP_ACT_KILL" | "SCMP_ACT_KILL_PROCESS" => SeccompAction::KillProcess,
            "SCMP_ACT_KILL_THREAD" => SeccompAction::KillThread,
            "SCMP_ACT_TRAP" => SeccompAction::Trap,
            "SCMP_ACT_LOG" => SeccompAction::Log,
            _ => SeccompAction::Errno(libc::EPERM as u32),
        }
    };

    let default_action = parse_action(default_action_str);
    let mut mismatch_action = SeccompAction::Errno(libc::EPERM as u32);
    let mut filter_map: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = BTreeMap::new();

    let insert_syscall_name = |filter_map: &mut BTreeMap<i64, Vec<seccompiler::SeccompRule>>,
                               name: &str| {
        if name == "link" || name == "linkat" {
            #[cfg(target_arch = "x86_64")]
            filter_map.insert(libc::SYS_link as i64, vec![]);
            filter_map.insert(libc::SYS_linkat as i64, vec![]);
        } else if name == "symlink" || name == "symlinkat" {
            #[cfg(target_arch = "x86_64")]
            filter_map.insert(libc::SYS_symlink as i64, vec![]);
            filter_map.insert(libc::SYS_symlinkat as i64, vec![]);
        } else if let Some(nr) = syscall_name_to_nr(name) {
            filter_map.insert(nr as i64, vec![]);
        }
    };

    if let Some(syscalls) = seccomp_val.get("syscalls").and_then(|v| v.as_array()) {
        for sc in syscalls {
            let act_str = sc
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("SCMP_ACT_ERRNO");
            let act = parse_action(act_str);
            if act != default_action {
                mismatch_action = act;
                if let Some(names) = sc.get("names").and_then(|v| v.as_array()) {
                    for name_val in names {
                        if let Some(name) = name_val.as_str() {
                            insert_syscall_name(&mut filter_map, name);
                        }
                    }
                }
                if let Some(name) = sc.get("name").and_then(|v| v.as_str()) {
                    insert_syscall_name(&mut filter_map, name);
                }
            }
        }
    } else {
        for name in &SeccompRule::default_filter().syscalls[0].names {
            insert_syscall_name(&mut filter_map, name);
        }
    }

    let arch = match std::env::consts::ARCH {
        "x86_64" => TargetArch::x86_64,
        "aarch64" => TargetArch::aarch64,
        "riscv64" => TargetArch::riscv64,
        _ => return Ok(()),
    };

    let bpf: BpfProgram =
        SeccompFilter::new(filter_map, default_action, mismatch_action, arch)?.try_into()?;

    // Install seccomp filter via SYS_seccomp directly while CAP_SYS_ADMIN is effective
    // in the container user namespace so NoNewPrivs stays 0 unless explicitly requested.
    #[repr(C)]
    struct SockFprog {
        len: libc::c_ushort,
        filter: *const seccompiler::sock_filter,
    }
    let prog = SockFprog {
        len: bpf.len() as libc::c_ushort,
        filter: bpf.as_ptr(),
    };
    const SECCOMP_SET_MODE_FILTER: libc::c_ulong = 1;
    let rc = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            0usize,
            &prog as *const SockFprog,
        )
    };
    if rc == 0 {
        return Ok(());
    }
    seccompiler::apply_filter(&bpf)?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn apply_seccomp_from_profile(_profile_path: Option<&str>) -> anyhow::Result<()> {
    Ok(())
}

/// Apply the default seccomp BPF filter inside the container process.
#[cfg(target_os = "linux")]
pub fn apply_default_seccomp() -> anyhow::Result<()> {
    apply_seccomp_from_profile(None)
}

#[cfg(not(target_os = "linux"))]
pub fn apply_default_seccomp() -> anyhow::Result<()> {
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn apply_seccomp_spec(_seccomp_val: &serde_json::Value) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn syscall_name_to_nr(name: &str) -> Option<i32> {
    fn to_i32(nr: libc::c_long) -> i32 {
        nr as i32
    }

    match name {
        "acct" => Some(to_i32(libc::SYS_acct)),
        "add_key" => Some(to_i32(libc::SYS_add_key)),
        "bpf" => Some(to_i32(libc::SYS_bpf)),
        "chmod" => {
            #[cfg(target_arch = "x86_64")]
            {
                Some(to_i32(libc::SYS_chmod))
            }
            #[cfg(not(target_arch = "x86_64"))]
            {
                None
            }
        }
        "fchmod" => Some(to_i32(libc::SYS_fchmod)),
        "fchmodat" => Some(to_i32(libc::SYS_fchmodat)),
        "chown" => {
            #[cfg(target_arch = "x86_64")]
            {
                Some(to_i32(libc::SYS_chown))
            }
            #[cfg(not(target_arch = "x86_64"))]
            {
                None
            }
        }
        "fchown" => Some(to_i32(libc::SYS_fchown)),
        "fchownat" => Some(to_i32(libc::SYS_fchownat)),
        "lchown" => {
            #[cfg(target_arch = "x86_64")]
            {
                Some(to_i32(libc::SYS_lchown))
            }
            #[cfg(not(target_arch = "x86_64"))]
            {
                None
            }
        }
        "clock_settime" => Some(to_i32(libc::SYS_clock_settime)),
        "init_module" => Some(to_i32(libc::SYS_init_module)),
        "finit_module" => Some(to_i32(libc::SYS_finit_module)),
        "delete_module" => Some(to_i32(libc::SYS_delete_module)),
        "kexec_load" => Some(to_i32(libc::SYS_kexec_load)),
        #[cfg(target_arch = "x86_64")]
        "kexec_file_load" => Some(to_i32(libc::SYS_kexec_file_load)),
        #[cfg(not(target_arch = "x86_64"))]
        "kexec_file_load" => None,
        "keyctl" => Some(to_i32(libc::SYS_keyctl)),
        "link" => {
            #[cfg(target_arch = "x86_64")]
            {
                Some(to_i32(libc::SYS_link))
            }
            #[cfg(not(target_arch = "x86_64"))]
            {
                None
            }
        }
        "linkat" => Some(to_i32(libc::SYS_linkat)),
        "symlink" => {
            #[cfg(target_arch = "x86_64")]
            {
                Some(to_i32(libc::SYS_symlink))
            }
            #[cfg(not(target_arch = "x86_64"))]
            {
                None
            }
        }
        "symlinkat" => Some(to_i32(libc::SYS_symlinkat)),
        "mkdir" => {
            #[cfg(target_arch = "x86_64")]
            {
                Some(to_i32(libc::SYS_mkdir))
            }
            #[cfg(not(target_arch = "x86_64"))]
            {
                None
            }
        }
        "mkdirat" => Some(to_i32(libc::SYS_mkdirat)),
        "mount" => Some(to_i32(libc::SYS_mount)),
        "lookup_dcookie" => Some(to_i32(libc::SYS_lookup_dcookie)),
        "perf_event_open" => Some(to_i32(libc::SYS_perf_event_open)),
        "pivot_root" => Some(to_i32(libc::SYS_pivot_root)),
        "ptrace" => Some(to_i32(libc::SYS_ptrace)),
        "reboot" => Some(to_i32(libc::SYS_reboot)),
        "request_key" => Some(to_i32(libc::SYS_request_key)),
        "set_mempolicy" => Some(to_i32(libc::SYS_set_mempolicy)),
        "settimeofday" => Some(to_i32(libc::SYS_settimeofday)),
        "sys_settimeofday" => Some(to_i32(libc::SYS_settimeofday)),
        "stime" => None,
        "swapoff" => Some(to_i32(libc::SYS_swapoff)),
        "swapon" => Some(to_i32(libc::SYS_swapon)),
        #[cfg(target_arch = "x86_64")]
        "sysfs" => Some(to_i32(libc::SYS_sysfs)),
        #[cfg(not(target_arch = "x86_64"))]
        "sysfs" => None,
        "umount2" => Some(to_i32(libc::SYS_umount2)),
        "unshare" => Some(to_i32(libc::SYS_unshare)),
        "userfaultfd" => Some(to_i32(libc::SYS_userfaultfd)),
        "vmsplice" => Some(to_i32(libc::SYS_vmsplice)),
        _ => None,
    }
}

impl SeccompRule {
    pub fn default_filter() -> Self {
        Self {
            default_action: "SCMP_ACT_ALLOW".to_string(),
            architectures: vec![
                "SCMP_ARCH_X86_64".to_string(),
                "SCMP_ARCH_AARCH64".to_string(),
            ],
            syscalls: vec![SeccompSyscall {
                names: vec![
                    "acct".to_string(),
                    "add_key".to_string(),
                    "bpf".to_string(),
                    "clock_settime".to_string(),
                    "init_module".to_string(),
                    "finit_module".to_string(),
                    "delete_module".to_string(),
                    "kexec_load".to_string(),
                    "kexec_file_load".to_string(),
                    "keyctl".to_string(),
                    "lookup_dcookie".to_string(),
                    "perf_event_open".to_string(),
                    "pivot_root".to_string(),
                    "ptrace".to_string(),
                    "reboot".to_string(),
                    "request_key".to_string(),
                    "set_mempolicy".to_string(),
                    "settimeofday".to_string(),
                    "stime".to_string(),
                    "swapoff".to_string(),
                    "swapon".to_string(),
                    "sysfs".to_string(),
                    "sys_settimeofday".to_string(),
                    "umount2".to_string(),
                    "unshare".to_string(),
                    "userfaultfd".to_string(),
                    "vmsplice".to_string(),
                ],
                action: "SCMP_ACT_ERRNO".to_string(),
            }],
        }
    }
}
