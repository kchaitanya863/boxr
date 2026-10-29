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

/// Apply the default seccomp BPF filter inside the container process.
#[cfg(target_os = "linux")]
pub fn apply_default_seccomp() -> anyhow::Result<()> {
    use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, TargetArch};
    use std::collections::BTreeMap;
    use std::convert::TryInto;

    let blocked = SeccompRule::default_filter().syscalls[0].names.clone();
    let mut filter_map: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = BTreeMap::new();
    for name in blocked {
        if let Some(nr) = syscall_name_to_nr(&name) {
            filter_map.insert(nr as i64, vec![]);
        }
    }

    let arch = match std::env::consts::ARCH {
        "x86_64" => TargetArch::x86_64,
        "aarch64" => TargetArch::aarch64,
        "riscv64" => TargetArch::riscv64,
        _ => return Ok(()),
    };

    let bpf: BpfProgram = SeccompFilter::new(
        filter_map,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        arch,
    )?
    .try_into()?;

    seccompiler::apply_filter(&bpf)?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn apply_default_seccomp() -> anyhow::Result<()> {
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
