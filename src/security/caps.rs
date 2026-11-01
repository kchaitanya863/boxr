use serde::{Deserialize, Serialize};

/// Standard safe Linux Capabilities conforming to Docker/Podman default capability whitelist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityProfile {
    pub bounding: Vec<String>,
    pub effective: Vec<String>,
    pub permitted: Vec<String>,
}

impl CapabilityProfile {
    /// Podman's 11 default container capabilities (`0x00000000800405fb`).
    pub fn podman_default_caps() -> Vec<String> {
        vec![
            "CAP_CHOWN".to_string(),
            "CAP_DAC_OVERRIDE".to_string(),
            "CAP_FOWNER".to_string(),
            "CAP_FSETID".to_string(),
            "CAP_KILL".to_string(),
            "CAP_NET_BIND_SERVICE".to_string(),
            "CAP_SETFCAP".to_string(),
            "CAP_SETGID".to_string(),
            "CAP_SETPCAP".to_string(),
            "CAP_SETUID".to_string(),
            "CAP_SYS_CHROOT".to_string(),
        ]
    }

    pub fn all_known_caps() -> Vec<String> {
        vec![
            "CAP_CHOWN",
            "CAP_DAC_OVERRIDE",
            "CAP_DAC_READ_SEARCH",
            "CAP_FOWNER",
            "CAP_FSETID",
            "CAP_KILL",
            "CAP_SETGID",
            "CAP_SETUID",
            "CAP_SETPCAP",
            "CAP_LINUX_IMMUTABLE",
            "CAP_NET_BIND_SERVICE",
            "CAP_NET_BROADCAST",
            "CAP_NET_ADMIN",
            "CAP_NET_RAW",
            "CAP_IPC_LOCK",
            "CAP_IPC_OWNER",
            "CAP_SYS_MODULE",
            "CAP_SYS_RAWIO",
            "CAP_SYS_CHROOT",
            "CAP_SYS_PTRACE",
            "CAP_SYS_PACCT",
            "CAP_SYS_ADMIN",
            "CAP_SYS_BOOT",
            "CAP_SYS_NICE",
            "CAP_SYS_RESOURCE",
            "CAP_SYS_TIME",
            "CAP_SYS_TTY_CONFIG",
            "CAP_MKNOD",
            "CAP_LEASE",
            "CAP_AUDIT_WRITE",
            "CAP_AUDIT_CONTROL",
            "CAP_SETFCAP",
            "CAP_MAC_OVERRIDE",
            "CAP_MAC_ADMIN",
            "CAP_SYSLOG",
            "CAP_WAKE_ALARM",
            "CAP_BLOCK_SUSPEND",
            "CAP_AUDIT_READ",
            "CAP_PERFMON",
            "CAP_BPF",
            "CAP_CHECKPOINT_RESTORE",
        ]
        .into_iter()
        .map(String::from)
        .collect()
    }

    pub fn cap_name_to_num(name: &str) -> Option<u32> {
        let norm = if name.starts_with("CAP_") || name.starts_with("cap_") {
            name.to_ascii_uppercase()
        } else {
            format!("CAP_{}", name.to_ascii_uppercase())
        };
        match norm.as_str() {
            "CAP_CHOWN" => Some(0),
            "CAP_DAC_OVERRIDE" => Some(1),
            "CAP_DAC_READ_SEARCH" => Some(2),
            "CAP_FOWNER" => Some(3),
            "CAP_FSETID" => Some(4),
            "CAP_KILL" => Some(5),
            "CAP_SETGID" => Some(6),
            "CAP_SETUID" => Some(7),
            "CAP_SETPCAP" => Some(8),
            "CAP_LINUX_IMMUTABLE" => Some(9),
            "CAP_NET_BIND_SERVICE" => Some(10),
            "CAP_NET_BROADCAST" => Some(11),
            "CAP_NET_ADMIN" => Some(12),
            "CAP_NET_RAW" => Some(13),
            "CAP_IPC_LOCK" => Some(14),
            "CAP_IPC_OWNER" => Some(15),
            "CAP_SYS_MODULE" => Some(16),
            "CAP_SYS_RAWIO" => Some(17),
            "CAP_SYS_CHROOT" => Some(18),
            "CAP_SYS_PTRACE" => Some(19),
            "CAP_SYS_PACCT" => Some(20),
            "CAP_SYS_ADMIN" => Some(21),
            "CAP_SYS_BOOT" => Some(22),
            "CAP_SYS_NICE" => Some(23),
            "CAP_SYS_RESOURCE" => Some(24),
            "CAP_SYS_TIME" => Some(25),
            "CAP_SYS_TTY_CONFIG" => Some(26),
            "CAP_MKNOD" => Some(27),
            "CAP_LEASE" => Some(28),
            "CAP_AUDIT_WRITE" => Some(29),
            "CAP_AUDIT_CONTROL" => Some(30),
            "CAP_SETFCAP" => Some(31),
            "CAP_MAC_OVERRIDE" => Some(32),
            "CAP_MAC_ADMIN" => Some(33),
            "CAP_SYSLOG" => Some(34),
            "CAP_WAKE_ALARM" => Some(35),
            "CAP_BLOCK_SUSPEND" => Some(36),
            "CAP_AUDIT_READ" => Some(37),
            "CAP_PERFMON" => Some(38),
            "CAP_BPF" => Some(39),
            "CAP_CHECKPOINT_RESTORE" => Some(40),
            _ => None,
        }
    }
}

impl Default for CapabilityProfile {
    fn default() -> Self {
        let conf_caps = crate::containers_conf_string_array("default_capabilities");
        let caps = if !conf_caps.is_empty() {
            conf_caps
                .into_iter()
                .map(|c| {
                    let up = c.trim().to_ascii_uppercase();
                    if up.starts_with("CAP_") {
                        up
                    } else {
                        format!("CAP_{}", up)
                    }
                })
                .collect()
        } else {
            vec![
                "CAP_CHOWN".to_string(),
                "CAP_DAC_OVERRIDE".to_string(),
                "CAP_FOWNER".to_string(),
                "CAP_FSETID".to_string(),
                "CAP_KILL".to_string(),
                "CAP_SETGID".to_string(),
                "CAP_SETUID".to_string(),
                "CAP_SETPCAP".to_string(),
                "CAP_NET_BIND_SERVICE".to_string(),
                "CAP_NET_RAW".to_string(),
                "CAP_SYS_CHROOT".to_string(),
                "CAP_MKNOD".to_string(),
                "CAP_AUDIT_WRITE".to_string(),
                "CAP_SETFCAP".to_string(),
            ]
        };
        Self {
            bounding: caps.clone(),
            effective: caps.clone(),
            permitted: caps,
        }
    }
}
