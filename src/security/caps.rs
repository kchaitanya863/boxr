use serde::{Deserialize, Serialize};

/// Standard safe Linux Capabilities conforming to Docker/Podman default capability whitelist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityProfile {
    pub bounding: Vec<String>,
    pub effective: Vec<String>,
    pub permitted: Vec<String>,
}

impl Default for CapabilityProfile {
    fn default() -> Self {
        let caps = vec![
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
        ];
        Self {
            bounding: caps.clone(),
            effective: caps.clone(),
            permitted: caps,
        }
    }
}
