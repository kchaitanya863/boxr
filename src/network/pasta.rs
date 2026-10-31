//! Pasta (Pack A Subtle Tap Abstraction) rootless networking integration.
//!
//! Provides user-mode virtual networking for rootless containers by attaching
//! to the container's network namespace (`CLONE_NEWNET`), configuring virtual IP addresses,
//! default routing, and high-performance user-space TCP/UDP port forwarding without root privileges.

use crate::network::PortMapping;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

/// Container network isolation mode
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkMode {
    /// Automatic resolution: use pasta if available, otherwise pure-Rust native usernet
    Auto,
    /// Explicit Pasta external tap driver
    Pasta,
    /// Native pure-Rust embedded user-mode network stack (zero external dependencies)
    UserNet,
    /// Standard virtual bridge network (e.g. boxr0)
    Bridge,
    /// Share host network namespace
    Host,
    /// Private loopback-only network namespace
    None,
    /// Share another container's network namespace (Podman/Docker `container:<name>`)
    Container(String),
}

impl Default for NetworkMode {
    fn default() -> Self {
        Self::Auto
    }
}

impl NetworkMode {
    /// When set, `--network usernet` uses the embedded TAP stack even if passt is installed (tests/CI).
    pub fn force_embedded_usernet() -> bool {
        fn truthy(var: &str) -> bool {
            matches!(
                std::env::var(var).as_deref(),
                Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes")
            )
        }
        truthy("BOXR_FORCE_EMBEDDED_USERNET") || truthy("BOXR_TEST_EMBEDDED_USERNET")
    }

    pub fn parse(s: &str) -> Self {
        let trimmed = s.trim();
        if let Some(target) = trimmed
            .strip_prefix("container:")
            .or_else(|| trimmed.strip_prefix("container://"))
        {
            if !target.is_empty() {
                return Self::Container(target.to_string());
            }
        }
        let lower = trimmed.to_lowercase();
        if lower == "pasta" || lower.starts_with("pasta:") {
            return Self::Pasta;
        }
        match lower.as_str() {
            "usernet" | "native" | "slirp" => Self::UserNet,
            "host" => Self::Host,
            "none" => Self::None,
            "bridge" => Self::Bridge,
            "auto" | "default" | "" => Self::Auto,
            _ => {
                // Named networks (e.g. "boxr0", "compose_default") act as user-defined bridge networks
                Self::Bridge
            }
        }
    }

    /// Target container for `container:` network mode, if any.
    pub fn container_target(&self) -> Option<&str> {
        match self {
            Self::Container(name) => Some(name.as_str()),
            _ => None,
        }
    }

    /// Determines whether Pasta rootless tap networking should be activated
    pub fn should_use_pasta(&self) -> bool {
        match self {
            Self::Pasta => true,
            Self::Auto | Self::UserNet => {
                PastaDriver::is_available() && !Self::force_embedded_usernet()
            }
            _ => false,
        }
    }

    /// Determines whether native pure-Rust usernet should be activated
    pub fn should_use_native_usernet(&self) -> bool {
        match self {
            Self::Bridge => true,
            Self::UserNet => Self::force_embedded_usernet() || !PastaDriver::is_available(),
            Self::Auto => !PastaDriver::is_available(),
            _ => false,
        }
    }

    /// Whether a private network namespace (CLONE_NEWNET) should be unshared
    pub fn requires_new_netns(&self) -> bool {
        match self {
            Self::Pasta | Self::UserNet | Self::None | Self::Auto | Self::Bridge => true,
            Self::Host | Self::Container(_) => false,
        }
    }
}

impl std::fmt::Display for NetworkMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auto => write!(f, "auto"),
            Self::Pasta => write!(f, "pasta"),
            Self::UserNet => write!(f, "usernet"),
            Self::Bridge => write!(f, "bridge"),
            Self::Host => write!(f, "host"),
            Self::None => write!(f, "none"),
            Self::Container(name) => write!(f, "container:{}", name),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PastaConfig {
    pub netns_pid: Option<i32>,
    pub netns_path: Option<PathBuf>,
    pub port_mappings: Vec<PortMapping>,
    pub ifname: Option<String>,
    pub address: Option<String>,
    pub gateway: Option<String>,
    pub dns: Vec<String>,
    pub quiet: bool,
    pub extra_args: Vec<String>,
}

impl PastaConfig {
    pub fn new() -> Self {
        Self {
            netns_pid: None,
            netns_path: None,
            port_mappings: Vec::new(),
            ifname: Some("eth0".to_string()),
            address: None,
            gateway: None,
            dns: Vec::new(),
            quiet: true,
            extra_args: Vec::new(),
        }
    }

    pub fn for_pid(pid: i32, ports: &[PortMapping]) -> Self {
        Self {
            netns_pid: Some(pid),
            netns_path: None,
            port_mappings: ports.to_vec(),
            ifname: Some("eth0".to_string()),
            address: None,
            gateway: None,
            dns: vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()],
            quiet: true,
            extra_args: Vec::new(),
        }
    }

    pub fn for_container(
        pid: i32,
        ports: &[PortMapping],
        raw_network: &str,
        conf_pasta_opts: &[String],
    ) -> Self {
        let mut extra_args: Vec<String> = conf_pasta_opts.to_vec();
        if let Some((_, rest)) = raw_network.trim().split_once(':') {
            for part in rest.split(',') {
                let p = part.trim();
                if !p.is_empty() {
                    extra_args.push(p.to_string());
                }
            }
        }
        let has_custom_ifname = extra_args
            .iter()
            .any(|a| a == "-I" || a == "--ns-ifname" || a.starts_with("--ns-ifname="));
        let has_dns_fwd = extra_args
            .iter()
            .any(|a| a == "--dns-forward" || a.starts_with("--dns-forward="));
        let has_v6_only = extra_args.iter().any(|a| a == "-6" || a == "--ipv6-only");
        if !has_dns_fwd && !has_v6_only {
            extra_args.push("--dns-forward".to_string());
            extra_args.push("169.254.1.1".to_string());
        }
        let has_tcp_flag = extra_args
            .iter()
            .any(|a| a == "-t" || a == "--tcp-ports" || a.starts_with("--tcp-ports="));
        let has_tcp_port = ports.iter().any(|p| p.protocol.eq_ignore_ascii_case("tcp"));
        if !has_tcp_flag && !has_tcp_port {
            extra_args.push("-t".to_string());
            extra_args.push("none".to_string());
        }
        let has_udp_flag = extra_args
            .iter()
            .any(|a| a == "-u" || a == "--udp-ports" || a.starts_with("--udp-ports="));
        let has_udp_port = ports.iter().any(|p| p.protocol.eq_ignore_ascii_case("udp"));
        if !has_udp_flag && !has_udp_port {
            extra_args.push("-u".to_string());
            extra_args.push("none".to_string());
        }
        let has_tcp_ns = extra_args
            .iter()
            .any(|a| a == "-T" || a == "--tcp-ns" || a.starts_with("--tcp-ns="));
        if !has_tcp_ns {
            extra_args.push("-T".to_string());
            extra_args.push("none".to_string());
        }
        let has_udp_ns = extra_args
            .iter()
            .any(|a| a == "-U" || a == "--udp-ns" || a.starts_with("--udp-ns="));
        if !has_udp_ns {
            extra_args.push("-U".to_string());
            extra_args.push("none".to_string());
        }
        let has_map_gw = extra_args
            .iter()
            .any(|a| a == "--no-map-gw" || a == "--map-gw");
        if !has_map_gw {
            extra_args.push("--no-map-gw".to_string());
        }
        let _ = has_custom_ifname;
        Self {
            netns_pid: Some(pid),
            netns_path: None,
            port_mappings: ports.to_vec(),
            ifname: None,
            address: None,
            gateway: None,
            dns: Vec::new(),
            quiet: true,
            extra_args,
        }
    }

    /// Build pasta command-line arguments for rootless networking
    pub fn build_args(&self) -> Vec<String> {
        let mut args = Vec::new();

        // Automatically configure network inside container namespace
        args.push("--config-net".to_string());

        if self.quiet {
            args.push("-q".to_string());
        }

        if let Some(ifname) = &self.ifname {
            args.push("-I".to_string());
            args.push(ifname.clone());
        }

        if let Some(addr) = &self.address {
            args.push("-a".to_string());
            args.push(addr.clone());
        }

        if let Some(gw) = &self.gateway {
            args.push("-g".to_string());
            args.push(gw.clone());
        }

        // DNS servers
        for d in &self.dns {
            args.push("-D".to_string());
            args.push(d.clone());
        }

        for arg in &self.extra_args {
            args.push(arg.clone());
        }

        // Port forwarding rules: -t <spec>, -u <spec> (coalescing contiguous ranges)
        let mut idx = 0;
        while idx < self.port_mappings.len() {
            let first = &self.port_mappings[idx];
            let mut end_idx = idx;
            while end_idx + 1 < self.port_mappings.len() {
                let prev = &self.port_mappings[end_idx];
                let next = &self.port_mappings[end_idx + 1];
                if next.protocol.eq_ignore_ascii_case(&first.protocol)
                    && next.host_ip == first.host_ip
                    && next.host_port == prev.host_port.wrapping_add(1)
                    && next.container_port == prev.container_port.wrapping_add(1)
                {
                    end_idx += 1;
                } else {
                    break;
                }
            }
            let last = &self.port_mappings[end_idx];
            let ports_part = if end_idx > idx {
                format!(
                    "{}-{}:{}-{}",
                    first.host_port, last.host_port, first.container_port, last.container_port
                )
            } else {
                format!("{}:{}", first.host_port, first.container_port)
            };
            let spec = if let Some(ip) = &first.host_ip {
                let clean_ip = ip.trim_matches(|c| c == '[' || c == ']');
                format!("{}/{}", clean_ip, ports_part)
            } else {
                ports_part
            };
            if first.protocol.eq_ignore_ascii_case("udp") {
                args.push("-u".to_string());
            } else {
                args.push("-t".to_string());
            }
            args.push(spec);
            idx = end_idx + 1;
        }

        // Target network namespace PID or path
        if let Some(pid) = self.netns_pid {
            args.push(pid.to_string());
        } else if let Some(path) = &self.netns_path {
            args.push(path.to_string_lossy().to_string());
        }

        args
    }
}

pub struct PastaDriver;

impl PastaDriver {
    /// Detect if pasta binary is available on the system PATH
    pub fn is_available() -> bool {
        which_pasta().is_some()
    }

    /// Find the path to the pasta executable
    pub fn binary_path() -> Option<PathBuf> {
        which_pasta()
    }

    /// Spawn pasta process to attach to container network namespace
    pub fn spawn(config: &PastaConfig) -> Result<Option<Child>> {
        let bin = match Self::binary_path() {
            Some(b) => b,
            None => return Ok(None),
        };

        let args = config.build_args();
        let mut child = Command::new(&bin)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("Failed to spawn pasta ({:?})", bin))?;

        let status = child
            .wait()
            .with_context(|| format!("Failed to wait for pasta ({:?})", bin))?;
        if !status.success() {
            return Err(anyhow::anyhow!(
                "pasta failed with exit code {}",
                status.code().unwrap_or(1)
            ));
        }

        Ok(Some(child))
    }
}

fn which_pasta() -> Option<PathBuf> {
    if let Ok(helper_dir) = std::env::var("CONTAINERS_HELPER_BINARY_DIR") {
        let candidate = Path::new(&helper_dir).join("pasta");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    for p in ["/usr/bin/pasta", "/bin/pasta", "/usr/local/bin/pasta"] {
        let path = Path::new(p);
        if path.exists() {
            return Some(path.to_path_buf());
        }
    }

    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join("pasta");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_mode_parsing() {
        assert_eq!(NetworkMode::parse("pasta"), NetworkMode::Pasta);
        assert_eq!(NetworkMode::parse("PASTA"), NetworkMode::Pasta);
        assert_eq!(NetworkMode::parse("host"), NetworkMode::Host);
        assert_eq!(NetworkMode::parse("none"), NetworkMode::None);
        assert_eq!(NetworkMode::parse("bridge"), NetworkMode::Bridge);
        assert_eq!(NetworkMode::parse("auto"), NetworkMode::Auto);
        assert_eq!(NetworkMode::parse("boxr0"), NetworkMode::Bridge);
        assert_eq!(NetworkMode::parse("unknown-net"), NetworkMode::Bridge);
    }

    #[test]
    fn test_embedded_usernet_ci_env_alias() {
        let saved_force = std::env::var("BOXR_FORCE_EMBEDDED_USERNET").ok();
        let saved_test = std::env::var("BOXR_TEST_EMBEDDED_USERNET").ok();
        unsafe {
            std::env::remove_var("BOXR_FORCE_EMBEDDED_USERNET");
            std::env::set_var("BOXR_TEST_EMBEDDED_USERNET", "1");
        }
        assert!(NetworkMode::force_embedded_usernet());
        unsafe {
            if let Some(v) = saved_force {
                std::env::set_var("BOXR_FORCE_EMBEDDED_USERNET", v);
            } else {
                std::env::remove_var("BOXR_FORCE_EMBEDDED_USERNET");
            }
            if let Some(v) = saved_test {
                std::env::set_var("BOXR_TEST_EMBEDDED_USERNET", v);
            } else {
                std::env::remove_var("BOXR_TEST_EMBEDDED_USERNET");
            }
        }
    }

    #[test]
    fn test_network_mode_requirements() {
        let saved_force_embedded = std::env::var("BOXR_FORCE_EMBEDDED_USERNET").ok();
        let saved_test_embedded = std::env::var("BOXR_TEST_EMBEDDED_USERNET").ok();
        unsafe {
            std::env::remove_var("BOXR_FORCE_EMBEDDED_USERNET");
            std::env::remove_var("BOXR_TEST_EMBEDDED_USERNET");
        }

        assert!(NetworkMode::Pasta.should_use_pasta());
        assert!(NetworkMode::Pasta.requires_new_netns());
        assert!(NetworkMode::None.requires_new_netns());
        assert!(!NetworkMode::None.should_use_pasta());
        assert!(!NetworkMode::Host.requires_new_netns());
        assert!(!NetworkMode::Host.should_use_pasta());

        // Issue #413: bridge and auto must isolate netns
        assert!(NetworkMode::Bridge.requires_new_netns());
        assert!(NetworkMode::Auto.requires_new_netns());
        assert!(NetworkMode::UserNet.requires_new_netns());

        // Issue #414: usernet & bridge activate native usernet
        if PastaDriver::is_available() {
            assert!(!NetworkMode::UserNet.should_use_native_usernet());
            assert!(NetworkMode::UserNet.should_use_pasta());
        } else {
            assert!(NetworkMode::UserNet.should_use_native_usernet());
        }
        assert!(NetworkMode::Bridge.should_use_native_usernet());

        if let Some(v) = saved_force_embedded {
            unsafe {
                std::env::set_var("BOXR_FORCE_EMBEDDED_USERNET", v);
            }
        } else {
            unsafe {
                std::env::remove_var("BOXR_FORCE_EMBEDDED_USERNET");
            }
        }
        if let Some(v) = saved_test_embedded {
            unsafe {
                std::env::set_var("BOXR_TEST_EMBEDDED_USERNET", v);
            }
        } else {
            unsafe {
                std::env::remove_var("BOXR_TEST_EMBEDDED_USERNET");
            }
        }
    }

    #[test]
    fn test_pasta_arg_generation_basic() {
        let ports = vec![
            PortMapping {
                host_ip: None,
                host_port: 8080,
                container_port: 80,
                protocol: "tcp".to_string(),
            },
            PortMapping {
                host_ip: Some("127.0.0.1".to_string()),
                host_port: 5353,
                container_port: 53,
                protocol: "udp".to_string(),
            },
        ];

        let mut config = PastaConfig::for_pid(12345, &ports);
        config.address = Some("10.0.2.15".to_string());
        config.gateway = Some("10.0.2.2".to_string());
        let args = config.build_args();

        assert!(args.contains(&"--config-net".to_string()));
        assert!(args.contains(&"-q".to_string()));
        assert!(args.contains(&"-I".to_string()));
        assert!(args.contains(&"eth0".to_string()));
        assert!(args.contains(&"-a".to_string()));
        assert!(args.contains(&"10.0.2.15".to_string()));
        assert!(args.contains(&"-g".to_string()));
        assert!(args.contains(&"10.0.2.2".to_string()));
        assert!(args.contains(&"-t".to_string()));
        assert!(args.contains(&"8080:80".to_string()));
        assert!(args.contains(&"-u".to_string()));
        assert!(args.contains(&"127.0.0.1/5353:53".to_string()));
        assert_eq!(args.last().unwrap(), "12345");
    }

    #[test]
    fn test_pasta_detection_logic() {
        // Verification that detection doesn't panic
        let _ = PastaDriver::is_available();
        let _ = PastaDriver::binary_path();
    }
}
