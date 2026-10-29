use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub fn resolve_bundle_ports(bundle_path: &Path, from_record: &[PortMapping]) -> Vec<PortMapping> {
    if !from_record.is_empty() {
        return from_record.to_vec();
    }
    let ports_path = bundle_path.join("ports.json");
    if !ports_path.exists() {
        return Vec::new();
    }
    match fs::read_to_string(&ports_path) {
        Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

/// Spawn the host-side `__internal-port-forward` daemon for a bundle (no-op when ports empty).
pub fn spawn_port_forward_daemon(bundle_path: &Path, ports: &[PortMapping]) -> Result<()> {
    if ports.is_empty() {
        return Ok(());
    }
    let ports_json = serde_json::to_string(ports)?;
    fs::write(bundle_path.join("ports.json"), ports_json)?;
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("boxr"));
    let mut fwd_cmd = std::process::Command::new(&exe);
    fwd_cmd
        .arg("__internal-port-forward")
        .arg(bundle_path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        fwd_cmd.process_group(0);
    }
    fwd_cmd.spawn().with_context(|| {
        format!(
            "failed to spawn port forward daemon for {}",
            bundle_path.display()
        )
    })?;
    Ok(())
}

/// Wait until the host forwarder daemon writes `forwarder.pid`.
pub fn wait_for_forwarder_pid(bundle_path: &Path, timeout: Duration) -> Result<()> {
    let pid_path = bundle_path.join("forwarder.pid");
    let start = Instant::now();
    while start.elapsed() < timeout {
        if pid_path.exists() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(anyhow!(
        "timed out waiting for port forward daemon on {}",
        bundle_path.display()
    ))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortMapping {
    pub host_ip: Option<String>,
    pub host_port: u16,
    pub container_port: u16,
    pub protocol: String, // "tcp" or "udp"
}

/// Resolve a user-facing network flag to a NetworkStore name for bridge attachment.
impl PortMapping {
    fn parse_port_or_range(s: &str) -> Result<Vec<u16>> {
        if let Some((start, end)) = s.split_once('-') {
            let start = start.parse::<u16>()?;
            let end = end.parse::<u16>()?;
            if start > end {
                return Err(anyhow!("invalid port range: {}", s));
            }
            Ok((start..=end).collect())
        } else {
            Ok(vec![s.parse()?])
        }
    }

    /// Parse port string, expanding ranges into multiple mappings.
    /// e.g. "8080:80", "127.0.0.1:3000:3000/tcp", "8000-8002:8000-8002"
    pub fn parse_all(spec: &str) -> Result<Vec<Self>> {
        let (proto, port_spec) = if let Some((p, pr)) = spec.split_once('/') {
            (pr.to_lowercase(), p)
        } else {
            ("tcp".to_string(), spec)
        };

        let parts: Vec<&str> = port_spec.split(':').collect();
        match parts.len() {
            1 => {
                let ports = Self::parse_port_or_range(parts[0])?;
                Ok(ports
                    .into_iter()
                    .map(|c_port| Self {
                        host_ip: None,
                        host_port: c_port,
                        container_port: c_port,
                        protocol: proto.clone(),
                    })
                    .collect())
            }
            2 => {
                let host_ports = Self::parse_port_or_range(parts[0])?;
                let container_ports = Self::parse_port_or_range(parts[1])?;
                if host_ports.len() != container_ports.len() {
                    return Err(anyhow!(
                        "host and container port ranges must have equal length: {}",
                        spec
                    ));
                }
                Ok(host_ports
                    .into_iter()
                    .zip(container_ports)
                    .map(|(h_port, c_port)| Self {
                        host_ip: None,
                        host_port: h_port,
                        container_port: c_port,
                        protocol: proto.clone(),
                    })
                    .collect())
            }
            3 => {
                let ip = parts[0].to_string();
                let host_ports = Self::parse_port_or_range(parts[1])?;
                let container_ports = Self::parse_port_or_range(parts[2])?;
                if host_ports.len() != container_ports.len() {
                    return Err(anyhow!(
                        "host and container port ranges must have equal length: {}",
                        spec
                    ));
                }
                Ok(host_ports
                    .into_iter()
                    .zip(container_ports)
                    .map(|(h_port, c_port)| Self {
                        host_ip: Some(ip.clone()),
                        host_port: h_port,
                        container_port: c_port,
                        protocol: proto.clone(),
                    })
                    .collect())
            }
            _ => Err(anyhow!("Invalid port specification: {}", spec)),
        }
    }

    /// Parse a single port mapping (no ranges).
    pub fn parse(spec: &str) -> Result<Self> {
        let all = Self::parse_all(spec)?;
        if all.len() != 1 {
            return Err(anyhow!(
                "port range '{}' expands to {} mappings; use parse_all",
                spec,
                all.len()
            ));
        }
        Ok(all[0].clone())
    }
}

fn probe_published_port(mapping: &PortMapping) -> bool {
    let host = mapping.host_ip.as_deref().unwrap_or("127.0.0.1");
    let connect_host = match host {
        "0.0.0.0" | "" => "127.0.0.1",
        "::" => "::1",
        other => other,
    };
    let addr: SocketAddr = match format!("{}:{}", connect_host, mapping.host_port).parse() {
        Ok(a) => a,
        Err(_) => return false,
    };

    TcpStream::connect_timeout(&addr, Duration::from_secs(2)).is_ok()
}

/// Wait until all published TCP ports accept connections on the host.
pub fn wait_for_published_ports(ports: &[PortMapping], timeout: Duration) -> Result<()> {
    let targets: Vec<&PortMapping> = ports.iter().filter(|p| p.protocol == "tcp").collect();
    if targets.is_empty() {
        return Ok(());
    }

    let start = Instant::now();
    while start.elapsed() < timeout {
        let ready = targets.iter().all(|p| probe_published_port(p));
        if ready {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(500));
    }

    Err(anyhow!(
        "timed out waiting for published TCP ports to become reachable"
    ))
}
