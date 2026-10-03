#![allow(dead_code)]

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;

/// A user-space TCP port forwarder proxy running in rootless user mode without requiring root/sudo privileges.
pub struct RootlessPortForwarder {
    host_addr: SocketAddr,
    target_addr: SocketAddr,
    stop_notify: Arc<Notify>,
    is_stopped: Arc<AtomicBool>,
}

impl RootlessPortForwarder {
    pub fn new(host_addr: SocketAddr, target_addr: SocketAddr) -> Self {
        Self {
            host_addr,
            target_addr,
            stop_notify: Arc::new(Notify::new()),
            is_stopped: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Start the user-space TCP proxy forwarding traffic between host and container target
    pub async fn start(&self) -> Result<()> {
        let listener = TcpListener::bind(self.host_addr).await.with_context(|| {
            format!(
                "Failed to bind rootless port forwarder on {}",
                self.host_addr
            )
        })?;

        let stop_notify = self.stop_notify.clone();
        let is_stopped = self.is_stopped.clone();
        let target = self.target_addr;

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = stop_notify.notified() => {
                        break;
                    }
                    accept_res = listener.accept() => {
                        if is_stopped.load(Ordering::SeqCst) {
                            break;
                        }
                        match accept_res {
                            Ok((mut inbound, _)) => {
                                let target = target;
                                tokio::spawn(async move {
                                    if let Ok(mut outbound) = TcpStream::connect(target).await {
                                        let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                                    }
                                });
                            }
                            Err(_) => break,
                        }
                    }
                }
            }
        });

        Ok(())
    }

    pub fn stop(&self) {
        self.is_stopped.store(true, Ordering::SeqCst);
        self.stop_notify.notify_waiters();
    }

    pub fn is_running(&self) -> bool {
        !self.is_stopped.load(Ordering::SeqCst)
    }
}

pub struct PortForwardManager;

impl PortForwardManager {
    /// Start forwarding for all requested port mappings
    pub async fn start_forwarding(
        ports: &[crate::network::PortMapping],
    ) -> Result<Vec<Arc<RootlessPortForwarder>>> {
        let mut forwarders = Vec::new();
        for p in ports {
            let host_ip_str = p.host_ip.as_deref().unwrap_or("0.0.0.0");
            let host_addr: SocketAddr = format!("{}:{}", host_ip_str, p.host_port)
                .parse()
                .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], p.host_port)));

            let target_addr: SocketAddr = format!("127.0.0.1:{}", p.container_port)
                .parse()
                .unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], p.container_port)));

            let forwarder = Arc::new(RootlessPortForwarder::new(host_addr, target_addr));
            let _ = forwarder.start().await;
            forwarders.push(forwarder);
        }
        Ok(forwarders)
    }
}

/// Persistent port forwarder daemon for a running container bundle.
/// Runs in a background process decoupled from the short-lived CLI process.
pub async fn run_port_forward_daemon(bundle_path: &Path) -> Result<()> {
    let ports_path = bundle_path.join("ports.json");
    if !ports_path.exists() {
        return Ok(());
    }
    let content = std::fs::read_to_string(&ports_path)?;
    let ports: Vec<crate::network::PortMapping> = serde_json::from_str(&content)?;
    if ports.is_empty() {
        return Ok(());
    }

    // Record forwarder PID so container stop/kill/rm can terminate it
    let my_pid = std::process::id();
    let _ = std::fs::write(bundle_path.join("forwarder.pid"), my_pid.to_string());

    // Start all port forwarders
    let forwarders = PortForwardManager::start_forwarding(&ports).await?;

    // Wait until target container exits
    let vm_pid_path = bundle_path.join("vm.pid");
    let cont_pid_path = bundle_path.join("container.pid");

    // Wait a brief moment for container PID file to be written
    let wait_start = std::time::Instant::now();
    while !vm_pid_path.exists()
        && !cont_pid_path.exists()
        && wait_start.elapsed() < std::time::Duration::from_secs(30)
    {
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    }

    loop {
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

        let mut target_pid: Option<i32> = None;
        if let Ok(pid_str) = std::fs::read_to_string(&vm_pid_path) {
            if let Ok(pid) = pid_str.trim().parse::<i32>() {
                target_pid = Some(pid);
            }
        }
        if target_pid.is_none() {
            if let Ok(pid_str) = std::fs::read_to_string(&cont_pid_path) {
                if let Ok(pid) = pid_str.trim().parse::<i32>() {
                    target_pid = Some(pid);
                }
            }
        }

        match target_pid {
            Some(pid) => {
                #[cfg(unix)]
                let alive = unsafe { libc::kill(pid, 0) == 0 };
                #[cfg(windows)]
                let alive = true;
                if !alive {
                    break;
                }
            }
            None => {
                // If PID files were removed (e.g. by stop_container), exit
                break;
            }
        }
    }

    for f in forwarders {
        f.stop();
    }
    let _ = std::fs::remove_file(bundle_path.join("forwarder.pid"));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rootless_port_forwarder_lifecycle() {
        let host: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let target: SocketAddr = "127.0.0.1:9".parse().unwrap(); // dummy target
        let forwarder = RootlessPortForwarder::new(host, target);
        assert!(forwarder.is_running());
        forwarder.stop();
        assert!(!forwarder.is_running());
    }

    #[tokio::test]
    async fn test_rootless_port_forwarder_unblocks_on_stop() {
        let host: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let target: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let forwarder = RootlessPortForwarder::new(host, target);
        forwarder.start().await.unwrap();
        // Immediately stop; should unblock without any client connection
        forwarder.stop();
        assert!(!forwarder.is_running());
    }

    #[tokio::test]
    async fn test_issue_415_port_forward_daemon_lifecycle() {
        use tempfile::tempdir;
        let dir = tempdir().unwrap();
        let bundle_path = dir.path().to_path_buf();

        let dummy_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let target_port = dummy_listener.local_addr().unwrap().port();

        // An available host port
        let host_port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };

        let ports = vec![crate::network::PortMapping {
            host_ip: Some("127.0.0.1".to_string()),
            host_port,
            container_port: target_port,
            protocol: "tcp".to_string(),
        }];
        let ports_json = serde_json::to_string(&ports).unwrap();
        std::fs::write(bundle_path.join("ports.json"), ports_json).unwrap();

        // Spawn mock target PID
        let mut mock_child = std::process::Command::new("sleep")
            .arg("5")
            .spawn()
            .unwrap();
        let pid = mock_child.id() as i32;
        std::fs::write(bundle_path.join("vm.pid"), pid.to_string()).unwrap();

        let bpath = bundle_path.clone();
        let daemon_handle = tokio::spawn(async move {
            run_port_forward_daemon(&bpath).await.unwrap();
        });

        // Give daemon a moment to bind and write forwarder.pid
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
        assert!(bundle_path.join("forwarder.pid").exists());

        // Connect to published host port
        let connect_res = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", host_port)).await;
        assert!(
            connect_res.is_ok(),
            "Forwarder should be listening on host port"
        );

        // Terminate mock child
        let _ = mock_child.kill();
        let _ = mock_child.wait();

        // Daemon should detect container exit and terminate cleanly
        let _ = tokio::time::timeout(tokio::time::Duration::from_secs(3), daemon_handle).await;
        assert!(!bundle_path.join("forwarder.pid").exists());
    }
}
