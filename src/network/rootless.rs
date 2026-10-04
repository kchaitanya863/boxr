#![allow(dead_code)]

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;

/// A user-space TCP port forwarder proxy running in rootless user mode without requiring root/sudo privileges.
/// On Unix, the forwarder listens on the host and relays each connection through a Unix
/// socket into the container's network namespace (see `run_forward_helper`).
/// Unix sockets are filesystem-scoped, so this works across network namespaces
/// without setns and without any host route into the container.
/// On Windows (no network namespaces), it dials the target TCP address directly.
pub struct RootlessPortForwarder {
    host_addr: SocketAddr,
    #[cfg(unix)]
    target_sock: PathBuf,
    #[cfg(windows)]
    target_addr: SocketAddr,
    stop_notify: Arc<Notify>,
    is_stopped: Arc<AtomicBool>,
}

impl RootlessPortForwarder {
    #[cfg(unix)]
    pub fn new(host_addr: SocketAddr, target_sock: PathBuf) -> Self {
        Self {
            host_addr,
            target_sock,
            stop_notify: Arc::new(Notify::new()),
            is_stopped: Arc::new(AtomicBool::new(false)),
        }
    }

    #[cfg(windows)]
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
        #[cfg(unix)]
        let target_sock = self.target_sock.clone();
        #[cfg(windows)]
        let target_addr = self.target_addr;

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
                                #[cfg(unix)]
                                {
                                    let sock_path = target_sock.clone();
                                    tokio::spawn(async move {
                                        // Relay through the in-netns forward helper's Unix socket.
                                        // If the helper is not (yet) running, drop the connection;
                                        // the client will retry.
                                        if let Ok(mut outbound) =
                                            tokio::net::UnixStream::connect(&sock_path).await
                                        {
                                            let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                                        }
                                    });
                                }
                                #[cfg(windows)]
                                {
                                    tokio::spawn(async move {
                                        // No network namespaces on Windows; dial directly.
                                        if let Ok(mut outbound) =
                                            TcpStream::connect(target_addr).await
                                        {
                                            let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                                        }
                                    });
                                }
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
    /// Start forwarding for all requested port mappings.
    /// On Unix, each mapping is relayed through the in-netns forward helper's Unix
    /// socket (`forward_sock_name`), which bridges to the container's localhost.
    /// On Windows (no netns), the forwarder dials the target TCP address directly.
    pub async fn start_forwarding(
        bundle_path: &Path,
        ports: &[crate::network::PortMapping],
    ) -> Result<Vec<Arc<RootlessPortForwarder>>> {
        let mut forwarders = Vec::new();
        for p in ports {
            let host_ip_str = p.host_ip.as_deref().unwrap_or("0.0.0.0");
            let host_addr: SocketAddr = format!("{}:{}", host_ip_str, p.host_port)
                .parse()
                .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], p.host_port)));

            #[cfg(unix)]
            let forwarder = {
                let sock_path = bundle_path.join(forward_sock_name(p.container_port));
                Arc::new(RootlessPortForwarder::new(host_addr, sock_path))
            };
            #[cfg(windows)]
            let forwarder = {
                let target_addr: SocketAddr = format!("127.0.0.1:{}", p.container_port)
                    .parse()
                    .unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], p.container_port)));
                Arc::new(RootlessPortForwarder::new(host_addr, target_addr))
            };
            let _ = forwarder.start().await;
            forwarders.push(forwarder);
        }
        Ok(forwarders)
    }
}

/// Unix socket name (inside the container bundle dir) for a published container
/// port. The in-netns forward helper listens here; the host-side forwarder
/// daemon connects here to relay inbound connections into the container.
/// Unix only; Windows has no network namespaces and dials TCP directly.
#[cfg(unix)]
pub fn forward_sock_name(container_port: u16) -> String {
    format!("forward-{}.sock", container_port)
}

/// Runs INSIDE the container's network namespace (call after unsharing
/// CLONE_NEWNET). For each published port, listens on a Unix socket in the
/// bundle dir and bridges connections to the container's localhost.
/// Returns when all listeners fail; normally killed with the container.
/// Unix only; Windows has no network namespaces.
#[cfg(unix)]
pub fn run_forward_helper(bundle_path: &Path, ports: &[crate::network::PortMapping]) -> Result<()> {
    use std::os::unix::net::UnixListener;

    let mut listeners = Vec::new();
    for p in ports {
        let sock_path = bundle_path.join(forward_sock_name(p.container_port));
        let _ = std::fs::remove_file(&sock_path); // stale socket from an earlier run
        match UnixListener::bind(&sock_path) {
            Ok(l) => listeners.push((p.container_port, l)),
            Err(e) => eprintln!(
                "forward helper: cannot bind {}: {:?}",
                sock_path.display(),
                e
            ),
        }
    }
    if listeners.is_empty() {
        return Ok(());
    }

    let mut handles = Vec::new();
    for (container_port, listener) in listeners {
        handles.push(std::thread::spawn(move || {
            for conn in listener.incoming() {
                let unix_stream = match conn {
                    Ok(s) => s,
                    Err(_) => break,
                };
                std::thread::spawn(move || {
                    let target = format!("127.0.0.1:{}", container_port);
                    let tcp = match std::net::TcpStream::connect(&target) {
                        Ok(s) => s,
                        Err(_) => return,
                    };
                    let _ = tcp.set_nodelay(true);
                    let mut unix_stream = unix_stream;
                    let mut tcp = tcp;
                    match (unix_stream.try_clone(), tcp.try_clone()) {
                        (Ok(mut u2), Ok(mut t2)) => {
                            let h = std::thread::spawn(move || {
                                let _ = std::io::copy(&mut u2, &mut t2);
                            });
                            let _ = std::io::copy(&mut tcp, &mut unix_stream);
                            let _ = h.join();
                        }
                        _ => {}
                    }
                });
            }
        }));
    }
    for h in handles {
        let _ = h.join();
    }
    Ok(())
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

    // Start all port forwarders (relayed via the in-netns forward helper)
    let forwarders = PortForwardManager::start_forwarding(bundle_path, &ports).await?;

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
    #[cfg(unix)]
    async fn test_rootless_port_forwarder_lifecycle() {
        let host: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let target = std::path::PathBuf::from("/tmp/boxr-test-nonexistent.sock"); // dummy target
        let forwarder = RootlessPortForwarder::new(host, target);
        assert!(forwarder.is_running());
        forwarder.stop();
        assert!(!forwarder.is_running());
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn test_rootless_port_forwarder_unblocks_on_stop() {
        let host: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let target = std::path::PathBuf::from("/tmp/boxr-test-nonexistent.sock");
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

    /// End-to-end: host TCP -> forwarder -> helper Unix socket -> container localhost.
    /// The helper runs in the same netns as the test here, so the dummy TCP
    /// echo server on 127.0.0.1 plays the role of the container's localhost.
    #[tokio::test]
    #[cfg(unix)]
    async fn test_forward_helper_bridges_into_container_netns() {
        use tempfile::tempdir;
        let dir = tempdir().unwrap();
        let bundle_path = dir.path().to_path_buf();

        // Dummy "container" service: echo server on localhost.
        let svc_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let svc_port = svc_listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for conn in svc_listener.incoming() {
                if let Ok(mut s) = conn {
                    std::thread::spawn(move || {
                        use std::io::{Read, Write};
                        let mut buf = [0u8; 64];
                        if let Ok(n) = s.read(&mut buf) {
                            let _ = s.write_all(&buf[..n]);
                        }
                    });
                }
            }
        });

        // Grab an ephemeral host port for the forwarder.
        let host_port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };

        let ports = vec![crate::network::PortMapping {
            host_ip: Some("127.0.0.1".to_string()),
            host_port,
            container_port: svc_port,
            protocol: "tcp".to_string(),
        }];

        // Start the in-netns helper in the background.
        let helper_bundle = bundle_path.clone();
        let helper_ports = ports.clone();
        std::thread::spawn(move || {
            let _ = run_forward_helper(&helper_bundle, &helper_ports);
        });

        // Wait for the helper's Unix socket to appear.
        let sock_path = bundle_path.join(forward_sock_name(svc_port));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !sock_path.exists() && std::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(
            sock_path.exists(),
            "forward helper did not create its socket"
        );

        // Start the host-side forwarder via the manager (as the daemon does).
        let _forwarders = PortForwardManager::start_forwarding(&bundle_path, &ports)
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Data sent to the published host port must come back from the echo server.
        let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", host_port))
            .await
            .expect("could not connect to forwarded host port");
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        stream.write_all(b"hello-boxr").await.unwrap();
        let mut buf = [0u8; 10];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut buf))
            .await
            .expect("timed out waiting for echo")
            .expect("failed to read echo");
        assert_eq!(&buf[..n], b"hello-boxr");
    }
}
