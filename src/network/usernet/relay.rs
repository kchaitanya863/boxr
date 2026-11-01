//! Host-side TCP relay for embedded usernet (TAP worker cannot setns into host net).
//!
//! Started from the trampoline (host network namespace). TAP workers open one Unix
//! connection per outbound flow and exchange length-framed payloads.

use anyhow::{Context, Result, anyhow};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::Duration;

pub fn relay_socket_path(bundle_path: &Path) -> std::path::PathBuf {
    let candidate = bundle_path.join("usernet-relay.sock");
    if candidate.to_string_lossy().len() < 100 {
        return candidate;
    }
    let cid = bundle_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("ctr");
    let short = &cid[..12.min(cid.len())];
    std::path::PathBuf::from(format!("/tmp/bx-relay-{}.sock", short))
}

pub fn peer_socket_path(bundle_path: &Path) -> std::path::PathBuf {
    let candidate = bundle_path.join("usernet-peer.sock");
    if candidate.to_string_lossy().len() < 100 {
        return candidate;
    }
    let cid = bundle_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("ctr");
    let short = &cid[..12.min(cid.len())];
    std::path::PathBuf::from(format!("/tmp/bx-peer-{}.sock", short))
}

/// Spawn a background thread inside the container's network namespace that accepts
/// connections from peer containers on the same custom network and relays them to
/// `127.0.0.1:<port>` inside this container's network namespace.
pub fn spawn_in_netns_peer_listener(bundle_path: &Path) {
    let sock_path = peer_socket_path(bundle_path);
    let _ = fs::remove_file(&sock_path);
    let Ok(listener) = UnixListener::bind(&sock_path) else {
        return;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&sock_path, fs::Permissions::from_mode(0o666));
    }
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut unix) = conn else {
                break;
            };
            std::thread::spawn(move || {
                let mut port_bytes = [0u8; 2];
                if unix.read_exact(&mut port_bytes).is_err() {
                    return;
                }
                let port = u16::from_be_bytes(port_bytes);
                let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
                let Ok(mut tcp) = TcpStream::connect_timeout(&addr, Duration::from_secs(2)) else {
                    let _ = unix.write_all(&[0]);
                    return;
                };
                let _ = tcp.set_nodelay(true);
                if unix.write_all(&[1]).is_err() {
                    return;
                }
                let (Ok(mut u2), Ok(mut t2)) = (unix.try_clone(), tcp.try_clone()) else {
                    return;
                };
                let h = std::thread::spawn(move || {
                    let _ = std::io::copy(&mut u2, &mut t2);
                    let _ = t2.shutdown(std::net::Shutdown::Write);
                });
                let _ = std::io::copy(&mut tcp, &mut unix);
                let _ = unix.shutdown(std::net::Shutdown::Write);
                let _ = h.join();
            });
        }
    });
}

/// Fork a relay child that serves `bundle/usernet-relay.sock`. Returns child PID.
#[cfg(target_os = "linux")]
pub fn spawn_host_relay(bundle_path: &Path) -> Result<i32> {
    let sock_path = relay_socket_path(bundle_path);
    let _ = fs::remove_file(&sock_path);
    let listener = UnixListener::bind(&sock_path)
        .with_context(|| format!("bind usernet relay at {}", sock_path.display()))?;
    listener
        .set_nonblocking(false)
        .context("relay listener nonblocking")?;
    let bundle_owned = bundle_path.to_path_buf();

    match unsafe { nix::unistd::fork() }? {
        nix::unistd::ForkResult::Parent { child } => Ok(child.as_raw()),
        nix::unistd::ForkResult::Child => {
            unsafe {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
                let devnull = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
                if devnull >= 0 {
                    libc::dup2(devnull, libc::STDIN_FILENO);
                    libc::dup2(devnull, libc::STDOUT_FILENO);
                    libc::dup2(devnull, libc::STDERR_FILENO);
                    if devnull > 2 {
                        libc::close(devnull);
                    }
                }
            }
            let _ = run_relay_server(listener, &bundle_owned);
            std::process::exit(0);
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub fn spawn_host_relay(_bundle_path: &Path) -> Result<i32> {
    anyhow::bail!("usernet relay is only supported on Linux")
}

fn run_relay_server(listener: UnixListener, bundle_path: &Path) -> Result<()> {
    for conn in listener.incoming() {
        let mut unix = match conn {
            Ok(s) => s,
            Err(_) => break,
        };
        let b_path = bundle_path.to_path_buf();
        std::thread::spawn(move || {
            if let Err(e) = dispatch_client(&mut unix, &b_path) {
                let _ = writeln!(unix, "ERR {}", e);
            }
        });
    }
    Ok(())
}

fn dispatch_client(unix: &mut UnixStream, bundle_path: &Path) -> Result<()> {
    let mut reader = BufReader::new(unix.try_clone()?);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let line = line.trim();
    if line.starts_with("DNSUDP ") {
        let len_s = line
            .strip_prefix("DNSUDP ")
            .ok_or_else(|| anyhow!("bad DNSUDP"))?;
        let len: usize = len_s.parse().context("bad DNSUDP length")?;
        let mut query = vec![0u8; len];
        reader.read_exact(&mut query)?;
        let reply = forward_dns_on_host(bundle_path, &query)?;
        writeln!(unix, "DATA {}", reply.len())?;
        unix.write_all(&reply)?;
        unix.flush()?;
        return Ok(());
    }
    let rest = line
        .strip_prefix("CONNECT ")
        .ok_or_else(|| anyhow!("expected CONNECT or DNSUDP"))?;
    serve_tcp_flow(unix, &mut reader, rest, bundle_path)
}

fn parse_dns_question(query: &[u8]) -> Option<(String, u16, usize)> {
    if query.len() < 17 {
        return None;
    }
    let mut pos = 12usize;
    let mut labels = Vec::new();
    loop {
        if pos >= query.len() {
            return None;
        }
        let len = query[pos] as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        if (len & 0xc0) != 0 || pos + len > query.len() {
            return None;
        }
        let label = String::from_utf8_lossy(&query[pos..pos + len]).to_ascii_lowercase();
        labels.push(label);
        pos += len;
    }
    if pos + 4 > query.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([query[pos], query[pos + 1]]);
    Some((labels.join("."), qtype, pos + 4))
}

fn build_dns_a_response(query: &[u8], question_end: usize, ip: Ipv4Addr) -> Vec<u8> {
    let mut resp = Vec::with_capacity(question_end + 16);
    resp.extend_from_slice(&query[0..2]); // Transaction ID
    resp.extend_from_slice(&[0x81, 0x80]); // Standard query response, NoError
    resp.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
    resp.extend_from_slice(&[0x00, 0x01]); // ANCOUNT = 1
    resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // NSCOUNT, ARCOUNT
    resp.extend_from_slice(&query[12..question_end]);
    resp.extend_from_slice(&[0xc0, 0x0c]); // Pointer to QNAME at offset 12
    resp.extend_from_slice(&[0x00, 0x01]); // TYPE A
    resp.extend_from_slice(&[0x00, 0x01]); // CLASS IN
    resp.extend_from_slice(&60u32.to_be_bytes()); // TTL = 60s
    resp.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH = 4
    resp.extend_from_slice(&ip.octets());
    resp
}

fn build_dns_empty_or_nxdomain(query: &[u8], question_end: usize, nxdomain: bool) -> Vec<u8> {
    let mut resp = Vec::with_capacity(question_end);
    resp.extend_from_slice(&query[0..2]);
    let rcode = if nxdomain { 0x83 } else { 0x80 };
    resp.extend_from_slice(&[0x81, rcode]);
    resp.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
    resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    resp.extend_from_slice(&query[12..question_end]);
    resp
}

fn forward_dns_on_host(bundle_path: &Path, query: &[u8]) -> Result<Vec<u8>> {
    use std::net::UdpSocket;

    let home = bundle_path
        .parent()
        .and_then(|p| p.parent())
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(crate::storage::boxr_home);
    let self_cid = bundle_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    let net_store = crate::network::NetworkStore::with_home(home.clone());
    let c_store = crate::storage::ContainerStore::with_home(home.clone());
    let pod_store = crate::pod::PodStore::with_home(home.clone());

    let connected_nets: Vec<crate::network::NetworkRecord> = net_store
        .list()
        .into_iter()
        .filter(|n| {
            n.name != crate::network::NetworkStore::DEFAULT_NETWORK
                && n.name != "podman"
                && !n.disable_dns
                && n.containers.contains_key(self_cid)
        })
        .collect();

    if let Some((qname, qtype, question_end)) = parse_dns_question(query) {
        let q_clean = qname
            .trim_end_matches('.')
            .strip_suffix(".dns.podman")
            .unwrap_or_else(|| qname.trim_end_matches('.'));
        let is_local_domain = !qname.contains('.') || qname.ends_with(".dns.podman");

        if !connected_nets.is_empty() {
            let pods = pod_store.list();
            for net in &connected_nets {
                for (cid, ep) in &net.containers {
                    let c_rec = c_store.find(cid);
                    let is_running = c_rec.as_ref().is_some_and(|c| {
                        matches!(c.status, crate::storage::ContainerStatus::Running)
                    });
                    if !is_running && cid != self_cid {
                        continue;
                    }
                    let mut matched = ep.container_name.eq_ignore_ascii_case(q_clean)
                        || (q_clean.len() >= 6 && cid.starts_with(q_clean));
                    if !matched {
                        if let Some(c) = &c_rec {
                            let cfg_path =
                                std::path::PathBuf::from(&c.bundle_path).join("config.json");
                            if let Ok(raw) = fs::read_to_string(cfg_path) {
                                if let Ok(sp) =
                                    serde_json::from_str::<crate::oci::runtime::Spec>(&raw)
                                {
                                    if sp
                                        .hostname
                                        .as_deref()
                                        .is_some_and(|h| h.eq_ignore_ascii_case(q_clean))
                                    {
                                        matched = true;
                                    }
                                }
                            }
                        }
                    }
                    if !matched {
                        for p in &pods {
                            let infra_name = pod_store.infra_name(p);
                            if p.infra_container_id == *cid || infra_name == ep.container_name {
                                if p.name.eq_ignore_ascii_case(q_clean)
                                    || p.hostname
                                        .as_deref()
                                        .is_some_and(|h| h.eq_ignore_ascii_case(q_clean))
                                {
                                    matched = true;
                                    break;
                                }
                            }
                        }
                    }
                    if matched {
                        if let Ok(ip) = ep.ipv4_address.parse::<Ipv4Addr>() {
                            if qtype == 1 {
                                return Ok(build_dns_a_response(query, question_end, ip));
                            } else {
                                return Ok(build_dns_empty_or_nxdomain(
                                    query,
                                    question_end,
                                    false,
                                ));
                            }
                        }
                    }
                }
            }
            if is_local_domain {
                return Ok(build_dns_empty_or_nxdomain(query, question_end, true));
            }
        }
    }

    let custom_dns_servers: Vec<String> = connected_nets
        .iter()
        .flat_map(|n| n.dns_servers.iter().cloned())
        .collect();

    let socket = UdpSocket::bind("0.0.0.0:0").context("bind DNS UDP")?;
    if !custom_dns_servers.is_empty() {
        socket.set_read_timeout(Some(Duration::from_millis(200)))?;
        for srv in &custom_dns_servers {
            let target = if srv.contains(':') {
                srv.clone()
            } else {
                format!("{}:53", srv.trim())
            };
            if socket.send_to(query, &target).is_ok() {
                let mut buf = [0u8; 4096];
                if let Ok((len, _)) = socket.recv_from(&mut buf) {
                    return Ok(buf[..len].to_vec());
                }
            }
        }
        return Err(anyhow!("Custom network DNS upstream timeout"));
    }

    socket.set_read_timeout(Some(Duration::from_millis(800)))?;
    for target in ["127.0.0.53:53", "1.1.1.1:53", "8.8.8.8:53"] {
        if socket.send_to(query, target).is_ok() {
            let mut buf = [0u8; 4096];
            if let Ok((len, _)) = socket.recv_from(&mut buf) {
                return Ok(buf[..len].to_vec());
            }
        }
    }
    Err(anyhow!("DNS upstream timeout"))
}

fn serve_tcp_flow(
    unix: &mut UnixStream,
    reader: &mut BufReader<UnixStream>,
    rest: &str,
    bundle_path: &Path,
) -> Result<()> {
    let (ip_s, port_s) = rest
        .split_once(' ')
        .ok_or_else(|| anyhow!("bad CONNECT line"))?;
    let ip: Ipv4Addr = ip_s.parse().context("bad ip")?;
    let port: u16 = port_s.parse().context("bad port")?;

    // Check if target IP belongs to a peer container in networks.json
    let home = bundle_path
        .parent()
        .and_then(|p| p.parent())
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(crate::storage::boxr_home);
    let net_store = crate::network::NetworkStore::with_home(home.clone());
    let mut peer_cid_opt = None;
    for net in net_store.list() {
        for (cid, ep) in &net.containers {
            if ep.ipv4_address == ip_s
                || ep.ips.iter().any(|(assigned_ip, _, _)| assigned_ip == ip_s)
            {
                peer_cid_opt = Some(cid.clone());
                break;
            }
        }
        if peer_cid_opt.is_some() {
            break;
        }
    }

    if let Some(peer_cid) = peer_cid_opt {
        let peer_bundle = home.join("containers").join(&peer_cid);
        let peer_sock = peer_socket_path(&peer_bundle);
        if let Ok(mut peer_stream) = UnixStream::connect(&peer_sock) {
            let _ = peer_stream.set_read_timeout(Some(Duration::from_millis(250)));
            let _ = peer_stream.set_write_timeout(Some(Duration::from_secs(5)));
            peer_stream.write_all(&port.to_be_bytes())?;
            peer_stream.flush()?;
            let mut status = [0u8; 1];
            if peer_stream.read_exact(&mut status).is_ok() && status[0] == 1 {
                writeln!(unix, "OK")?;
                unix.flush()?;
                loop {
                    let mut hdr = String::new();
                    reader.read_line(&mut hdr)?;
                    let hdr = hdr.trim();
                    if hdr == "CLOSE" || hdr.is_empty() {
                        break;
                    }
                    let len_s = hdr
                        .strip_prefix("DATA ")
                        .ok_or_else(|| anyhow!("expected DATA or CLOSE"))?;
                    let len: usize = len_s.parse().context("bad DATA length")?;
                    let mut buf = vec![0u8; len];
                    reader.read_exact(&mut buf)?;
                    peer_stream.write_all(&buf)?;
                    peer_stream.flush()?;
                    let mut resp = [0u8; 65536];
                    let n = match peer_stream.read(&mut resp) {
                        Ok(n) => n,
                        Err(ref e)
                            if e.kind() == std::io::ErrorKind::WouldBlock
                                || e.kind() == std::io::ErrorKind::TimedOut =>
                        {
                            0
                        }
                        Err(_) => 0,
                    };
                    writeln!(unix, "DATA {}", n)?;
                    if n > 0 {
                        unix.write_all(&resp[..n])?;
                    }
                    unix.flush()?;
                }
                return Ok(());
            }
        }
    }

    let addr = std::net::SocketAddr::from((ip, port));
    let mut tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(10))
        .with_context(|| format!("connect {}", addr))?;
    tcp.set_read_timeout(Some(Duration::from_secs(20)))?;
    tcp.set_write_timeout(Some(Duration::from_secs(20)))?;
    writeln!(unix, "OK")?;
    unix.flush()?;

    loop {
        let mut hdr = String::new();
        reader.read_line(&mut hdr)?;
        let hdr = hdr.trim();
        if hdr == "CLOSE" {
            break;
        }
        let len_s = hdr
            .strip_prefix("DATA ")
            .ok_or_else(|| anyhow!("expected DATA or CLOSE"))?;
        let len: usize = len_s.parse().context("bad DATA length")?;
        let mut buf = vec![0u8; len];
        reader.read_exact(&mut buf)?;
        tcp.write_all(&buf)?;
        tcp.flush()?;
        let mut resp = [0u8; 65536];
        let n = tcp.read(&mut resp)?;
        writeln!(unix, "DATA {}", n)?;
        unix.write_all(&resp[..n])?;
        unix.flush()?;
    }
    Ok(())
}

/// Dial outbound TCP via the host relay (must run inside container/TAP context).
pub fn dial_via_relay(bundle_path: &Path, ip: Ipv4Addr, port: u16) -> Result<UnixStream> {
    let mut s = UnixStream::connect(relay_socket_path(bundle_path))
        .context("connect usernet-relay.sock")?;
    writeln!(s, "CONNECT {} {}", ip, port)?;
    s.flush()?;
    let mut reader = BufReader::new(s.try_clone()?);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    if !line.trim().starts_with("OK") {
        return Err(anyhow!("relay refused: {}", line.trim()));
    }
    Ok(s)
}

/// Forward a DNS UDP query via the host relay (one-shot connection).
pub fn dns_via_relay(bundle_path: &Path, query: &[u8]) -> Result<Vec<u8>> {
    let mut s = UnixStream::connect(relay_socket_path(bundle_path))
        .context("connect usernet-relay.sock for DNS")?;
    writeln!(s, "DNSUDP {}", query.len())?;
    s.write_all(query)?;
    s.flush()?;
    let mut reader = BufReader::new(s.try_clone()?);
    let mut hdr = String::new();
    reader.read_line(&mut hdr)?;
    let len_s = hdr
        .trim()
        .strip_prefix("DATA ")
        .ok_or_else(|| anyhow!("bad DNS relay response"))?;
    let len: usize = len_s.parse()?;
    let mut out = vec![0u8; len];
    reader.read_exact(&mut out)?;
    Ok(out)
}

pub fn relay_exchange(unix: &mut UnixStream, payload: &[u8]) -> Result<Vec<u8>> {
    writeln!(unix, "DATA {}", payload.len())?;
    unix.write_all(payload)?;
    unix.flush()?;
    let mut reader = BufReader::new(unix.try_clone()?);
    let mut hdr = String::new();
    reader.read_line(&mut hdr)?;
    let len_s = hdr
        .trim()
        .strip_prefix("DATA ")
        .ok_or_else(|| anyhow!("bad relay response"))?;
    let len: usize = len_s.parse()?;
    let mut out = vec![0u8; len];
    reader.read_exact(&mut out)?;
    Ok(out)
}
