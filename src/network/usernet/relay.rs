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

    match unsafe { nix::unistd::fork() }? {
        nix::unistd::ForkResult::Parent { child } => Ok(child.as_raw()),
        nix::unistd::ForkResult::Child => {
            unsafe {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
            }
            if let Err(e) = run_relay_server(listener, bundle_path.to_path_buf()) {
                eprintln!("usernet relay exited: {:?}", e);
            }
            std::process::exit(0);
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub fn spawn_host_relay(_bundle_path: &Path) -> Result<i32> {
    anyhow::bail!("usernet relay is only supported on Linux")
}

fn run_relay_server(listener: UnixListener, bundle_path: std::path::PathBuf) -> Result<()> {
    for conn in listener.incoming() {
        let mut unix = match conn {
            Ok(s) => s,
            Err(_) => break,
        };
        let bp = bundle_path.clone();
        std::thread::spawn(move || {
            if let Err(e) = dispatch_client(&mut unix, &bp) {
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
        let reply = if let Some(synth) = try_answer_dns_from_bundle_hosts(bundle_path, &query) {
            synth
        } else {
            forward_dns_on_host(&query)?
        };
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

fn forward_dns_on_host(query: &[u8]) -> Result<Vec<u8>> {
    use std::net::UdpSocket;
    let socket = UdpSocket::bind("0.0.0.0:0").context("bind DNS UDP")?;
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

fn try_answer_dns_from_bundle_hosts(bundle_path: &Path, query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([query[4], query[5]]);
    if qdcount == 0 {
        return None;
    }
    let mut idx = 12usize;
    let mut labels = Vec::new();
    while idx < query.len() {
        let len = query[idx] as usize;
        idx += 1;
        if len == 0 {
            break;
        }
        if idx + len > query.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&query[idx..idx + len]).to_lowercase());
        idx += len;
    }
    if idx + 4 > query.len() || labels.is_empty() {
        return None;
    }
    let qtype = u16::from_be_bytes([query[idx], query[idx + 1]]);
    let qclass = u16::from_be_bytes([query[idx + 2], query[idx + 3]]);
    if qclass != 1 {
        return None;
    }
    let qend = idx + 4;
    let qname = labels.join(".");
    let stripped = qname
        .strip_suffix(".dns.podman")
        .unwrap_or(&qname)
        .to_string();

    let mut candidate_hosts_files = vec![bundle_path.join("hosts")];
    if let Some(containers_dir) = bundle_path.parent() {
        if let Ok(entries) = fs::read_dir(containers_dir) {
            for e in entries.flatten() {
                let hp = e.path().join("hosts");
                if hp.is_file() && !candidate_hosts_files.contains(&hp) {
                    candidate_hosts_files.push(hp);
                }
            }
        }
    }
    let mut matched_v4: Option<Ipv4Addr> = None;
    for hp in candidate_hosts_files {
        let Ok(content) = fs::read_to_string(&hp) else {
            continue;
        };
        for line in content.lines() {
            let clean = line.split('#').next().unwrap_or("").trim();
            if clean.is_empty() {
                continue;
            }
            let mut parts = clean.split_whitespace();
            let Some(ip_tok) = parts.next() else {
                continue;
            };
            let Ok(v4) = ip_tok.parse::<Ipv4Addr>() else {
                continue;
            };
            if v4.is_loopback() {
                continue;
            }
            for host_tok in parts {
                let ht = host_tok.to_lowercase();
                if ht == qname || ht == stripped {
                    matched_v4 = Some(v4);
                    break;
                }
            }
            if matched_v4.is_some() {
                break;
            }
        }
        if matched_v4.is_some() {
            break;
        }
    }
    let v4 = matched_v4?;
    let mut resp = Vec::with_capacity(qend + 16);
    resp.extend_from_slice(&query[0..2]); // ID
    resp.extend_from_slice(&[0x81, 0x80]); // QR=1, RD=1, RA=1, RCODE=0
    resp.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    if qtype == 1 {
        resp.extend_from_slice(&[0x00, 0x01]); // ANCOUNT=1
    } else {
        resp.extend_from_slice(&[0x00, 0x00]); // ANCOUNT=0 (e.g. AAAA query -> NODATA)
    }
    resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // NSCOUNT=0, ARCOUNT=0
    resp.extend_from_slice(&query[12..qend]); // Question section
    if qtype == 1 {
        resp.extend_from_slice(&[0xc0, 0x0c]); // Name pointer to offset 12
        resp.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
        resp.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
        resp.extend_from_slice(&60u32.to_be_bytes()); // TTL 60s
        resp.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH 4
        resp.extend_from_slice(&v4.octets());
    }
    Some(resp)
}

fn connect_peer_bundle_sock(peer_bundle: &Path, port: u16) -> Option<UnixStream> {
    let sock_cand = peer_bundle.join("peer-tcp.sock");
    let sock_path = if sock_cand.exists() {
        sock_cand
    } else {
        let cid = peer_bundle.file_name()?.to_str()?;
        let short = &cid[..12.min(cid.len())];
        std::path::PathBuf::from(format!("/tmp/bx-{}-peer-tcp.sock", short))
    };
    let mut s = UnixStream::connect(&sock_path).ok()?;
    let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = s.set_write_timeout(Some(Duration::from_secs(10)));
    s.write_all(&port.to_be_bytes()).ok()?;
    s.flush().ok()?;
    let mut status = [0u8; 1];
    s.read_exact(&mut status).ok()?;
    if status[0] == 1 {
        return Some(s);
    }
    None
}

fn try_connect_peer_container(bundle_path: &Path, ip: Ipv4Addr, port: u16) -> Option<UnixStream> {
    let ip_str = ip.to_string();
    if let Some(containers_dir) = bundle_path.parent() {
        if let Ok(entries) = fs::read_dir(containers_dir) {
            for entry in entries.flatten() {
                let peer_bundle = entry.path();
                if !peer_bundle.is_dir() {
                    continue;
                }
                let mut matches_ip = false;
                if let Ok(p_ip) = fs::read_to_string(peer_bundle.join("primary_ip.txt")) {
                    if p_ip.trim() == ip_str {
                        matches_ip = true;
                    }
                }
                if !matches_ip {
                    if let Ok(ifaces_raw) =
                        fs::read_to_string(peer_bundle.join("network_interfaces.json"))
                    {
                        if let Ok(ifaces) =
                            serde_json::from_str::<Vec<(String, String, String)>>(&ifaces_raw)
                        {
                            if ifaces.iter().any(|(_, cidr, _)| {
                                cidr.split('/').next().unwrap_or("") == ip_str
                            }) {
                                matches_ip = true;
                            }
                        }
                    }
                }
                if matches_ip {
                    if let Some(s) = connect_peer_bundle_sock(&peer_bundle, port) {
                        return Some(s);
                    }
                }
            }
        }
    }
    let home = bundle_path.parent()?.parent()?;
    let net_store = crate::network::NetworkStore::new();
    let net_store_home = crate::network::NetworkStore::with_home(home.to_path_buf());
    let c_store = crate::storage::ContainerStore::with_home(home.to_path_buf());
    let mut all_nets = net_store.list();
    for n in net_store_home.list() {
        if !all_nets.iter().any(|existing| existing.name == n.name) {
            all_nets.push(n);
        }
    }
    for net in all_nets {
        for (cid, ep) in &net.containers {
            if ep.ipv4_address == ip_str {
                let peer = c_store
                    .find(cid)
                    .or_else(|| c_store.find(&ep.container_name))?;
                let peer_bundle = std::path::PathBuf::from(&peer.bundle_path);
                if let Some(s) = connect_peer_bundle_sock(&peer_bundle, port) {
                    return Some(s);
                }
            }
        }
    }
    None
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

    if let Some(mut peer_stream) = try_connect_peer_container(bundle_path, ip, port) {
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
            peer_stream.write_all(&buf)?;
            peer_stream.flush()?;
            let mut resp = [0u8; 65536];
            let n = peer_stream.read(&mut resp)?;
            writeln!(unix, "DATA {}", n)?;
            unix.write_all(&resp[..n])?;
            unix.flush()?;
        }
        return Ok(());
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
