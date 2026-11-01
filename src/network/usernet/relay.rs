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
    let bundle_owned = bundle_path.to_path_buf();

    match unsafe { nix::unistd::fork() }? {
        nix::unistd::ForkResult::Parent { child } => Ok(child.as_raw()),
        nix::unistd::ForkResult::Child => {
            unsafe {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
            }
            if let Err(e) = run_relay_server(listener, &bundle_owned) {
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

fn run_relay_server(listener: UnixListener, bundle_path: &Path) -> Result<()> {
    for conn in listener.incoming() {
        let mut unix = match conn {
            Ok(s) => s,
            Err(_) => break,
        };
        let b = bundle_path.to_path_buf();
        std::thread::spawn(move || {
            if let Err(e) = dispatch_client(&mut unix, &b) {
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
        let reply = try_resolve_aardvark_dns(&query, bundle_path)
            .unwrap_or_else(|| forward_dns_on_host(&query).unwrap_or_default());
        writeln!(unix, "DATA {}", reply.len())?;
        unix.write_all(&reply)?;
        unix.flush()?;
        return Ok(());
    }
    let rest = line
        .strip_prefix("CONNECT ")
        .ok_or_else(|| anyhow!("expected CONNECT or DNSUDP"))?;
    serve_tcp_flow(unix, &mut reader, rest)
}

fn parse_dns_qname(pkt: &[u8], start: usize) -> Option<(String, usize)> {
    let mut pos = start;
    let mut labels = Vec::new();
    while pos < pkt.len() {
        let len = pkt[pos] as usize;
        pos += 1;
        if len == 0 {
            return Some((labels.join("."), pos));
        }
        if (len & 0xc0) != 0 {
            return None;
        }
        if pos + len > pkt.len() {
            return None;
        }
        let s = std::str::from_utf8(&pkt[pos..pos + len]).ok()?;
        labels.push(s.to_string());
        pos += len;
    }
    None
}

fn encode_dns_name(name: &str, out: &mut Vec<u8>) {
    for label in name.trim_end_matches('.').split('.').filter(|s| !s.is_empty()) {
        let bytes = label.as_bytes();
        let l = bytes.len().min(63);
        out.push(l as u8);
        out.extend_from_slice(&bytes[..l]);
    }
    out.push(0);
}

pub fn try_resolve_aardvark_dns(query: &[u8], bundle_path: &Path) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([query[4], query[5]]);
    if qdcount == 0 {
        return None;
    }
    let (qname, qend) = parse_dns_qname(query, 12)?;
    if qend + 4 > query.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([query[qend], query[qend + 1]]);
    let qclass = u16::from_be_bytes([query[qend + 2], query[qend + 3]]);
    if qclass != 1 {
        return None;
    }

    let container_id = bundle_path.file_name()?.to_str()?;
    let home = bundle_path.parent()?.parent()?;
    let net_store = crate::network::NetworkStore::with_home(home.to_path_buf());
    let all_nets = net_store.list();
    let caller_nets: Vec<&crate::network::NetworkRecord> = all_nets
        .iter()
        .filter(|n| {
            n.name != crate::network::NetworkStore::DEFAULT_NETWORK
                && n.name != "podman"
                && n.containers.contains_key(container_id)
        })
        .collect();
    if caller_nets.is_empty() {
        return None;
    }

    let qname_clean = qname.trim_end_matches('.').to_ascii_lowercase();
    let question_slice = &query[12..qend + 4];

    // PTR reverse lookup (qtype == 12)
    if qtype == 12 {
        if let Some(ip_rev) = qname_clean.strip_suffix(".in-addr.arpa") {
            let octs: Vec<&str> = ip_rev.split('.').collect();
            if octs.len() == 4 {
                let target_ip = format!("{}.{}.{}.{}", octs[3], octs[2], octs[1], octs[0]);
                for net in &caller_nets {
                    for (cid, ep) in &net.containers {
                        if ep.ipv4_address == target_ip {
                            let short_id = &cid[..12.min(cid.len())];
                            let ptr_names = vec![ep.container_name.clone(), short_id.to_string()];
                            let mut resp = Vec::with_capacity(128);
                            resp.extend_from_slice(&query[0..2]); // ID
                            resp.extend_from_slice(&[0x85, 0x80]); // QR=1, AA=1, RD=1, RA=1
                            resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
                            resp.extend_from_slice(&(ptr_names.len() as u16).to_be_bytes()); // ANCOUNT
                            resp.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
                            resp.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
                            resp.extend_from_slice(question_slice);
                            for pname in ptr_names {
                                resp.extend_from_slice(&[0xc0, 0x0c]); // Pointer to qname
                                resp.extend_from_slice(&12u16.to_be_bytes()); // TYPE PTR
                                resp.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
                                resp.extend_from_slice(&60u32.to_be_bytes()); // TTL
                                let mut rdata = Vec::new();
                                encode_dns_name(&pname, &mut rdata);
                                resp.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
                                resp.extend_from_slice(&rdata);
                            }
                            return Some(resp);
                        }
                    }
                }
            }
        }
        return None;
    }

    // A / AAAA lookup on container names / short IDs / aliases
    let mut matched_ips: Vec<Ipv4Addr> = Vec::new();
    for net in &caller_nets {
        let lookup_key = qname_clean
            .strip_suffix(&format!(".{}", net.name.to_ascii_lowercase()))
            .or_else(|| qname_clean.strip_suffix(".dns.podman"))
            .unwrap_or(&qname_clean);
        for (cid, ep) in &net.containers {
            let short_id = &cid[..12.min(cid.len())];
            let name_match = ep.container_name.eq_ignore_ascii_case(lookup_key)
                || short_id.eq_ignore_ascii_case(lookup_key)
                || cid.eq_ignore_ascii_case(lookup_key)
                || ep
                    .aliases
                    .iter()
                    .any(|a| a.eq_ignore_ascii_case(lookup_key));
            if name_match {
                if let Ok(ipv4) = ep.ipv4_address.parse::<Ipv4Addr>() {
                    if !matched_ips.contains(&ipv4) {
                        matched_ips.push(ipv4);
                    }
                }
            }
        }
    }

    if !matched_ips.is_empty() {
        let mut resp = Vec::with_capacity(128);
        resp.extend_from_slice(&query[0..2]); // ID
        resp.extend_from_slice(&[0x85, 0x80]); // QR=1, AA=1, RD=1, RA=1, RCODE=0
        resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        if qtype == 1 {
            resp.extend_from_slice(&(matched_ips.len() as u16).to_be_bytes()); // ANCOUNT
        } else {
            resp.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT=0 for AAAA when IPv4 matched
        }
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(question_slice);
        if qtype == 1 {
            for ip in matched_ips {
                resp.extend_from_slice(&[0xc0, 0x0c]); // Name pointer
                resp.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
                resp.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
                resp.extend_from_slice(&60u32.to_be_bytes()); // TTL
                resp.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
                resp.extend_from_slice(&ip.octets());
            }
        }
        return Some(resp);
    }

    // Single-label name not found in caller's networks -> return NXDOMAIN immediately
    // (like aardvark-dns when a container name is on a different network)
    if !qname_clean.contains('.') {
        let mut resp = Vec::with_capacity(64);
        resp.extend_from_slice(&query[0..2]); // ID
        resp.extend_from_slice(&[0x85, 0x83]); // QR=1, RCODE=3 (NXDOMAIN)
        resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        resp.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        resp.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        resp.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        resp.extend_from_slice(question_slice);
        return Some(resp);
    }

    None
}

/// Run an in-netns UDP/TCP port 53 DNS server bound to `bind_ip:53` (or `0.0.0.0:53`)
/// that delegates queries to the host relay (`dns_via_relay`).
pub fn run_in_netns_dns_server(bundle_path: &Path, bind_ip: Ipv4Addr) {
    #[cfg(target_os = "linux")]
    unsafe {
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
    }
    let udp_sock = std::net::UdpSocket::bind((bind_ip, 53))
        .or_else(|_| std::net::UdpSocket::bind(("0.0.0.0", 53)));
    let Ok(sock) = udp_sock else {
        return;
    };
    let mut buf = [0u8; 4096];
    while let Ok((len, peer)) = sock.recv_from(&mut buf) {
        let query = &buf[..len];
        if let Some(reply) =
            try_resolve_aardvark_dns(query, bundle_path).or_else(|| dns_via_relay(bundle_path, query).ok())
        {
            let _ = sock.send_to(&reply, peer);
        }
    }
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

fn serve_tcp_flow(
    unix: &mut UnixStream,
    reader: &mut BufReader<UnixStream>,
    rest: &str,
) -> Result<()> {
    let (ip_s, port_s) = rest
        .split_once(' ')
        .ok_or_else(|| anyhow!("bad CONNECT line"))?;
    let ip: Ipv4Addr = ip_s.parse().context("bad ip")?;
    let port: u16 = port_s.parse().context("bad port")?;
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
