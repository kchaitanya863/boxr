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
                libc::signal(libc::SIGPIPE, libc::SIG_IGN);
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
        let reply = if let Some(r) = try_resolve_aardvark_dns(&query, bundle_path) {
            r
        } else if let Some(synth) = try_answer_dns_from_bundle_hosts(bundle_path, &query) {
            synth
        } else {
            forward_dns_on_host(bundle_path, &query)?
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
    let c_store = crate::storage::ContainerStore::with_home(home.to_path_buf());
    let pod_store = crate::pod::PodStore::with_home(home.to_path_buf());
    let all_nets = net_store.list();
    let caller_nets: Vec<&crate::network::NetworkRecord> = all_nets
        .iter()
        .filter(|n| {
            n.name != crate::network::NetworkStore::DEFAULT_NETWORK
                && n.name != "podman"
                && !n.disable_dns
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

    // A / AAAA lookup on container names / short IDs / aliases / hostnames / pods
    let pods = pod_store.list();
    let mut matched_ips: Vec<Ipv4Addr> = Vec::new();
    for net in &caller_nets {
        let lookup_key = qname_clean
            .strip_suffix(&format!(".{}", net.name.to_ascii_lowercase()))
            .or_else(|| qname_clean.strip_suffix(".dns.podman"))
            .unwrap_or(&qname_clean);
        for (cid, ep) in &net.containers {
            let c_rec = c_store.find(cid);
            let is_running = c_rec
                .as_ref()
                .is_some_and(|c| matches!(c.status, crate::storage::ContainerStatus::Running));
            if !is_running && cid != container_id {
                continue;
            }
            let short_id = &cid[..12.min(cid.len())];
            let mut name_match = ep.container_name.eq_ignore_ascii_case(lookup_key)
                || short_id.eq_ignore_ascii_case(lookup_key)
                || cid.eq_ignore_ascii_case(lookup_key)
                || ep
                    .aliases
                    .iter()
                    .any(|a| a.eq_ignore_ascii_case(lookup_key));
            if !name_match {
                if let Some(c) = &c_rec {
                    let cfg_path = std::path::PathBuf::from(&c.bundle_path).join("config.json");
                    if let Ok(raw) = fs::read_to_string(cfg_path) {
                        if let Ok(sp) = serde_json::from_str::<crate::oci::runtime::Spec>(&raw) {
                            if sp
                                .hostname
                                .as_deref()
                                .is_some_and(|h| h.eq_ignore_ascii_case(lookup_key))
                            {
                                name_match = true;
                            }
                        }
                    }
                }
            }
            if !name_match {
                for p in &pods {
                    let infra_name = pod_store.infra_name(p);
                    if p.infra_container_id == *cid || infra_name == ep.container_name {
                        if p.name.eq_ignore_ascii_case(lookup_key)
                            || p.hostname
                                .as_deref()
                                .is_some_and(|h| h.eq_ignore_ascii_case(lookup_key))
                        {
                            name_match = true;
                            break;
                        }
                    }
                }
            }
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

    // Single-label name or .dns.podman not found in caller's networks -> return NXDOMAIN immediately
    if !qname_clean.contains('.') || qname_clean.ends_with(".dns.podman") {
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
        if let Some(reply) = try_resolve_aardvark_dns(query, bundle_path)
            .or_else(|| dns_via_relay(bundle_path, query).ok())
        {
            let _ = sock.send_to(&reply, peer);
        }
    }
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
