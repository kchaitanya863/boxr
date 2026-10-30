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
    bundle_path.join("usernet-relay.sock")
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
            if let Err(e) = run_relay_server(listener) {
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

fn run_relay_server(listener: UnixListener) -> Result<()> {
    for conn in listener.incoming() {
        let mut unix = match conn {
            Ok(s) => s,
            Err(_) => break,
        };
        std::thread::spawn(move || {
            if let Err(e) = dispatch_client(&mut unix) {
                let _ = writeln!(unix, "ERR {}", e);
            }
        });
    }
    Ok(())
}

fn dispatch_client(unix: &mut UnixStream) -> Result<()> {
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
        let reply = forward_dns_on_host(&query)?;
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
