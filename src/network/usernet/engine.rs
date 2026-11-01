use super::packets::*;
use crate::network::PortMapping;
use anyhow::{Context, Result, anyhow};
use std::collections::HashMap;
use std::fs::File;
use std::net::Ipv4Addr;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TcpFlowKey {
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
}

struct TcpFlowState {
    relay: UnixStream,
    /// Next sequence number we send toward the container.
    host_seq: u32,
}

const TCP_FLAG_FIN: u16 = 0x01;
const TCP_FLAG_SYN: u16 = 0x02;
const TCP_FLAG_RST: u16 = 0x04;
const TCP_FLAG_PSH: u16 = 0x08;
const TCP_FLAG_ACK: u16 = 0x10;

pub struct UserNetEngine {
    pub container_ip: Ipv4Addr,
    pub gateway_ip: Ipv4Addr,
    pub dns_ip: Ipv4Addr,
    pub ports: Vec<PortMapping>,
    pub running: Arc<AtomicBool>,
    #[allow(dead_code)]
    bundle_path: Option<PathBuf>,
    host_netns: Option<File>,
    tcp_flows: Mutex<HashMap<TcpFlowKey, TcpFlowState>>,
}

impl UserNetEngine {
    pub fn new(
        bundle_path: Option<&Path>,
        ports: &[PortMapping],
        host_netns: Option<File>,
    ) -> Self {
        Self {
            container_ip: DEFAULT_CONTAINER_IP,
            gateway_ip: DEFAULT_GATEWAY_IP,
            dns_ip: DEFAULT_DNS_IP,
            ports: ports.to_vec(),
            running: Arc::new(AtomicBool::new(true)),
            bundle_path: bundle_path.map(Path::to_path_buf),
            host_netns,
            tcp_flows: Mutex::new(HashMap::new()),
        }
    }

    fn tcp_debug(msg: &str) {
        if matches!(
            std::env::var("BOXR_USERNET_DEBUG").as_deref(),
            Ok("1") | Ok("true")
        ) {
            eprintln!("usernet: {}", msg);
        }
    }

    fn is_outbound_ipv4(&self, ip: &Ipv4Header) -> bool {
        ip.dst_ip != ip.src_ip
            && ip.dst_ip != self.container_ip
            && ip.dst_ip != self.gateway_ip
            && ip.dst_ip != self.dns_ip
    }

    fn tcp_flow_key(tcp: &TcpHeader, ip: &Ipv4Header) -> TcpFlowKey {
        TcpFlowKey {
            src_port: tcp.src_port,
            dst_ip: ip.dst_ip,
            dst_port: tcp.dst_port,
        }
    }

    fn build_tcp_reply(
        eth: &EthernetHeader,
        ip: &Ipv4Header,
        reply_tcp: TcpHeader,
        payload: &[u8],
    ) -> Vec<u8> {
        let reply_ip = Ipv4Header {
            ihl: 5,
            tos: 0,
            total_length: (20 + 20 + payload.len()) as u16,
            id: ip.id.wrapping_add(1),
            flags_and_frag: 0x4000,
            ttl: 64,
            protocol: IP_PROTO_TCP,
            checksum: 0,
            src_ip: ip.dst_ip,
            dst_ip: ip.src_ip,
        };

        let reply_eth = EthernetHeader {
            dst_mac: eth.src_mac,
            src_mac: VIRTUAL_GATEWAY_MAC,
            ethertype: ETHERTYPE_IPV4,
        };

        let mut tcp_bytes = Vec::with_capacity(20 + payload.len());
        reply_tcp.write_to(&mut tcp_bytes);
        tcp_bytes.extend_from_slice(payload);

        let csum =
            compute_tcp_checksum(&reply_ip.src_ip, &reply_ip.dst_ip, IP_PROTO_TCP, &tcp_bytes);
        tcp_bytes[16..18].copy_from_slice(&csum.to_be_bytes());

        let mut out = Vec::with_capacity(14 + 20 + tcp_bytes.len());
        reply_eth.write_to(&mut out);
        reply_ip.write_to(&mut out);
        out.extend_from_slice(&tcp_bytes);
        out
    }

    /// Process a received raw Ethernet frame from the container TAP interface
    /// Returns an optional reply Ethernet frame to write back to the TAP interface.
    pub fn handle_incoming_frame(&self, frame: &[u8]) -> Option<Vec<u8>> {
        let (eth, payload) = EthernetHeader::parse(frame)?;

        match eth.ethertype {
            ETHERTYPE_ARP => self.handle_arp(&eth, payload),
            ETHERTYPE_IPV4 => self.handle_ipv4(&eth, payload),
            _ => None,
        }
    }

    fn handle_arp(&self, eth: &EthernetHeader, payload: &[u8]) -> Option<Vec<u8>> {
        let arp = ArpPacket::parse(payload)?;

        // Only answer ARP requests (opcode == 1)
        if arp.opcode != 1 {
            return None;
        }

        // If target IP is gateway, DNS, or any virtual subnet gateway, respond with our virtual gateway MAC
        if arp.target_ip == self.gateway_ip
            || arp.target_ip == self.dns_ip
            || (self.bundle_path.is_some() && arp.target_ip != arp.sender_ip)
        {
            let mut reply = Vec::with_capacity(42);
            let reply_eth = EthernetHeader {
                dst_mac: eth.src_mac,
                src_mac: VIRTUAL_GATEWAY_MAC,
                ethertype: ETHERTYPE_ARP,
            };
            reply_eth.write_to(&mut reply);
            arp.write_reply(VIRTUAL_GATEWAY_MAC, &mut reply);
            return Some(reply);
        }

        None
    }

    fn handle_ipv4(&self, eth: &EthernetHeader, payload: &[u8]) -> Option<Vec<u8>> {
        let (ip, ip_payload) = Ipv4Header::parse(payload)?;

        match ip.protocol {
            IP_PROTO_ICMP => self.handle_icmp(eth, &ip, ip_payload),
            IP_PROTO_UDP => self.handle_udp(eth, &ip, ip_payload),
            IP_PROTO_TCP => self.handle_tcp(eth, &ip, ip_payload),
            _ => None,
        }
    }

    fn handle_tcp(&self, eth: &EthernetHeader, ip: &Ipv4Header, payload: &[u8]) -> Option<Vec<u8>> {
        let (tcp, tcp_data) = TcpHeader::parse(payload)?;
        let outbound = self.is_outbound_ipv4(ip);
        let flow = Self::tcp_flow_key(&tcp, ip);

        // Outbound SYN (no ACK): dial from host network namespace and track the socket.
        let is_syn = (tcp.flags & TCP_FLAG_SYN) != 0 && (tcp.flags & TCP_FLAG_ACK) == 0;
        if outbound && is_syn && tcp_data.is_empty() {
            let bundle = self.bundle_path.as_deref();
            let connected =
                bundle.and_then(|b| super::relay::dial_via_relay(b, ip.dst_ip, tcp.dst_port).ok());
            match connected {
                Some(relay) => {
                    let host_seq = 1000u32;
                    if let Ok(mut guard) = self.tcp_flows.lock() {
                        guard.insert(
                            flow,
                            TcpFlowState {
                                relay,
                                host_seq: host_seq + 1,
                            },
                        );
                    }
                    let reply_tcp = TcpHeader {
                        src_port: tcp.dst_port,
                        dst_port: tcp.src_port,
                        seq_num: host_seq,
                        ack_num: tcp.seq_num.wrapping_add(1),
                        data_offset: 20,
                        flags: TCP_FLAG_SYN | TCP_FLAG_ACK,
                        window_size: 65535,
                        checksum: 0,
                        urgent_ptr: 0,
                    };
                    Self::tcp_debug(&format!(
                        "syn-ack {}:{} -> container port {}",
                        ip.dst_ip, tcp.dst_port, tcp.src_port
                    ));
                    return Some(Self::build_tcp_reply(eth, ip, reply_tcp, &[]));
                }
                None => {
                    Self::tcp_debug(&format!(
                        "syn relay dial failed {}:{}",
                        ip.dst_ip, tcp.dst_port
                    ));
                    return None;
                }
            }
        }

        // FIN: tear down tracked flow
        if outbound && (tcp.flags & TCP_FLAG_FIN) != 0 {
            if let Ok(mut guard) = self.tcp_flows.lock() {
                guard.remove(&flow);
            }
            let reply_tcp = TcpHeader {
                src_port: tcp.dst_port,
                dst_port: tcp.src_port,
                seq_num: tcp.ack_num,
                ack_num: tcp.seq_num.wrapping_add(1),
                data_offset: 20,
                flags: 0x11,
                window_size: 65535,
                checksum: 0,
                urgent_ptr: 0,
            };
            return Some(Self::build_tcp_reply(eth, ip, reply_tcp, &[]));
        }

        // Payload on established outbound flow (or late connect for unit tests)
        if outbound && !tcp_data.is_empty() {
            let mut guard = self.tcp_flows.lock().ok()?;
            if !guard.contains_key(&flow) {
                if let Some(b) = self.bundle_path.as_deref() {
                    if let Ok(relay) = super::relay::dial_via_relay(b, ip.dst_ip, tcp.dst_port) {
                        guard.insert(
                            flow,
                            TcpFlowState {
                                relay,
                                host_seq: 1001,
                            },
                        );
                    }
                }
            }
            if let Some(flow_state) = guard.get_mut(&flow) {
                if let Ok(response_data) =
                    super::relay::relay_exchange(&mut flow_state.relay, tcp_data)
                {
                    if !response_data.is_empty() {
                        let n = response_data.len();
                        let reply_tcp = TcpHeader {
                            src_port: tcp.dst_port,
                            dst_port: tcp.src_port,
                            seq_num: flow_state.host_seq,
                            ack_num: tcp.seq_num.wrapping_add(tcp_data.len() as u32),
                            data_offset: 20,
                            flags: TCP_FLAG_PSH | TCP_FLAG_ACK,
                            window_size: 65535,
                            checksum: 0,
                            urgent_ptr: 0,
                        };
                        flow_state.host_seq = flow_state.host_seq.wrapping_add(n as u32);
                        return Some(Self::build_tcp_reply(eth, ip, reply_tcp, &response_data));
                    } else {
                        let reply_tcp = TcpHeader {
                            src_port: tcp.dst_port,
                            dst_port: tcp.src_port,
                            seq_num: flow_state.host_seq,
                            ack_num: tcp.seq_num.wrapping_add(tcp_data.len() as u32),
                            data_offset: 20,
                            flags: TCP_FLAG_ACK,
                            window_size: 65535,
                            checksum: 0,
                            urgent_ptr: 0,
                        };
                        return Some(Self::build_tcp_reply(eth, ip, reply_tcp, &[]));
                    }
                }
            }
            return None;
        }

        // Legacy SYN-ACK for non-outbound probes (unit tests)
        if is_syn {
            let reply_tcp = TcpHeader {
                src_port: tcp.dst_port,
                dst_port: tcp.src_port,
                seq_num: 1000,
                ack_num: tcp.seq_num.wrapping_add(1),
                data_offset: 20,
                flags: 0x12,
                window_size: 65535,
                checksum: 0,
                urgent_ptr: 0,
            };
            return Some(Self::build_tcp_reply(eth, ip, reply_tcp, &[]));
        }

        None
    }

    fn handle_icmp(
        &self,
        eth: &EthernetHeader,
        ip: &Ipv4Header,
        payload: &[u8],
    ) -> Option<Vec<u8>> {
        // Echo Request is type 8, code 0
        if payload.len() < 8 || payload[0] != 8 || payload[1] != 0 {
            return None;
        }

        // If pinging gateway, construct Echo Reply (type 0, code 0)
        if ip.dst_ip == self.gateway_ip {
            let mut reply_payload = payload.to_vec();
            reply_payload[0] = 0; // Echo Reply
            reply_payload[2] = 0; // Reset checksum
            reply_payload[3] = 0;
            let csum = compute_checksum(&reply_payload);
            reply_payload[2..4].copy_from_slice(&csum.to_be_bytes());

            let reply_ip = Ipv4Header {
                ihl: 5,
                tos: 0,
                total_length: 20 + reply_payload.len() as u16,
                id: ip.id.wrapping_add(1),
                flags_and_frag: 0,
                ttl: 64,
                protocol: IP_PROTO_ICMP,
                checksum: 0,
                src_ip: self.gateway_ip,
                dst_ip: ip.src_ip,
            };

            let reply_eth = EthernetHeader {
                dst_mac: eth.src_mac,
                src_mac: VIRTUAL_GATEWAY_MAC,
                ethertype: ETHERTYPE_IPV4,
            };

            let mut out = Vec::with_capacity(14 + 20 + reply_payload.len());
            reply_eth.write_to(&mut out);
            reply_ip.write_to(&mut out);
            out.extend_from_slice(&reply_payload);
            return Some(out);
        }

        None
    }

    fn handle_udp(&self, eth: &EthernetHeader, ip: &Ipv4Header, payload: &[u8]) -> Option<Vec<u8>> {
        let (udp, udp_payload) = UdpHeader::parse(payload)?;

        // Intercept DNS requests on port 53 sent to virtual gateway, DNS IP, or custom bridge gateway
        if udp.dst_port == 53 {
            let dns_reply = self
                .bundle_path
                .as_deref()
                .and_then(|b| {
                    super::relay::try_resolve_aardvark_dns(udp_payload, b)
                        .or_else(|| super::relay::dns_via_relay(b, udp_payload).ok())
                })
                .or_else(|| forward_dns_query(self.host_netns.as_ref(), udp_payload).ok());
            if let Some(dns_reply) = dns_reply {
                return self.build_udp_reply(eth, ip, &udp, &dns_reply);
            }
        }

        // Generic UDP outbound forwarding to host network
        if ip.dst_ip != self.gateway_ip && ip.dst_ip != self.container_ip {
            if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
                let _ = socket.set_read_timeout(Some(std::time::Duration::from_millis(500)));
                let target =
                    std::net::SocketAddr::V4(std::net::SocketAddrV4::new(ip.dst_ip, udp.dst_port));
                if socket.send_to(udp_payload, target).is_ok() {
                    let mut buf = [0u8; 65507];
                    if let Ok((len, _)) = socket.recv_from(&mut buf) {
                        return self.build_udp_reply(eth, ip, &udp, &buf[..len]);
                    }
                }
            }
        }

        None
    }

    fn build_udp_reply(
        &self,
        eth: &EthernetHeader,
        ip: &Ipv4Header,
        udp: &UdpHeader,
        reply_payload: &[u8],
    ) -> Option<Vec<u8>> {
        let reply_udp = UdpHeader {
            src_port: udp.dst_port,
            dst_port: udp.src_port,
            length: (8 + reply_payload.len()) as u16,
            checksum: 0,
        };

        let reply_ip = Ipv4Header {
            ihl: 5,
            tos: 0,
            total_length: (20 + 8 + reply_payload.len()) as u16,
            id: ip.id.wrapping_add(1),
            flags_and_frag: 0,
            ttl: 64,
            protocol: IP_PROTO_UDP,
            checksum: 0,
            src_ip: ip.dst_ip,
            dst_ip: ip.src_ip,
        };

        let reply_eth = EthernetHeader {
            dst_mac: eth.src_mac,
            src_mac: VIRTUAL_GATEWAY_MAC,
            ethertype: ETHERTYPE_IPV4,
        };

        let mut out = Vec::with_capacity(14 + 20 + 8 + reply_payload.len());
        reply_eth.write_to(&mut out);
        reply_ip.write_to(&mut out);
        reply_udp.write_to(&mut out);
        out.extend_from_slice(reply_payload);
        Some(out)
    }
}

#[cfg(target_os = "linux")]
fn with_host_network<T, F: FnOnce() -> Result<T>>(host_netns: Option<&File>, f: F) -> Result<T> {
    use nix::sched::{CloneFlags, setns};

    if let Some(host_ns) = host_netns {
        if let Ok(self_ns) = File::open("/proc/self/ns/net") {
            match setns(host_ns, CloneFlags::CLONE_NEWNET) {
                Ok(()) => {
                    let result = f();
                    let _ = setns(&self_ns, CloneFlags::CLONE_NEWNET);
                    return result;
                }
                Err(e) => {
                    UserNetEngine::tcp_debug(&format!("setns(host) failed: {:?}", e));
                }
            }
        } else {
            UserNetEngine::tcp_debug("open /proc/self/ns/net failed");
        }
    } else {
        UserNetEngine::tcp_debug("host_netns fd missing in TAP worker");
    }
    f()
}

#[cfg(not(target_os = "linux"))]
fn with_host_network<T, F: FnOnce() -> Result<T>>(_host_netns: Option<&File>, f: F) -> Result<T> {
    f()
}

/// Forward DNS query buffer to standard host DNS servers and await response
fn forward_dns_query(host_netns: Option<&File>, query: &[u8]) -> Result<Vec<u8>> {
    use std::net::UdpSocket;
    use std::time::Duration;

    with_host_network(host_netns, || {
        let socket = UdpSocket::bind("0.0.0.0:0").context("Failed to bind UDP socket for DNS")?;
        socket
            .set_read_timeout(Some(Duration::from_millis(600)))
            .context("Failed to set DNS read timeout")?;

        let upstream_targets = ["127.0.0.53:53", "1.1.1.1:53", "8.8.8.8:53"];
        for target in upstream_targets {
            if socket.send_to(query, target).is_ok() {
                let mut buf = [0u8; 4096];
                if let Ok((len, _)) = socket.recv_from(&mut buf) {
                    return Ok(buf[..len].to_vec());
                }
            }
        }

        Err(anyhow!("All upstream DNS resolvers timed out"))
    })
}

/// Linux-specific TAP Device Setup and IP/Route configuration
#[cfg(target_os = "linux")]
pub mod platform {
    use super::*;
    use std::fs::File;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::{AsRawFd, FromRawFd};
    use std::process::Command;
    use std::sync::OnceLock;

    fn ip_command() -> &'static str {
        static IP: OnceLock<String> = OnceLock::new();
        IP.get_or_init(|| {
            for candidate in ["/usr/sbin/ip", "/sbin/ip", "/bin/ip"] {
                if std::path::Path::new(candidate).exists() {
                    return candidate.to_string();
                }
            }
            "ip".to_string()
        })
    }

    const TUNSETIFF: libc::c_ulong = 0x400454ca;
    const TUNSETPERSIST: libc::c_ulong = 0x400454cb;
    const IFF_TAP: libc::c_short = 0x0002;
    const IFF_NO_PI: libc::c_short = 0x1000;

    #[repr(C)]
    struct Ifreq {
        ifr_name: [u8; 16],
        ifr_flags: libc::c_short,
        _padding: [u8; 22],
    }

    /// Open and configure TAP network interface inside the current network namespace
    pub fn create_tap_device(dev_name: &str) -> Result<File> {
        let tun_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open("/dev/net/tun")
            .context("Failed to open /dev/net/tun")?;

        let mut ifr = Ifreq {
            ifr_name: [0u8; 16],
            ifr_flags: IFF_TAP | IFF_NO_PI,
            _padding: [0u8; 22],
        };

        let bytes = dev_name.as_bytes();
        let len = bytes.len().min(15);
        ifr.ifr_name[..len].copy_from_slice(&bytes[..len]);

        let ret = unsafe { libc::ioctl(tun_file.as_raw_fd(), TUNSETIFF as _, &ifr) };
        if ret < 0 {
            return Err(std::io::Error::last_os_error())
                .context("Failed to create TAP device with TUNSETIFF");
        }

        Ok(tun_file)
    }

    fn run_ip(args: &[&str]) {
        use std::os::unix::process::CommandExt;
        use std::process::Stdio;
        let ip_bin = ip_command();
        let mut cmd = Command::new(ip_bin);
        cmd.args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        unsafe {
            cmd.pre_exec(|| {
                let _ = libc::setresgid(0, 0, 0);
                let _ = libc::setresuid(0, 0, 0);
                Ok(())
            });
        }
        let _ = cmd.status();
    }

    pub fn create_persistent_tap_device(dev_name: &str) -> Result<()> {
        let f = create_tap_device(dev_name)?;
        unsafe {
            let _ = libc::ioctl(f.as_raw_fd(), TUNSETPERSIST as _, 1);
        }
        Ok(())
    }

    pub fn destroy_tap_device(dev_name: &str) {
        if let Ok(f) = create_tap_device(dev_name) {
            unsafe {
                let _ = libc::ioctl(f.as_raw_fd(), TUNSETPERSIST as _, 0);
            }
            drop(f);
        }
        let ip_bin = ip_command();
        let _ = Command::new(ip_bin)
            .args(["link", "delete", dev_name])
            .output();
    }

    /// Configure IP address, netmask, MTU, and default gateway inside the container network namespace
    pub fn configure_container_netns(ifname: &str, ip: Ipv4Addr, gateway: Ipv4Addr) -> Result<()> {
        run_ip(&["link", "set", "lo", "up"]);
        let ip_cidr = format!("{}/24", ip);
        run_ip(&["addr", "add", &ip_cidr, "brd", "+", "dev", ifname]);
        run_ip(&["link", "set", ifname, "up"]);
        let gw_str = gateway.to_string();
        run_ip(&["route", "add", "default", "via", &gw_str, "dev", ifname]);
        Ok(())
    }

    /// Run the pure-Rust user-mode TAP network engine in the current process
    pub fn run_tap_network_loop(
        bundle_path: &Path,
        mut tap_file: File,
        ports: &[PortMapping],
        host_netns: Option<File>,
    ) {
        use std::io::{Read, Write};
        crate::network::usernet::relay::spawn_in_netns_peer_listener(bundle_path);
        let engine = UserNetEngine::new(Some(bundle_path), ports, host_netns);
        let mut buf = [0u8; 65536];
        let mut _dynamic_taps: Vec<File> = Vec::new();
        let mut synced_iface_count: usize = 1;

        loop {
            if let Ok(raw) = std::fs::read_to_string(bundle_path.join("network_interfaces.json")) {
                if let Ok(ifaces) = serde_json::from_str::<Vec<(String, String, String)>>(&raw) {
                    if ifaces.len() > synced_iface_count {
                        for (ifn, ip_str, _) in ifaces.iter().skip(synced_iface_count) {
                            if let Ok(tf) = create_tap_device(ifn) {
                                if !ip_str.is_empty() {
                                    let _ = Command::new("/sbin/ip")
                                        .args([
                                            "addr",
                                            "add",
                                            &format!("{}/24", ip_str),
                                            "brd",
                                            "+",
                                            "dev",
                                            ifn,
                                        ])
                                        .status()
                                        .or_else(|_| {
                                            Command::new("ip")
                                                .args([
                                                    "addr",
                                                    "add",
                                                    &format!("{}/24", ip_str),
                                                    "brd",
                                                    "+",
                                                    "dev",
                                                    ifn,
                                                ])
                                                .status()
                                        });
                                }
                                let _ = Command::new("/sbin/ip")
                                    .args(["link", "set", ifn, "up"])
                                    .status()
                                    .or_else(|_| {
                                        Command::new("ip").args(["link", "set", ifn, "up"]).status()
                                    });
                                _dynamic_taps.push(tf);
                            }
                        }
                        synced_iface_count = ifaces.len();
                    }
                }
            }
            // Wait for readability using poll() to eliminate busy polling
            let mut pollfd = libc::pollfd {
                fd: tap_file.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let poll_ret = unsafe { libc::poll(&mut pollfd, 1, 100) };
            if poll_ret < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                break;
            }

            match tap_file.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if let Some(reply) = engine.handle_incoming_frame(&buf[..n]) {
                        let _ = tap_file.write_all(&reply);
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // Handled by poll above; short yield
                    std::thread::yield_now();
                }
                Err(_) => break,
            }
        }
    }

    /// Spawn the pure-Rust user-mode TAP network engine on an active TAP device
    pub fn spawn_tap_network_stack(mut tap_file: File, ports: Vec<PortMapping>) -> Arc<AtomicBool> {
        let running = Arc::new(AtomicBool::new(true));
        let flag = running.clone();

        std::thread::spawn(move || {
            use std::io::{Read, Write};
            let engine = UserNetEngine::new(None, &ports, None);
            let mut buf = [0u8; 65536];

            while flag.load(std::sync::atomic::Ordering::Relaxed) {
                let mut pollfd = libc::pollfd {
                    fd: tap_file.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                let poll_ret = unsafe { libc::poll(&mut pollfd, 1, 100) };
                if poll_ret < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    break;
                }

                match tap_file.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if let Some(reply) = engine.handle_incoming_frame(&buf[..n]) {
                            let _ = tap_file.write_all(&reply);
                        }
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::yield_now();
                    }
                    Err(_) => break,
                }
            }
        });

        running
    }
}
