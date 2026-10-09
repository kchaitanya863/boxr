use super::packets::*;
use crate::network::PortMapping;
use anyhow::{Context, Result, anyhow};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

pub struct UserNetEngine {
    pub container_ip: Ipv4Addr,
    pub gateway_ip: Ipv4Addr,
    pub dns_ip: Ipv4Addr,
    pub ports: Vec<PortMapping>,
    pub running: Arc<AtomicBool>,
}

impl UserNetEngine {
    pub fn new(ports: &[PortMapping]) -> Self {
        Self {
            container_ip: DEFAULT_CONTAINER_IP,
            gateway_ip: DEFAULT_GATEWAY_IP,
            dns_ip: DEFAULT_DNS_IP,
            ports: ports.to_vec(),
            running: Arc::new(AtomicBool::new(true)),
        }
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

        // If target IP is gateway or DNS, respond with our virtual gateway MAC
        if arp.target_ip == self.gateway_ip || arp.target_ip == self.dns_ip {
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
        let (tcp, _) = TcpHeader::parse(payload)?;

        // Intercept SYN: reply with SYN-ACK to establish TCP handshake with virtual gateway
        if (tcp.flags & 0x02) != 0 {
            let reply_seq = 1000u32;
            let reply_ack = tcp.seq_num.wrapping_add(1);

            let reply_tcp = TcpHeader {
                src_port: tcp.dst_port,
                dst_port: tcp.src_port,
                seq_num: reply_seq,
                ack_num: reply_ack,
                data_offset: 20,
                flags: 0x12, // SYN | ACK
                window_size: 65535,
                checksum: 0,
                urgent_ptr: 0,
            };

            let reply_ip = Ipv4Header {
                ihl: 5,
                tos: 0,
                total_length: 40,
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

            let mut tcp_bytes = Vec::with_capacity(20);
            reply_tcp.write_to(&mut tcp_bytes);

            let csum =
                compute_tcp_checksum(&reply_ip.src_ip, &reply_ip.dst_ip, IP_PROTO_TCP, &tcp_bytes);
            tcp_bytes[16..18].copy_from_slice(&csum.to_be_bytes());

            let mut out = Vec::with_capacity(14 + 20 + 20);
            reply_eth.write_to(&mut out);
            reply_ip.write_to(&mut out);
            out.extend_from_slice(&tcp_bytes);
            return Some(out);
        }

        // Intercept FIN: reply with FIN-ACK
        if (tcp.flags & 0x01) != 0 {
            let reply_tcp = TcpHeader {
                src_port: tcp.dst_port,
                dst_port: tcp.src_port,
                seq_num: tcp.ack_num,
                ack_num: tcp.seq_num.wrapping_add(1),
                data_offset: 20,
                flags: 0x11, // FIN | ACK
                window_size: 65535,
                checksum: 0,
                urgent_ptr: 0,
            };

            let reply_ip = Ipv4Header {
                ihl: 5,
                tos: 0,
                total_length: 40,
                id: ip.id.wrapping_add(1),
                flags_and_frag: 0,
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

            let mut tcp_bytes = Vec::with_capacity(20);
            reply_tcp.write_to(&mut tcp_bytes);
            let csum =
                compute_tcp_checksum(&reply_ip.src_ip, &reply_ip.dst_ip, IP_PROTO_TCP, &tcp_bytes);
            tcp_bytes[16..18].copy_from_slice(&csum.to_be_bytes());

            let mut out = Vec::with_capacity(14 + 40);
            reply_eth.write_to(&mut out);
            reply_ip.write_to(&mut out);
            out.extend_from_slice(&tcp_bytes);
            return Some(out);
        }

        // Forward outbound TCP data payload to host network and return response
        let (_, tcp_data) = TcpHeader::parse(payload)?;
        if !tcp_data.is_empty() {
            let target_addr =
                std::net::SocketAddr::V4(std::net::SocketAddrV4::new(ip.dst_ip, tcp.dst_port));
            if let Ok(mut stream) = std::net::TcpStream::connect_timeout(
                &target_addr,
                std::time::Duration::from_millis(500),
            ) {
                use std::io::{Read, Write};
                let _ = stream.write_all(tcp_data);
                let _ = stream.flush();
                let mut resp_buf = [0u8; 16384];
                let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(500)));
                if let Ok(n) = stream.read(&mut resp_buf) {
                    if n > 0 {
                        let response_data = &resp_buf[..n];
                        let reply_tcp = TcpHeader {
                            src_port: tcp.dst_port,
                            dst_port: tcp.src_port,
                            seq_num: tcp.ack_num,
                            ack_num: tcp.seq_num.wrapping_add(tcp_data.len() as u32),
                            data_offset: 20,
                            flags: 0x18, // PSH | ACK
                            window_size: 65535,
                            checksum: 0,
                            urgent_ptr: 0,
                        };

                        let reply_ip = Ipv4Header {
                            ihl: 5,
                            tos: 0,
                            total_length: (20 + 20 + response_data.len()) as u16,
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

                        let mut tcp_bytes = Vec::with_capacity(20 + response_data.len());
                        reply_tcp.write_to(&mut tcp_bytes);
                        tcp_bytes.extend_from_slice(response_data);

                        let csum = compute_tcp_checksum(
                            &reply_ip.src_ip,
                            &reply_ip.dst_ip,
                            IP_PROTO_TCP,
                            &tcp_bytes,
                        );
                        tcp_bytes[16..18].copy_from_slice(&csum.to_be_bytes());

                        let mut out = Vec::with_capacity(14 + 20 + tcp_bytes.len());
                        reply_eth.write_to(&mut out);
                        reply_ip.write_to(&mut out);
                        out.extend_from_slice(&tcp_bytes);
                        return Some(out);
                    }
                }
            }
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

        // Intercept DNS requests on port 53 sent to virtual gateway or DNS IP
        if (ip.dst_ip == self.gateway_ip || ip.dst_ip == self.dns_ip) && udp.dst_port == 53 {
            // Forward DNS query to host resolver
            if let Ok(dns_reply) = forward_dns_query(udp_payload) {
                return self.build_udp_reply(eth, ip, &udp, &dns_reply);
            }
        }

        // Generic UDP outbound forwarding to host network
        if ip.dst_ip != self.gateway_ip && ip.dst_ip != self.container_ip {
            if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
                let _ = socket.set_read_timeout(Some(std::time::Duration::from_millis(500)));
                let target = std::net::SocketAddr::V4(std::net::SocketAddrV4::new(ip.dst_ip, udp.dst_port));
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

/// Forward DNS query buffer to standard host DNS servers and await response
fn forward_dns_query(query: &[u8]) -> Result<Vec<u8>> {
    use std::net::UdpSocket;
    use std::time::Duration;

    let socket = UdpSocket::bind("0.0.0.0:0").context("Failed to bind UDP socket for DNS")?;
    socket
        .set_read_timeout(Some(Duration::from_millis(600)))
        .context("Failed to set DNS read timeout")?;

    // Try multiple standard upstream resolvers: local host resolver, Cloudflare, Google
    let upstream_targets = [
        "127.0.0.53:53",
        "192.168.64.1:53",
        "1.1.1.1:53",
        "8.8.8.8:53",
    ];
    for target in upstream_targets {
        if socket.send_to(query, target).is_ok() {
            let mut buf = [0u8; 4096];
            if let Ok((len, _)) = socket.recv_from(&mut buf) {
                return Ok(buf[..len].to_vec());
            }
        }
    }

    Err(anyhow!("All upstream DNS resolvers timed out"))
}

/// Linux-specific TAP Device Setup and IP/Route configuration
#[cfg(target_os = "linux")]
pub mod platform {
    use super::*;
    use std::fs::File;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::{AsRawFd, FromRawFd};
    use std::process::Command;

    const TUNSETIFF: libc::c_ulong = 0x400454ca;
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

    /// Configure IP address, netmask, MTU, and default gateway inside the container network namespace
    pub fn configure_container_netns(ifname: &str, ip: Ipv4Addr, gateway: Ipv4Addr) -> Result<()> {
        // Bring loopback up
        let _ = Command::new("ip")
            .args(["link", "set", "lo", "up"])
            .status();

        // Assign IP address to TAP device
        let ip_cidr = format!("{}/24", ip);
        let _ = Command::new("ip")
            .args(["addr", "add", &ip_cidr, "dev", ifname])
            .status();

        // Bring TAP interface up
        let _ = Command::new("ip")
            .args(["link", "set", ifname, "up"])
            .status();

        // Set default route via gateway
        let _ = Command::new("ip")
            .args([
                "route",
                "add",
                "default",
                "via",
                &gateway.to_string(),
                "dev",
                ifname,
            ])
            .status();

        Ok(())
    }

    /// Run the pure-Rust user-mode TAP network engine in the current process
    pub fn run_tap_network_loop(mut tap_file: File, ports: &[PortMapping]) {
        use std::io::{Read, Write};
        let engine = UserNetEngine::new(ports);
        let mut buf = [0u8; 65536];

        loop {
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
            let engine = UserNetEngine::new(&ports);
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
