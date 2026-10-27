use std::net::Ipv4Addr;

pub const DEFAULT_CONTAINER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 15);
pub const DEFAULT_GATEWAY_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 2);
pub const DEFAULT_DNS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 3);
pub const VIRTUAL_GATEWAY_MAC: [u8; 6] = [0x02, 0x00, 0x0a, 0x00, 0x02, 0x02];
pub const CONTAINER_MAC: [u8; 6] = [0x02, 0x42, 0x0a, 0x00, 0x02, 0x0f];

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;

pub const IP_PROTO_ICMP: u8 = 1;
pub const IP_PROTO_TCP: u8 = 6;
pub const IP_PROTO_UDP: u8 = 17;

/// Ethernet Frame Header (14 bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthernetHeader {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ethertype: u16,
}

impl EthernetHeader {
    pub fn parse(buf: &[u8]) -> Option<(Self, &[u8])> {
        if buf.len() < 14 {
            return None;
        }
        let mut dst_mac = [0u8; 6];
        let mut src_mac = [0u8; 6];
        dst_mac.copy_from_slice(&buf[0..6]);
        src_mac.copy_from_slice(&buf[6..12]);
        let ethertype = u16::from_be_bytes([buf[12], buf[13]]);
        Some((
            Self {
                dst_mac,
                src_mac,
                ethertype,
            },
            &buf[14..],
        ))
    }

    pub fn write_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.dst_mac);
        out.extend_from_slice(&self.src_mac);
        out.extend_from_slice(&self.ethertype.to_be_bytes());
    }
}

/// ARP Packet Representation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArpPacket {
    pub htype: u16,
    pub ptype: u16,
    pub hlen: u8,
    pub plen: u8,
    pub opcode: u16, // 1 = Request, 2 = Reply
    pub sender_mac: [u8; 6],
    pub sender_ip: Ipv4Addr,
    pub target_mac: [u8; 6],
    pub target_ip: Ipv4Addr,
}

impl ArpPacket {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 28 {
            return None;
        }
        let htype = u16::from_be_bytes([buf[0], buf[1]]);
        let ptype = u16::from_be_bytes([buf[2], buf[3]]);
        let hlen = buf[4];
        let plen = buf[5];
        let opcode = u16::from_be_bytes([buf[6], buf[7]]);

        let mut sender_mac = [0u8; 6];
        sender_mac.copy_from_slice(&buf[8..14]);
        let sender_ip = Ipv4Addr::new(buf[14], buf[15], buf[16], buf[17]);

        let mut target_mac = [0u8; 6];
        target_mac.copy_from_slice(&buf[18..24]);
        let target_ip = Ipv4Addr::new(buf[24], buf[25], buf[26], buf[27]);

        Some(Self {
            htype,
            ptype,
            hlen,
            plen,
            opcode,
            sender_mac,
            sender_ip,
            target_mac,
            target_ip,
        })
    }

    pub fn write_request(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.htype.to_be_bytes());
        out.extend_from_slice(&self.ptype.to_be_bytes());
        out.push(self.hlen);
        out.push(self.plen);
        out.extend_from_slice(&1u16.to_be_bytes()); // Opcode: Request
        out.extend_from_slice(&self.sender_mac);
        out.extend_from_slice(&self.sender_ip.octets());
        out.extend_from_slice(&self.target_mac);
        out.extend_from_slice(&self.target_ip.octets());
    }

    pub fn write_reply(&self, reply_mac: [u8; 6], out: &mut Vec<u8>) {
        out.extend_from_slice(&self.htype.to_be_bytes());
        out.extend_from_slice(&self.ptype.to_be_bytes());
        out.push(self.hlen);
        out.push(self.plen);
        out.extend_from_slice(&2u16.to_be_bytes()); // Opcode: Reply
        out.extend_from_slice(&reply_mac); // Sender is now virtual gateway
        out.extend_from_slice(&self.target_ip.octets());
        out.extend_from_slice(&self.sender_mac); // Target is container
        out.extend_from_slice(&self.sender_ip.octets());
    }
}

/// IPv4 Header
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Header {
    pub ihl: u8,
    pub tos: u8,
    pub total_length: u16,
    pub id: u16,
    pub flags_and_frag: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
}

impl Ipv4Header {
    pub fn parse(buf: &[u8]) -> Option<(Self, &[u8])> {
        if buf.len() < 20 {
            return None;
        }
        let ver_ihl = buf[0];
        let ver = ver_ihl >> 4;
        let ihl = ver_ihl & 0x0f;
        if ver != 4 || ihl < 5 {
            return None;
        }
        let header_len = (ihl as usize) * 4;
        if buf.len() < header_len {
            return None;
        }

        let tos = buf[1];
        let total_length = u16::from_be_bytes([buf[2], buf[3]]);
        let id = u16::from_be_bytes([buf[4], buf[5]]);
        let flags_and_frag = u16::from_be_bytes([buf[6], buf[7]]);
        let ttl = buf[8];
        let protocol = buf[9];
        let checksum = u16::from_be_bytes([buf[10], buf[11]]);
        let src_ip = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
        let dst_ip = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);

        let payload_len = (total_length as usize).saturating_sub(header_len);
        let end = (header_len + payload_len).min(buf.len());

        Some((
            Self {
                ihl,
                tos,
                total_length,
                id,
                flags_and_frag,
                ttl,
                protocol,
                checksum,
                src_ip,
                dst_ip,
            },
            &buf[header_len..end],
        ))
    }

    pub fn write_to(&self, out: &mut Vec<u8>) {
        let start = out.len();
        out.push((4 << 4) | (self.ihl & 0x0f));
        out.push(self.tos);
        out.extend_from_slice(&self.total_length.to_be_bytes());
        out.extend_from_slice(&self.id.to_be_bytes());
        out.extend_from_slice(&self.flags_and_frag.to_be_bytes());
        out.push(self.ttl);
        out.push(self.protocol);
        out.extend_from_slice(&0u16.to_be_bytes()); // Checksum placeholder
        out.extend_from_slice(&self.src_ip.octets());
        out.extend_from_slice(&self.dst_ip.octets());

        // Calculate checksum
        let csum = compute_checksum(&out[start..start + (self.ihl as usize * 4)]);
        out[start + 10..start + 12].copy_from_slice(&csum.to_be_bytes());
    }
}

/// UDP Header
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

impl UdpHeader {
    pub fn parse(buf: &[u8]) -> Option<(Self, &[u8])> {
        if buf.len() < 8 {
            return None;
        }
        let src_port = u16::from_be_bytes([buf[0], buf[1]]);
        let dst_port = u16::from_be_bytes([buf[2], buf[3]]);
        let length = u16::from_be_bytes([buf[4], buf[5]]);
        let checksum = u16::from_be_bytes([buf[6], buf[7]]);
        let payload_len = (length as usize).saturating_sub(8);
        let end = (8 + payload_len).min(buf.len());
        Some((
            Self {
                src_port,
                dst_port,
                length,
                checksum,
            },
            &buf[8..end],
        ))
    }

    pub fn write_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.src_port.to_be_bytes());
        out.extend_from_slice(&self.dst_port.to_be_bytes());
        out.extend_from_slice(&self.length.to_be_bytes());
        out.extend_from_slice(&self.checksum.to_be_bytes());
    }
}

/// TCP Header (minimum 20 bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    pub data_offset: u8,
    pub flags: u16,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
}

impl TcpHeader {
    pub fn parse(buf: &[u8]) -> Option<(Self, &[u8])> {
        if buf.len() < 20 {
            return None;
        }
        let src_port = u16::from_be_bytes([buf[0], buf[1]]);
        let dst_port = u16::from_be_bytes([buf[2], buf[3]]);
        let seq_num = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let ack_num = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let data_offset = (buf[12] >> 4) * 4;
        // TCP control flags live in the low 6 bits of byte 13 (FIN/SYN/RST/PSH/ACK/URG).
        let flags = buf[13] as u16;
        let window_size = u16::from_be_bytes([buf[14], buf[15]]);
        let checksum = u16::from_be_bytes([buf[16], buf[17]]);
        let urgent_ptr = u16::from_be_bytes([buf[18], buf[19]]);

        if (data_offset as usize) < 20 || buf.len() < data_offset as usize {
            return None;
        }

        Some((
            Self {
                src_port,
                dst_port,
                seq_num,
                ack_num,
                data_offset,
                flags,
                window_size,
                checksum,
                urgent_ptr,
            },
            &buf[data_offset as usize..],
        ))
    }

    pub fn write_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.src_port.to_be_bytes());
        out.extend_from_slice(&self.dst_port.to_be_bytes());
        out.extend_from_slice(&self.seq_num.to_be_bytes());
        out.extend_from_slice(&self.ack_num.to_be_bytes());
        out.push((self.data_offset / 4) << 4);
        out.push((self.flags & 0xff) as u8);
        out.extend_from_slice(&self.window_size.to_be_bytes());
        out.extend_from_slice(&self.checksum.to_be_bytes());
        out.extend_from_slice(&self.urgent_ptr.to_be_bytes());
    }
}

/// Compute TCP checksum over IPv4 pseudo header and TCP segment
pub fn compute_tcp_checksum(
    src_ip: &Ipv4Addr,
    dst_ip: &Ipv4Addr,
    proto: u8,
    tcp_segment: &[u8],
) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + tcp_segment.len());
    pseudo.extend_from_slice(&src_ip.octets());
    pseudo.extend_from_slice(&dst_ip.octets());
    pseudo.push(0);
    pseudo.push(proto);
    pseudo.extend_from_slice(&(tcp_segment.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(tcp_segment);
    compute_checksum(&pseudo)
}

/// Standard Internet Checksum computation (RFC 1071)
pub fn compute_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        let word = u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        sum += word;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while (sum >> 16) > 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
