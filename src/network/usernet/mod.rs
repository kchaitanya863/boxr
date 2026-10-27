pub mod engine;
pub mod packets;
pub mod relay;

pub use engine::UserNetEngine;
pub use packets::*;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_ethernet_header_parse_and_write() {
        let header = EthernetHeader {
            dst_mac: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
            src_mac: [0x11, 0x12, 0x13, 0x14, 0x15, 0x16],
            ethertype: ETHERTYPE_IPV4,
        };
        let mut out = Vec::new();
        header.write_to(&mut out);
        assert_eq!(out.len(), 14);

        let (parsed, rest) = EthernetHeader::parse(&out).unwrap();
        assert_eq!(parsed, header);
        assert!(rest.is_empty());
    }

    #[test]
    fn test_arp_request_and_reply_cycle() {
        let engine = UserNetEngine::new(None, &[], None);
        let arp = ArpPacket {
            htype: 1,
            ptype: 0x0800,
            hlen: 6,
            plen: 4,
            opcode: 1,
            sender_mac: CONTAINER_MAC,
            sender_ip: DEFAULT_CONTAINER_IP,
            target_mac: [0; 6],
            target_ip: DEFAULT_GATEWAY_IP,
        };

        let mut arp_bytes = Vec::new();
        arp.write_request(&mut arp_bytes);

        let eth = EthernetHeader {
            dst_mac: [0xff; 6],
            src_mac: CONTAINER_MAC,
            ethertype: ETHERTYPE_ARP,
        };

        let mut frame = Vec::new();
        eth.write_to(&mut frame);
        frame.extend_from_slice(&arp_bytes);

        let reply = engine.handle_incoming_frame(&frame);
        assert!(reply.is_some());
        let reply_frame = reply.unwrap();

        let (r_eth, r_payload) = EthernetHeader::parse(&reply_frame).unwrap();
        assert_eq!(r_eth.dst_mac, CONTAINER_MAC);
        assert_eq!(r_eth.src_mac, VIRTUAL_GATEWAY_MAC);

        let r_arp = ArpPacket::parse(r_payload).unwrap();
        assert_eq!(r_arp.opcode, 2); // Reply
        assert_eq!(r_arp.sender_mac, VIRTUAL_GATEWAY_MAC);
        assert_eq!(r_arp.sender_ip, DEFAULT_GATEWAY_IP);
        assert_eq!(r_arp.target_ip, DEFAULT_CONTAINER_IP);
    }

    #[test]
    fn test_icmp_echo_ping_handling() {
        let engine = UserNetEngine::new(None, &[], None);
        let icmp_echo = [
            0x08, 0x00, // Type: 8 (Echo), Code: 0
            0xf7, 0xff, // Checksum placeholder
            0x00, 0x01, // Identifier
            0x00, 0x01, // Sequence
            0x61, 0x62, 0x63, 0x64, // Payload "abcd"
        ];

        let ip = Ipv4Header {
            ihl: 5,
            tos: 0,
            total_length: 20 + icmp_echo.len() as u16,
            id: 1,
            flags_and_frag: 0,
            ttl: 64,
            protocol: IP_PROTO_ICMP,
            checksum: 0,
            src_ip: DEFAULT_CONTAINER_IP,
            dst_ip: DEFAULT_GATEWAY_IP,
        };

        let eth = EthernetHeader {
            dst_mac: VIRTUAL_GATEWAY_MAC,
            src_mac: CONTAINER_MAC,
            ethertype: ETHERTYPE_IPV4,
        };

        let mut frame = Vec::new();
        eth.write_to(&mut frame);
        ip.write_to(&mut frame);
        frame.extend_from_slice(&icmp_echo);

        let reply = engine.handle_incoming_frame(&frame);
        assert!(reply.is_some());
        let reply_frame = reply.unwrap();

        let (r_eth, r_payload) = EthernetHeader::parse(&reply_frame).unwrap();
        assert_eq!(r_eth.dst_mac, CONTAINER_MAC);

        let (r_ip, r_icmp) = Ipv4Header::parse(r_payload).unwrap();
        assert_eq!(r_ip.protocol, IP_PROTO_ICMP);
        assert_eq!(r_ip.src_ip, DEFAULT_GATEWAY_IP);
        assert_eq!(r_ip.dst_ip, DEFAULT_CONTAINER_IP);

        assert_eq!(r_icmp[0], 0); // Type: 0 (Echo Reply)
        assert_eq!(r_icmp[1], 0); // Code: 0
        assert_eq!(&r_icmp[4..8], &icmp_echo[4..8]); // ID and Sequence match
    }

    #[test]
    fn test_usernet_tcp_syn_and_handshake() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let _ = listener.accept();
        });

        let bundle = std::env::temp_dir().join(format!("boxr-usernet-syn-{}", port));
        std::fs::create_dir_all(&bundle).unwrap();
        let _relay_pid = relay::spawn_host_relay(&bundle).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));

        let engine = UserNetEngine::new(Some(&bundle), &[], None);

        let tcp_syn = TcpHeader {
            src_port: 54321,
            dst_port: port,
            seq_num: 500,
            ack_num: 0,
            data_offset: 20,
            flags: 0x02, // SYN
            window_size: 65535,
            checksum: 0,
            urgent_ptr: 0,
        };

        let mut tcp_bytes = Vec::new();
        tcp_syn.write_to(&mut tcp_bytes);

        let ip = Ipv4Header {
            ihl: 5,
            tos: 0,
            total_length: 40,
            id: 1,
            flags_and_frag: 0,
            ttl: 64,
            protocol: IP_PROTO_TCP,
            checksum: 0,
            src_ip: DEFAULT_CONTAINER_IP,
            dst_ip: Ipv4Addr::new(127, 0, 0, 1),
        };

        let eth = EthernetHeader {
            dst_mac: VIRTUAL_GATEWAY_MAC,
            src_mac: CONTAINER_MAC,
            ethertype: ETHERTYPE_IPV4,
        };

        let mut frame = Vec::new();
        eth.write_to(&mut frame);
        ip.write_to(&mut frame);
        frame.extend_from_slice(&tcp_bytes);

        let reply = engine.handle_incoming_frame(&frame);
        assert!(
            reply.is_some(),
            "UserNetEngine must handle outbound TCP SYN"
        );
        let reply_frame = reply.unwrap();

        let (r_eth, r_payload) = EthernetHeader::parse(&reply_frame).unwrap();
        assert_eq!(r_eth.dst_mac, CONTAINER_MAC);

        let (r_ip, r_tcp_raw) = Ipv4Header::parse(r_payload).unwrap();
        assert_eq!(r_ip.protocol, IP_PROTO_TCP);
        let (r_tcp, _) = TcpHeader::parse(r_tcp_raw).unwrap();
        assert_eq!(r_tcp.src_port, port);
        assert_eq!(r_tcp.dst_port, 54321);
        assert_eq!(r_tcp.flags, 0x12); // SYN | ACK
        assert_eq!(r_tcp.ack_num, 501); // ACK = SEQ + 1
    }

    #[test]
    fn test_usernet_tcp_payload_forwarding() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 128];
                if let Ok(n) = stream.read(&mut buf) {
                    if n > 0 {
                        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n");
                    }
                }
            }
        });

        let bundle = std::env::temp_dir().join(format!("boxr-usernet-test-{}", port));
        std::fs::create_dir_all(&bundle).unwrap();
        let _relay_pid = relay::spawn_host_relay(&bundle).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));

        let engine = UserNetEngine::new(Some(&bundle), &[], None);

        let tcp_payload = b"GET / HTTP/1.1\r\n\r\n";
        let tcp_data = TcpHeader {
            src_port: 43210,
            dst_port: port,
            seq_num: 501,
            ack_num: 1001,
            data_offset: 20,
            flags: 0x18, // PSH | ACK
            window_size: 65535,
            checksum: 0,
            urgent_ptr: 0,
        };

        let mut tcp_bytes = Vec::new();
        tcp_data.write_to(&mut tcp_bytes);
        tcp_bytes.extend_from_slice(tcp_payload);

        let ip = Ipv4Header {
            ihl: 5,
            tos: 0,
            total_length: 20 + 20 + tcp_payload.len() as u16,
            id: 2,
            flags_and_frag: 0,
            ttl: 64,
            protocol: IP_PROTO_TCP,
            checksum: 0,
            src_ip: DEFAULT_CONTAINER_IP,
            dst_ip: Ipv4Addr::new(127, 0, 0, 1),
        };

        let eth = EthernetHeader {
            dst_mac: VIRTUAL_GATEWAY_MAC,
            src_mac: CONTAINER_MAC,
            ethertype: ETHERTYPE_IPV4,
        };

        let mut frame = Vec::new();
        eth.write_to(&mut frame);
        ip.write_to(&mut frame);
        frame.extend_from_slice(&tcp_bytes);

        let reply = engine.handle_incoming_frame(&frame);
        assert!(
            reply.is_some(),
            "UserNetEngine must reply with forwarded TCP response"
        );
        let reply_frame = reply.unwrap();

        let (r_eth, r_payload) = EthernetHeader::parse(&reply_frame).unwrap();
        assert_eq!(r_eth.dst_mac, CONTAINER_MAC);

        let (r_ip, r_tcp_raw) = Ipv4Header::parse(r_payload).unwrap();
        assert_eq!(r_ip.protocol, IP_PROTO_TCP);
        let (r_tcp, r_data) = TcpHeader::parse(r_tcp_raw).unwrap();
        assert_eq!(r_tcp.src_port, port);
        assert_eq!(r_tcp.dst_port, 43210);
        assert_eq!(r_tcp.flags, 0x18);
        assert!(r_data.starts_with(b"HTTP/1.1 200 OK"));
    }

    #[test]
    fn test_compute_checksum() {
        // Standard sample data
        let sample = [
            0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xac, 0x10,
            0x0a, 0x63, 0xac, 0x10, 0x0a, 0x0c,
        ];
        let csum = compute_checksum(&sample);
        assert_ne!(csum, 0);
    }
}
