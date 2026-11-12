//! Known-answer tests.
//!
//! Each frame below was produced by this crate's builders, written to a
//! pcap file, and checked with `tcpdump -nn -vv -e` (libpcap 1.10), which
//! verified every IPv4, TCP, UDP and `ICMPv6` checksum independently
//! ("cksum ... (correct)", "udp sum ok", "icmp6 sum ok"). The tests pin
//! both directions: the builders still produce these bytes, and the
//! parsers decode them to the fields tcpdump printed.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail loudly on bad fixtures"
)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rune_packet::{
    ArpBuilder, ArpOperation, Echo, EtherType, EthernetBuilder, IcmpBuilder, Icmpv6Type, IpPacket,
    IpProtocol, Ipv4Builder, Ipv6Builder, MacAddr, Packet, PacketBuilder, TcpBuilder, TcpFlags,
    TcpOption, Transport, UdpBuilder, VlanTag,
};

const VLAN_IPV4_TCP_SYN: &str = "0200000000020200000000018100602a08004500003f1c46400040063237c0000201c63364079c4001bb0102030400000000a002faf0badc0000020405b40402080a123456780000000001030307474554";
const IPV6_UDP: &str = "02000000000202000000000186dd620123450012114020010db800000000000000000000000120010db800000000000000000000000214e900350012c65368656c6c6f2c20756470";
const IPV6_HBH_ICMPV6_ECHO: &str = "02000000000202000000000186dd600000000015000120010db800000000000000000000000120010db80000000000000000000000023a000502000001008000507fbeef000370696e6736";
const IPV4_ICMP_ECHO: &str = "0200000000020200000000010800450000240007400040014e96c0000201c633640708005435123400016162636465666768";
const ARP_REQUEST: &str = "ffffffffffff02000000000108060001080006040001020000000001c0000201000000000000c00002fe000000000000000000000000000000000000";
const IPV4_OPTIONS_UDP: &str = "020000000002020000000001080046000021000040000111f88bc0000201c6336407940400000001000200099b9c78";

const A: MacAddr = MacAddr([0x02, 0, 0, 0, 0, 0x01]);
const B: MacAddr = MacAddr([0x02, 0, 0, 0, 0, 0x02]);
const V4A: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const V4B: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);

fn v6a() -> Ipv6Addr {
    "2001:db8::1".parse().unwrap()
}

fn v6b() -> Ipv6Addr {
    "2001:db8::2".parse().unwrap()
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Every checksum-bearing byte flip must be caught.
fn assert_corruption_detected(frame: &[u8], from: usize) {
    for i in from..frame.len() {
        let mut bad = frame.to_vec();
        bad[i] ^= 0x01;
        let packet = Packet::from_ethernet(&bad);
        let ok = packet.ip_checksum_ok() != Some(false)
            && packet.transport_checksum_ok() == Some(true)
            && packet.error.is_none();
        assert!(!ok, "flip at byte {i} went unnoticed");
    }
}

#[test]
fn vlan_ipv4_tcp_syn() {
    let frame = hex(VLAN_IPV4_TCP_SYN);
    let built = PacketBuilder::new()
        .ethernet(EthernetBuilder::new(A, B).with_vlan(VlanTag::new(42).with_pcp(3)))
        .ipv4(Ipv4Builder::new(V4A, V4B).with_identification(0x1c46))
        .tcp(
            TcpBuilder::new(40000, 443)
                .with_flags(TcpFlags::SYN)
                .with_seq(0x0102_0304)
                .with_window(64240)
                .with_option(&TcpOption::MaxSegmentSize(1460))
                .with_option(&TcpOption::SackPermitted)
                .with_option(&TcpOption::Timestamps {
                    value: 0x1234_5678,
                    echo_reply: 0,
                })
                .with_option(&TcpOption::Nop)
                .with_option(&TcpOption::WindowScale(7)),
        )
        .payload(b"GET")
        .build()
        .unwrap();
    assert_eq!(built, frame);

    let packet = Packet::from_ethernet(&frame);
    assert_eq!(packet.error, None);
    let eth = packet.ethernet.unwrap();
    assert_eq!((eth.src, eth.dst), (A, B));
    let tag = eth.vlan_tags().next().unwrap();
    assert_eq!((tag.vid, tag.pcp), (42, 3));
    let Some(IpPacket::V4(ip)) = packet.ip else {
        panic!("not IPv4")
    };
    assert_eq!(ip.identification, 7238);
    assert_eq!(ip.total_len, 63);
    assert!(ip.dont_fragment);
    assert_eq!(ip.checksum, 0x3237);
    let Some(Transport::Tcp(tcp)) = packet.transport else {
        panic!("not TCP")
    };
    assert_eq!(tcp.checksum, 0xbadc);
    assert_eq!(tcp.seq, 16_909_060);
    assert_eq!(tcp.window, 64240);
    let kinds: Vec<u8> = tcp.option_iter().map(|o| o.unwrap().kind()).collect();
    assert_eq!(kinds, [2, 4, 8, 1, 3]);
    assert_eq!(packet.payload, b"GET");
    assert_eq!(packet.ip_checksum_ok(), Some(true));
    assert_eq!(packet.transport_checksum_ok(), Some(true));
    assert_corruption_detected(&frame, 18);
}

#[test]
fn ipv6_udp() {
    let frame = hex(IPV6_UDP);
    let built = PacketBuilder::new()
        .ethernet(EthernetBuilder::new(A, B))
        .ipv6(
            Ipv6Builder::new(v6a(), v6b())
                .with_flow_label(0x12345)
                .with_traffic_class(0x20),
        )
        .udp(UdpBuilder::new(5353, 53))
        .payload(b"hello, udp")
        .build()
        .unwrap();
    assert_eq!(built, frame);

    let packet = Packet::from_ethernet(&frame);
    assert_eq!(packet.error, None);
    let Some(IpPacket::V6(ip)) = packet.ip else {
        panic!("not IPv6")
    };
    assert_eq!(ip.traffic_class, 0x20);
    assert_eq!(ip.flow_label, 0x12345);
    assert_eq!(ip.payload_len, 18);
    assert_eq!(packet.ip.unwrap().src(), IpAddr::V6(v6a()));
    let transport = packet.transport.unwrap();
    assert_eq!(transport.src_port(), Some(5353));
    assert_eq!(transport.dst_port(), Some(53));
    let Transport::Udp(udp) = transport else {
        panic!("not UDP")
    };
    assert_eq!(udp.checksum, 0xc653);
    assert_eq!(packet.payload, b"hello, udp");
    assert_eq!(packet.ip_checksum_ok(), None);
    assert_eq!(packet.transport_checksum_ok(), Some(true));
    // Addresses (in the pseudo-header) onwards are covered.
    assert_corruption_detected(&frame, 14 + 8);
}

#[test]
fn ipv6_hop_by_hop_icmpv6_echo() {
    let frame = hex(IPV6_HBH_ICMPV6_ECHO);
    let built = PacketBuilder::new()
        .ethernet(EthernetBuilder::new(A, B))
        .ipv6(
            Ipv6Builder::new(v6a(), v6b())
                .with_hop_limit(1)
                .with_extension(IpProtocol::HOPOPT, &[5, 2, 0, 0, 1, 0]),
        )
        .icmp(IcmpBuilder::echo_request_v6(Echo {
            identifier: 0xbeef,
            sequence: 3,
        }))
        .payload(b"ping6")
        .build()
        .unwrap();
    assert_eq!(built, frame);

    let packet = Packet::from_ethernet(&frame);
    assert_eq!(packet.error, None);
    let Some(IpPacket::V6(ip)) = packet.ip else {
        panic!("not IPv6")
    };
    assert_eq!(ip.next_header, IpProtocol::HOPOPT);
    assert_eq!(ip.upper_protocol, IpProtocol::ICMPV6);
    let ext: Vec<_> = ip.extension_headers().collect();
    assert_eq!(ext.len(), 1);
    assert_eq!(ext[0].body(), &[5, 2, 0, 0, 1, 0]);
    let Some(Transport::Icmpv6(icmp)) = packet.transport else {
        panic!("not ICMPv6")
    };
    assert_eq!(icmp.icmp_type, Icmpv6Type::ECHO_REQUEST);
    assert_eq!(icmp.checksum, 0x507f);
    assert_eq!(
        icmp.echo(),
        Some(Echo {
            identifier: 48879,
            sequence: 3
        })
    );
    assert_eq!(packet.payload, b"ping6");
    assert_eq!(packet.transport_checksum_ok(), Some(true));
}

#[test]
fn ipv4_icmp_echo() {
    let frame = hex(IPV4_ICMP_ECHO);
    let built = PacketBuilder::new()
        .ethernet(EthernetBuilder::new(A, B))
        .ipv4(Ipv4Builder::new(V4A, V4B).with_identification(7))
        .icmp(IcmpBuilder::echo_request_v4(Echo {
            identifier: 0x1234,
            sequence: 1,
        }))
        .payload(b"abcdefgh")
        .build()
        .unwrap();
    assert_eq!(built, frame);

    let packet = Packet::from_ethernet(&frame);
    assert_eq!(packet.error, None);
    let Some(Transport::Icmpv4(icmp)) = packet.transport else {
        panic!("not ICMP")
    };
    assert_eq!(icmp.checksum, 0x5435);
    assert_eq!(icmp.echo().unwrap().identifier, 4660);
    assert_eq!(packet.ip_checksum_ok(), Some(true));
    assert_eq!(packet.transport_checksum_ok(), Some(true));
    assert_corruption_detected(&frame, 14);
}

#[test]
fn arp_request_with_padding() {
    let frame = hex(ARP_REQUEST);
    let target = Ipv4Addr::new(192, 0, 2, 254);
    let built = PacketBuilder::new()
        .ethernet(EthernetBuilder::new(A, MacAddr::BROADCAST).with_padding(true))
        .arp(ArpBuilder::request(A, V4A, target))
        .build()
        .unwrap();
    assert_eq!(built, frame);
    assert_eq!(frame.len(), 60);

    let packet = Packet::from_ethernet(&frame);
    assert_eq!(packet.error, None);
    assert_eq!(packet.ethernet.unwrap().ethertype, EtherType::ARP);
    let arp = packet.arp.unwrap();
    assert_eq!(arp.operation, ArpOperation::REQUEST);
    assert_eq!(arp.sender_mac(), Some(A));
    assert_eq!(arp.sender_ipv4(), Some(V4A));
    assert_eq!(arp.target_ipv4(), Some(target));
    assert_eq!(packet.payload, &[0; 18]);
    assert!(packet.ip.is_none());
}

#[test]
fn ipv4_router_alert_option_udp() {
    let frame = hex(IPV4_OPTIONS_UDP);
    let built = PacketBuilder::new()
        .ethernet(EthernetBuilder::new(A, B))
        .ipv4(
            Ipv4Builder::new(V4A, V4B)
                .with_options(&[0x94, 0x04, 0, 0])
                .with_ttl(1),
        )
        .udp(UdpBuilder::new(1, 2))
        .payload(b"x")
        .build()
        .unwrap();
    assert_eq!(built, frame);

    let packet = Packet::from_ethernet(&frame);
    assert_eq!(packet.error, None);
    let Some(IpPacket::V4(ip)) = packet.ip else {
        panic!("not IPv4")
    };
    assert_eq!(ip.header_len(), 24);
    assert_eq!(ip.options, &[0x94, 0x04, 0, 0]);
    assert_eq!(ip.ttl, 1);
    assert_eq!(packet.payload, b"x");
    assert_eq!(packet.ip_checksum_ok(), Some(true));
    assert_eq!(packet.transport_checksum_ok(), Some(true));
    assert_corruption_detected(&frame, 14);
}

#[test]
fn raw_ip_link_type() {
    let frame = hex(IPV6_UDP);
    let packet = Packet::from_ip(&frame[14..]);
    assert!(packet.ethernet.is_none());
    assert_eq!(packet.payload, b"hello, udp");
    assert_eq!(packet.transport_checksum_ok(), Some(true));
}

#[test]
fn every_prefix_is_handled() {
    for fixture in [
        VLAN_IPV4_TCP_SYN,
        IPV6_UDP,
        IPV6_HBH_ICMPV6_ECHO,
        IPV4_ICMP_ECHO,
        IPV4_OPTIONS_UDP,
    ] {
        let frame = hex(fixture);
        for len in 0..frame.len() {
            let packet = Packet::from_ethernet(&frame[..len]);
            // A cut-short frame is always flagged as truncated, never as
            // malformed, and the checksum is never claimed to be valid.
            let err = packet.error.clone().expect("prefix must be flagged");
            assert!(err.is_truncated(), "{fixture} at {len}: {err}");
            assert_ne!(packet.transport_checksum_ok(), Some(true));
        }
    }
}

#[test]
fn fragments_stop_at_ip() {
    let first = PacketBuilder::new()
        .ipv4(
            Ipv4Builder::new(V4A, V4B)
                .with_fragmentation(false, false, 185)
                .with_protocol(IpProtocol::UDP),
        )
        .payload(&[0xaa; 16])
        .build()
        .unwrap();
    let packet = Packet::from_ip(&first);
    assert_eq!(packet.error, None);
    assert!(packet.transport.is_none());
    assert_eq!(packet.payload, &[0xaa; 16]);
    assert_eq!(packet.transport_checksum_ok(), None);

    let v6 = PacketBuilder::new()
        .ipv6(
            Ipv6Builder::new(v6a(), v6b()).with_fragment(rune_packet::Ipv6Fragment {
                offset: 0,
                more_fragments: true,
                identification: 9,
            }),
        )
        .tcp(TcpBuilder::new(1, 2))
        .payload(b"first")
        .build()
        .unwrap();
    let packet = Packet::from_ip(&v6);
    // First fragment: the transport header is there, its checksum is not
    // checkable without the rest of the datagram.
    assert!(matches!(packet.transport, Some(Transport::Tcp(_))));
    assert_eq!(packet.transport_checksum_ok(), None);
}

#[test]
fn builder_errors() {
    let no_ip = PacketBuilder::new().udp(UdpBuilder::new(1, 2)).build();
    assert!(no_ip.is_err());
    let no_protocol = PacketBuilder::new()
        .ipv4(Ipv4Builder::new(V4A, V4B))
        .build();
    assert!(no_protocol.is_err());
    let no_ethertype = PacketBuilder::new()
        .ethernet(EthernetBuilder::new(A, B))
        .build();
    assert!(no_ethertype.is_err());
    let bad_ext = PacketBuilder::new()
        .ipv6(Ipv6Builder::new(v6a(), v6b()).with_extension(IpProtocol::IPV6_OPTS, &[0; 5]))
        .udp(UdpBuilder::new(1, 2))
        .build();
    assert!(bad_ext.is_err());
    let long_options = PacketBuilder::new()
        .ipv4(Ipv4Builder::new(V4A, V4B))
        .tcp(TcpBuilder::new(1, 2).with_sack(&[(1, 2); 5]))
        .build();
    assert!(matches!(
        long_options,
        Err(rune_packet::Error::TooLarge { .. })
    ));
    let huge = PacketBuilder::new()
        .ipv4(Ipv4Builder::new(V4A, V4B))
        .udp(UdpBuilder::new(1, 2))
        .payload(&vec![0; 70_000])
        .build();
    assert!(matches!(huge, Err(rune_packet::Error::TooLarge { .. })));
    let arp_with_transport = PacketBuilder::new()
        .arp(ArpBuilder::request(A, V4A, V4B))
        .tcp(TcpBuilder::new(1, 2))
        .build();
    assert!(arp_with_transport.is_err());
}

#[test]
fn checksum_overrides_are_detected() {
    let frame = PacketBuilder::new()
        .ipv4(Ipv4Builder::new(V4A, V4B).with_checksum(0xdead))
        .tcp(TcpBuilder::new(1, 2).with_checksum(0xbeef))
        .build()
        .unwrap();
    let packet = Packet::from_ip(&frame);
    assert_eq!(packet.ip_checksum_ok(), Some(false));
    assert_eq!(packet.transport_checksum_ok(), Some(false));
}
