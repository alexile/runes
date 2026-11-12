//! Property tests: built packets dissect back to what was built, with
//! valid checksums, and no input makes a parser panic.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail loudly on bad fixtures"
)]

use std::net::{Ipv4Addr, Ipv6Addr};

use proptest::prelude::*;
use rune_packet::{
    ArpPacket, Checksum, Echo, EthernetBuilder, EthernetFrame, IcmpBuilder, Icmpv4Packet,
    Icmpv6Packet, IpPacket, Ipv4Builder, Ipv4Packet, Ipv6Builder, Ipv6Packet, MacAddr, Packet,
    PacketBuilder, TcpBuilder, TcpFlags, TcpOption, TcpSegment, Transport, UdpBuilder, UdpDatagram,
    VlanTag, internet_checksum,
};

#[derive(Debug, Clone)]
enum L4 {
    Tcp {
        seq: u32,
        ack: u32,
        flags: u16,
        window: u16,
        mss: Option<u16>,
        wscale: Option<u8>,
    },
    Udp,
    Icmp(u16, u16),
}

#[derive(Debug, Clone)]
struct Spec {
    vlans: Vec<u16>,
    v6: bool,
    v4: (u32, u32, u8, u16),
    v6_addrs: (u128, u128, u32),
    ports: (u16, u16),
    l4: L4,
    payload: Vec<u8>,
}

fn l4() -> impl Strategy<Value = L4> {
    prop_oneof![
        (
            any::<u32>(),
            any::<u32>(),
            0u16..0x200,
            any::<u16>(),
            proptest::option::of(any::<u16>()),
            proptest::option::of(any::<u8>()),
        )
            .prop_map(|(seq, ack, flags, window, mss, wscale)| L4::Tcp {
                seq,
                ack,
                flags,
                window,
                mss,
                wscale
            }),
        Just(L4::Udp),
        (any::<u16>(), any::<u16>()).prop_map(|(i, s)| L4::Icmp(i, s)),
    ]
}

fn spec() -> impl Strategy<Value = Spec> {
    (
        proptest::collection::vec(0u16..4096, 0..3),
        any::<bool>(),
        (any::<u32>(), any::<u32>(), any::<u8>(), any::<u16>()),
        (any::<u128>(), any::<u128>(), 0u32..0x10_0000),
        (any::<u16>(), any::<u16>()),
        l4(),
        proptest::collection::vec(any::<u8>(), 0..300),
    )
        .prop_map(|(vlans, v6, v4, v6_addrs, ports, l4, payload)| Spec {
            vlans,
            v6,
            v4,
            v6_addrs,
            ports,
            l4,
            payload,
        })
}

fn build(spec: &Spec) -> Vec<u8> {
    let mut eth = EthernetBuilder::new(MacAddr([2, 0, 0, 0, 0, 1]), MacAddr([2, 0, 0, 0, 0, 2]));
    for vid in &spec.vlans {
        eth = eth.with_vlan(VlanTag::new(*vid));
    }
    let mut b = PacketBuilder::new().ethernet(eth);
    b = if spec.v6 {
        let (src, dst, flow) = spec.v6_addrs;
        b.ipv6(Ipv6Builder::new(Ipv6Addr::from(src), Ipv6Addr::from(dst)).with_flow_label(flow))
    } else {
        let (src, dst, ttl, id) = spec.v4;
        b.ipv4(
            Ipv4Builder::new(Ipv4Addr::from(src), Ipv4Addr::from(dst))
                .with_ttl(ttl)
                .with_identification(id),
        )
    };
    let (sp, dp) = spec.ports;
    b = match &spec.l4 {
        L4::Tcp {
            seq,
            ack,
            flags,
            window,
            mss,
            wscale,
        } => {
            let mut tcp = TcpBuilder::new(sp, dp)
                .with_seq(*seq)
                .with_ack(*ack)
                .with_flags(TcpFlags(*flags))
                .with_window(*window);
            if let Some(mss) = mss {
                tcp = tcp.with_option(&TcpOption::MaxSegmentSize(*mss));
            }
            if let Some(shift) = wscale {
                tcp = tcp.with_option(&TcpOption::WindowScale(*shift));
            }
            b.tcp(tcp)
        }
        L4::Udp => b.udp(UdpBuilder::new(sp, dp)),
        L4::Icmp(identifier, sequence) => {
            let echo = Echo {
                identifier: *identifier,
                sequence: *sequence,
            };
            b.icmp(if spec.v6 {
                IcmpBuilder::echo_request_v6(echo)
            } else {
                IcmpBuilder::echo_request_v4(echo)
            })
        }
    };
    b.payload(&spec.payload).build().unwrap()
}

fn within(outer: &[u8], inner: &[u8]) -> bool {
    let start = outer.as_ptr() as usize;
    let inner_start = inner.as_ptr() as usize;
    inner.is_empty() || (inner_start >= start && inner_start + inner.len() <= start + outer.len())
}

fn exercise(data: &[u8]) {
    let _ = EthernetFrame::parse(data).map(|f| f.vlan_tags().count());
    let _ = ArpPacket::parse(data).map(|a| (a.sender_mac(), a.sender_ipv4()));
    if let Ok(ip) = Ipv4Packet::parse_partial(data) {
        assert!(within(data, ip.payload));
        let _ = ip.verify_checksum();
    }
    if let Ok(ip) = Ipv6Packet::parse_partial(data) {
        assert!(within(data, ip.payload));
        assert!(ip.header_len() + ip.payload.len() <= data.len());
        let _ = ip.extension_headers().count();
    }
    if let Ok(tcp) = TcpSegment::parse(data) {
        let _ = tcp.option_iter().count();
        let _ = (tcp.mss(), tcp.window_scale());
    }
    let _ = UdpDatagram::parse_partial(data);
    let _ = Icmpv4Packet::parse(data).map(|i| (i.echo(), i.next_hop_mtu(), i.gateway()));
    let _ = Icmpv6Packet::parse(data).map(|i| (i.echo(), i.mtu()));
    for packet in [Packet::from_ethernet(data), Packet::from_ip(data)] {
        assert!(within(data, packet.payload));
        let _ = (packet.ip_checksum_ok(), packet.transport_checksum_ok());
    }
}

proptest! {
    #[test]
    fn built_packets_dissect_back(spec in spec()) {
        let frame = build(&spec);
        let packet = Packet::from_ethernet(&frame);
        prop_assert_eq!(&packet.error, &None);
        let eth = packet.ethernet.unwrap();
        let vids: Vec<u16> = eth.vlan_tags().map(|t| t.vid).collect();
        prop_assert_eq!(vids, spec.vlans);
        let ip = packet.ip.unwrap();
        match ip {
            IpPacket::V4(v4) => {
                prop_assert!(!spec.v6);
                prop_assert_eq!(u32::from(v4.src), spec.v4.0);
                prop_assert_eq!(v4.ttl, spec.v4.2);
                prop_assert_eq!(v4.identification, spec.v4.3);
            }
            IpPacket::V6(v6) => {
                prop_assert!(spec.v6);
                prop_assert_eq!(u128::from(v6.dst), spec.v6_addrs.1);
                prop_assert_eq!(v6.flow_label, spec.v6_addrs.2);
            }
            _ => prop_assert!(false),
        }
        prop_assert_eq!(packet.ip_checksum_ok(), (!spec.v6).then_some(true));
        prop_assert_eq!(packet.transport_checksum_ok(), Some(true));
        prop_assert_eq!(packet.payload, &spec.payload[..]);
        match (&spec.l4, packet.transport.unwrap()) {
            (L4::Tcp { seq, ack, flags, window, mss, wscale }, Transport::Tcp(tcp)) => {
                prop_assert_eq!(tcp.seq, *seq);
                prop_assert_eq!(tcp.ack, *ack);
                prop_assert_eq!(tcp.flags, TcpFlags(*flags));
                prop_assert_eq!(tcp.window, *window);
                prop_assert_eq!(tcp.mss(), *mss);
                prop_assert_eq!(tcp.window_scale(), *wscale);
                prop_assert_eq!((tcp.src_port, tcp.dst_port), spec.ports);
            }
            (L4::Udp, Transport::Udp(udp)) => {
                prop_assert_eq!((udp.src_port, udp.dst_port), spec.ports);
            }
            (L4::Icmp(i, s), Transport::Icmpv4(icmp)) => {
                prop_assert_eq!(icmp.echo(), Some(Echo { identifier: *i, sequence: *s }));
            }
            (L4::Icmp(i, s), Transport::Icmpv6(icmp)) => {
                prop_assert_eq!(icmp.echo(), Some(Echo { identifier: *i, sequence: *s }));
            }
            (l4, t) => prop_assert!(false, "{l4:?} vs {t:?}"),
        }
    }

    #[test]
    fn prefixes_are_truncated_not_malformed(spec in spec(), cut in any::<prop::sample::Index>()) {
        let frame = build(&spec);
        let len = cut.index(frame.len());
        let packet = Packet::from_ethernet(&frame[..len]);
        let err = packet.error.clone().unwrap();
        prop_assert!(err.is_truncated(), "{}", err);
        prop_assert_ne!(packet.transport_checksum_ok(), Some(true));
        exercise(&frame[..len]);
    }

    #[test]
    fn never_panics(data in proptest::collection::vec(any::<u8>(), 0..200)) {
        exercise(&data);
    }

    #[test]
    fn never_panics_behind_valid_headers(spec in spec(), noise in proptest::collection::vec(any::<u8>(), 0..80), at in any::<prop::sample::Index>()) {
        // Overwrite part of a valid frame, so the fuzzing reaches deep layers.
        let mut frame = build(&spec);
        let start = at.index(frame.len());
        for (i, byte) in noise.iter().enumerate() {
            if let Some(slot) = frame.get_mut(start + i) {
                *slot = *byte;
            }
        }
        exercise(&frame);
    }

    #[test]
    fn checksum_is_split_invariant(data in proptest::collection::vec(any::<u8>(), 0..500), cuts in proptest::collection::vec(any::<prop::sample::Index>(), 0..5)) {
        let mut points: Vec<usize> = cuts.iter().map(|c| c.index(data.len() + 1)).collect();
        points.sort_unstable();
        let mut sum = Checksum::new();
        let mut last = 0;
        for p in points {
            sum.add_bytes(&data[last..p]);
            last = p;
        }
        sum.add_bytes(&data[last..]);
        prop_assert_eq!(sum.finish(), internet_checksum(&data));
    }
}
