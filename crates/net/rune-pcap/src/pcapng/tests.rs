use super::*;

fn section(endian: Endian) -> (Vec<u8>, Encoder) {
    let mut out = Vec::new();
    let enc = Encoder::new(
        &SectionBuilder::new()
            .with_endian(endian)
            .with_hardware("hw")
            .with_os("os")
            .with_user_application("app")
            .with_comment("c1")
            .with_comment("c2"),
        &mut out,
    )
    .unwrap();
    (out, enc)
}

fn blocks(mut data: &[u8]) -> Vec<Block<'_>> {
    let mut endian = Endian::Little;
    let mut blocks = Vec::new();
    while !data.is_empty() {
        let (block, e, used) = Block::parse(data, endian).unwrap();
        endian = e;
        blocks.push(block);
        data = &data[used..];
    }
    blocks
}

#[test]
fn section_header_round_trip() {
    for endian in [Endian::Little, Endian::Big] {
        let (out, _) = section(endian);
        let [Block::SectionHeader(shb)] = blocks(&out)[..] else {
            panic!()
        };
        assert_eq!(shb.endian, endian);
        assert_eq!((shb.version_major, shb.version_minor), (1, 0));
        assert_eq!(shb.section_len, None);
        assert_eq!(shb.hardware(), Some("hw"));
        assert_eq!(shb.os(), Some("os"));
        assert_eq!(shb.user_application(), Some("app"));
        assert_eq!(shb.options.comments().collect::<Vec<_>>(), ["c1", "c2"]);
    }
}

#[test]
fn interface_and_packet_round_trip() {
    for endian in [Endian::Little, Endian::Big] {
        let (mut out, mut enc) = section(endian);
        let iface = InterfaceBuilder::new(LinkType::ETHERNET)
            .with_snaplen(96)
            .with_ts_resolution(TsResolution::Binary(20))
            .with_ts_offset(1_000)
            .with_name("eth0")
            .with_description("desc")
            .with_os("os")
            .with_hardware("nic")
            .with_filter("tcp port 443")
            .with_fcs_len(4)
            .with_speed(1_000_000_000)
            .with_option(opt::IF_MACADDR, &[2, 0, 0, 0, 0, 1])
            .with_comment("ifc");
        assert_eq!(enc.interface(&iface, &mut out).unwrap(), 0);
        assert_eq!(enc.interface_count(), 1);
        let ts = Timestamp::new(1_700_000_000, 500_000_000);
        let packet = EnhancedPacketBuilder::new(0, ts, b"hello")
            .with_original_len(1500)
            .with_flags(1)
            .with_drop_count(2)
            .with_packet_id(3)
            .with_queue(4)
            .with_comment("pc");
        enc.packet(&packet, &mut out).unwrap();
        let parsed = blocks(&out);
        let Block::InterfaceDescription(idb) = parsed[1] else {
            panic!()
        };
        assert_eq!(idb.link_type, LinkType::ETHERNET);
        assert_eq!(idb.snaplen, 96);
        assert_eq!(idb.ts_resolution(), TsResolution::Binary(20));
        assert_eq!(idb.ts_offset(), 1_000);
        assert_eq!(idb.name(), Some("eth0"));
        assert_eq!(idb.description(), Some("desc"));
        assert_eq!(idb.os(), Some("os"));
        assert_eq!(idb.hardware(), Some("nic"));
        assert_eq!(idb.filter(), Some((0, &b"tcp port 443"[..])));
        assert_eq!(idb.fcs_len(), Some(4));
        assert_eq!(idb.speed(), Some(1_000_000_000));
        assert_eq!(idb.mac_addr(), Some([2, 0, 0, 0, 0, 1]));
        let Block::EnhancedPacket(epb) = parsed[2] else {
            panic!()
        };
        assert_eq!(epb.interface_id, 0);
        assert_eq!(epb.data, b"hello");
        assert_eq!(epb.original_len, 1500);
        assert_eq!(epb.ticks, (1_699_999_000u64 << 20) + (1 << 19));
        assert_eq!(epb.timestamp(idb.ts_resolution(), idb.ts_offset()), ts);
        assert_eq!(epb.flags(), Some(1));
        assert_eq!(epb.drop_count(), Some(2));
        assert_eq!(epb.packet_id(), Some(3));
        assert_eq!(epb.queue(), Some(4));
        assert_eq!(epb.options.comments().next(), Some("pc"));
        assert_eq!(parsed[2].block_type(), BlockType::ENHANCED_PACKET);
    }
}

#[test]
fn encoder_rejects_bad_packets() {
    let (mut out, mut enc) = section(Endian::Little);
    let before = out.len();
    let ts = Timestamp::default();
    assert!(matches!(
        enc.packet(&EnhancedPacketBuilder::new(0, ts, b""), &mut out),
        Err(Error::UnknownInterface(0))
    ));
    enc.interface(&InterfaceBuilder::new(LinkType::RAW), &mut out)
        .unwrap();
    let before_packet = out.len();
    assert!(
        enc.packet(
            &EnhancedPacketBuilder::new(0, ts, b"ab").with_original_len(1),
            &mut out
        )
        .is_err()
    );
    let huge = EnhancedPacketBuilder::new(0, Timestamp::new(u64::MAX, 0), b"");
    assert!(matches!(
        enc.packet(&huge, &mut out),
        Err(Error::TimestampOutOfRange)
    ));
    let long = "x".repeat(70_000);
    assert!(matches!(
        enc.packet(
            &EnhancedPacketBuilder::new(0, ts, b"").with_comment(&long),
            &mut out
        ),
        Err(Error::TooLarge { .. })
    ));
    // Failed writes leave the buffer as it was.
    assert_eq!(out.len(), before_packet);
    assert!(before < before_packet);
    // A new section forgets the interfaces.
    enc.section(&SectionBuilder::new().with_endian(Endian::Big), &mut out)
        .unwrap();
    assert_eq!(enc.interface_count(), 0);
    assert_eq!(enc.endian(), Endian::Big);
}

#[test]
fn other_blocks() {
    let (mut out, enc) = section(Endian::Big);
    enc.decryption_secrets(
        DecryptionSecrets::TLS_KEY_LOG,
        b"CLIENT_RANDOM a b\n",
        &mut out,
    )
    .unwrap();
    enc.raw_block(BlockType::CUSTOM, &[0, 0, 0x7e, 0xd9, 1], &mut out)
        .unwrap();
    let parsed = blocks(&out);
    let Block::DecryptionSecrets(dsb) = parsed[1] else {
        panic!()
    };
    assert_eq!(dsb.secrets_type, DecryptionSecrets::TLS_KEY_LOG);
    assert_eq!(dsb.data, b"CLIENT_RANDOM a b\n");
    let Block::Other(raw) = parsed[2] else {
        panic!()
    };
    assert_eq!(raw.block_type, BlockType::CUSTOM);
    assert_eq!(raw.body, [0, 0, 0x7e, 0xd9, 1, 0, 0, 0]);
    assert_eq!(parsed[2].block_type().to_string(), "0x00000bad");
}

fn le_block(block_type: u32, body: &[u8]) -> Vec<u8> {
    let mut body = body.to_vec();
    body.resize(pad4(body.len()), 0);
    let len = u32::try_from(body.len() + 12).unwrap().to_le_bytes();
    [&block_type.to_le_bytes()[..], &len, &body, &len].concat()
}

#[test]
fn simple_and_obsolete_packets() {
    let mut body = 10u32.to_le_bytes().to_vec();
    body.extend_from_slice(b"0123456789");
    let spb = le_block(3, &body);
    let (Block::SimplePacket(p), _, _) = Block::parse(&spb, Endian::Little).unwrap() else {
        panic!()
    };
    assert_eq!(p.original_len, 10);
    assert_eq!(p.data.len(), 12);
    assert_eq!(p.packet(0), b"0123456789");
    assert_eq!(p.packet(4), b"0123");
    // Original length beyond the block: take what is there.
    let mut body = 100u32.to_le_bytes().to_vec();
    body.extend_from_slice(b"abcd");
    let spb = le_block(3, &body);
    let (Block::SimplePacket(p), _, _) = Block::parse(&spb, Endian::Little).unwrap() else {
        panic!()
    };
    assert_eq!(p.packet(0), b"abcd");

    let mut body = Vec::new();
    body.extend_from_slice(&1u16.to_le_bytes());
    body.extend_from_slice(&5u16.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&7u32.to_le_bytes());
    body.extend_from_slice(&3u32.to_le_bytes());
    body.extend_from_slice(&9u32.to_le_bytes());
    body.extend_from_slice(b"xyz\0");
    body.extend_from_slice(&[1, 0, 2, 0, b'h', b'i', 0, 0, 0, 0, 0, 0]);
    let pb = le_block(2, &body);
    let (Block::ObsoletePacket(p), _, _) = Block::parse(&pb, Endian::Little).unwrap() else {
        panic!()
    };
    assert_eq!((p.interface_id, p.drops_count, p.ticks), (1, 5, 7));
    assert_eq!((p.data, p.original_len), (&b"xyz"[..], 9));
    assert_eq!(p.options.comments().next(), Some("hi"));
}

#[test]
fn name_resolution_and_statistics() {
    let mut body = Vec::new();
    body.extend_from_slice(&[1, 0, 14, 0, 192, 0, 2, 1]);
    body.extend_from_slice(b"a.example\0\0\0");
    let mut v6 = vec![2, 0, 22, 0];
    v6.extend_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
    v6.extend_from_slice(b"b\0c\0\xff\0\0\0");
    body.extend_from_slice(&v6);
    body.extend_from_slice(&[0x99, 0, 2, 0, 0xaa, 0xbb, 0, 0]);
    body.extend_from_slice(&[0, 0, 0, 0]);
    body.extend_from_slice(&[1, 0, 1, 0, b'n', 0, 0, 0, 0, 0, 0, 0]);
    let nrb = le_block(4, &body);
    let (Block::NameResolution(n), _, _) = Block::parse(&nrb, Endian::Little).unwrap() else {
        panic!()
    };
    let records: Vec<_> = n.records.iter().collect();
    assert_eq!(records.len(), 3);
    assert_eq!(
        records[0].ip_addr(),
        Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
    );
    assert_eq!(records[0].names().collect::<Vec<_>>(), ["a.example"]);
    assert_eq!(records[1].ip_addr(), "2001:db8::1".parse().ok());
    assert_eq!(records[1].names().collect::<Vec<_>>(), ["b", "c"]);
    assert_eq!(records[2].ip_addr(), None);
    assert_eq!(records[2].names().count(), 0);
    assert_eq!(n.options.comments().next(), Some("n"));
    assert_eq!((&n.records).into_iter().count(), 3);

    // A record running past the block.
    let nrb = le_block(4, &[1, 0, 200, 0, 1, 2, 3, 4]);
    assert!(
        Block::parse(&nrb, Endian::Little)
            .unwrap_err()
            .is_truncated()
    );
    // No end-of-records marker.
    let nrb = le_block(4, &[1, 0, 4, 0, 1, 2, 3, 4]);
    assert!(
        Block::parse(&nrb, Endian::Little)
            .unwrap_err()
            .is_truncated()
    );

    let mut body = vec![2, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0];
    for (code, v) in [(4u16, 10u64), (5, 1), (6, 2), (7, 3), (8, 4)] {
        body.extend_from_slice(&code.to_le_bytes());
        body.extend_from_slice(&8u16.to_le_bytes());
        body.extend_from_slice(&v.to_le_bytes());
    }
    let isb = le_block(5, &body);
    let (Block::InterfaceStatistics(s), _, _) = Block::parse(&isb, Endian::Little).unwrap() else {
        panic!()
    };
    assert_eq!((s.interface_id, s.ticks), (2, 5));
    assert_eq!(s.received(), Some(10));
    assert_eq!(s.dropped(), Some(1));
    assert_eq!(s.filter_accepted(), Some(2));
    assert_eq!(s.os_dropped(), Some(3));
    assert_eq!(s.delivered(), Some(4));
}

#[test]
fn options_edge_cases() {
    let data = [
        1, 0, 3, 0, b'a', b'b', 0, 0, // comment "ab" with a trailing NUL
        9, 0, 2, 0, 1, 2, 0, 0, // wrong length for u8 / u32
        2, 0, 9, 0, 1, // runs past the end
    ];
    let options = Options::new(&data, Endian::Little);
    let all: Vec<_> = options.iter().collect();
    assert_eq!(all.len(), 3);
    assert!(all[2].as_ref().unwrap_err().is_truncated());
    assert_eq!(options.str(1), Some("ab"));
    assert_eq!(options.u8(9), None);
    assert_eq!(options.u32(9), None);
    assert_eq!(options.u64(9), None);
    assert_eq!(options.get(2), None);
    assert_eq!(options.as_bytes().len(), data.len());
    assert_eq!((&options).into_iter().count(), 3);
    assert_eq!(Options::empty().iter().count(), 0);
    // opt_endofopt stops the iteration even with bytes after it.
    let data = [0, 0, 0, 0, 1, 0, 1, 0, b'x', 0, 0, 0];
    assert_eq!(Options::new(&data, Endian::Little).iter().count(), 0);
    // Invalid UTF-8 comments are skipped.
    let data = [1, 0, 1, 0, 0xff, 0, 0, 0];
    assert_eq!(Options::new(&data, Endian::Little).comments().count(), 0);
}

#[test]
fn framing_errors() {
    let (out, _) = section(Endian::Little);
    // Truncated anywhere.
    for cut in 0..out.len() {
        assert!(
            Block::parse(&out[..cut], Endian::Little).is_err(),
            "cut {cut}"
        );
    }
    // Trailing length mismatch.
    let mut bad = out.clone();
    let n = bad.len();
    bad[n - 1] ^= 1;
    assert!(matches!(
        Block::parse(&bad, Endian::Little),
        Err(Error::Malformed { .. })
    ));
    // Bad byte-order magic.
    let mut bad = out.clone();
    bad[8] = 0;
    assert!(matches!(
        Block::parse(&bad, Endian::Little),
        Err(Error::Malformed { .. })
    ));
    // Length not a multiple of four, or too small.
    for len in [13u32, 8, 0] {
        let mut bad = le_block(0x99, &[]);
        bad[4..8].copy_from_slice(&len.to_le_bytes());
        assert!(Block::parse(&bad, Endian::Little).is_err(), "len {len}");
    }
    // Section version 2.
    let mut bad = out;
    bad[12] = 2;
    assert!(matches!(
        Block::parse(&bad, Endian::Little),
        Err(Error::UnsupportedVersion { major: 2, .. })
    ));
    // Bodies too short for their type.
    for ty in [1, 2, 3, 5, 6, 0x0a] {
        assert!(
            Block::parse(&le_block(ty, &[]), Endian::Little)
                .unwrap_err()
                .is_truncated()
        );
    }
    // Captured length past the block.
    let mut body = vec![0; 20];
    body[12..16].copy_from_slice(&100u32.to_le_bytes());
    assert!(
        Block::parse(&le_block(6, &body), Endian::Little)
            .unwrap_err()
            .is_truncated()
    );
}

#[test]
fn byte_order_follows_section() {
    let (mut out, _) = section(Endian::Big);
    let (mut le, _) = section(Endian::Little);
    out.append(&mut le);
    let (_, endian, used) = Block::parse(&out, Endian::Little).unwrap();
    assert_eq!(endian, Endian::Big);
    let (_, endian, _) = Block::parse(&out[used..], endian).unwrap();
    assert_eq!(endian, Endian::Little);
}
