//! Reading capture files written by other tools.
//!
//! - `le-nanos.pcapng` and `be-micros-two-sections.pcapng` were written by
//!   `fixtures/make_pcapng.py`, a pcapng writer independent of this crate.
//!   They hold four frames from `rune-packet`'s known-answer tests (a
//!   VLAN-tagged TCP SYN, IPv6/UDP, an ICMP echo cut to 40 of 50 bytes and
//!   an ARP request), interleaved with Name Resolution, Decryption Secrets,
//!   custom and Interface Statistics blocks. The second file is
//!   big-endian, at microsecond resolution, with the section repeated.
//! - `libpcap-micros.pcap` and `libpcap-nanos.pcap` were written by
//!   libpcap 1.10.6 (`tcpdump [--time-stamp-precision=nano] -r
//!   le-nanos.pcapng -w …`).
//!
//! tcpdump 4.99.6 reads all four; the expectations below are what it
//! printed with `-nn -tt -vv --time-stamp-precision=nano`.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers fail loudly on bad fixtures"
)]

use std::net::IpAddr;

use rune_packet::Transport;
use rune_pcap::pcapng::{Block, DecryptionSecrets};
use rune_pcap::{
    CaptureReader, Endian, Format, LinkType, PcapHeader, PcapNgReader, PcapWriter, Precision,
    Timestamp, TsResolution,
};

const LE_NANOS: &[u8] = include_bytes!("fixtures/le-nanos.pcapng");
const BE_MICROS: &[u8] = include_bytes!("fixtures/be-micros-two-sections.pcapng");
const LIBPCAP_MICROS: &[u8] = include_bytes!("fixtures/libpcap-micros.pcap");
const LIBPCAP_NANOS: &[u8] = include_bytes!("fixtures/libpcap-nanos.pcap");

/// What tcpdump printed for each packet: timestamp, captured and
/// original length.
const EXPECTED: [(u64, u32, usize, u32); 4] = [
    (1_700_000_000, 123_456_789, 81, 81),
    (1_700_000_001, 1_000, 72, 72),
    (1_700_000_002, 500_000_000, 40, 50),
    (1_700_000_003, 0, 60, 60),
];

fn check_packets(file: &[u8], format: Format, nanos: bool, repeats: usize) {
    let mut reader = CaptureReader::new(file).unwrap();
    assert_eq!(reader.format(), format);
    let mut seen = 0;
    while let Some(rec) = reader.next_packet().unwrap() {
        let (secs, ns, caplen, orig) = EXPECTED[seen % 4];
        let ns = if nanos { ns } else { ns / 1_000 * 1_000 };
        assert_eq!(
            rec.timestamp,
            Some(Timestamp::new(secs, ns)),
            "packet {seen}"
        );
        assert_eq!((rec.data.len(), rec.original_len), (caplen, orig));
        assert_eq!(rec.link_type, LinkType::ETHERNET);
        let packet = rec.dissect().unwrap();
        match seen % 4 {
            0 => {
                // 192.0.2.1.40000 > 198.51.100.7.443: Flags [S], cksum 0xbadc (correct)
                assert!(packet.error.is_none());
                let eth = packet.ethernet.unwrap();
                assert_eq!(eth.vlan_tags().next().map(|t| t.vid), Some(42));
                let ip = packet.ip.unwrap();
                assert_eq!(ip.src(), "192.0.2.1".parse::<IpAddr>().unwrap());
                assert_eq!(ip.dst(), "198.51.100.7".parse::<IpAddr>().unwrap());
                let Some(Transport::Tcp(tcp)) = packet.transport else {
                    panic!()
                };
                assert_eq!(
                    (tcp.src_port, tcp.dst_port, tcp.mss()),
                    (40_000, 443, Some(1460))
                );
                assert_eq!(packet.transport_checksum_ok(), Some(true));
            }
            1 => {
                // 2001:db8::1.5353 > 2001:db8::2.53: [udp sum ok]
                let ip = packet.ip.unwrap();
                assert_eq!(ip.src(), "2001:db8::1".parse::<IpAddr>().unwrap());
                assert_eq!(packet.transport.unwrap().dst_port(), Some(53));
                assert_eq!(packet.transport_checksum_ok(), Some(true));
            }
            2 => {
                // 192.0.2.1 > 198.51.100.7: [|icmp] (cut by the snap length)
                assert!(rec.is_truncated());
                assert!(packet.ip.unwrap().is_truncated());
                assert!(packet.error.as_ref().unwrap().is_truncated());
                assert_eq!(packet.ip_checksum_ok(), Some(true));
            }
            _ => {
                // ARP, Request who-has 192.0.2.254 tell 192.0.2.1
                let arp = packet.arp.unwrap();
                assert_eq!(arp.sender_ipv4().unwrap().to_string(), "192.0.2.1");
                assert_eq!(arp.target_ipv4().unwrap().to_string(), "192.0.2.254");
            }
        }
        seen += 1;
    }
    assert_eq!(seen, 4 * repeats);
}

#[test]
fn reads_pcapng_little_endian_nanos() {
    check_packets(LE_NANOS, Format::PcapNg, true, 1);
}

#[test]
fn reads_pcapng_big_endian_two_sections() {
    check_packets(BE_MICROS, Format::PcapNg, false, 2);
}

#[test]
fn reads_libpcap_files() {
    check_packets(LIBPCAP_MICROS, Format::Pcap, false, 1);
    check_packets(LIBPCAP_NANOS, Format::Pcap, true, 1);
    let header = PcapHeader::parse(LIBPCAP_NANOS).unwrap();
    assert_eq!(header.precision, Precision::Nanos);
    assert_eq!(header.snaplen, 262_144);
    assert_eq!(header.link_type, LinkType::ETHERNET);
}

#[test]
fn rewriting_libpcap_files_is_byte_exact() {
    for file in [LIBPCAP_MICROS, LIBPCAP_NANOS] {
        let header = PcapHeader::parse(file).unwrap();
        let mut writer = PcapWriter::new(Vec::new(), header).unwrap();
        let mut reader = CaptureReader::new(file).unwrap();
        while let Some(rec) = reader.next_packet().unwrap() {
            writer
                .write_truncated(rec.timestamp.unwrap(), rec.data, rec.original_len)
                .unwrap();
        }
        assert_eq!(writer.into_inner(), file);
    }
}

#[test]
fn pcapng_blocks_and_options() {
    for (file, endian, resolution) in [
        (LE_NANOS, Endian::Little, TsResolution::NANOS),
        (BE_MICROS, Endian::Big, TsResolution::MICROS),
    ] {
        let mut reader = PcapNgReader::new(file);
        let mut kinds = String::new();
        while let Some(block) = reader.next_block().unwrap() {
            match block {
                Block::SectionHeader(shb) => {
                    kinds.push('S');
                    assert_eq!(shb.endian, endian);
                    assert_eq!(shb.hardware(), Some("x86_64"));
                    assert_eq!(shb.os(), Some("Linux 6.1"));
                    assert_eq!(shb.user_application(), Some("rune-pcap fixture generator"));
                    assert!(
                        shb.options
                            .comments()
                            .next()
                            .unwrap()
                            .starts_with("section ")
                    );
                }
                Block::InterfaceDescription(idb) => {
                    kinds.push('I');
                    assert_eq!(idb.name(), Some("eth0"));
                    assert_eq!(idb.description(), Some("test interface"));
                    assert_eq!(idb.os(), Some("Linux 6.1"));
                    assert_eq!(idb.snaplen, 262_144);
                    assert_eq!(idb.ts_resolution(), resolution);
                }
                Block::NameResolution(nrb) => {
                    kinds.push('N');
                    let record = nrb.records.iter().next().unwrap();
                    assert_eq!(record.ip_addr(), "192.0.2.1".parse().ok());
                    assert_eq!(record.names().collect::<Vec<_>>(), ["client.example"]);
                    assert_eq!(nrb.options.comments().next(), Some("names"));
                }
                Block::EnhancedPacket(epb) => {
                    kinds.push('E');
                    if epb.options.comments().next() == Some("tcp syn") {
                        assert_eq!(epb.flags(), Some(1));
                    }
                    if epb.data.len() == 60 {
                        assert_eq!(epb.drop_count(), Some(7));
                    }
                }
                Block::DecryptionSecrets(dsb) => {
                    kinds.push('D');
                    assert_eq!(dsb.secrets_type, DecryptionSecrets::TLS_KEY_LOG);
                    assert_eq!(dsb.data, b"CLIENT_RANDOM 00 11 22 33 4\n");
                }
                Block::InterfaceStatistics(isb) => {
                    kinds.push('T');
                    assert_eq!((isb.received(), isb.dropped()), (Some(4), Some(0)));
                }
                Block::Other(raw) => {
                    kinds.push('C');
                    assert_eq!(raw.block_type.0, 0xbad);
                    assert_eq!(&raw.body[4..], b"rune");
                }
                other => panic!("unexpected {other:?}"),
            }
        }
        let one = "SINEDECEET";
        let expect = if endian == Endian::Big {
            one.repeat(2)
        } else {
            one.to_owned()
        };
        assert_eq!(kinds, expect);
    }
}
