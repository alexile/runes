# rune-pcap

> Streaming pcap and pcapng reader and writer with link-type aware dissection via rune-packet

[![crates.io](https://img.shields.io/crates/v/rune-pcap)](https://crates.io/crates/rune-pcap)
[![docs.rs](https://img.shields.io/docsrs/rune-pcap)](https://docs.rs/rune-pcap)
[![license](https://img.shields.io/crates/l/rune-pcap)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

A capture-file library for offline traffic analysis and for turning
captured (or crafted) traffic into test fixtures. It reads and writes
classic pcap and pcapng, streams records without loading the file, and
hands each frame to [`rune-packet`](../rune-packet) for dissection.

- **Classic pcap:** microsecond and nanosecond files in either byte order,
  FCS-length bits, and reading of the modified (Kuznetzov) variant.
  Rewriting a libpcap-written file reproduces it byte for byte.
- **pcapng:** multiple sections (each with its own byte order), interfaces
  with their own link types, snap lengths, timestamp resolutions
  (`if_tsresol`, decimal or binary) and offsets; Enhanced, Simple and
  obsolete Packet Blocks; Name Resolution, Interface Statistics and
  Decryption Secrets Blocks (e.g. TLS key logs); custom and unknown blocks
  kept raw. Options are read lazily with typed accessors (comments,
  `if_name`, `epb_flags`, `isb_ifdrop`, ...).
- **Streaming:** `CaptureReader` detects the format and reads from any
  `std::io::Read`, one record in memory at a time. Records and blocks are
  capped (16 MiB by default), so a hostile length field can't trigger a
  huge allocation.
- **Sans-I/O core:** `PcapHeader` and `pcapng::{Block, Encoder}` parse and
  encode on byte slices; the readers and writers are thin wrappers.
- **Link types:** `Record::dissect` understands Ethernet, raw IP
  (`RAW`/`IPV4`/`IPV6`), BSD/OpenBSD loopback and Linux cooked captures
  (SLL, SLL2).
- **No panics:** malformed or truncated input gives an `Error`. The
  readers are property-tested, and the test fixtures are read by tcpdump/libpcap
  as well.

## Installation

```toml
[dependencies]
rune-pcap = "0.1"
```

The `rune-pcap` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-pcap --features cli
```

## Usage

### Library

```rust
use rune_pcap::pcapng::{EnhancedPacketBuilder, InterfaceBuilder, SectionBuilder};
use rune_pcap::{CaptureReader, LinkType, PcapNgWriter, Timestamp, TsResolution};

// An IPv4/UDP datagram from 192.0.2.1:53 to 198.51.100.7:4242.
let ip = [
    0x45, 0, 0, 28, 0, 0, 0x40, 0, 64, 17, 0, 0, 192, 0, 2, 1, 198, 51, 100, 7,
    0, 53, 0x10, 0x92, 0, 8, 0, 0,
];

// Write a pcapng file with one raw-IP interface at nanosecond resolution.
let mut file = Vec::new();
let mut writer = PcapNgWriter::new(&mut file, &SectionBuilder::new())?;
let tun = writer.add_interface(
    &InterfaceBuilder::new(LinkType::RAW)
        .with_name("tun0")
        .with_ts_resolution(TsResolution::NANOS),
)?;
let ts = Timestamp::new(1_700_000_000, 123_456_789);
writer.write(&EnhancedPacketBuilder::new(tun, ts, &ip).with_comment("dns reply"))?;

// Stream it back (from a file, wrap it in a BufReader) and dissect.
let mut reader = CaptureReader::new(file.as_slice())?;
while let Some(record) = reader.next_packet()? {
    assert_eq!(record.timestamp, Some(ts));
    let packet = record.dissect().unwrap();
    assert_eq!(packet.transport.unwrap().src_port(), Some(53));
}
# Ok::<(), rune_pcap::Error>(())
```

For a fixture, `write_pcap(file, LinkType::ETHERNET, packets)` writes a
classic pcap from `(Timestamp, &[u8])` pairs in one call. For block-level
access (comments, statistics, name resolution, key logs) use
`PcapNgReader::next_block`.

### CLI

```bash
rune-pcap capture.pcapng -c 3
# # pcapng
# 1700000000.123456789 if0 81/81 192.0.2.1:40000 > 198.51.100.7:443 TCP
# 1700000001.000001000 if0 72/72 [2001:db8::1]:5353 > [2001:db8::2]:53 UDP
# 1700000002.500000000 if0 40/50 192.0.2.1 > 198.51.100.7 [IPv4 truncated: need 36 bytes, have 26]
```

Each line has the timestamp, interface, captured/original length and a
summary from `rune-packet`. `-` reads standard input.

## Specifications

pcap [draft-ietf-opsawg-pcap](https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcap/)
and [pcap-savefile(5)](https://www.tcpdump.org/manpages/pcap-savefile.5.html);
pcapng [draft-ietf-opsawg-pcapng](https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/);
the [link-layer header type registry](https://www.tcpdump.org/linktypes.html).

## License

MIT
