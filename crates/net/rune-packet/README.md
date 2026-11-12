# rune-packet

> Zero-copy, sans-I/O Ethernet/802.1Q/ARP/IPv4/IPv6/TCP/UDP/ICMP parser and builder with checksums

[![crates.io](https://img.shields.io/crates/v/rune-packet)](https://crates.io/crates/rune-packet)
[![docs.rs](https://img.shields.io/docsrs/rune-packet)](https://docs.rs/rune-packet)
[![license](https://img.shields.io/crates/l/rune-packet)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

A packet-dissection library for offline traffic analysis, pcap tooling and
TCP/OS fingerprinting. It never opens a socket: give it bytes, get back
views that borrow from them.

- **Layers:** Ethernet II / IEEE 802.3, stacked 802.1Q / 802.1ad VLAN tags,
  ARP, IPv4 with options, IPv6 with extension headers (Hop-by-Hop, Routing,
  Fragment, Destination Options, AH, Mobility, HIP, Shim6), TCP with typed
  options (MSS, window scale, SACK, timestamps; others kept raw and in wire
  order), UDP, ICMP and ICMPv6.
- **Zero-copy:** options and payloads are sub-slices of the input; fixed
  header fields are decoded into plain struct fields.
- **Forgiving dissection:** `Packet::from_ethernet` and `Packet::from_ip`
  keep every layer they could parse and record the first problem, so a
  capture truncated by its snap length still yields its headers.
- **Checksums:** RFC 1071 Internet checksum (incremental), and the TCP, UDP
  and ICMPv6 pseudo-headers for IPv4 and IPv6.
- **Builders** for crafting test and probe packets. They fill in lengths,
  protocol numbers and checksums, and let you override any of them to make
  broken packets on purpose.
- **No panics:** malformed or truncated input gives an `Error`. The parsers
  are property-tested, and
  the builders' output is checked against tcpdump's checksum verification.

## Installation

```toml
[dependencies]
rune-packet = "0.1"
```

## Usage

```rust
use std::net::Ipv4Addr;
use rune_packet::{
    EthernetBuilder, Ipv4Builder, MacAddr, Packet, PacketBuilder, TcpBuilder, TcpFlags,
    TcpOption, Transport,
};

// Craft a TCP SYN in an Ethernet frame.
let frame = PacketBuilder::new()
    .ethernet(EthernetBuilder::new(MacAddr([2, 0, 0, 0, 0, 1]), MacAddr([2, 0, 0, 0, 0, 2])))
    .ipv4(Ipv4Builder::new(Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(198, 51, 100, 7)))
    .tcp(
        TcpBuilder::new(40_000, 443)
            .with_flags(TcpFlags::SYN)
            .with_option(&TcpOption::MaxSegmentSize(1460)),
    )
    .build()?;

// Dissect it.
let packet = Packet::from_ethernet(&frame);
assert!(packet.error.is_none());
assert_eq!(packet.transport_checksum_ok(), Some(true));
if let Some(Transport::Tcp(tcp)) = packet.transport {
    assert_eq!(tcp.flags, TcpFlags::SYN);
    assert_eq!(tcp.mss(), Some(1460));
}

// Per-layer parsers work on their own, too.
let ip = rune_packet::Ipv4Packet::parse(&frame[14..])?;
assert!(ip.verify_checksum());
# Ok::<(), rune_packet::Error>(())
```

IP fragments other than the first, ESP and unknown protocols stop at the IP
layer; their bytes are in `Packet::payload`. Reassembly is left to the
caller.

## Specifications

ARP [RFC 826](https://www.rfc-editor.org/rfc/rfc826), IPv4
[RFC 791](https://www.rfc-editor.org/rfc/rfc791), IPv6
[RFC 8200](https://www.rfc-editor.org/rfc/rfc8200), TCP
[RFC 9293](https://www.rfc-editor.org/rfc/rfc9293) (options:
[RFC 7323](https://www.rfc-editor.org/rfc/rfc7323),
[RFC 2018](https://www.rfc-editor.org/rfc/rfc2018)), UDP
[RFC 768](https://www.rfc-editor.org/rfc/rfc768), ICMP
[RFC 792](https://www.rfc-editor.org/rfc/rfc792), ICMPv6
[RFC 4443](https://www.rfc-editor.org/rfc/rfc4443), checksum
[RFC 1071](https://www.rfc-editor.org/rfc/rfc1071), IEEE 802.3 and 802.1Q.

## License

MIT
