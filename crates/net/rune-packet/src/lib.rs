//! Zero-copy, sans-I/O packet dissection and crafting.
//!
//! `rune-packet` parses Ethernet II / IEEE 802.3 frames with stacked
//! 802.1Q / 802.1ad VLAN tags, ARP, IPv4 (with options), IPv6 (walking its
//! extension headers), TCP (with typed options), UDP, ICMP and `ICMPv6`. It
//! does no I/O: hand it bytes from a capture file, a raw socket or a test,
//! and it hands back views that borrow from them.
//!
//! - **Per-layer parsers** such as [`Ipv4Packet::parse`] and
//!   [`TcpSegment::parse`] return views whose headers are decoded into
//!   plain fields and whose options and payloads are sub-slices of the
//!   input.
//! - **[`Packet`]** dissects a whole frame layer by layer. It never fails:
//!   it keeps every layer it could parse and records the first problem in
//!   [`Packet::error`], so truncated captures (snap length) still yield
//!   their headers.
//! - **Checksums.** [`Checksum`] and [`internet_checksum`] implement
//!   RFC 1071, and [`PseudoHeader`] covers the TCP, UDP and `ICMPv6`
//!   pseudo-headers for both IP versions.
//! - **Builders** ([`PacketBuilder`] and one builder per layer) craft
//!   packets for tests and probes, filling in lengths, protocol numbers and
//!   checksums unless told otherwise.
//!
//! Malformed or truncated input gives an [`Error`], never a panic.
//!
//! Specifications: Ethernet / VLAN [IEEE 802.3](https://standards.ieee.org/ieee/802.3/10422/),
//! [IEEE 802.1Q](https://standards.ieee.org/ieee/802.1Q/10323/); ARP
//! [RFC 826](https://www.rfc-editor.org/rfc/rfc826); IPv4
//! [RFC 791](https://www.rfc-editor.org/rfc/rfc791); IPv6
//! [RFC 8200](https://www.rfc-editor.org/rfc/rfc8200); TCP
//! [RFC 9293](https://www.rfc-editor.org/rfc/rfc9293) with options from
//! [RFC 7323](https://www.rfc-editor.org/rfc/rfc7323) and
//! [RFC 2018](https://www.rfc-editor.org/rfc/rfc2018); UDP
//! [RFC 768](https://www.rfc-editor.org/rfc/rfc768); ICMP
//! [RFC 792](https://www.rfc-editor.org/rfc/rfc792); `ICMPv6`
//! [RFC 4443](https://www.rfc-editor.org/rfc/rfc4443); checksum
//! [RFC 1071](https://www.rfc-editor.org/rfc/rfc1071).
//!
//! # Example
//!
//! ```
//! use std::net::Ipv4Addr;
//! use rune_packet::{
//!     EthernetBuilder, Ipv4Builder, MacAddr, Packet, PacketBuilder, TcpBuilder, TcpFlags,
//!     TcpOption, Transport, VlanTag,
//! };
//!
//! // Craft a VLAN-tagged TCP SYN.
//! let frame = PacketBuilder::new()
//!     .ethernet(
//!         EthernetBuilder::new(MacAddr([2, 0, 0, 0, 0, 1]), MacAddr([2, 0, 0, 0, 0, 2]))
//!             .with_vlan(VlanTag::new(42)),
//!     )
//!     .ipv4(Ipv4Builder::new(Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(198, 51, 100, 7)))
//!     .tcp(
//!         TcpBuilder::new(40_000, 443)
//!             .with_flags(TcpFlags::SYN)
//!             .with_seq(1)
//!             .with_option(&TcpOption::MaxSegmentSize(1460))
//!             .with_option(&TcpOption::SackPermitted),
//!     )
//!     .build()?;
//!
//! // Dissect it again.
//! let packet = Packet::from_ethernet(&frame);
//! assert!(packet.error.is_none());
//! assert_eq!(packet.ethernet.unwrap().vlan_tags().next(), Some(VlanTag::new(42)));
//! assert_eq!(packet.ip.unwrap().ttl(), 64);
//! assert_eq!(packet.ip_checksum_ok(), Some(true));
//! assert_eq!(packet.transport_checksum_ok(), Some(true));
//! let Some(Transport::Tcp(tcp)) = packet.transport else { unreachable!() };
//! assert_eq!(tcp.flags, TcpFlags::SYN);
//! assert_eq!(tcp.mss(), Some(1460));
//!
//! // A capture cut short keeps the headers it has and flags the truncation.
//! let cut = Packet::from_ethernet(&frame[..40]);
//! assert!(cut.ip.is_some());
//! assert!(cut.error.unwrap().is_truncated());
//! # Ok::<(), rune_packet::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod arp;
mod builder;
mod checksum;
mod dissect;
mod error;
mod ethernet;
mod icmp;
mod ip;
mod ipv4;
mod ipv6;
mod tcp;
mod udp;

pub use arp::{ARP_HARDWARE_ETHERNET, ArpOperation, ArpPacket};
pub use builder::{
    ArpBuilder, EthernetBuilder, IcmpBuilder, Ipv4Builder, Ipv6Builder, PacketBuilder, TcpBuilder,
    UdpBuilder,
};
pub use checksum::{Checksum, PseudoHeader, internet_checksum};
pub use dissect::{IpPacket, Packet, Transport};
pub use error::{Error, Layer};
pub use ethernet::{EtherType, EthernetFrame, MacAddr, VlanTag, VlanTags};
pub use icmp::{Echo, Icmpv4Packet, Icmpv4Type, Icmpv6Packet, Icmpv6Type};
pub use ip::IpProtocol;
pub use ipv4::Ipv4Packet;
pub use ipv6::{ExtensionHeader, ExtensionHeaders, Ipv6Fragment, Ipv6Packet};
pub use tcp::{SackBlocks, TcpFlags, TcpOption, TcpOptions, TcpSegment};
pub use udp::UdpDatagram;
