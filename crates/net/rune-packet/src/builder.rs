//! Builders for crafting packets, mostly for tests and probes.
//!
//! Each layer has its own builder; [`PacketBuilder`] stacks them and
//! fills in what depends on the layers around it: `EtherType`, IP protocol,
//! lengths and checksums. Every derived field can be overridden to craft
//! deliberately broken packets.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::arp::{ARP_HARDWARE_ETHERNET, ArpOperation};
use crate::checksum::{PseudoHeader, internet_checksum};
use crate::error::{Error, Layer};
use crate::ethernet::{EtherType, MacAddr, VlanTag};
use crate::icmp::{Echo, Icmpv4Type, Icmpv6Type};
use crate::ip::IpProtocol;
use crate::ipv6::Ipv6Fragment;
use crate::tcp::{TcpFlags, TcpOption};

/// Smallest Ethernet frame without FCS.
const MIN_FRAME_LEN: usize = 60;

const fn too_large(layer: Layer, len: usize, max: usize) -> Error {
    Error::TooLarge { layer, len, max }
}

fn u16_len(layer: Layer, len: usize) -> Result<u16, Error> {
    u16::try_from(len).map_err(|_| too_large(layer, len, usize::from(u16::MAX)))
}

/// Ethernet header builder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthernetBuilder {
    src: MacAddr,
    dst: MacAddr,
    vlan_tags: Vec<VlanTag>,
    ethertype: Option<EtherType>,
    pad: bool,
}

impl EthernetBuilder {
    /// A frame from `src` to `dst`.
    #[must_use]
    pub const fn new(src: MacAddr, dst: MacAddr) -> Self {
        Self {
            src,
            dst,
            vlan_tags: Vec::new(),
            ethertype: None,
            pad: false,
        }
    }

    /// Add a VLAN tag (outermost first).
    #[must_use]
    pub fn with_vlan(mut self, tag: VlanTag) -> Self {
        self.vlan_tags.push(tag);
        self
    }

    /// Set the `EtherType` instead of deriving it from the next layer.
    #[must_use]
    pub const fn with_ethertype(mut self, ethertype: EtherType) -> Self {
        self.ethertype = Some(ethertype);
        self
    }

    /// Pad the frame with zeros to the 60-byte Ethernet minimum.
    #[must_use]
    pub const fn with_padding(mut self, pad: bool) -> Self {
        self.pad = pad;
        self
    }

    fn write(&self, ethertype: Option<EtherType>, body: &[u8]) -> Result<Vec<u8>, Error> {
        let ethertype = self
            .ethertype
            .or(ethertype)
            .ok_or_else(|| Error::malformed(Layer::Ethernet, "no EtherType for payload"))?;
        let mut out = Vec::with_capacity(14 + 4 * self.vlan_tags.len() + body.len());
        out.extend_from_slice(&self.dst.0);
        out.extend_from_slice(&self.src.0);
        for tag in &self.vlan_tags {
            out.extend_from_slice(&tag.tpid.0.to_be_bytes());
            out.extend_from_slice(&tag.tci().to_be_bytes());
        }
        out.extend_from_slice(&ethertype.0.to_be_bytes());
        out.extend_from_slice(body);
        if self.pad && out.len() < MIN_FRAME_LEN {
            out.resize(MIN_FRAME_LEN, 0);
        }
        Ok(out)
    }
}

/// Ethernet/IPv4 ARP packet builder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArpBuilder {
    operation: ArpOperation,
    sender_mac: MacAddr,
    sender_ip: Ipv4Addr,
    target_mac: MacAddr,
    target_ip: Ipv4Addr,
}

impl ArpBuilder {
    /// "Who has `target_ip`? Tell `sender_ip`."
    #[must_use]
    pub const fn request(sender_mac: MacAddr, sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Self {
        Self {
            operation: ArpOperation::REQUEST,
            sender_mac,
            sender_ip,
            target_mac: MacAddr::ZERO,
            target_ip,
        }
    }

    /// "`sender_ip` is at `sender_mac`", sent to the requester.
    #[must_use]
    pub const fn reply(
        sender_mac: MacAddr,
        sender_ip: Ipv4Addr,
        target_mac: MacAddr,
        target_ip: Ipv4Addr,
    ) -> Self {
        Self {
            operation: ArpOperation::REPLY,
            sender_mac,
            sender_ip,
            target_mac,
            target_ip,
        }
    }

    /// Use another operation code.
    #[must_use]
    pub const fn with_operation(mut self, operation: ArpOperation) -> Self {
        self.operation = operation;
        self
    }

    fn write(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(28);
        out.extend_from_slice(&ARP_HARDWARE_ETHERNET.to_be_bytes());
        out.extend_from_slice(&EtherType::IPV4.0.to_be_bytes());
        out.extend_from_slice(&[6, 4]);
        out.extend_from_slice(&self.operation.0.to_be_bytes());
        out.extend_from_slice(&self.sender_mac.0);
        out.extend_from_slice(&self.sender_ip.octets());
        out.extend_from_slice(&self.target_mac.0);
        out.extend_from_slice(&self.target_ip.octets());
        out
    }
}

/// IPv4 header builder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Builder {
    src: Ipv4Addr,
    dst: Ipv4Addr,
    ttl: u8,
    dscp: u8,
    ecn: u8,
    identification: u16,
    dont_fragment: bool,
    more_fragments: bool,
    fragment_offset: u16,
    options: Vec<u8>,
    protocol: Option<IpProtocol>,
    checksum: Option<u16>,
}

impl Ipv4Builder {
    /// A packet from `src` to `dst`, TTL 64, don't-fragment set.
    #[must_use]
    pub const fn new(src: Ipv4Addr, dst: Ipv4Addr) -> Self {
        Self {
            src,
            dst,
            ttl: 64,
            dscp: 0,
            ecn: 0,
            identification: 0,
            dont_fragment: true,
            more_fragments: false,
            fragment_offset: 0,
            options: Vec::new(),
            protocol: None,
            checksum: None,
        }
    }

    /// Time to live.
    #[must_use]
    pub const fn with_ttl(mut self, ttl: u8) -> Self {
        self.ttl = ttl;
        self
    }

    /// DSCP (masked to 6 bits) and ECN (masked to 2 bits).
    #[must_use]
    pub const fn with_tos(mut self, dscp: u8, ecn: u8) -> Self {
        self.dscp = dscp & 0x3f;
        self.ecn = ecn & 0x03;
        self
    }

    /// Identification.
    #[must_use]
    pub const fn with_identification(mut self, identification: u16) -> Self {
        self.identification = identification;
        self
    }

    /// Fragmentation fields; `offset` is in 8-byte units (masked to 13
    /// bits).
    #[must_use]
    pub const fn with_fragmentation(
        mut self,
        dont_fragment: bool,
        more_fragments: bool,
        offset: u16,
    ) -> Self {
        self.dont_fragment = dont_fragment;
        self.more_fragments = more_fragments;
        self.fragment_offset = offset & 0x1fff;
        self
    }

    /// Raw options, padded with zeros (End of Options) to 4 bytes.
    #[must_use]
    pub fn with_options(mut self, options: &[u8]) -> Self {
        options.clone_into(&mut self.options);
        self
    }

    /// Protocol number, instead of deriving it from the transport layer.
    #[must_use]
    pub const fn with_protocol(mut self, protocol: IpProtocol) -> Self {
        self.protocol = Some(protocol);
        self
    }

    /// Store this header checksum instead of the correct one.
    #[must_use]
    pub const fn with_checksum(mut self, checksum: u16) -> Self {
        self.checksum = Some(checksum);
        self
    }

    fn write(&self, protocol: Option<IpProtocol>, body: &[u8]) -> Result<Vec<u8>, Error> {
        let protocol = self
            .protocol
            .or(protocol)
            .ok_or_else(|| Error::malformed(Layer::Ipv4, "no protocol for payload"))?;
        let options_len = self.options.len().div_ceil(4) * 4;
        if options_len > 40 {
            return Err(too_large(Layer::Ipv4, self.options.len(), 40));
        }
        let header_len = 20 + options_len;
        let total = u16_len(Layer::Ipv4, header_len + body.len())?;
        let flags = (u16::from(self.dont_fragment) << 14)
            | (u16::from(self.more_fragments) << 13)
            | self.fragment_offset;
        let mut out = Vec::with_capacity(header_len + body.len());
        #[allow(clippy::cast_possible_truncation, reason = "at most 15 words")]
        out.push(0x40 | (header_len / 4) as u8);
        out.push((self.dscp << 2) | self.ecn);
        out.extend_from_slice(&total.to_be_bytes());
        out.extend_from_slice(&self.identification.to_be_bytes());
        out.extend_from_slice(&flags.to_be_bytes());
        out.extend_from_slice(&[self.ttl, protocol.0, 0, 0]);
        out.extend_from_slice(&self.src.octets());
        out.extend_from_slice(&self.dst.octets());
        out.extend_from_slice(&self.options);
        out.resize(header_len, 0);
        let checksum = self.checksum.unwrap_or_else(|| internet_checksum(&out));
        out[10..12].copy_from_slice(&checksum.to_be_bytes());
        out.extend_from_slice(body);
        Ok(out)
    }

    const fn pseudo_header(&self) -> PseudoHeader {
        PseudoHeader::V4 {
            src: self.src,
            dst: self.dst,
        }
    }
}

/// IPv6 header builder, with optional extension headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6Builder {
    src: Ipv6Addr,
    dst: Ipv6Addr,
    hop_limit: u8,
    traffic_class: u8,
    flow_label: u32,
    extensions: Vec<(IpProtocol, Vec<u8>)>,
    next_header: Option<IpProtocol>,
}

impl Ipv6Builder {
    /// A packet from `src` to `dst`, hop limit 64.
    #[must_use]
    pub const fn new(src: Ipv6Addr, dst: Ipv6Addr) -> Self {
        Self {
            src,
            dst,
            hop_limit: 64,
            traffic_class: 0,
            flow_label: 0,
            extensions: Vec::new(),
            next_header: None,
        }
    }

    /// Hop limit.
    #[must_use]
    pub const fn with_hop_limit(mut self, hop_limit: u8) -> Self {
        self.hop_limit = hop_limit;
        self
    }

    /// Traffic class.
    #[must_use]
    pub const fn with_traffic_class(mut self, traffic_class: u8) -> Self {
        self.traffic_class = traffic_class;
        self
    }

    /// Flow label (masked to 20 bits).
    #[must_use]
    pub const fn with_flow_label(mut self, flow_label: u32) -> Self {
        self.flow_label = flow_label & 0x000f_ffff;
        self
    }

    /// Append an extension header of type `kind`. `body` is everything
    /// after its next-header and length bytes; the whole header must come
    /// to a multiple of 8 bytes (4 for AH, exactly 8 for Fragment), which
    /// [`PacketBuilder::build`] checks.
    #[must_use]
    pub fn with_extension(mut self, kind: IpProtocol, body: &[u8]) -> Self {
        self.extensions.push((kind, body.to_vec()));
        self
    }

    /// Append a Fragment header.
    #[must_use]
    pub fn with_fragment(self, fragment: Ipv6Fragment) -> Self {
        self.with_extension(IpProtocol::IPV6_FRAG, &fragment.encode_body())
    }

    /// Next header after the extension headers, instead of deriving it
    /// from the transport layer.
    #[must_use]
    pub const fn with_next_header(mut self, next_header: IpProtocol) -> Self {
        self.next_header = Some(next_header);
        self
    }

    fn write(&self, protocol: Option<IpProtocol>, body: &[u8]) -> Result<Vec<u8>, Error> {
        let upper = self
            .next_header
            .or(protocol)
            .ok_or_else(|| Error::malformed(Layer::Ipv6, "no next header for payload"))?;
        let mut ext = Vec::new();
        for (i, (kind, data)) in self.extensions.iter().enumerate() {
            let next = self.extensions.get(i + 1).map_or(upper, |(k, _)| *k);
            let total = data.len() + 2;
            let len_byte = match *kind {
                IpProtocol::IPV6_FRAG => (total == 8).then_some(0),
                IpProtocol::AH => (total % 4 == 0 && total >= 8)
                    .then(|| u8::try_from(total / 4 - 2).ok())
                    .flatten(),
                _ => (total % 8 == 0)
                    .then(|| u8::try_from(total / 8 - 1).ok())
                    .flatten(),
            }
            .ok_or_else(|| {
                Error::malformed(
                    Layer::Ipv6Extension,
                    "extension header length not a valid multiple",
                )
            })?;
            ext.push(next.0);
            ext.push(len_byte);
            ext.extend_from_slice(data);
        }
        let first = self.extensions.first().map_or(upper, |(k, _)| *k);
        let payload_len = u16_len(Layer::Ipv6, ext.len() + body.len())?;
        let mut out = Vec::with_capacity(40 + ext.len() + body.len());
        let word = (6u32 << 28) | (u32::from(self.traffic_class) << 20) | self.flow_label;
        out.extend_from_slice(&word.to_be_bytes());
        out.extend_from_slice(&payload_len.to_be_bytes());
        out.extend_from_slice(&[first.0, self.hop_limit]);
        out.extend_from_slice(&self.src.octets());
        out.extend_from_slice(&self.dst.octets());
        out.extend_from_slice(&ext);
        out.extend_from_slice(body);
        Ok(out)
    }

    const fn pseudo_header(&self) -> PseudoHeader {
        PseudoHeader::V6 {
            src: self.src,
            dst: self.dst,
        }
    }
}

/// TCP header builder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpBuilder {
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: TcpFlags,
    window: u16,
    urgent_ptr: u16,
    options: Vec<u8>,
    option_error: Option<Error>,
    checksum: Option<u16>,
}

impl TcpBuilder {
    /// A segment between two ports, no flags, window 65535.
    #[must_use]
    pub const fn new(src_port: u16, dst_port: u16) -> Self {
        Self {
            src_port,
            dst_port,
            seq: 0,
            ack: 0,
            flags: TcpFlags(0),
            window: u16::MAX,
            urgent_ptr: 0,
            options: Vec::new(),
            option_error: None,
            checksum: None,
        }
    }

    /// Sequence number.
    #[must_use]
    pub const fn with_seq(mut self, seq: u32) -> Self {
        self.seq = seq;
        self
    }

    /// Acknowledgment number.
    #[must_use]
    pub const fn with_ack(mut self, ack: u32) -> Self {
        self.ack = ack;
        self
    }

    /// Control bits.
    #[must_use]
    pub const fn with_flags(mut self, flags: TcpFlags) -> Self {
        self.flags = flags;
        self
    }

    /// Receive window.
    #[must_use]
    pub const fn with_window(mut self, window: u16) -> Self {
        self.window = window;
        self
    }

    /// Urgent pointer.
    #[must_use]
    pub const fn with_urgent_ptr(mut self, urgent_ptr: u16) -> Self {
        self.urgent_ptr = urgent_ptr;
        self
    }

    /// Append an option. Options are padded with zeros to 4 bytes and
    /// may total 40 bytes.
    #[must_use]
    pub fn with_option(mut self, option: &TcpOption<'_>) -> Self {
        if let Err(err) = option.encode(&mut self.options) {
            self.option_error.get_or_insert(err);
        }
        self
    }

    /// Append a SACK option with these `(left, right)` edges.
    #[must_use]
    pub fn with_sack(mut self, blocks: &[(u32, u32)]) -> Self {
        let mut data = Vec::with_capacity(blocks.len() * 8);
        for (left, right) in blocks {
            data.extend_from_slice(&left.to_be_bytes());
            data.extend_from_slice(&right.to_be_bytes());
        }
        let option = TcpOption::Unknown {
            kind: 5,
            data: &data,
        };
        if let Err(err) = option.encode(&mut self.options) {
            self.option_error.get_or_insert(err);
        }
        self
    }

    /// Store this checksum instead of the correct one.
    #[must_use]
    pub const fn with_checksum(mut self, checksum: u16) -> Self {
        self.checksum = Some(checksum);
        self
    }

    fn write(&self, pseudo: &PseudoHeader, payload: &[u8]) -> Result<Vec<u8>, Error> {
        if let Some(err) = &self.option_error {
            return Err(err.clone());
        }
        let options_len = self.options.len().div_ceil(4) * 4;
        if options_len > 40 {
            return Err(too_large(Layer::Tcp, self.options.len(), 40));
        }
        let header_len = 20 + options_len;
        let mut out = Vec::with_capacity(header_len + payload.len());
        out.extend_from_slice(&self.src_port.to_be_bytes());
        out.extend_from_slice(&self.dst_port.to_be_bytes());
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.ack.to_be_bytes());
        #[allow(clippy::cast_possible_truncation, reason = "at most 15 words")]
        let offset = ((header_len / 4) as u8) << 4;
        let [flags_high, flags_low] = self.flags.0.to_be_bytes();
        out.extend_from_slice(&[offset | (flags_high & 0x01), flags_low]);
        out.extend_from_slice(&self.window.to_be_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&self.urgent_ptr.to_be_bytes());
        out.extend_from_slice(&self.options);
        out.resize(header_len, 0);
        out.extend_from_slice(payload);
        u16_len(Layer::Tcp, out.len())?;
        let checksum = self
            .checksum
            .unwrap_or_else(|| pseudo.compute(IpProtocol::TCP, &out));
        out[16..18].copy_from_slice(&checksum.to_be_bytes());
        Ok(out)
    }
}

/// UDP header builder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpBuilder {
    src_port: u16,
    dst_port: u16,
    checksum: Option<u16>,
}

impl UdpBuilder {
    /// A datagram between two ports.
    #[must_use]
    pub const fn new(src_port: u16, dst_port: u16) -> Self {
        Self {
            src_port,
            dst_port,
            checksum: None,
        }
    }

    /// Store this checksum instead of the correct one (`0` for none over
    /// IPv4).
    #[must_use]
    pub const fn with_checksum(mut self, checksum: u16) -> Self {
        self.checksum = Some(checksum);
        self
    }

    fn write(self, pseudo: &PseudoHeader, payload: &[u8]) -> Result<Vec<u8>, Error> {
        let length = u16_len(Layer::Udp, 8 + payload.len())?;
        let mut out = Vec::with_capacity(usize::from(length));
        out.extend_from_slice(&self.src_port.to_be_bytes());
        out.extend_from_slice(&self.dst_port.to_be_bytes());
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(payload);
        let checksum = self.checksum.unwrap_or_else(|| {
            // A computed zero is sent as all ones (RFC 768).
            match pseudo.compute(IpProtocol::UDP, &out) {
                0 => 0xffff,
                sum => sum,
            }
        });
        out[6..8].copy_from_slice(&checksum.to_be_bytes());
        Ok(out)
    }
}

/// ICMP or `ICMPv6` message builder; the version follows the IP layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IcmpBuilder {
    icmp_type: u8,
    code: u8,
    rest_of_header: [u8; 4],
    checksum: Option<u16>,
}

impl IcmpBuilder {
    /// A message of raw `icmp_type` and `code`.
    #[must_use]
    pub const fn new(icmp_type: u8, code: u8) -> Self {
        Self {
            icmp_type,
            code,
            rest_of_header: [0; 4],
            checksum: None,
        }
    }

    /// An ICMP (IPv4) message.
    #[must_use]
    pub const fn v4(icmp_type: Icmpv4Type, code: u8) -> Self {
        Self::new(icmp_type.0, code)
    }

    /// An `ICMPv6` message.
    #[must_use]
    pub const fn v6(icmp_type: Icmpv6Type, code: u8) -> Self {
        Self::new(icmp_type.0, code)
    }

    /// An ICMP (IPv4) echo request.
    #[must_use]
    pub const fn echo_request_v4(echo: Echo) -> Self {
        Self::v4(Icmpv4Type::ECHO_REQUEST, 0).with_rest_of_header(echo.to_rest_of_header())
    }

    /// An `ICMPv6` echo request.
    #[must_use]
    pub const fn echo_request_v6(echo: Echo) -> Self {
        Self::v6(Icmpv6Type::ECHO_REQUEST, 0).with_rest_of_header(echo.to_rest_of_header())
    }

    /// The four type-specific header bytes.
    #[must_use]
    pub const fn with_rest_of_header(mut self, rest: [u8; 4]) -> Self {
        self.rest_of_header = rest;
        self
    }

    /// Store this checksum instead of the correct one.
    #[must_use]
    pub const fn with_checksum(mut self, checksum: u16) -> Self {
        self.checksum = Some(checksum);
        self
    }

    fn write(self, pseudo: Option<&PseudoHeader>, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + payload.len());
        out.extend_from_slice(&[self.icmp_type, self.code, 0, 0]);
        out.extend_from_slice(&self.rest_of_header);
        out.extend_from_slice(payload);
        let checksum = self.checksum.unwrap_or_else(|| {
            pseudo.map_or_else(
                || internet_checksum(&out),
                |pseudo| pseudo.compute(IpProtocol::ICMPV6, &out),
            )
        });
        out[2..4].copy_from_slice(&checksum.to_be_bytes());
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Network {
    Arp(ArpBuilder),
    Ipv4(Ipv4Builder),
    Ipv6(Ipv6Builder),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TransportSpec {
    Tcp(TcpBuilder),
    Udp(UdpBuilder),
    Icmp(IcmpBuilder),
}

/// Stacks layer builders into one packet.
///
/// ```
/// use std::net::Ipv4Addr;
/// use rune_packet::{EthernetBuilder, Ipv4Builder, MacAddr, Packet, PacketBuilder, UdpBuilder};
///
/// let frame = PacketBuilder::new()
///     .ethernet(EthernetBuilder::new(MacAddr([2, 0, 0, 0, 0, 1]), MacAddr::BROADCAST))
///     .ipv4(Ipv4Builder::new(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 255)))
///     .udp(UdpBuilder::new(68, 67))
///     .payload(b"hello")
///     .build()?;
/// let packet = Packet::from_ethernet(&frame);
/// assert_eq!(packet.payload, b"hello");
/// assert_eq!(packet.transport_checksum_ok(), Some(true));
/// # Ok::<(), rune_packet::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PacketBuilder {
    ethernet: Option<EthernetBuilder>,
    network: Option<Network>,
    transport: Option<TransportSpec>,
    payload: Vec<u8>,
}

impl PacketBuilder {
    /// An empty stack.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Wrap the packet in an Ethernet frame.
    #[must_use]
    pub fn ethernet(mut self, ethernet: EthernetBuilder) -> Self {
        self.ethernet = Some(ethernet);
        self
    }

    /// Carry ARP (no transport layer allowed).
    #[must_use]
    pub fn arp(mut self, arp: ArpBuilder) -> Self {
        self.network = Some(Network::Arp(arp));
        self
    }

    /// Carry IPv4.
    #[must_use]
    pub fn ipv4(mut self, ip: Ipv4Builder) -> Self {
        self.network = Some(Network::Ipv4(ip));
        self
    }

    /// Carry IPv6.
    #[must_use]
    pub fn ipv6(mut self, ip: Ipv6Builder) -> Self {
        self.network = Some(Network::Ipv6(ip));
        self
    }

    /// Carry TCP.
    #[must_use]
    pub fn tcp(mut self, tcp: TcpBuilder) -> Self {
        self.transport = Some(TransportSpec::Tcp(tcp));
        self
    }

    /// Carry UDP.
    #[must_use]
    pub fn udp(mut self, udp: UdpBuilder) -> Self {
        self.transport = Some(TransportSpec::Udp(udp));
        self
    }

    /// Carry ICMP (over IPv4) or `ICMPv6` (over IPv6).
    #[must_use]
    pub fn icmp(mut self, icmp: IcmpBuilder) -> Self {
        self.transport = Some(TransportSpec::Icmp(icmp));
        self
    }

    /// The innermost payload.
    #[must_use]
    pub fn payload(mut self, payload: &[u8]) -> Self {
        payload.clone_into(&mut self.payload);
        self
    }

    /// Encode the packet, filling in lengths, protocol numbers and
    /// checksums that were not overridden.
    ///
    /// # Errors
    ///
    /// [`Error::TooLarge`] when a length or option area overflows its
    /// field; [`Error::Malformed`] for impossible stacks (a transport
    /// without IP, ARP with a transport, a layer whose type cannot be
    /// derived, or a badly sized IPv6 extension header).
    pub fn build(&self) -> Result<Vec<u8>, Error> {
        let pseudo = match &self.network {
            Some(Network::Ipv4(ip)) => Some(ip.pseudo_header()),
            Some(Network::Ipv6(ip)) => Some(ip.pseudo_header()),
            Some(Network::Arp(_)) | None => None,
        };
        let (protocol, transport) = match (&self.transport, pseudo) {
            (None, _) => (None, None),
            (Some(_), None) => {
                return Err(Error::malformed(
                    Layer::Ethernet,
                    "transport layer needs IPv4 or IPv6",
                ));
            }
            (Some(TransportSpec::Tcp(tcp)), Some(pseudo)) => (
                Some(IpProtocol::TCP),
                Some(tcp.write(&pseudo, &self.payload)?),
            ),
            (Some(TransportSpec::Udp(udp)), Some(pseudo)) => (
                Some(IpProtocol::UDP),
                Some(udp.write(&pseudo, &self.payload)?),
            ),
            (Some(TransportSpec::Icmp(icmp)), Some(pseudo)) if pseudo.is_v6() => (
                Some(IpProtocol::ICMPV6),
                Some(icmp.write(Some(&pseudo), &self.payload)),
            ),
            (Some(TransportSpec::Icmp(icmp)), Some(_)) => (
                Some(IpProtocol::ICMP),
                Some(icmp.write(None, &self.payload)),
            ),
        };
        let body = transport.as_deref().unwrap_or(&self.payload);
        let (ethertype, network) = match &self.network {
            None => (None, None),
            Some(Network::Arp(arp)) => {
                let mut out = arp.write();
                out.extend_from_slice(&self.payload);
                (Some(EtherType::ARP), Some(out))
            }
            Some(Network::Ipv4(ip)) => (Some(EtherType::IPV4), Some(ip.write(protocol, body)?)),
            Some(Network::Ipv6(ip)) => (Some(EtherType::IPV6), Some(ip.write(protocol, body)?)),
        };
        let body = network.as_deref().unwrap_or(body);
        self.ethernet.as_ref().map_or_else(
            || Ok(body.to_vec()),
            |ethernet| ethernet.write(ethertype, body),
        )
    }
}
