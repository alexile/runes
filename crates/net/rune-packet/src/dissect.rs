//! Whole-packet dissection: walk the layers of a frame as far as they go.

use std::net::IpAddr;

use crate::arp::ArpPacket;
use crate::checksum::PseudoHeader;
use crate::error::{Error, Layer};
use crate::ethernet::{EtherType, EthernetFrame};
use crate::icmp::{Icmpv4Packet, Icmpv6Packet};
use crate::ip::IpProtocol;
use crate::ipv4::Ipv4Packet;
use crate::ipv6::Ipv6Packet;
use crate::tcp::TcpSegment;
use crate::udp::UdpDatagram;

/// An IPv4 or IPv6 packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IpPacket<'a> {
    /// IPv4.
    V4(Ipv4Packet<'a>),
    /// IPv6.
    V6(Ipv6Packet<'a>),
}

impl<'a> IpPacket<'a> {
    /// Parse an IPv4 or IPv6 packet, picking the version from the first
    /// nibble, accepting a short payload (see `parse_partial`).
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for a version other than 4 or 6, otherwise
    /// as [`Ipv4Packet::parse_partial`] / [`Ipv6Packet::parse_partial`].
    pub fn parse_partial(data: &'a [u8]) -> Result<Self, Error> {
        match data.first().map(|b| b >> 4) {
            Some(4) => Ipv4Packet::parse_partial(data).map(Self::V4),
            Some(6) => Ipv6Packet::parse_partial(data).map(Self::V6),
            Some(_) => Err(Error::malformed(Layer::Ipv4, "IP version is not 4 or 6")),
            None => Err(Error::truncated(Layer::Ipv4, 1, 0)),
        }
    }

    /// Source address.
    #[must_use]
    pub fn src(&self) -> IpAddr {
        match self {
            Self::V4(ip) => ip.src.into(),
            Self::V6(ip) => ip.src.into(),
        }
    }

    /// Destination address.
    #[must_use]
    pub fn dst(&self) -> IpAddr {
        match self {
            Self::V4(ip) => ip.dst.into(),
            Self::V6(ip) => ip.dst.into(),
        }
    }

    /// TTL or hop limit.
    #[must_use]
    pub const fn ttl(&self) -> u8 {
        match self {
            Self::V4(ip) => ip.ttl,
            Self::V6(ip) => ip.hop_limit,
        }
    }

    /// Protocol of the upper layer (after IPv6 extension headers).
    #[must_use]
    pub const fn protocol(&self) -> IpProtocol {
        match self {
            Self::V4(ip) => ip.protocol,
            Self::V6(ip) => ip.upper_protocol,
        }
    }

    /// Upper-layer bytes.
    #[must_use]
    pub const fn payload(&self) -> &'a [u8] {
        match self {
            Self::V4(ip) => ip.payload,
            Self::V6(ip) => ip.payload,
        }
    }

    /// Whether the input ended before the IP length did.
    #[must_use]
    pub fn is_truncated(&self) -> bool {
        match self {
            Self::V4(ip) => ip.is_truncated(),
            Self::V6(ip) => ip.is_truncated(),
        }
    }

    /// Whether this packet is any fragment of a larger datagram.
    #[must_use]
    pub const fn is_fragment(&self) -> bool {
        match self {
            Self::V4(ip) => ip.is_fragment(),
            Self::V6(ip) => ip.is_fragment(),
        }
    }

    /// Whether the payload starts with the upper-layer header: not a
    /// fragment, or the first one.
    #[must_use]
    pub fn starts_upper_layer(&self) -> bool {
        match self {
            Self::V4(ip) => ip.fragment_offset == 0,
            Self::V6(ip) => ip.fragment().is_none_or(|f| f.offset == 0),
        }
    }

    /// The pseudo-header for the transport checksum.
    #[must_use]
    pub const fn pseudo_header(&self) -> PseudoHeader {
        match self {
            Self::V4(ip) => ip.pseudo_header(),
            Self::V6(ip) => ip.pseudo_header(),
        }
    }
}

/// A transport-layer message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Transport<'a> {
    /// TCP segment.
    Tcp(TcpSegment<'a>),
    /// UDP datagram.
    Udp(UdpDatagram<'a>),
    /// ICMP (IPv4) message.
    Icmpv4(Icmpv4Packet<'a>),
    /// `ICMPv6` message.
    Icmpv6(Icmpv6Packet<'a>),
}

impl<'a> Transport<'a> {
    /// Source port, for TCP and UDP.
    #[must_use]
    pub const fn src_port(&self) -> Option<u16> {
        match self {
            Self::Tcp(t) => Some(t.src_port),
            Self::Udp(u) => Some(u.src_port),
            _ => None,
        }
    }

    /// Destination port, for TCP and UDP.
    #[must_use]
    pub const fn dst_port(&self) -> Option<u16> {
        match self {
            Self::Tcp(t) => Some(t.dst_port),
            Self::Udp(u) => Some(u.dst_port),
            _ => None,
        }
    }

    /// Application bytes after the transport header.
    #[must_use]
    pub const fn payload(&self) -> &'a [u8] {
        match self {
            Self::Tcp(t) => t.payload,
            Self::Udp(u) => u.payload,
            Self::Icmpv4(i) => i.payload,
            Self::Icmpv6(i) => i.payload,
        }
    }
}

/// The layers of one packet, as far as they could be parsed.
///
/// Dissection never fails outright: it fills in every layer it can and
/// records the first problem in [`Packet::error`]. IP fragments after the
/// first, ESP, and unknown protocols stop at the IP layer without an
/// error; their bytes are in [`Packet::payload`].
///
/// ```
/// use rune_packet::{Packet, Transport};
///
/// let frame = [0u8; 13];
/// let packet = Packet::from_ethernet(&frame);
/// assert!(packet.ethernet.is_none());
/// assert!(packet.error.unwrap().is_truncated());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Packet<'a> {
    /// Link layer, for [`Packet::from_ethernet`].
    pub ethernet: Option<EthernetFrame<'a>>,
    /// ARP, when the frame carries it.
    pub arp: Option<ArpPacket<'a>>,
    /// Network layer.
    pub ip: Option<IpPacket<'a>>,
    /// Transport layer.
    pub transport: Option<Transport<'a>>,
    /// The innermost bytes not dissected further.
    pub payload: &'a [u8],
    /// The first problem met, if any.
    pub error: Option<Error>,
}

impl<'a> Packet<'a> {
    /// Dissect an Ethernet frame (pcap `LINKTYPE_ETHERNET`).
    #[must_use]
    pub fn from_ethernet(data: &'a [u8]) -> Self {
        let mut packet = Self {
            payload: data,
            ..Self::default()
        };
        let frame = match EthernetFrame::parse(data) {
            Ok(frame) => frame,
            Err(err) => {
                packet.error = Some(err);
                return packet;
            }
        };
        packet.ethernet = Some(frame);
        packet.payload = frame.payload;
        match frame.ethertype {
            EtherType::IPV4 | EtherType::IPV6 => packet.network(frame.payload),
            EtherType::ARP => match ArpPacket::parse(frame.payload) {
                Ok(arp) => {
                    packet.arp = Some(arp);
                    packet.payload = frame.payload.get(arp.len()..).unwrap_or_default();
                }
                Err(err) => packet.error = Some(err),
            },
            _ => {}
        }
        packet
    }

    /// Dissect a bare IPv4 or IPv6 packet (pcap `LINKTYPE_RAW`).
    #[must_use]
    pub fn from_ip(data: &'a [u8]) -> Self {
        let mut packet = Self {
            payload: data,
            ..Self::default()
        };
        packet.network(data);
        packet
    }

    fn network(&mut self, data: &'a [u8]) {
        let ip = match IpPacket::parse_partial(data) {
            Ok(ip) => ip,
            Err(err) => {
                self.error = Some(err);
                return;
            }
        };
        self.ip = Some(ip);
        self.payload = ip.payload();
        if ip.is_truncated() {
            let (layer, needed) = match ip {
                IpPacket::V4(v4) => (Layer::Ipv4, usize::from(v4.total_len)),
                IpPacket::V6(v6) => (
                    Layer::Ipv6,
                    Ipv6Packet::HEADER_LEN + usize::from(v6.payload_len),
                ),
            };
            self.error = Some(Error::truncated(layer, needed, data.len()));
        }
        if !ip.starts_upper_layer() {
            return;
        }
        let body = ip.payload();
        let transport = match (ip, ip.protocol()) {
            (_, IpProtocol::TCP) => TcpSegment::parse(body).map(Transport::Tcp),
            (_, IpProtocol::UDP) => UdpDatagram::parse_partial(body).map(Transport::Udp),
            (IpPacket::V4(_), IpProtocol::ICMP) => Icmpv4Packet::parse(body).map(Transport::Icmpv4),
            (IpPacket::V6(_), IpProtocol::ICMPV6) => {
                Icmpv6Packet::parse(body).map(Transport::Icmpv6)
            }
            _ => return,
        };
        match transport {
            Ok(transport) => {
                self.payload = transport.payload();
                if let Transport::Udp(udp) = transport
                    && udp.is_truncated()
                    && self.error.is_none()
                    && !ip.is_fragment()
                {
                    self.error = Some(Error::truncated(
                        Layer::Udp,
                        usize::from(udp.length),
                        body.len(),
                    ));
                }
                self.transport = Some(transport);
            }
            Err(err) => {
                if self.error.is_none() {
                    self.error = Some(err);
                }
            }
        }
    }

    /// Whether the IPv4 header checksum is correct (`None` without IPv4;
    /// IPv6 has no header checksum).
    #[must_use]
    pub fn ip_checksum_ok(&self) -> Option<bool> {
        match self.ip? {
            IpPacket::V4(ip) => Some(ip.verify_checksum()),
            IpPacket::V6(_) => None,
        }
    }

    /// Whether the TCP, UDP or ICMP checksum is correct. `None` when
    /// there is no transport layer or it cannot be checked: a truncated
    /// capture or a fragmented datagram.
    #[must_use]
    pub fn transport_checksum_ok(&self) -> Option<bool> {
        let ip = self.ip?;
        if ip.is_truncated() || ip.is_fragment() {
            return None;
        }
        let pseudo = ip.pseudo_header();
        Some(match self.transport? {
            Transport::Tcp(tcp) => tcp.verify_checksum(&pseudo),
            Transport::Udp(udp) if udp.is_truncated() => return None,
            Transport::Udp(udp) => udp.verify_checksum(&pseudo),
            Transport::Icmpv4(icmp) => icmp.verify_checksum(),
            Transport::Icmpv6(icmp) => icmp.verify_checksum(&pseudo),
        })
    }
}
