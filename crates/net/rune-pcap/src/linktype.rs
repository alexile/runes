//! Link-layer header types, and handing frames to `rune-packet`.

use std::fmt;

use rune_packet::Packet;

/// A link-layer header type (`LINKTYPE_*`) from the
/// [tcpdump.org registry](https://www.tcpdump.org/linktypes.html).
///
/// It says how to read the first bytes of every packet on an interface.
/// Values without a constant here are kept as they are.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LinkType(pub u16);

impl LinkType {
    /// BSD loopback: a 4-byte address family in the writer's byte order.
    pub const NULL: Self = Self(0);
    /// Ethernet II / IEEE 802.3.
    pub const ETHERNET: Self = Self(1);
    /// PPP (RFC 1661).
    pub const PPP: Self = Self(9);
    /// Raw IPv4 or IPv6, the version taken from the first nibble.
    pub const RAW: Self = Self(101);
    /// IEEE 802.11 wireless LAN.
    pub const IEEE802_11: Self = Self(105);
    /// OpenBSD loopback: a 4-byte address family in network byte order.
    pub const LOOP: Self = Self(108);
    /// Linux "cooked" capture, version 1 (`tcpdump -i any`).
    pub const LINUX_SLL: Self = Self(113);
    /// IEEE 802.11 with a radiotap header.
    pub const IEEE802_11_RADIOTAP: Self = Self(127);
    /// Raw IPv4.
    pub const IPV4: Self = Self(228);
    /// Raw IPv6.
    pub const IPV6: Self = Self(229);
    /// Linux netlink.
    pub const NETLINK: Self = Self(253);
    /// Linux "cooked" capture, version 2.
    pub const LINUX_SLL2: Self = Self(276);

    /// The registry name without its `LINKTYPE_` prefix, for the types
    /// this crate names.
    #[must_use]
    pub const fn name(self) -> Option<&'static str> {
        Some(match self.0 {
            0 => "NULL",
            1 => "ETHERNET",
            9 => "PPP",
            101 => "RAW",
            105 => "IEEE802_11",
            108 => "LOOP",
            113 => "LINUX_SLL",
            127 => "IEEE802_11_RADIOTAP",
            228 => "IPV4",
            229 => "IPV6",
            253 => "NETLINK",
            276 => "LINUX_SLL2",
            _ => return None,
        })
    }

    /// Whether [`dissect`](Self::dissect) understands this link type.
    #[must_use]
    pub const fn is_dissectable(self) -> bool {
        matches!(
            self,
            Self::NULL
                | Self::ETHERNET
                | Self::RAW
                | Self::LOOP
                | Self::LINUX_SLL
                | Self::IPV4
                | Self::IPV6
                | Self::LINUX_SLL2
        )
    }

    /// Dissect a captured frame of this link type with `rune-packet`.
    ///
    /// Ethernet frames go to [`Packet::from_ethernet`]. Raw IP, BSD/OpenBSD
    /// loopback and Linux cooked captures have their link header (if any)
    /// stripped and the IP packet goes to [`Packet::from_ip`]. Like those
    /// functions this never fails: a truncated or malformed packet comes
    /// back with [`Packet::error`] set.
    ///
    /// Returns `None` when there is no IP or Ethernet packet to hand over:
    /// the link type is not one of those above, its header is cut short,
    /// or it carries another protocol (such as ARP inside a cooked
    /// capture, or an IPX loopback frame).
    #[must_use]
    pub fn dissect(self, frame: &[u8]) -> Option<Packet<'_>> {
        const ETHERTYPE_IPV4: u16 = 0x0800;
        const ETHERTYPE_IPV6: u16 = 0x86dd;
        let ip_by_ethertype = |ethertype: u16, rest| {
            matches!(ethertype, ETHERTYPE_IPV4 | ETHERTYPE_IPV6).then(|| Packet::from_ip(rest))
        };
        match self {
            Self::ETHERNET => Some(Packet::from_ethernet(frame)),
            Self::RAW | Self::IPV4 | Self::IPV6 => Some(Packet::from_ip(frame)),
            Self::NULL | Self::LOOP => {
                let (family, rest) = frame.split_first_chunk::<4>()?;
                // NULL is in the writer's byte order, which the frame
                // doesn't record: AF values are small, so whichever end
                // is non-zero holds it.
                let family = if self == Self::LOOP || family[0] == 0 {
                    u32::from_be_bytes(*family)
                } else {
                    u32::from_le_bytes(*family)
                };
                // AF_INET everywhere; AF_INET6 is 24 (NetBSD, OpenBSD),
                // 28 (FreeBSD) or 30 (macOS).
                matches!(family, 2 | 24 | 28 | 30).then(|| Packet::from_ip(rest))
            }
            Self::LINUX_SLL => {
                let (header, rest) = frame.split_first_chunk::<16>()?;
                ip_by_ethertype(u16::from_be_bytes([header[14], header[15]]), rest)
            }
            Self::LINUX_SLL2 => {
                let (header, rest) = frame.split_first_chunk::<20>()?;
                ip_by_ethertype(u16::from_be_bytes([header[0], header[1]]), rest)
            }
            _ => None,
        }
    }
}

impl From<u16> for LinkType {
    fn from(v: u16) -> Self {
        Self(v)
    }
}

impl From<LinkType> for u16 {
    fn from(v: LinkType) -> Self {
        v.0
    }
}

impl fmt::Display for LinkType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(name) => f.write_str(name),
            None => write!(f, "LINKTYPE({})", self.0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // IPv4 UDP 192.0.2.1:1 -> 198.51.100.7:2, no payload.
    const IPV4_UDP: [u8; 28] = [
        0x45, 0, 0, 28, 0, 0, 0x40, 0, 64, 17, 0, 0, 192, 0, 2, 1, 198, 51, 100, 7, 0, 1, 0, 2, 0,
        8, 0, 0,
    ];

    fn with_prefix(prefix: &[u8]) -> Vec<u8> {
        [prefix, &IPV4_UDP].concat()
    }

    #[test]
    fn names() {
        assert_eq!(LinkType::ETHERNET.to_string(), "ETHERNET");
        assert_eq!(LinkType(4242).to_string(), "LINKTYPE(4242)");
        assert_eq!(u16::from(LinkType::from(113)), 113);
        assert!(LinkType::LINUX_SLL2.is_dissectable());
        assert!(!LinkType::PPP.is_dissectable());
    }

    #[test]
    fn dissects_ip_link_types() {
        for (link, frame) in [
            (LinkType::RAW, with_prefix(&[])),
            (LinkType::IPV4, with_prefix(&[])),
            (LinkType::NULL, with_prefix(&[2, 0, 0, 0])),
            (LinkType::NULL, with_prefix(&[0, 0, 0, 2])),
            (LinkType::LOOP, with_prefix(&[0, 0, 0, 2])),
            (
                LinkType::LINUX_SLL,
                with_prefix(&[0, 0, 0, 1, 0, 6, 2, 0, 0, 0, 0, 1, 0, 0, 0x08, 0x00]),
            ),
            (
                LinkType::LINUX_SLL2,
                with_prefix(&[
                    0x08, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 6, 2, 0, 0, 0, 0, 1, 0, 0,
                ]),
            ),
        ] {
            let packet = link.dissect(&frame).unwrap_or_else(|| panic!("{link}"));
            assert!(packet.error.is_none(), "{link}: {:?}", packet.error);
            assert_eq!(
                packet.transport.and_then(|t| t.dst_port()),
                Some(2),
                "{link}"
            );
        }
    }

    #[test]
    fn declines_what_it_cannot_dissect() {
        assert!(LinkType::PPP.dissect(&IPV4_UDP).is_none());
        assert!(LinkType::LINUX_SLL.dissect(&[0; 15]).is_none());
        assert!(LinkType::LINUX_SLL2.dissect(&[0; 19]).is_none());
        assert!(LinkType::NULL.dissect(&[2, 0, 0]).is_none());
        // ARP in a cooked capture; IPX over loopback.
        let mut arp = [0u8; 44];
        arp[14..16].copy_from_slice(&[0x08, 0x06]);
        assert!(LinkType::LINUX_SLL.dissect(&arp).is_none());
        assert!(
            LinkType::LOOP
                .dissect(&with_prefix(&[0, 0, 0, 23]))
                .is_none()
        );
        // Truncated Ethernet still dissects, with the error recorded.
        assert!(LinkType::ETHERNET.dissect(&[0; 5]).unwrap().error.is_some());
    }
}
