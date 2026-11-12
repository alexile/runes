//! ARP ([RFC 826](https://www.rfc-editor.org/rfc/rfc826)).

use std::net::Ipv4Addr;

use crate::error::{Error, Layer, fixed};
use crate::ethernet::{EtherType, MacAddr};

/// ARP hardware type for Ethernet.
pub const ARP_HARDWARE_ETHERNET: u16 = 1;

/// An ARP operation code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ArpOperation(pub u16);

impl ArpOperation {
    /// Request.
    pub const REQUEST: Self = Self(1);
    /// Reply.
    pub const REPLY: Self = Self(2);
    /// Reverse ARP request.
    pub const RARP_REQUEST: Self = Self(3);
    /// Reverse ARP reply.
    pub const RARP_REPLY: Self = Self(4);
}

/// A parsed ARP packet, with addresses borrowed from the input.
///
/// Any hardware and protocol address sizes are accepted; the typed
/// accessors apply to the common Ethernet/IPv4 case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArpPacket<'a> {
    /// Hardware type, e.g. [`ARP_HARDWARE_ETHERNET`].
    pub hardware_type: u16,
    /// Protocol type, e.g. [`EtherType::IPV4`].
    pub protocol_type: EtherType,
    /// Operation.
    pub operation: ArpOperation,
    /// Sender hardware address.
    pub sender_hardware: &'a [u8],
    /// Sender protocol address.
    pub sender_protocol: &'a [u8],
    /// Target hardware address.
    pub target_hardware: &'a [u8],
    /// Target protocol address.
    pub target_protocol: &'a [u8],
}

impl<'a> ArpPacket<'a> {
    /// Parse an ARP packet. Trailing bytes (frame padding) are ignored;
    /// [`ArpPacket::len`] says where the packet ends.
    ///
    /// # Errors
    ///
    /// [`Error::Truncated`] if the addresses run past the end of `data`.
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        let header = fixed::<8>(data, Layer::Arp)?;
        let hlen = usize::from(header[4]);
        let plen = usize::from(header[5]);
        let needed = 8 + 2 * (hlen + plen);
        let body = data
            .get(8..needed)
            .ok_or_else(|| Error::truncated(Layer::Arp, needed, data.len()))?;
        let (sender_hardware, body) = body.split_at(hlen);
        let (sender_protocol, body) = body.split_at(plen);
        let (target_hardware, target_protocol) = body.split_at(hlen);
        Ok(Self {
            hardware_type: u16::from_be_bytes([header[0], header[1]]),
            protocol_type: EtherType(u16::from_be_bytes([header[2], header[3]])),
            operation: ArpOperation(u16::from_be_bytes([header[6], header[7]])),
            sender_hardware,
            sender_protocol,
            target_hardware,
            target_protocol,
        })
    }

    /// Length of the packet in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        8 + 2 * (self.sender_hardware.len() + self.sender_protocol.len())
    }

    /// Always `false`: an ARP packet has at least its 8-byte header.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// Whether this is Ethernet/IPv4 ARP with 6- and 4-byte addresses.
    #[must_use]
    pub fn is_ethernet_ipv4(&self) -> bool {
        self.hardware_type == ARP_HARDWARE_ETHERNET
            && self.protocol_type == EtherType::IPV4
            && self.sender_hardware.len() == 6
            && self.sender_protocol.len() == 4
    }

    /// Sender MAC address, if the hardware address is 6 bytes.
    #[must_use]
    pub fn sender_mac(&self) -> Option<MacAddr> {
        mac(self.sender_hardware)
    }

    /// Target MAC address, if the hardware address is 6 bytes.
    #[must_use]
    pub fn target_mac(&self) -> Option<MacAddr> {
        mac(self.target_hardware)
    }

    /// Sender IPv4 address, if the protocol is IPv4 with 4-byte addresses.
    #[must_use]
    pub fn sender_ipv4(&self) -> Option<Ipv4Addr> {
        self.ipv4(self.sender_protocol)
    }

    /// Target IPv4 address, if the protocol is IPv4 with 4-byte addresses.
    #[must_use]
    pub fn target_ipv4(&self) -> Option<Ipv4Addr> {
        self.ipv4(self.target_protocol)
    }

    fn ipv4(&self, bytes: &[u8]) -> Option<Ipv4Addr> {
        if self.protocol_type != EtherType::IPV4 {
            return None;
        }
        bytes
            .first_chunk::<4>()
            .filter(|_| bytes.len() == 4)
            .map(|b| Ipv4Addr::from(*b))
    }
}

fn mac(bytes: &[u8]) -> Option<MacAddr> {
    bytes
        .first_chunk::<6>()
        .filter(|_| bytes.len() == 6)
        .map(|b| MacAddr(*b))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Who has 192.168.1.1? Tell 192.168.1.10 — plus 4 bytes of padding.
    const REQUEST: [u8; 32] = [
        0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 192,
        168, 1, 10, 0, 0, 0, 0, 0, 0, 192, 168, 1, 1, 0, 0, 0, 0,
    ];

    #[test]
    fn ethernet_ipv4_request() {
        let arp = ArpPacket::parse(&REQUEST).unwrap();
        assert!(arp.is_ethernet_ipv4());
        assert_eq!(arp.operation, ArpOperation::REQUEST);
        assert_eq!(arp.sender_mac(), Some(MacAddr([2, 0, 0, 0, 0, 1])));
        assert_eq!(arp.sender_ipv4(), Some(Ipv4Addr::new(192, 168, 1, 10)));
        assert_eq!(arp.target_mac(), Some(MacAddr::ZERO));
        assert_eq!(arp.target_ipv4(), Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(arp.len(), 28);
    }

    #[test]
    fn truncated() {
        for len in 0..28 {
            assert!(
                ArpPacket::parse(&REQUEST[..len])
                    .unwrap_err()
                    .is_truncated()
            );
        }
    }

    #[test]
    fn odd_sizes() {
        let data = [0, 6, 0x86, 0xdd, 1, 0, 0, 2, 0xaa, 0xbb];
        let arp = ArpPacket::parse(&data).unwrap();
        assert_eq!(arp.sender_hardware, &[0xaa]);
        assert_eq!(arp.sender_protocol, &[] as &[u8]);
        assert_eq!(arp.sender_mac(), None);
        assert_eq!(arp.sender_ipv4(), None);
        assert!(!arp.is_ethernet_ipv4());
    }
}
