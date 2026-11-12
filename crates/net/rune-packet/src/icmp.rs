//! ICMP for IPv4 ([RFC 792](https://www.rfc-editor.org/rfc/rfc792)) and
//! `ICMPv6` ([RFC 4443](https://www.rfc-editor.org/rfc/rfc4443)).

use crate::checksum::{PseudoHeader, internet_checksum};
use crate::error::{Error, Layer, fixed};
use crate::ip::IpProtocol;

/// Identifier and sequence number of an echo request or reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Echo {
    /// Identifier.
    pub identifier: u16,
    /// Sequence number.
    pub sequence: u16,
}

impl Echo {
    /// The four "rest of header" bytes for this echo.
    #[must_use]
    pub const fn to_rest_of_header(self) -> [u8; 4] {
        let [i0, i1] = self.identifier.to_be_bytes();
        let [s0, s1] = self.sequence.to_be_bytes();
        [i0, i1, s0, s1]
    }

    const fn from_rest(rest: [u8; 4]) -> Self {
        Self {
            identifier: u16::from_be_bytes([rest[0], rest[1]]),
            sequence: u16::from_be_bytes([rest[2], rest[3]]),
        }
    }
}

/// An ICMP (IPv4) message type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Icmpv4Type(pub u8);

impl Icmpv4Type {
    /// Echo reply.
    pub const ECHO_REPLY: Self = Self(0);
    /// Destination unreachable.
    pub const DEST_UNREACHABLE: Self = Self(3);
    /// Source quench (deprecated).
    pub const SOURCE_QUENCH: Self = Self(4);
    /// Redirect.
    pub const REDIRECT: Self = Self(5);
    /// Echo request.
    pub const ECHO_REQUEST: Self = Self(8);
    /// Router advertisement.
    pub const ROUTER_ADVERTISEMENT: Self = Self(9);
    /// Router solicitation.
    pub const ROUTER_SOLICITATION: Self = Self(10);
    /// Time exceeded.
    pub const TIME_EXCEEDED: Self = Self(11);
    /// Parameter problem.
    pub const PARAMETER_PROBLEM: Self = Self(12);
    /// Timestamp request.
    pub const TIMESTAMP: Self = Self(13);
    /// Timestamp reply.
    pub const TIMESTAMP_REPLY: Self = Self(14);

    /// Whether this is an error message, which quotes the invoking packet.
    #[must_use]
    pub const fn is_error(self) -> bool {
        matches!(self.0, 3 | 4 | 5 | 11 | 12)
    }
}

/// An `ICMPv6` message type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Icmpv6Type(pub u8);

impl Icmpv6Type {
    /// Destination unreachable.
    pub const DEST_UNREACHABLE: Self = Self(1);
    /// Packet too big.
    pub const PACKET_TOO_BIG: Self = Self(2);
    /// Time exceeded.
    pub const TIME_EXCEEDED: Self = Self(3);
    /// Parameter problem.
    pub const PARAMETER_PROBLEM: Self = Self(4);
    /// Echo request.
    pub const ECHO_REQUEST: Self = Self(128);
    /// Echo reply.
    pub const ECHO_REPLY: Self = Self(129);
    /// Multicast listener query.
    pub const MLD_QUERY: Self = Self(130);
    /// Router solicitation (RFC 4861).
    pub const ROUTER_SOLICITATION: Self = Self(133);
    /// Router advertisement (RFC 4861).
    pub const ROUTER_ADVERTISEMENT: Self = Self(134);
    /// Neighbor solicitation (RFC 4861).
    pub const NEIGHBOR_SOLICITATION: Self = Self(135);
    /// Neighbor advertisement (RFC 4861).
    pub const NEIGHBOR_ADVERTISEMENT: Self = Self(136);
    /// Redirect (RFC 4861).
    pub const REDIRECT: Self = Self(137);
    /// Version 2 multicast listener report (RFC 3810).
    pub const MLDV2_REPORT: Self = Self(143);

    /// Whether this is an error message (types 0–127).
    #[must_use]
    pub const fn is_error(self) -> bool {
        self.0 < 128
    }
}

/// Fields shared by both ICMP versions: a 4-byte header and 4 more
/// type-specific bytes, then the body.
struct Common<'a> {
    kind: u8,
    code: u8,
    checksum: u16,
    rest_of_header: [u8; 4],
    payload: &'a [u8],
}

fn split_message(data: &[u8], layer: Layer) -> Result<Common<'_>, Error> {
    let h = fixed::<8>(data, layer)?;
    Ok(Common {
        kind: h[0],
        code: h[1],
        checksum: u16::from_be_bytes([h[2], h[3]]),
        rest_of_header: [h[4], h[5], h[6], h[7]],
        payload: data.get(8..).unwrap_or_default(),
    })
}

/// A parsed ICMP (IPv4) message, borrowing its body from the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Icmpv4Packet<'a> {
    /// Message type.
    pub icmp_type: Icmpv4Type,
    /// Code.
    pub code: u8,
    /// Checksum as stored.
    pub checksum: u16,
    /// The four type-specific header bytes.
    pub rest_of_header: [u8; 4],
    /// Bytes after the 8-byte header. For error messages, the start of
    /// the packet that caused the error.
    pub payload: &'a [u8],
    message: &'a [u8],
}

impl<'a> Icmpv4Packet<'a> {
    /// Parse an ICMP message; everything after the header is its body.
    ///
    /// # Errors
    ///
    /// [`Error::Truncated`] if `data` is shorter than 8 bytes.
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        let Common {
            kind,
            code,
            checksum,
            rest_of_header,
            payload,
        } = split_message(data, Layer::Icmpv4)?;
        Ok(Self {
            icmp_type: Icmpv4Type(kind),
            code,
            checksum,
            rest_of_header,
            payload,
            message: data,
        })
    }

    /// Whether the checksum over the whole message is correct.
    #[must_use]
    pub fn verify_checksum(&self) -> bool {
        internet_checksum(self.message) == 0
    }

    /// Identifier and sequence of an echo request or reply.
    #[must_use]
    pub fn echo(&self) -> Option<Echo> {
        matches!(
            self.icmp_type,
            Icmpv4Type::ECHO_REQUEST | Icmpv4Type::ECHO_REPLY
        )
        .then(|| Echo::from_rest(self.rest_of_header))
    }

    /// Next-hop MTU of a "fragmentation needed" message (RFC 1191).
    #[must_use]
    pub fn next_hop_mtu(&self) -> Option<u16> {
        (self.icmp_type == Icmpv4Type::DEST_UNREACHABLE && self.code == 4)
            .then(|| u16::from_be_bytes([self.rest_of_header[2], self.rest_of_header[3]]))
    }

    /// Gateway address of a redirect.
    #[must_use]
    pub fn gateway(&self) -> Option<std::net::Ipv4Addr> {
        (self.icmp_type == Icmpv4Type::REDIRECT).then(|| self.rest_of_header.into())
    }

    /// The quoted invoking packet of an error message.
    #[must_use]
    pub fn invoking_packet(&self) -> Option<&'a [u8]> {
        self.icmp_type.is_error().then_some(self.payload)
    }

    /// The whole message, header included.
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.message
    }
}

/// A parsed `ICMPv6` message, borrowing its body from the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Icmpv6Packet<'a> {
    /// Message type.
    pub icmp_type: Icmpv6Type,
    /// Code.
    pub code: u8,
    /// Checksum as stored.
    pub checksum: u16,
    /// The four type-specific header bytes.
    pub rest_of_header: [u8; 4],
    /// Bytes after the 8-byte header (for Neighbor Discovery, the target
    /// address and options; for errors, the invoking packet).
    pub payload: &'a [u8],
    message: &'a [u8],
}

impl<'a> Icmpv6Packet<'a> {
    /// Parse an `ICMPv6` message; everything after the header is its body.
    ///
    /// # Errors
    ///
    /// [`Error::Truncated`] if `data` is shorter than 8 bytes.
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        let Common {
            kind,
            code,
            checksum,
            rest_of_header,
            payload,
        } = split_message(data, Layer::Icmpv6)?;
        Ok(Self {
            icmp_type: Icmpv6Type(kind),
            code,
            checksum,
            rest_of_header,
            payload,
            message: data,
        })
    }

    /// Whether the checksum is correct under `pseudo`.
    #[must_use]
    pub fn verify_checksum(&self, pseudo: &PseudoHeader) -> bool {
        pseudo.compute(IpProtocol::ICMPV6, self.message) == 0
    }

    /// Identifier and sequence of an echo request or reply.
    #[must_use]
    pub fn echo(&self) -> Option<Echo> {
        matches!(
            self.icmp_type,
            Icmpv6Type::ECHO_REQUEST | Icmpv6Type::ECHO_REPLY
        )
        .then(|| Echo::from_rest(self.rest_of_header))
    }

    /// MTU of a "packet too big" message.
    #[must_use]
    pub fn mtu(&self) -> Option<u32> {
        (self.icmp_type == Icmpv6Type::PACKET_TOO_BIG)
            .then(|| u32::from_be_bytes(self.rest_of_header))
    }

    /// The quoted invoking packet of an error message.
    #[must_use]
    pub fn invoking_packet(&self) -> Option<&'a [u8]> {
        self.icmp_type.is_error().then_some(self.payload)
    }

    /// The whole message, header included.
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.message
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use super::*;

    #[test]
    fn echo_request_v4() {
        // `ping` style echo request, id 0x1234 seq 1, payload "ping".
        let mut data = vec![8, 0, 0, 0, 0x12, 0x34, 0, 1, b'p', b'i', b'n', b'g'];
        let sum = internet_checksum(&data);
        data[2..4].copy_from_slice(&sum.to_be_bytes());
        let icmp = Icmpv4Packet::parse(&data).unwrap();
        assert!(icmp.verify_checksum());
        assert_eq!(
            icmp.echo(),
            Some(Echo {
                identifier: 0x1234,
                sequence: 1
            })
        );
        assert_eq!(icmp.payload, b"ping");
        assert_eq!(icmp.invoking_packet(), None);
        assert_eq!(icmp.next_hop_mtu(), None);
    }

    #[test]
    fn errors_v4() {
        let data = [3, 4, 0, 0, 0, 0, 0x05, 0xdc, 0x45];
        let icmp = Icmpv4Packet::parse(&data).unwrap();
        assert_eq!(icmp.next_hop_mtu(), Some(1500));
        assert_eq!(icmp.invoking_packet(), Some(&[0x45][..]));
        assert_eq!(icmp.echo(), None);
        let redirect = Icmpv4Packet::parse(&[5, 1, 0, 0, 10, 0, 0, 1]).unwrap();
        assert_eq!(
            redirect.gateway(),
            Some(std::net::Ipv4Addr::new(10, 0, 0, 1))
        );
        assert!(Icmpv4Packet::parse(&data[..7]).unwrap_err().is_truncated());
    }

    #[test]
    fn v6_messages() {
        let pseudo = PseudoHeader::V6 {
            src: Ipv6Addr::LOCALHOST,
            dst: Ipv6Addr::LOCALHOST,
        };
        let mut data = vec![128, 0, 0, 0, 0, 7, 0, 9];
        let sum = pseudo.compute(IpProtocol::ICMPV6, &data);
        data[2..4].copy_from_slice(&sum.to_be_bytes());
        let icmp = Icmpv6Packet::parse(&data).unwrap();
        assert!(icmp.verify_checksum(&pseudo));
        assert_eq!(
            icmp.echo(),
            Some(Echo {
                identifier: 7,
                sequence: 9
            })
        );
        assert_eq!(icmp.echo().unwrap().to_rest_of_header(), [0, 7, 0, 9]);
        let ptb = Icmpv6Packet::parse(&[2, 0, 0, 0, 0, 0, 0x05, 0x00, 0x60]).unwrap();
        assert_eq!(ptb.mtu(), Some(1280));
        assert_eq!(ptb.invoking_packet(), Some(&[0x60][..]));
        assert!(Icmpv6Packet::parse(&[0; 3]).unwrap_err().is_truncated());
    }
}
