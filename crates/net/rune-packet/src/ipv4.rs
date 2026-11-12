//! IPv4 ([RFC 791](https://www.rfc-editor.org/rfc/rfc791)).

use std::net::Ipv4Addr;

use crate::checksum::{PseudoHeader, internet_checksum};
use crate::error::{Error, Layer, fixed};
use crate::ip::IpProtocol;

/// A parsed IPv4 packet, borrowing its options and payload from the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Packet<'a> {
    /// Differentiated services code point (6 bits).
    pub dscp: u8,
    /// Explicit congestion notification (2 bits).
    pub ecn: u8,
    /// Total length field: header plus payload.
    pub total_len: u16,
    /// Identification.
    pub identification: u16,
    /// The reserved ("evil", RFC 3514) flag bit.
    pub reserved_flag: bool,
    /// Don't fragment.
    pub dont_fragment: bool,
    /// More fragments.
    pub more_fragments: bool,
    /// Fragment offset in 8-byte units.
    pub fragment_offset: u16,
    /// Time to live.
    pub ttl: u8,
    /// Protocol of the payload.
    pub protocol: IpProtocol,
    /// Header checksum as stored.
    pub checksum: u16,
    /// Source address.
    pub src: Ipv4Addr,
    /// Destination address.
    pub dst: Ipv4Addr,
    /// Raw options (header bytes after the first 20).
    pub options: &'a [u8],
    /// Payload: up to `total_len`, or less if the input was cut short
    /// (see [`Ipv4Packet::is_truncated`]).
    pub payload: &'a [u8],
    header: &'a [u8],
}

impl<'a> Ipv4Packet<'a> {
    /// Length of a header without options.
    pub const MIN_HEADER_LEN: usize = 20;

    /// Parse a complete IPv4 packet. Bytes past `total_len` (link-layer
    /// padding) are ignored.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for a version other than 4, a header length
    /// under 20 bytes, or a total length shorter than the header;
    /// [`Error::Truncated`] if the header or payload runs past `data`.
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        let packet = Self::parse_partial(data)?;
        if packet.is_truncated() {
            return Err(Error::truncated(
                Layer::Ipv4,
                usize::from(packet.total_len),
                data.len(),
            ));
        }
        Ok(packet)
    }

    /// Like [`Ipv4Packet::parse`], but accept a payload cut short of
    /// `total_len`, as a capture with a snap length produces. The header
    /// itself must be complete.
    ///
    /// # Errors
    ///
    /// As [`Ipv4Packet::parse`], except for a short payload.
    pub fn parse_partial(data: &'a [u8]) -> Result<Self, Error> {
        let h = fixed::<20>(data, Layer::Ipv4)?;
        if h[0] >> 4 != 4 {
            return Err(Error::malformed(Layer::Ipv4, "version is not 4"));
        }
        let header_len = usize::from(h[0] & 0x0f) * 4;
        if header_len < Self::MIN_HEADER_LEN {
            return Err(Error::malformed(
                Layer::Ipv4,
                "header length under 20 bytes",
            ));
        }
        let header = data
            .get(..header_len)
            .ok_or_else(|| Error::truncated(Layer::Ipv4, header_len, data.len()))?;
        let total_len = u16::from_be_bytes([h[2], h[3]]);
        if usize::from(total_len) < header_len {
            return Err(Error::malformed(
                Layer::Ipv4,
                "total length shorter than header",
            ));
        }
        let end = usize::from(total_len).min(data.len());
        let payload = data.get(header_len..end).unwrap_or_default();
        let flags = u16::from_be_bytes([h[6], h[7]]);
        Ok(Self {
            dscp: h[1] >> 2,
            ecn: h[1] & 0x03,
            total_len,
            identification: u16::from_be_bytes([h[4], h[5]]),
            reserved_flag: flags & 0x8000 != 0,
            dont_fragment: flags & 0x4000 != 0,
            more_fragments: flags & 0x2000 != 0,
            fragment_offset: flags & 0x1fff,
            ttl: h[8],
            protocol: IpProtocol(h[9]),
            checksum: u16::from_be_bytes([h[10], h[11]]),
            src: Ipv4Addr::new(h[12], h[13], h[14], h[15]),
            dst: Ipv4Addr::new(h[16], h[17], h[18], h[19]),
            options: header.get(Self::MIN_HEADER_LEN..).unwrap_or_default(),
            payload,
            header,
        })
    }

    /// The raw header bytes, options included.
    #[must_use]
    pub const fn header(&self) -> &'a [u8] {
        self.header
    }

    /// Header length in bytes.
    #[must_use]
    pub const fn header_len(&self) -> usize {
        self.header.len()
    }

    /// Whether the input ended before `total_len` did.
    #[must_use]
    pub fn is_truncated(&self) -> bool {
        self.header.len() + self.payload.len() < usize::from(self.total_len)
    }

    /// Whether the header checksum is correct.
    #[must_use]
    pub fn verify_checksum(&self) -> bool {
        internet_checksum(self.header) == 0
    }

    /// Whether this packet is a fragment (offset non-zero or more to come).
    #[must_use]
    pub const fn is_fragment(&self) -> bool {
        self.more_fragments || self.fragment_offset != 0
    }

    /// The pseudo-header for the transport checksum of this packet.
    #[must_use]
    pub const fn pseudo_header(&self) -> PseudoHeader {
        PseudoHeader::V4 {
            src: self.src,
            dst: self.dst,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UDP_HEADER: [u8; 20] = [
        0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8, 0x00,
        0x01, 0xc0, 0xa8, 0x00, 0xc7,
    ];

    fn packet() -> Vec<u8> {
        let mut data = UDP_HEADER.to_vec();
        data.resize(0x73, 0xab);
        data
    }

    #[test]
    fn known_header() {
        let data = packet();
        let ip = Ipv4Packet::parse(&data).unwrap();
        assert_eq!(ip.total_len, 0x73);
        assert!(ip.dont_fragment);
        assert!(!ip.is_fragment());
        assert_eq!(ip.ttl, 64);
        assert_eq!(ip.protocol, IpProtocol::UDP);
        assert_eq!(ip.src, Ipv4Addr::new(192, 168, 0, 1));
        assert_eq!(ip.dst, Ipv4Addr::new(192, 168, 0, 199));
        assert!(ip.verify_checksum());
        assert_eq!(ip.payload.len(), 0x73 - 20);
        assert_eq!(ip.options.len(), 0);
    }

    #[test]
    fn padding_is_trimmed() {
        let mut data = packet();
        data.extend_from_slice(&[0; 10]);
        assert_eq!(Ipv4Packet::parse(&data).unwrap().payload.len(), 0x73 - 20);
    }

    #[test]
    fn truncated_payload() {
        let data = packet();
        let short = &data[..40];
        assert_eq!(
            Ipv4Packet::parse(short).unwrap_err(),
            Error::truncated(Layer::Ipv4, 0x73, 40)
        );
        let ip = Ipv4Packet::parse_partial(short).unwrap();
        assert!(ip.is_truncated());
        assert_eq!(ip.payload.len(), 20);
        assert!(
            Ipv4Packet::parse_partial(&data[..19])
                .unwrap_err()
                .is_truncated()
        );
    }

    #[test]
    fn malformed() {
        let mut data = packet();
        data[0] = 0x65;
        assert!(matches!(
            Ipv4Packet::parse(&data),
            Err(Error::Malformed { .. })
        ));
        data[0] = 0x44;
        assert!(matches!(
            Ipv4Packet::parse(&data),
            Err(Error::Malformed { .. })
        ));
        data[0] = 0x45;
        data[2] = 0;
        data[3] = 19;
        assert!(matches!(
            Ipv4Packet::parse(&data),
            Err(Error::Malformed { .. })
        ));
        let mut data = packet();
        data[0] = 0x4f; // 60-byte header
        data[2] = 0;
        data[3] = 60;
        assert!(Ipv4Packet::parse(&data[..40]).unwrap_err().is_truncated());
        let ip = Ipv4Packet::parse(&data).unwrap();
        assert_eq!(ip.options.len(), 40);
        assert_eq!(ip.payload.len(), 0);
        assert!(!ip.verify_checksum());
    }
}
