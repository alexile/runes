//! UDP ([RFC 768](https://www.rfc-editor.org/rfc/rfc768)).

use crate::checksum::PseudoHeader;
use crate::error::{Error, Layer, fixed};
use crate::ip::IpProtocol;

/// A parsed UDP datagram, borrowing its payload from the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpDatagram<'a> {
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
    /// Length field: header plus payload.
    pub length: u16,
    /// Checksum as stored (`0` means none, allowed over IPv4 only).
    pub checksum: u16,
    /// Payload, possibly cut short (see [`UdpDatagram::is_truncated`]).
    pub payload: &'a [u8],
    datagram: &'a [u8],
}

impl<'a> UdpDatagram<'a> {
    /// Header length.
    pub const HEADER_LEN: usize = 8;

    /// Parse a complete datagram. Bytes past `length` are ignored.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if `length` is under 8; [`Error::Truncated`]
    /// if the header or the payload runs past `data`.
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        let udp = Self::parse_partial(data)?;
        if udp.is_truncated() {
            return Err(Error::truncated(
                Layer::Udp,
                usize::from(udp.length),
                data.len(),
            ));
        }
        Ok(udp)
    }

    /// Like [`UdpDatagram::parse`], but accept a payload cut short of
    /// `length`.
    ///
    /// # Errors
    ///
    /// As [`UdpDatagram::parse`], except for a short payload.
    pub fn parse_partial(data: &'a [u8]) -> Result<Self, Error> {
        let h = fixed::<8>(data, Layer::Udp)?;
        let length = u16::from_be_bytes([h[4], h[5]]);
        if usize::from(length) < Self::HEADER_LEN {
            return Err(Error::malformed(Layer::Udp, "length under 8"));
        }
        let end = usize::from(length).min(data.len());
        Ok(Self {
            src_port: u16::from_be_bytes([h[0], h[1]]),
            dst_port: u16::from_be_bytes([h[2], h[3]]),
            length,
            checksum: u16::from_be_bytes([h[6], h[7]]),
            payload: data.get(Self::HEADER_LEN..end).unwrap_or_default(),
            datagram: data.get(..end).unwrap_or_default(),
        })
    }

    /// Whether the input ended before `length` did.
    #[must_use]
    pub fn is_truncated(&self) -> bool {
        self.datagram.len() < usize::from(self.length)
    }

    /// The datagram bytes, header included, up to `length`.
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.datagram
    }

    /// Whether the checksum is correct under `pseudo`. A zero checksum
    /// passes over IPv4 (it means "not computed") and fails over IPv6.
    #[must_use]
    pub fn verify_checksum(&self, pseudo: &PseudoHeader) -> bool {
        if self.checksum == 0 {
            return !pseudo.is_v6();
        }
        pseudo.compute(IpProtocol::UDP, self.datagram) == 0
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn parse_and_checksum() {
        // DNS-ish datagram 10.0.0.1:1234 -> 10.0.0.2:53, payload "abc".
        let mut data = vec![0x04, 0xd2, 0x00, 0x35, 0x00, 0x0b, 0, 0, b'a', b'b', b'c'];
        let pseudo = PseudoHeader::V4 {
            src: Ipv4Addr::new(10, 0, 0, 1),
            dst: Ipv4Addr::new(10, 0, 0, 2),
        };
        assert!(UdpDatagram::parse(&data).unwrap().verify_checksum(&pseudo));
        let sum = pseudo.compute(IpProtocol::UDP, &data);
        data[6..8].copy_from_slice(&sum.to_be_bytes());
        data.push(0); // padding
        let udp = UdpDatagram::parse(&data).unwrap();
        assert_eq!(udp.src_port, 1234);
        assert_eq!(udp.dst_port, 53);
        assert_eq!(udp.payload, b"abc");
        assert!(udp.verify_checksum(&pseudo));
        data[8] = b'x';
        assert!(!UdpDatagram::parse(&data).unwrap().verify_checksum(&pseudo));
    }

    #[test]
    fn zero_checksum_over_ipv6_fails() {
        let data = [0, 1, 0, 2, 0, 8, 0, 0];
        let udp = UdpDatagram::parse(&data).unwrap();
        let v6 = PseudoHeader::V6 {
            src: std::net::Ipv6Addr::LOCALHOST,
            dst: std::net::Ipv6Addr::LOCALHOST,
        };
        assert!(!udp.verify_checksum(&v6));
    }

    #[test]
    fn errors() {
        assert!(UdpDatagram::parse(&[0; 7]).unwrap_err().is_truncated());
        assert!(matches!(
            UdpDatagram::parse(&[0, 0, 0, 0, 0, 7, 0, 0]),
            Err(Error::Malformed { .. })
        ));
        let short = [0, 0, 0, 0, 0, 12, 0, 0, 1];
        assert!(UdpDatagram::parse(&short).unwrap_err().is_truncated());
        let partial = UdpDatagram::parse_partial(&short).unwrap();
        assert!(partial.is_truncated());
        assert_eq!(partial.payload, &[1]);
    }
}
