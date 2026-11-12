//! The Internet checksum ([RFC 1071](https://www.rfc-editor.org/rfc/rfc1071))
//! and the transport-layer pseudo-headers that feed it.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::ip::IpProtocol;

/// Incremental Internet checksum (16-bit one's-complement sum).
///
/// Feed it bytes in any split — an odd-length chunk carries its last
/// byte over to the next one — then call [`Checksum::finish`].
///
/// ```
/// use rune_packet::Checksum;
///
/// // RFC 1071 section 3 example.
/// let mut sum = Checksum::new();
/// sum.add_bytes(&[0x00, 0x01, 0xf2]).add_bytes(&[0x03, 0xf4, 0xf5, 0xf6, 0xf7]);
/// assert_eq!(sum.finish(), !0xddf2);
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Checksum {
    sum: u64,
    pending: Option<u8>,
}

impl Checksum {
    /// An empty sum.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            sum: 0,
            pending: None,
        }
    }

    /// Add bytes, as if appended to everything added so far.
    pub fn add_bytes(&mut self, mut bytes: &[u8]) -> &mut Self {
        if let Some(high) = self.pending {
            let Some((&low, rest)) = bytes.split_first() else {
                return self;
            };
            self.sum += u64::from(u16::from_be_bytes([high, low]));
            self.pending = None;
            bytes = rest;
        }
        // Summing 32-bit words and folding later gives the same
        // one's-complement result as summing 16-bit words; a u64 cannot
        // overflow before 2^32 words (16 GiB).
        let (words, mut rest) = bytes.as_chunks::<4>();
        for word in words {
            self.sum += u64::from(u32::from_be_bytes(*word));
        }
        if let Some(pair) = rest.first_chunk::<2>() {
            self.sum += u64::from(u16::from_be_bytes(*pair));
            rest = &rest[2..];
        }
        self.pending = rest.first().copied();
        self
    }

    /// Add a 16-bit big-endian word.
    pub fn add_u16(&mut self, word: u16) -> &mut Self {
        self.add_bytes(&word.to_be_bytes())
    }

    /// Add a 32-bit big-endian word.
    pub fn add_u32(&mut self, word: u32) -> &mut Self {
        self.add_bytes(&word.to_be_bytes())
    }

    /// The checksum: the one's complement of the folded sum. An odd
    /// trailing byte is padded with a zero byte.
    ///
    /// Summing a header *including* a correct checksum field gives `0`.
    #[must_use]
    pub fn finish(&self) -> u16 {
        let mut sum = self.sum;
        if let Some(high) = self.pending {
            sum += u64::from(high) << 8;
        }
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        #[allow(
            clippy::cast_possible_truncation,
            reason = "folded to 16 bits by the loop above"
        )]
        let folded = sum as u16;
        !folded
    }
}

/// The Internet checksum of `data` in one call.
///
/// ```
/// // The example IPv4 header from RFC 791 tutorials: checksum 0xb861.
/// let header = [
///     0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00,
///     0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
/// ];
/// assert_eq!(rune_packet::internet_checksum(&header), 0xb861);
/// ```
#[must_use]
pub fn internet_checksum(data: &[u8]) -> u16 {
    Checksum::new().add_bytes(data).finish()
}

/// The addresses of the IP header that carries a TCP, UDP or `ICMPv6`
/// message, which those checksums cover through a pseudo-header
/// ([RFC 9293 §3.1](https://www.rfc-editor.org/rfc/rfc9293#section-3.1),
/// [RFC 768](https://www.rfc-editor.org/rfc/rfc768),
/// [RFC 8200 §8.1](https://www.rfc-editor.org/rfc/rfc8200#section-8.1)).
///
/// For IPv6 with a routing header the destination should be the final
/// one; this crate uses the address in the fixed header as given.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PseudoHeader {
    /// Addresses of an IPv4 header.
    V4 {
        /// Source address.
        src: Ipv4Addr,
        /// Destination address.
        dst: Ipv4Addr,
    },
    /// Addresses of an IPv6 header.
    V6 {
        /// Source address.
        src: Ipv6Addr,
        /// Destination address.
        dst: Ipv6Addr,
    },
}

impl PseudoHeader {
    /// A checksum primed with this pseudo-header for an upper-layer
    /// message of `len` bytes carried as `protocol`.
    #[must_use]
    pub fn checksum(&self, protocol: IpProtocol, len: u32) -> Checksum {
        let mut sum = Checksum::new();
        match self {
            Self::V4 { src, dst } => {
                // The IPv4 pseudo-header has a 16-bit length; callers only
                // pass lengths that came from (or fit) 16-bit fields.
                sum.add_bytes(&src.octets())
                    .add_bytes(&dst.octets())
                    .add_u16(u16::from(protocol.0))
                    .add_u16(u16::try_from(len).unwrap_or(u16::MAX));
            }
            Self::V6 { src, dst } => {
                sum.add_bytes(&src.octets())
                    .add_bytes(&dst.octets())
                    .add_u32(len)
                    .add_u32(u32::from(protocol.0));
            }
        }
        sum
    }

    /// The checksum of `message` (which includes its own checksum field)
    /// under this pseudo-header. `0` means the stored checksum is correct;
    /// with the field zeroed it is the value to store.
    #[must_use]
    pub fn compute(&self, protocol: IpProtocol, message: &[u8]) -> u16 {
        let len = u32::try_from(message.len()).unwrap_or(u32::MAX);
        self.checksum(protocol, len).add_bytes(message).finish()
    }

    /// Whether this is an IPv6 pseudo-header.
    #[must_use]
    pub const fn is_v6(&self) -> bool {
        matches!(self, Self::V6 { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc1071_example() {
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(internet_checksum(&data), !0xddf2);
    }

    #[test]
    fn split_points_do_not_matter() {
        let data: Vec<u8> = (0..=255u8).cycle().take(1001).collect();
        let whole = internet_checksum(&data);
        for at in 0..data.len() {
            let mut sum = Checksum::new();
            sum.add_bytes(&data[..at])
                .add_bytes(&[])
                .add_bytes(&data[at..]);
            assert_eq!(sum.finish(), whole, "split at {at}");
        }
        // Byte-at-a-time.
        let mut sum = Checksum::new();
        for byte in &data {
            sum.add_bytes(std::slice::from_ref(byte));
        }
        assert_eq!(sum.finish(), whole);
    }

    #[test]
    fn odd_length_pads_with_zero() {
        assert_eq!(internet_checksum(&[0x12]), internet_checksum(&[0x12, 0x00]));
        assert_eq!(internet_checksum(&[]), 0xffff);
    }

    #[test]
    fn ipv4_header_verifies_to_zero() {
        let header = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        assert_eq!(internet_checksum(&header), 0);
    }

    #[test]
    fn carries_fold_repeatedly() {
        let data = [0xff; 64];
        // Sum of 0xffff words is 0xffff in one's complement: checksum 0.
        assert_eq!(internet_checksum(&data), 0);
    }
}
