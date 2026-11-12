//! IPv6 ([RFC 8200](https://www.rfc-editor.org/rfc/rfc8200)) and its
//! extension headers.

use std::net::Ipv6Addr;

use crate::checksum::PseudoHeader;
use crate::error::{Error, Layer, fixed};
use crate::ip::IpProtocol;

/// A parsed IPv6 packet, borrowing its extension headers and payload
/// from the input.
///
/// Parsing walks the extension headers (Hop-by-Hop, Routing, Fragment,
/// Destination Options, AH, Mobility, HIP, Shim6) to find the upper
/// layer. It stops at ESP, No Next Header, or any other protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Packet<'a> {
    /// Traffic class.
    pub traffic_class: u8,
    /// Flow label (20 bits).
    pub flow_label: u32,
    /// Payload length field: extension headers plus upper layer. `0` with
    /// a Hop-by-Hop header marks a jumbogram (RFC 2675).
    pub payload_len: u16,
    /// Next header of the fixed header.
    pub next_header: IpProtocol,
    /// Hop limit.
    pub hop_limit: u8,
    /// Source address.
    pub src: Ipv6Addr,
    /// Destination address.
    pub dst: Ipv6Addr,
    /// Protocol after the last extension header.
    pub upper_protocol: IpProtocol,
    /// Bytes after the last extension header, possibly cut short (see
    /// [`Ipv6Packet::is_truncated`]).
    pub payload: &'a [u8],
    extensions: &'a [u8],
    fragment: Option<Ipv6Fragment>,
    truncated: bool,
}

/// The contents of an IPv6 Fragment header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv6Fragment {
    /// Offset in 8-byte units.
    pub offset: u16,
    /// More fragments follow.
    pub more_fragments: bool,
    /// Identification.
    pub identification: u32,
}

impl Ipv6Fragment {
    const fn decode(header: [u8; 8]) -> Self {
        let word = u16::from_be_bytes([header[2], header[3]]);
        Self {
            offset: word >> 3,
            more_fragments: word & 1 != 0,
            identification: u32::from_be_bytes([header[4], header[5], header[6], header[7]]),
        }
    }

    /// The six bytes after the next-header and reserved bytes, as the
    /// builder takes them.
    #[must_use]
    pub const fn encode_body(self) -> [u8; 6] {
        let word = (self.offset << 3) | self.more_fragments as u16;
        let [w0, w1] = word.to_be_bytes();
        let [i0, i1, i2, i3] = self.identification.to_be_bytes();
        [w0, w1, i0, i1, i2, i3]
    }
}

/// One IPv6 extension header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtensionHeader<'a> {
    /// Which header this is.
    pub kind: IpProtocol,
    /// The header that follows it.
    pub next_header: IpProtocol,
    /// The whole header, next-header and length bytes included.
    pub data: &'a [u8],
}

impl<'a> ExtensionHeader<'a> {
    /// The header after its two leading (next header, length) bytes.
    #[must_use]
    pub fn body(&self) -> &'a [u8] {
        self.data.get(2..).unwrap_or_default()
    }
}

/// Length of the extension header `kind` starting with `head`.
fn extension_len(kind: IpProtocol, head: [u8; 2]) -> usize {
    match kind {
        IpProtocol::IPV6_FRAG => 8,
        IpProtocol::AH => (usize::from(head[1]) + 2) * 4,
        _ => (usize::from(head[1]) + 1) * 8,
    }
}

impl<'a> Ipv6Packet<'a> {
    /// Length of the fixed header.
    pub const HEADER_LEN: usize = 40;

    /// Parse a complete IPv6 packet. Bytes past the payload length
    /// (link-layer padding) are ignored.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for a version other than 6;
    /// [`Error::Truncated`] if the header, an extension header or the
    /// payload runs past `data`.
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        let packet = Self::parse_partial(data)?;
        if packet.truncated {
            return Err(Error::truncated(
                Layer::Ipv6,
                Self::HEADER_LEN + usize::from(packet.payload_len),
                data.len(),
            ));
        }
        Ok(packet)
    }

    /// Like [`Ipv6Packet::parse`], but accept a payload cut short of the
    /// payload length. The fixed header and every extension header must
    /// still be complete.
    ///
    /// # Errors
    ///
    /// As [`Ipv6Packet::parse`], except for a short upper-layer payload.
    pub fn parse_partial(data: &'a [u8]) -> Result<Self, Error> {
        let h = fixed::<40>(data, Layer::Ipv6)?;
        if h[0] >> 4 != 6 {
            return Err(Error::malformed(Layer::Ipv6, "version is not 6"));
        }
        let payload_len = u16::from_be_bytes([h[4], h[5]]);
        let next_header = IpProtocol(h[6]);
        let rest = data.get(Self::HEADER_LEN..).unwrap_or_default();
        let jumbo = payload_len == 0 && next_header == IpProtocol::HOPOPT;
        let declared = if jumbo {
            rest.len()
        } else {
            usize::from(payload_len)
        };
        let truncated = rest.len() < declared;
        let body = rest.get(..declared).unwrap_or(rest);

        // Walk the extension headers. Each one is at least 8 bytes long,
        // so the loop ends.
        let mut kind = next_header;
        let mut offset = 0;
        let mut fragment = None;
        while kind.is_ipv6_extension() {
            let needed_from = |len: usize| Self::HEADER_LEN + offset + len;
            let head = body
                .get(offset..)
                .and_then(<[u8]>::first_chunk::<2>)
                .ok_or_else(|| {
                    Error::truncated(
                        Layer::Ipv6Extension,
                        needed_from(2),
                        data.len().min(Self::HEADER_LEN + body.len()),
                    )
                })?;
            let len = extension_len(kind, *head);
            let ext = body.get(offset..offset + len).ok_or_else(|| {
                Error::truncated(
                    Layer::Ipv6Extension,
                    needed_from(len),
                    data.len().min(Self::HEADER_LEN + body.len()),
                )
            })?;
            if kind == IpProtocol::IPV6_FRAG
                && let Some(frag) = ext.first_chunk::<8>()
            {
                fragment = Some(Ipv6Fragment::decode(*frag));
            }
            kind = IpProtocol(head[0]);
            offset += len;
        }
        Ok(Self {
            traffic_class: (h[0] << 4) | (h[1] >> 4),
            flow_label: u32::from_be_bytes([0, h[1] & 0x0f, h[2], h[3]]),
            payload_len,
            next_header,
            hop_limit: h[7],
            src: Ipv6Addr::from(*h[8..24].first_chunk::<16>().unwrap_or(&[0; 16])),
            dst: Ipv6Addr::from(*h[24..40].first_chunk::<16>().unwrap_or(&[0; 16])),
            upper_protocol: kind,
            payload: body.get(offset..).unwrap_or_default(),
            extensions: body.get(..offset).unwrap_or_default(),
            fragment,
            truncated,
        })
    }

    /// The extension headers, in order.
    #[must_use]
    pub const fn extension_headers(&self) -> ExtensionHeaders<'a> {
        ExtensionHeaders {
            kind: self.next_header,
            rest: self.extensions,
        }
    }

    /// The Fragment header, if there is one.
    #[must_use]
    pub const fn fragment(&self) -> Option<Ipv6Fragment> {
        self.fragment
    }

    /// Whether this packet is a fragment.
    #[must_use]
    pub const fn is_fragment(&self) -> bool {
        self.fragment.is_some()
    }

    /// Whether the input ended before the payload length did.
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// Bytes of fixed and extension headers.
    #[must_use]
    pub const fn header_len(&self) -> usize {
        Self::HEADER_LEN + self.extensions.len()
    }

    /// The pseudo-header for the transport checksum of this packet.
    #[must_use]
    pub const fn pseudo_header(&self) -> PseudoHeader {
        PseudoHeader::V6 {
            src: self.src,
            dst: self.dst,
        }
    }
}

/// Iterator over the extension headers of an [`Ipv6Packet`].
#[derive(Debug, Clone)]
pub struct ExtensionHeaders<'a> {
    kind: IpProtocol,
    rest: &'a [u8],
}

impl<'a> Iterator for ExtensionHeaders<'a> {
    type Item = ExtensionHeader<'a>;

    fn next(&mut self) -> Option<ExtensionHeader<'a>> {
        let head = self.rest.first_chunk::<2>()?;
        let (data, rest) = self
            .rest
            .split_at_checked(extension_len(self.kind, *head))?;
        let header = ExtensionHeader {
            kind: self.kind,
            next_header: IpProtocol(head[0]),
            data,
        };
        self.kind = header.next_header;
        self.rest = rest;
        Some(header)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_header(payload_len: u16, next: u8) -> Vec<u8> {
        let mut h = vec![0x6b, 0x81, 0x23, 0x45];
        h.extend_from_slice(&payload_len.to_be_bytes());
        h.extend_from_slice(&[next, 64]);
        h.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        h.extend_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        h
    }

    #[test]
    fn plain() {
        let mut data = fixed_header(3, 17);
        data.extend_from_slice(&[1, 2, 3, 0, 0]);
        let ip = Ipv6Packet::parse(&data).unwrap();
        assert_eq!(ip.traffic_class, 0xb8);
        assert_eq!(ip.flow_label, 0x12345);
        assert_eq!(ip.hop_limit, 64);
        assert_eq!(ip.upper_protocol, IpProtocol::UDP);
        assert_eq!(ip.payload, &[1, 2, 3]);
        assert_eq!(ip.extension_headers().count(), 0);
        assert_eq!(ip.dst, "2001:db8::1".parse::<Ipv6Addr>().unwrap());
        assert!(!ip.is_fragment());
    }

    #[test]
    fn extension_chain() {
        // Hop-by-Hop (8) -> Fragment (8) -> AH (12) -> TCP payload (2).
        let mut data = fixed_header(30, 0);
        data.extend_from_slice(&[44, 0, 1, 4, 0, 0, 0, 0]); // PadN
        data.extend_from_slice(&[51, 0, 0x00, 0x29, 0xde, 0xad, 0xbe, 0xef]); // off 5, M
        data.extend_from_slice(&[6, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2]);
        data.extend_from_slice(&[0xaa, 0xbb]);
        let ip = Ipv6Packet::parse(&data).unwrap();
        assert_eq!(ip.upper_protocol, IpProtocol::TCP);
        assert_eq!(ip.payload, &[0xaa, 0xbb]);
        assert_eq!(ip.header_len(), 68);
        let kinds: Vec<_> = ip.extension_headers().map(|e| e.kind).collect();
        assert_eq!(
            kinds,
            [IpProtocol::HOPOPT, IpProtocol::IPV6_FRAG, IpProtocol::AH]
        );
        let frag = ip.fragment().unwrap();
        assert_eq!(frag.offset, 5);
        assert!(frag.more_fragments);
        assert_eq!(frag.identification, 0xdead_beef);
        assert_eq!(frag.encode_body(), [0x00, 0x29, 0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(ip.extension_headers().nth(2).unwrap().body().len(), 10);
    }

    #[test]
    fn stops_at_esp() {
        let mut data = fixed_header(4, 50);
        data.extend_from_slice(&[1, 2, 3, 4]);
        let ip = Ipv6Packet::parse(&data).unwrap();
        assert_eq!(ip.upper_protocol, IpProtocol::ESP);
        assert_eq!(ip.payload.len(), 4);
    }

    #[test]
    fn truncation() {
        let mut data = fixed_header(16, 60);
        data.extend_from_slice(&[17, 0, 0, 0, 0, 0, 0, 0, 9, 9]);
        // Payload length says 16, only 10 present; the extension is whole.
        assert!(Ipv6Packet::parse(&data).unwrap_err().is_truncated());
        let ip = Ipv6Packet::parse_partial(&data).unwrap();
        assert!(ip.is_truncated());
        assert_eq!(ip.payload, &[9, 9]);
        // Extension header cut short is an error even when partial.
        let err = Ipv6Packet::parse_partial(&data[..44]).unwrap_err();
        assert_eq!(err.layer(), Layer::Ipv6Extension);
        assert!(
            Ipv6Packet::parse_partial(&data[..39])
                .unwrap_err()
                .is_truncated()
        );
    }

    #[test]
    fn extension_longer_than_payload_length() {
        // Payload length 8 but the header claims 16 bytes.
        let mut data = fixed_header(8, 60);
        data.extend_from_slice(&[17, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert!(Ipv6Packet::parse_partial(&data).unwrap_err().is_truncated());
    }

    #[test]
    fn jumbogram_takes_everything() {
        let mut data = fixed_header(0, 0);
        data.extend_from_slice(&[59, 0, 0xc2, 4, 0, 1, 0, 0, 7, 7, 7]);
        let ip = Ipv6Packet::parse(&data).unwrap();
        assert_eq!(ip.upper_protocol, IpProtocol::IPV6_NONXT);
        assert_eq!(ip.payload, &[7, 7, 7]);
    }

    #[test]
    fn wrong_version() {
        let mut data = fixed_header(0, 59);
        data[0] = 0x45;
        assert!(matches!(
            Ipv6Packet::parse(&data),
            Err(Error::Malformed { .. })
        ));
    }
}
