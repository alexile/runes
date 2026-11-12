//! `HAProxy` [PROXY protocol] v1 (text) and v2 (binary, with TLV extensions):
//! a sans-I/O decoder and encoder, with an optional tokio adapter.
//!
//! A load balancer that relays a TCP (or UDP) connection prepends a PROXY
//! header so the backend can recover the real client address. [`decode`]
//! parses either version from the start of a buffer and reports how many
//! bytes the header took; everything after it is application data.
//! [`Header::encode_v1`] and [`Header::encode_v2`] produce headers for the
//! sending side.
//!
//! v2 TLVs are kept raw in [`Header::tlvs`], with typed accessors for the
//! registered ones ([`Header::alpn`], [`Header::authority`],
//! [`Header::unique_id`], [`Header::netns`], [`Header::ssl`]). A
//! `PP2_TYPE_CRC32C` TLV is verified when decoding and filled in when
//! encoding.
//!
//! **Trust:** only accept a PROXY header from peers you trust (your own load
//! balancers). Anyone who can send one can claim any client address.
//!
//! [PROXY protocol]: https://www.haproxy.org/download/3.0/doc/proxy-protocol.txt
//!
//! # Example
//!
//! ```
//! use rune_proxy_protocol::{Header, Version, decode};
//!
//! // Receiving side: the header, then the application data.
//! let input = b"PROXY TCP4 192.0.2.10 198.51.100.1 51234 443\r\nGET / HTTP/1.1\r\n";
//! let parsed = decode(input)?.expect("complete header");
//! assert_eq!(parsed.version, Version::V1);
//! assert_eq!(parsed.header.source(), Some("192.0.2.10:51234".parse()?));
//! assert_eq!(&input[parsed.len..], b"GET / HTTP/1.1\r\n");
//!
//! // Sending side: a v2 header with an authority TLV and a checksum.
//! let header = Header::tcp("[2001:db8::7]:40000".parse()?, "[2001:db8::1]:443".parse()?)
//!     .expect("same IP family")
//!     .with_tlv(rune_proxy_protocol::Tlv::new(
//!         rune_proxy_protocol::tlv::PP2_TYPE_AUTHORITY,
//!         "api.example.com",
//!     ))
//!     .with_crc32c();
//! let bytes = header.encode_v2()?;
//! let back = decode(&bytes)?.expect("complete header");
//! assert_eq!(back.header.authority(), Some("api.example.com"));
//! assert_eq!(back.len, bytes.len());
//!
//! // A truncated header asks for more bytes instead of failing.
//! assert!(decode(&bytes[..20])?.is_none());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod error;
mod header;
pub mod tlv;
#[cfg(feature = "tokio")]
pub mod tokio;
pub mod v1;
pub mod v2;

pub use error::Error;
pub use header::{Addresses, Command, Header, Transport, UNIX_ADDR_LEN, Version};
pub use tlv::{Ssl, Tlv};

/// A header decoded by [`decode`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Parsed {
    /// The decoded header.
    pub header: Header,
    /// Which wire version it used.
    pub version: Version,
    /// How many bytes of the input the header took. Application data starts
    /// at this offset.
    pub len: usize,
}

/// Decodes a PROXY header (v1 or v2) at the start of `buf`.
///
/// Returns `Ok(None)` while `buf` is a valid but incomplete prefix of a
/// header (including an empty buffer): read more bytes and call again.
///
/// # Errors
///
/// [`Error::NotProxyProtocol`] if `buf` cannot start a PROXY header, and
/// the version-specific errors for a malformed one.
pub fn decode(buf: &[u8]) -> Result<Option<Parsed>, Error> {
    let (result, version) = if buf.starts_with(v2::SIGNATURE) {
        (v2::decode(buf)?, Version::V2)
    } else if buf.starts_with(v1::SIGNATURE) {
        (v1::decode(buf)?, Version::V1)
    } else if v2::SIGNATURE.starts_with(buf) || v1::SIGNATURE.starts_with(buf) {
        return Ok(None);
    } else {
        return Err(Error::NotProxyProtocol);
    };
    Ok(result.map(|(header, len)| Parsed {
        header,
        version,
        len,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes_need_more_bytes() {
        assert!(decode(b"").unwrap().is_none());
        assert!(decode(b"PRO").unwrap().is_none());
        assert!(decode(b"PROXY").unwrap().is_none());
        assert!(decode(b"\r\n\r\n\0\r\nQU").unwrap().is_none());
    }

    #[test]
    fn other_protocols_are_rejected() {
        for bad in [
            &b"GET / HTTP/1.1\r\n"[..],
            b"\x16\x03\x01",
            b"\r\n\r\nX",
            b"PROXZ",
        ] {
            assert!(matches!(decode(bad), Err(Error::NotProxyProtocol)));
        }
    }

    #[test]
    fn versions_are_reported() {
        let v1 = decode(b"PROXY UNKNOWN\r\n").unwrap().unwrap();
        assert_eq!(v1.version, Version::V1);
        let bytes = Header::local().encode_v2().unwrap();
        let v2 = decode(&bytes).unwrap().unwrap();
        assert_eq!(v2.version, Version::V2);
        assert_eq!(v2.len, 16);
    }
}
