//! The decoded header model shared by v1 and v2.

use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

use crate::Error;
use crate::tlv::{self, Ssl, Tlv};

/// Length of a UNIX socket address field in a v2 header.
pub const UNIX_ADDR_LEN: usize = 108;

/// PROXY protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Version {
    /// Version 1, the human-readable text form.
    V1,
    /// Version 2, the binary form with TLV extensions.
    V2,
}

/// What the receiver should do with the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Command {
    /// The proxy opened the connection itself (for example a health check).
    /// The receiver uses the real connection endpoints.
    Local,
    /// The connection is relayed on behalf of a client; the header carries
    /// the original endpoints.
    Proxy,
}

/// The transport protocol of the proxied connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Transport {
    /// Unknown or unspecified (`UNKNOWN` in v1, `UNSPEC` in v2).
    Unspecified,
    /// A stream protocol: TCP, or `SOCK_STREAM` for UNIX sockets.
    Stream,
    /// A datagram protocol: UDP, or `SOCK_DGRAM` for UNIX sockets.
    Datagram,
}

/// The original source and destination of the proxied connection.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Addresses {
    /// No address information (`UNKNOWN` in v1, `AF_UNSPEC` or `LOCAL` in v2).
    Unspecified,
    /// IPv4 endpoints.
    Ipv4 {
        /// The client (source) address.
        source: SocketAddrV4,
        /// The address the client connected to.
        destination: SocketAddrV4,
    },
    /// IPv6 endpoints. Flow info and scope id are not carried on the wire
    /// and decode as zero.
    Ipv6 {
        /// The client (source) address.
        source: SocketAddrV6,
        /// The address the client connected to.
        destination: SocketAddrV6,
    },
    /// UNIX socket paths (v2 only). Each is at most [`UNIX_ADDR_LEN`] bytes;
    /// the NUL padding on the wire is stripped when decoding.
    Unix {
        /// The source path.
        source: Vec<u8>,
        /// The destination path.
        destination: Vec<u8>,
    },
}

impl Addresses {
    /// IP endpoints from a pair of socket addresses, or `None` if one is
    /// IPv4 and the other IPv6.
    #[must_use]
    pub const fn from_socket_addrs(source: SocketAddr, destination: SocketAddr) -> Option<Self> {
        match (source, destination) {
            (SocketAddr::V4(source), SocketAddr::V4(destination)) => Some(Self::Ipv4 {
                source,
                destination,
            }),
            (SocketAddr::V6(source), SocketAddr::V6(destination)) => Some(Self::Ipv6 {
                source,
                destination,
            }),
            _ => None,
        }
    }

    /// The client address, for IP endpoints.
    #[must_use]
    pub const fn source(&self) -> Option<SocketAddr> {
        match self {
            Self::Ipv4 { source, .. } => Some(SocketAddr::V4(*source)),
            Self::Ipv6 { source, .. } => Some(SocketAddr::V6(*source)),
            Self::Unspecified | Self::Unix { .. } => None,
        }
    }

    /// The address the client connected to, for IP endpoints.
    #[must_use]
    pub const fn destination(&self) -> Option<SocketAddr> {
        match self {
            Self::Ipv4 { destination, .. } => Some(SocketAddr::V4(*destination)),
            Self::Ipv6 { destination, .. } => Some(SocketAddr::V6(*destination)),
            Self::Unspecified | Self::Unix { .. } => None,
        }
    }
}

/// A PROXY protocol header, independent of its wire version.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Header {
    /// `LOCAL` or `PROXY`. v1 headers are always [`Command::Proxy`].
    pub command: Command,
    /// The transport protocol of the proxied connection.
    pub transport: Transport,
    /// The original endpoints.
    pub addresses: Addresses,
    /// v2 TLV extensions, in wire order. Always empty for v1.
    pub tlvs: Vec<Tlv>,
}

impl Header {
    /// A `PROXY` header for a TCP connection between two socket addresses,
    /// or `None` if one is IPv4 and the other IPv6.
    #[must_use]
    pub fn tcp(source: SocketAddr, destination: SocketAddr) -> Option<Self> {
        Addresses::from_socket_addrs(source, destination)
            .map(|addresses| Self::new(Command::Proxy, Transport::Stream, addresses))
    }

    /// A `PROXY` header for a UDP flow between two socket addresses (v2
    /// only), or `None` if one is IPv4 and the other IPv6.
    #[must_use]
    pub fn udp(source: SocketAddr, destination: SocketAddr) -> Option<Self> {
        Addresses::from_socket_addrs(source, destination)
            .map(|addresses| Self::new(Command::Proxy, Transport::Datagram, addresses))
    }

    /// A `LOCAL` header with no address information, as sent by health
    /// checks (v2), or `PROXY UNKNOWN` when encoded as v1.
    #[must_use]
    pub const fn local() -> Self {
        Self::new(
            Command::Local,
            Transport::Unspecified,
            Addresses::Unspecified,
        )
    }

    /// A header from its parts, with no TLVs.
    #[must_use]
    pub const fn new(command: Command, transport: Transport, addresses: Addresses) -> Self {
        Self {
            command,
            transport,
            addresses,
            tlvs: Vec::new(),
        }
    }

    /// Appends a TLV.
    #[must_use]
    pub fn with_tlv(mut self, tlv: Tlv) -> Self {
        self.tlvs.push(tlv);
        self
    }

    /// Appends a `PP2_TYPE_CRC32C` TLV. [`Header::encode_v2`] fills in the
    /// checksum over the finished header.
    #[must_use]
    pub fn with_crc32c(self) -> Self {
        self.with_tlv(Tlv::new(tlv::PP2_TYPE_CRC32C, vec![0; 4]))
    }

    /// The client address, for IP endpoints.
    #[must_use]
    pub const fn source(&self) -> Option<SocketAddr> {
        self.addresses.source()
    }

    /// The address the client connected to, for IP endpoints.
    #[must_use]
    pub const fn destination(&self) -> Option<SocketAddr> {
        self.addresses.destination()
    }

    /// The first TLV of the given type.
    #[must_use]
    pub fn tlv(&self, kind: u8) -> Option<&Tlv> {
        self.tlvs.iter().find(|t| t.kind == kind)
    }

    /// The `PP2_TYPE_ALPN` value: the negotiated application protocol.
    #[must_use]
    pub fn alpn(&self) -> Option<&[u8]> {
        self.tlv(tlv::PP2_TYPE_ALPN).map(|t| t.value.as_slice())
    }

    /// The `PP2_TYPE_AUTHORITY` value (the TLS SNI host name), if it is UTF-8.
    #[must_use]
    pub fn authority(&self) -> Option<&str> {
        self.tlv(tlv::PP2_TYPE_AUTHORITY)
            .and_then(|t| std::str::from_utf8(&t.value).ok())
    }

    /// The `PP2_TYPE_UNIQUE_ID` value: an opaque connection identifier.
    #[must_use]
    pub fn unique_id(&self) -> Option<&[u8]> {
        self.tlv(tlv::PP2_TYPE_UNIQUE_ID)
            .map(|t| t.value.as_slice())
    }

    /// The `PP2_TYPE_NETNS` value (network namespace name), if it is UTF-8.
    #[must_use]
    pub fn netns(&self) -> Option<&str> {
        self.tlv(tlv::PP2_TYPE_NETNS)
            .and_then(|t| std::str::from_utf8(&t.value).ok())
    }

    /// The `PP2_TYPE_SSL` TLV, parsed with its sub-TLVs.
    ///
    /// Returns `None` when absent and `Some(Err(_))` when malformed.
    #[must_use]
    pub fn ssl(&self) -> Option<Result<Ssl, Error>> {
        self.tlv(tlv::PP2_TYPE_SSL).map(|t| Ssl::decode(&t.value))
    }

    /// Encodes the header in the given version.
    ///
    /// # Errors
    ///
    /// As [`Header::encode_v1`] or [`Header::encode_v2`].
    pub fn encode(&self, version: Version) -> Result<Vec<u8>, Error> {
        match version {
            Version::V1 => self.encode_v1().map(String::into_bytes),
            Version::V2 => self.encode_v2(),
        }
    }

    /// Encodes the header as a v1 text line, including the trailing CRLF.
    ///
    /// IP endpoints over TCP give `PROXY TCP4 …` or `PROXY TCP6 …`;
    /// [`Addresses::Unspecified`] (with any command) gives `PROXY UNKNOWN`.
    ///
    /// # Errors
    ///
    /// [`Error::NotRepresentableInV1`] for UNIX addresses, a non-stream
    /// transport, a `LOCAL` header with addresses, or any TLV.
    pub fn encode_v1(&self) -> Result<String, Error> {
        crate::v1::encode(self)
    }

    /// Encodes the header as a v2 binary block.
    ///
    /// If a `PP2_TYPE_CRC32C` TLV with a 4-byte value is present, its value
    /// is replaced by the checksum of the encoded header.
    ///
    /// # Errors
    ///
    /// [`Error::TooLong`] if a TLV value, a UNIX path or the whole block does
    /// not fit its length field.
    pub fn encode_v2(&self) -> Result<Vec<u8>, Error> {
        crate::v2::encode(self)
    }
}
