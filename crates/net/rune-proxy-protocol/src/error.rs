//! The crate's error type.

/// Errors returned when decoding or encoding a PROXY protocol header.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The input does not start with a PROXY protocol v1 or v2 signature.
    #[error("not a PROXY protocol header")]
    NotProxyProtocol,
    /// A v1 header has no CRLF within the 107-byte limit.
    #[error("PROXY v1 header is longer than 107 bytes")]
    V1TooLong,
    /// A v1 header is malformed.
    #[error("invalid PROXY v1 header: {0}")]
    InvalidV1(&'static str),
    /// A v2 header has a version nibble other than 2.
    #[error("unsupported PROXY v2 version nibble {0:#x}")]
    UnsupportedVersion(u8),
    /// A v2 header has a command other than LOCAL (0) or PROXY (1).
    #[error("unsupported PROXY v2 command {0:#x}")]
    UnsupportedCommand(u8),
    /// A v2 header has an unknown address family (high nibble of byte 13).
    #[error("unsupported PROXY v2 address family {0:#x}")]
    UnsupportedFamily(u8),
    /// A v2 header has an unknown transport protocol (low nibble of byte 13).
    #[error("unsupported PROXY v2 transport protocol {0:#x}")]
    UnsupportedTransport(u8),
    /// A v2 address block is shorter than its address family requires.
    #[error("PROXY v2 address block is {len} bytes, the family needs {needed}")]
    AddressBlockTooShort {
        /// Length of the block announced by the header.
        len: usize,
        /// Length the address family needs.
        needed: usize,
    },
    /// A TLV (or SSL sub-TLV) runs past the end of its enclosing block.
    #[error("truncated TLV")]
    TruncatedTlv,
    /// The `PP2_TYPE_CRC32C` TLV does not match the header.
    #[error("CRC32C mismatch: header says {expected:#010x}, computed {actual:#010x}")]
    ChecksumMismatch {
        /// Checksum carried in the TLV.
        expected: u32,
        /// Checksum computed over the header.
        actual: u32,
    },
    /// The header cannot be encoded in the requested version (for example
    /// UNIX addresses, UDP or TLVs in v1).
    #[error("cannot encode in PROXY v1: {0}")]
    NotRepresentableInV1(&'static str),
    /// A value does not fit its wire field (v2 length over 65 535 bytes, a
    /// TLV over 65 535 bytes, a UNIX path over 108 bytes).
    #[error("{0} is too long to encode")]
    TooLong(&'static str),
    /// An I/O error from the tokio adapter.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
