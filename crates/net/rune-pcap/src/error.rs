//! The crate's error type.

use std::io;

/// Everything that can go wrong when reading or writing a capture file.
///
/// Parsers never panic: input that ends early is reported as
/// [`Error::Truncated`], a structure that contradicts itself as
/// [`Error::Malformed`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The first four bytes are neither a pcap magic number nor a pcapng
    /// Section Header Block.
    #[error("not a pcap or pcapng file (magic {magic:02x?})")]
    UnknownFormat {
        /// The bytes found where the magic number should be.
        magic: [u8; 4],
    },
    /// The file declares a format version this crate cannot read.
    #[error("unsupported {what} version {major}.{minor}")]
    UnsupportedVersion {
        /// `"pcap"` or `"pcapng"`.
        what: &'static str,
        /// Major version.
        major: u16,
        /// Minor version.
        minor: u16,
    },
    /// The input ended before a header, record or block did.
    #[error("{what} truncated: need {needed} bytes, have {available}")]
    Truncated {
        /// The structure being read.
        what: &'static str,
        /// Bytes the structure needs.
        needed: usize,
        /// Bytes that were available.
        available: usize,
    },
    /// A field holds a value that makes the structure invalid.
    #[error("malformed {what}: {reason}")]
    Malformed {
        /// The structure being read.
        what: &'static str,
        /// What is wrong.
        reason: &'static str,
    },
    /// A record or block is longer than the reader's limit, or a value is
    /// too large for the field that must hold it.
    #[error("{what} too large: {len} bytes, at most {max}")]
    TooLarge {
        /// The structure being read or written.
        what: &'static str,
        /// Its length in bytes.
        len: u64,
        /// The largest length allowed.
        max: u64,
    },
    /// A pcapng packet refers to an interface that no Interface
    /// Description Block in its section declared.
    #[error("packet refers to undeclared interface {0}")]
    UnknownInterface(u32),
    /// A timestamp cannot be represented at the interface's resolution.
    #[error("timestamp out of range for the interface's resolution")]
    TimestampOutOfRange,
    /// The underlying reader or writer failed.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

impl Error {
    /// Whether the input simply ended too early, rather than being invalid.
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        matches!(self, Self::Truncated { .. })
    }

    pub(crate) const fn truncated(what: &'static str, needed: usize, available: usize) -> Self {
        Self::Truncated {
            what,
            needed,
            available,
        }
    }

    pub(crate) const fn malformed(what: &'static str, reason: &'static str) -> Self {
        Self::Malformed { what, reason }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display() {
        let err = Error::truncated("pcap record", 16, 3);
        assert_eq!(
            err.to_string(),
            "pcap record truncated: need 16 bytes, have 3"
        );
        assert!(err.is_truncated());
        let err = Error::UnknownFormat {
            magic: [0xde, 0xad, 0xbe, 0xef],
        };
        assert_eq!(
            err.to_string(),
            "not a pcap or pcapng file (magic [de, ad, be, ef])"
        );
        assert!(!err.is_truncated());
    }
}
