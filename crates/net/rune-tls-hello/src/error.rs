//! The crate's error type.

use crate::{ContentType, ExtensionType, HandshakeType};

/// Errors returned by this crate.
///
/// [`Error::Incomplete`] is the one recoverable variant: the input ends
/// before a record or message does, and the caller should read more bytes
/// and try again. Every other variant means the bytes are not a valid TLS
/// structure (or, when encoding, that a value does not fit its length
/// prefix).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The input ends inside a record or handshake message. At least
    /// `needed` more bytes are required; a later header can ask for more.
    #[error("incomplete input: need at least {needed} more bytes")]
    Incomplete {
        /// Minimum number of further bytes needed to make progress.
        needed: usize,
    },
    /// A field is cut short by the record, message or vector holding it.
    #[error("{what} is truncated")]
    Truncated {
        /// The structure being read.
        what: &'static str,
    },
    /// A structure is followed by bytes its length prefix does not cover.
    #[error("{what} has {count} unexpected trailing bytes")]
    TrailingBytes {
        /// The structure being read.
        what: &'static str,
        /// Number of bytes left over.
        count: usize,
    },
    /// A value breaks the wire format's rules.
    #[error("malformed {what}: {reason}")]
    Malformed {
        /// The structure being read.
        what: &'static str,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// A length exceeds a protocol or configured limit.
    #[error("{what} is {len} bytes, more than the limit of {max}")]
    TooLong {
        /// The structure being read or written.
        what: &'static str,
        /// Its length in bytes.
        len: usize,
        /// The limit in bytes.
        max: usize,
    },
    /// The input starts with an SSL 2.0 record header, which this crate
    /// does not parse.
    #[error("SSL 2.0 record header (not supported)")]
    Sslv2,
    /// A record of another content type arrived where a different one was
    /// required.
    #[error("expected a {expected} record, found {found}")]
    UnexpectedContentType {
        /// The content type required here.
        expected: ContentType,
        /// The content type found.
        found: ContentType,
    },
    /// A handshake message of another type arrived where a different one
    /// was required.
    #[error("expected a {expected} message, found {found}")]
    UnexpectedHandshakeType {
        /// The message type required here.
        expected: HandshakeType,
        /// The message type found.
        found: HandshakeType,
    },
    /// The same extension type appears twice in one hello
    /// ([RFC 8446 §4.2](https://www.rfc-editor.org/rfc/rfc8446#section-4.2)).
    #[error("duplicate extension {0}")]
    DuplicateExtension(ExtensionType),
}

impl Error {
    /// Whether more input could resolve this error ([`Error::Incomplete`]).
    #[must_use]
    pub const fn is_incomplete(&self) -> bool {
        matches!(self, Self::Incomplete { .. })
    }
}
