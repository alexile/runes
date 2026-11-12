//! The crate's error type.

/// Errors from parsing SMTP and FTP replies.
///
/// The probes report through [`rune_service_probe::Error`]; this is what
/// [`parse_reply`](crate::parse_reply) returns.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The bytes are not a reply in the expected format.
    #[error("malformed {0}")]
    Malformed(&'static str),
    /// A multi-line reply has more than
    /// [`MAX_REPLY_LINES`](crate::MAX_REPLY_LINES) lines.
    #[error("reply has too many lines")]
    TooManyLines,
}
