//! The crate's error type.

/// Errors from parsing SSH wire data.
///
/// The probe itself reports through [`rune_service_probe::Error`]; this
/// type is what the sans-I/O parsers ([`Identification::parse`],
/// [`parse_packet`], [`KexInit::parse`], [`HostKey::parse`]) return.
///
/// [`Identification::parse`]: crate::Identification::parse
/// [`parse_packet`]: crate::parse_packet
/// [`KexInit::parse`]: crate::KexInit::parse
/// [`HostKey::parse`]: crate::HostKey::parse
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The identification string does not follow RFC 4253 §4.2.
    #[error("invalid identification string: {0}")]
    Identification(&'static str),
    /// The data ended in the middle of a field.
    #[error("truncated {0}")]
    Truncated(&'static str),
    /// A field holds a value the format does not allow.
    #[error("malformed {0}")]
    Malformed(&'static str),
    /// A binary packet's length is out of range.
    #[error("packet length {0} is out of range")]
    PacketLength(u32),
    /// The payload is not the message the parser expects.
    #[error("expected SSH message {expected}, got {actual}")]
    UnexpectedMessage {
        /// The message number the parser wanted.
        expected: u8,
        /// The message number that arrived.
        actual: u8,
    },
}
