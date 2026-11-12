//! The crate's error type.

/// Errors from parsing fingerprint inputs and fingerprint lists.
///
/// Computing a fingerprint from an already parsed hello, request or SYN
/// never fails; only the parsers in this crate return errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// An HTTP/1 request head could not be read.
    #[error("invalid HTTP request head: {reason}")]
    InvalidHttpRequest {
        /// What was wrong.
        reason: &'static str,
    },

    /// TCP options were truncated or carried a bad length byte.
    #[error("invalid TCP options at offset {offset}: {reason}")]
    InvalidTcpOptions {
        /// Byte offset of the bad option.
        offset: usize,
        /// What was wrong.
        reason: &'static str,
    },

    /// A line of a fingerprint list could not be read.
    #[error("fingerprint list line {line}: {reason}")]
    InvalidDatabaseLine {
        /// 1-based line number.
        line: usize,
        /// What was wrong.
        reason: &'static str,
    },
}
