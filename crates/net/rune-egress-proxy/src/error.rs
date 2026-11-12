//! The crate's error type.

/// Why a policy entry or a client's request head was rejected.
///
/// Socket errors in the [`Proxy`](crate::Proxy) are plain
/// [`std::io::Error`]s; this enum covers configuration and the sans-I/O
/// request parser.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A host allowlist pattern failed to parse.
    #[error("invalid host pattern {pattern:?}: {source}")]
    HostPattern {
        /// The pattern as given.
        pattern: String,
        /// Why it was rejected.
        source: rune_host_match::Error,
    },
    /// An IP or CIDR allowlist entry failed to parse.
    #[error("invalid IP or CIDR {entry:?}: {reason}")]
    Cidr {
        /// The entry as given.
        entry: String,
        /// Why it was rejected.
        reason: String,
    },
    /// The request head is longer than the configured limit and still has
    /// no terminating blank line.
    #[error("request head exceeds {max} bytes")]
    HeadTooLarge {
        /// The configured limit.
        max: usize,
    },
    /// The request head is not valid HTTP/1.x (bad request line, non-UTF-8
    /// bytes, a control character, an unsupported version).
    #[error("malformed request: {0}")]
    Malformed(&'static str),
    /// The method is not `CONNECT`. This proxy only tunnels.
    #[error("method {0:?} is not supported, only CONNECT")]
    UnsupportedMethod(String),
    /// The CONNECT target is not `host:port` authority form
    /// ([RFC 9110 §9.3.6](https://www.rfc-editor.org/rfc/rfc9110#section-9.3.6)).
    #[error("invalid CONNECT target {target:?}: {reason}")]
    InvalidTarget {
        /// The target as sent (truncated to 256 bytes).
        target: String,
        /// Why it was rejected.
        reason: &'static str,
    },
}

impl Error {
    /// The HTTP status code a proxy answers this error with, if it is a
    /// request error: 400, 431 or 501. Configuration errors return `None`.
    ///
    /// ```
    /// use rune_egress_proxy::Error;
    ///
    /// assert_eq!(Error::UnsupportedMethod("GET".into()).status(), Some(501));
    /// assert_eq!(Error::HeadTooLarge { max: 8192 }.status(), Some(431));
    /// ```
    #[must_use]
    pub const fn status(&self) -> Option<u16> {
        match self {
            Self::HostPattern { .. } | Self::Cidr { .. } => None,
            Self::HeadTooLarge { .. } => Some(431),
            Self::Malformed(_) | Self::InvalidTarget { .. } => Some(400),
            Self::UnsupportedMethod(_) => Some(501),
        }
    }
}
