//! The crate's error type.

/// Errors from decoding LDAP messages.
///
/// The probes report through [`rune_service_probe::Error`]; this type is
/// what the sans-I/O decoders ([`parse_message`](crate::parse_message),
/// [`Message::decode`](crate::Message::decode)) return. Probe sessions
/// treat [`Error::Truncated`] as "keep reading" while the connection is
/// open.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The bytes end before the element does. More bytes may complete it.
    #[error("truncated {what}")]
    Truncated {
        /// The element being read, e.g. `LDAPMessage`.
        what: &'static str,
    },
    /// The bytes cannot be the element, however many more arrive.
    #[error("malformed {what}: {reason}")]
    Malformed {
        /// The element being read.
        what: &'static str,
        /// What is wrong with it.
        reason: String,
    },
}

impl Error {
    pub(crate) fn malformed(what: &'static str, reason: impl Into<String>) -> Self {
        Self::Malformed {
            what,
            reason: reason.into(),
        }
    }

    /// True for [`Error::Truncated`]: more bytes may complete the input.
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        matches!(self, Self::Truncated { .. })
    }
}
