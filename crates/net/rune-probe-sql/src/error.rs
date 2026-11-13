//! The crate's error type.

/// Errors from parsing a server's handshake bytes.
///
/// Probe sessions treat [`Error::Truncated`] as "keep reading" while the
/// connection is open, and turn either variant into
/// [`rune_service_probe::Error::Unrecognized`] when it ends.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The bytes end before the structure does. More bytes may complete it.
    #[error("truncated {what}")]
    Truncated {
        /// The structure being read, e.g. `mysql handshake`.
        what: &'static str,
    },
    /// The bytes cannot be the structure, however many more arrive.
    #[error("malformed {what}: {reason}")]
    Malformed {
        /// The structure being read.
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

    /// This error as the [`rune_service_probe::Error`] a session reports.
    /// For errors inside a message whose length said it was complete: a
    /// short element there is malformed, since more bytes cannot fix it.
    pub(crate) fn within_complete_message(self) -> Self {
        match self {
            Self::Truncated { what } => Self::malformed(what, "element overruns its message"),
            e @ Self::Malformed { .. } => e,
        }
    }

    pub(crate) fn into_probe_error(self, probe: &str) -> rune_service_probe::Error {
        rune_service_probe::Error::unrecognized(probe, self.to_string())
    }
}
