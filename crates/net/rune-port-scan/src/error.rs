//! The crate's error type.

/// Errors from parsing port lists and planning a scan.
///
/// Per-port connect failures are not errors: they are reported as a
/// [`PortState`](crate::PortState) in the scan report.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// An item of a port list could not be parsed.
    #[error("invalid port list item {item:?}: {reason}")]
    InvalidPorts {
        /// The offending item, trimmed (bounded to 64 characters).
        item: String,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// The scan would make more connection attempts than
    /// [`Options::max_targets`](crate::Options::max_targets) allows.
    #[error("scan of {count} host/port pairs exceeds the limit of {max}")]
    TooManyTargets {
        /// Hosts × ports requested.
        count: u64,
        /// The configured limit.
        max: u64,
    },
}

impl Error {
    pub(crate) fn invalid(item: &str, reason: &'static str) -> Self {
        Self::InvalidPorts {
            item: item.chars().take(64).collect(),
            reason,
        }
    }
}

/// Shorthand for results with this crate's [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;
