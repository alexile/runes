//! The crate's error type.

use std::io;

/// Errors from probing a service.
///
/// Probe sessions return [`Error::Unrecognized`] when the peer does not
/// speak their protocol, and [`Error::NoResponse`] when it said nothing.
/// The other variants come from the runner and the driver.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The peer answered, but not in the probe's protocol (or not in a way
    /// the probe understands).
    #[error("not recognised as {probe}: {reason}")]
    Unrecognized {
        /// The probe's [`id`](crate::ServiceProbe::id).
        probe: String,
        /// What did not match.
        reason: String,
    },
    /// The peer sent nothing before the connection ended or timed out.
    #[error("{probe}: no response from the service")]
    NoResponse {
        /// The probe's [`id`](crate::ServiceProbe::id).
        probe: String,
    },
    /// The probe is [`Safety::Intrusive`](crate::Safety::Intrusive) and
    /// [`Options::allow_intrusive`](crate::Options::allow_intrusive) is off.
    #[error("{probe} is an intrusive probe and intrusive probes are not allowed")]
    IntrusiveNotAllowed {
        /// The probe's [`id`](crate::ServiceProbe::id).
        probe: String,
    },
    /// The probe needs a different transport than the one supplied, e.g. a
    /// UDP probe handed a byte stream.
    #[error("{probe} needs {expected}, not {actual}")]
    TransportMismatch {
        /// The probe's [`id`](crate::ServiceProbe::id).
        probe: String,
        /// The transport the probe declares.
        expected: crate::Transport,
        /// The transport it was given.
        actual: crate::Transport,
    },
    /// The host name resolved to no address.
    #[error("{host} resolved to no address")]
    Resolve {
        /// The host name that was looked up.
        host: String,
    },
    /// Connecting (including name resolution) took longer than the connect
    /// timeout or the total timeout.
    #[error("connecting to {host}:{port} timed out")]
    ConnectTimeout {
        /// Target host.
        host: String,
        /// Target port.
        port: u16,
    },
    /// Connecting failed, e.g. the port is closed.
    #[error("connecting to {host}:{port} failed: {source}")]
    Connect {
        /// Target host.
        host: String,
        /// Target port.
        port: u16,
        /// The underlying error.
        source: io::Error,
    },
}

impl Error {
    /// [`Error::Unrecognized`] for `probe`.
    pub fn unrecognized(probe: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::Unrecognized {
            probe: probe.into(),
            reason: reason.into(),
        }
    }

    /// [`Error::NoResponse`] for `probe`.
    pub fn no_response(probe: impl Into<String>) -> Self {
        Self::NoResponse {
            probe: probe.into(),
        }
    }

    /// True when the target could not be reached at all (resolution or
    /// connection failed), as opposed to a service that answered.
    #[must_use]
    pub const fn is_unreachable(&self) -> bool {
        matches!(
            self,
            Self::Resolve { .. } | Self::ConnectTimeout { .. } | Self::Connect { .. }
        )
    }
}
