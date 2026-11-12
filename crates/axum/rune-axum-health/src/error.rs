use std::time::Duration;

/// Errors returned by this crate.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// [`HealthState::drain`](crate::HealthState::drain) gave up before
    /// every tracked request finished.
    #[error("{in_flight} request(s) still in flight after waiting {timeout:?} to drain")]
    DrainTimeout {
        /// Requests still in flight when the timeout expired.
        in_flight: usize,
        /// The timeout that expired.
        timeout: Duration,
    },
    /// Installing an OS signal handler failed (`shutdown_signal`, behind
    /// the `signal` feature).
    #[error("installing a shutdown signal handler failed: {0}")]
    Signal(#[from] std::io::Error),
}
