//! The crate's error type.

/// Why a scan could not run.
///
/// What the server answers (alerts, refusals, garbage) is not an error: it
/// is an [`Outcome`](crate::Outcome) recorded in the
/// [`Report`](crate::Report).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A hello could not be encoded (a field over its length limit).
    #[error("cannot build the ClientHello: {0}")]
    Hello(#[from] rune_tls_hello::Error),
    /// The target could not be reached.
    #[error(transparent)]
    Probe(#[from] rune_service_probe::Error),
}
