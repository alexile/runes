//! The crate's error type.

/// Why the middleware could not be set up.
///
/// Per-request outcomes are not errors: they are
/// [`ClientCertRejection`](crate::ClientCertRejection) responses.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The trust anchors could not be read.
    #[error("invalid trust anchors: {0}")]
    TrustStore(#[from] rune_x509::Error),
    /// A socket operation failed.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
