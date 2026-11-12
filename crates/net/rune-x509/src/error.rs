//! The crate's error type.

/// Why certificate input could not be read.
///
/// Problems found *in* a well-formed certificate (weak keys, expiry, a
/// broken chain) are not errors: they are reported as
/// [`Weakness`](crate::Weakness) and [`ChainIssue`](crate::ChainIssue)
/// values.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The DER bytes are not a valid X.509 certificate.
    #[error("invalid certificate DER: {reason}")]
    Der {
        /// What the parser rejected.
        reason: String,
    },
    /// The certificate parsed, but bytes follow its outer `SEQUENCE`.
    #[error("{len} trailing bytes after the certificate")]
    TrailingData {
        /// Number of bytes after the certificate.
        len: usize,
    },
    /// A PEM block is malformed (bad header, missing end line, bad base64).
    #[error("invalid PEM: {reason}")]
    Pem {
        /// What the PEM reader rejected.
        reason: String,
    },
    /// The input holds no `CERTIFICATE` PEM block.
    #[error("no CERTIFICATE block in the PEM input")]
    NoCertificate,
}
