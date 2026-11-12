//! The crate's error type.

/// Errors returned by this crate.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A parameter is out of its valid range.
    #[error("invalid parameter `{name}`: {reason}")]
    InvalidParameter {
        /// Name of the parameter.
        name: &'static str,
        /// Why the value was rejected.
        reason: &'static str,
    },
    /// Two MinHash signatures of different lengths were compared.
    #[error("signature lengths differ: {left} vs {right}")]
    LengthMismatch {
        /// Length of the left-hand signature.
        left: usize,
        /// Length of the right-hand signature.
        right: usize,
    },
}
