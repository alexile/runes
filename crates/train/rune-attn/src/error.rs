//! Error type.

use rune_gemm::GemmError;
use thiserror::Error;

/// Everything that can go wrong in an attention call. Inputs are validated
/// before any work starts; no input makes the crate panic.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum AttnError {
    /// A slice does not have the length the layout implies.
    #[error("{what} has {found} elements, expected {expected}")]
    ShapeMismatch {
        /// Which argument.
        what: &'static str,
        /// Length implied by the layout.
        expected: usize,
        /// Length found.
        found: usize,
    },
    /// `heads_kv` is zero or does not divide `heads_q`.
    #[error("heads_q = {heads_q} must be a positive multiple of heads_kv = {heads_kv}")]
    Heads {
        /// Query heads.
        heads_q: usize,
        /// Key/value heads.
        heads_kv: usize,
    },
    /// A head dimension or block size is zero.
    #[error("{what} must be positive")]
    Zero {
        /// Which size.
        what: &'static str,
    },
    /// Cumulative sequence lengths are malformed.
    #[error("invalid cumulative sequence lengths: {reason}")]
    Seqlens {
        /// What is wrong.
        reason: &'static str,
    },
    /// A scalar parameter is out of range (non-finite scale, softcap not
    /// positive and finite, empty key range, ...).
    #[error("invalid parameter: {what}")]
    Parameter {
        /// Which parameter and why.
        what: &'static str,
    },
    /// Size arithmetic overflows `usize`.
    #[error("tensor sizes overflow usize")]
    Overflow,
    /// The tile matrix multiply rejected its operands (an internal error).
    #[error(transparent)]
    Gemm(#[from] GemmError),
}
