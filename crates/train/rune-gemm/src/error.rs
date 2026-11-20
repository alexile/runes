//! Error type.

use thiserror::Error;

/// Everything that can go wrong in a GEMM call. Every input is validated
/// before any output is written, so on error `C` is left untouched.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum GemmError {
    /// A view reaches past the end of its slice.
    #[error("view needs {needed} elements but the slice holds {len}")]
    OutOfBounds {
        /// Elements the view addresses (highest offset + 1).
        needed: usize,
        /// Length of the slice.
        len: usize,
    },
    /// Offset arithmetic for a view overflows `usize`.
    #[error("view offsets overflow usize")]
    Overflow,
    /// A mutable view addresses the same element twice.
    #[error("mutable view has overlapping elements (strides {strides:?})")]
    Overlapping {
        /// The strides of the rejected view.
        strides: Vec<usize>,
    },
    /// Operand shapes do not chain: `op(A)` is `m × k`, `op(B)` is `k × n`,
    /// `C` is `m × n`.
    #[error("dimension mismatch: {what} is {found}, expected {expected}")]
    DimensionMismatch {
        /// Which dimension disagrees.
        what: &'static str,
        /// The value implied by the other operands.
        expected: usize,
        /// The value found.
        found: usize,
    },
    /// A BLAS-style leading dimension is smaller than the stored row length.
    #[error("leading dimension {what} = {found} is less than {min}")]
    LeadingDimension {
        /// Which leading dimension (`lda`, `ldb` or `ldc`).
        what: &'static str,
        /// The value passed.
        found: usize,
        /// The smallest legal value.
        min: usize,
    },
}
