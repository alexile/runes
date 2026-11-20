//! Error type.

use rune_gemm::GemmError;
use thiserror::Error;

/// Everything that can go wrong in a fused op. Inputs are validated before
/// any output is written, so on error the outputs are left untouched.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum FusedError {
    /// A buffer has the wrong length for the shape of the call.
    #[error("length mismatch: {what} has {found} elements, expected {expected}")]
    LengthMismatch {
        /// Which buffer.
        what: &'static str,
        /// The length implied by the shape.
        expected: usize,
        /// The length found.
        found: usize,
    },
    /// A buffer length is not a whole number of rows.
    #[error("{what} has {len} elements, not a multiple of the row length {row}")]
    RaggedRows {
        /// Which buffer.
        what: &'static str,
        /// Its length.
        len: usize,
        /// The row length it should be a multiple of.
        row: usize,
    },
    /// A size or scalar parameter is out of its legal range.
    #[error("invalid parameter {name}: {reason}")]
    InvalidParameter {
        /// The parameter.
        name: &'static str,
        /// What it must satisfy.
        reason: &'static str,
    },
    /// A target class is neither `ignore_index` nor in `0..vocab`.
    #[error("target {target} at token {index} is outside 0..{vocab}")]
    TargetOutOfRange {
        /// Token index.
        index: usize,
        /// The target found.
        target: i64,
        /// Vocabulary size.
        vocab: usize,
    },
    /// A position id is not covered by the rotary table.
    #[error("position {position} at token {index} is outside the table (0..{len})")]
    PositionOutOfRange {
        /// Token index.
        index: usize,
        /// The position found.
        position: usize,
        /// Number of positions in the table.
        len: usize,
    },
    /// A size computation overflows `usize`.
    #[error("size computation overflows usize")]
    Overflow,
    /// The matrix multiply inside the fused linear cross-entropy failed.
    #[error(transparent)]
    Gemm(#[from] GemmError),
}

pub const fn check_len(
    what: &'static str,
    expected: usize,
    found: usize,
) -> Result<(), FusedError> {
    if expected == found {
        Ok(())
    } else {
        Err(FusedError::LengthMismatch {
            what,
            expected,
            found,
        })
    }
}

/// Number of rows of length `row` in a buffer, failing on 0 or ragged
/// lengths.
pub const fn rows_of(what: &'static str, len: usize, row: usize) -> Result<usize, FusedError> {
    if row == 0 {
        return Err(FusedError::InvalidParameter {
            name: "row length",
            reason: "must be positive",
        });
    }
    if !len.is_multiple_of(row) {
        return Err(FusedError::RaggedRows { what, len, row });
    }
    Ok(len / row)
}

pub fn mul(a: usize, b: usize) -> Result<usize, FusedError> {
    a.checked_mul(b).ok_or(FusedError::Overflow)
}

pub const fn invalid(name: &'static str, reason: &'static str) -> FusedError {
    FusedError::InvalidParameter { name, reason }
}
