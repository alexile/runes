//! Error type.

use rune_gemm::GemmError;
use thiserror::Error;

/// Everything that can go wrong. Inputs are validated before anything is
/// written, so on error parameters, gradients and optimizer state are left
/// untouched.
#[derive(Debug, Clone, PartialEq, Error)]
#[non_exhaustive]
pub enum OptimError {
    /// The number of parameter or gradient slices differs from the number of
    /// registered tensors.
    #[error("{what}: expected {expected} tensors, found {found}")]
    TensorCount {
        /// `"params"` or `"grads"` (or another list name).
        what: &'static str,
        /// Number of registered tensors.
        expected: usize,
        /// Number passed.
        found: usize,
    },
    /// A slice has the wrong length.
    #[error("{what} {index}: expected {expected} elements, found {found}")]
    LengthMismatch {
        /// Which buffer.
        what: &'static str,
        /// Tensor index.
        index: usize,
        /// Expected length.
        expected: usize,
        /// Length found.
        found: usize,
    },
    /// A matrix shape does not match the tensor length, or a dimension is
    /// zero where it may not be.
    #[error("tensor {index}: shape {rows} x {cols} does not fit {len} elements")]
    BadShape {
        /// Tensor index.
        index: usize,
        /// Rows.
        rows: usize,
        /// Columns.
        cols: usize,
        /// Tensor length.
        len: usize,
    },
    /// A tensor refers to a parameter group that does not exist.
    #[error("tensor {index}: group {group} does not exist ({groups} groups)")]
    UnknownGroup {
        /// Tensor index.
        index: usize,
        /// Requested group.
        group: usize,
        /// Number of groups.
        groups: usize,
    },
    /// A hyperparameter is out of range or not finite.
    #[error("invalid {name} = {value}: {reason}")]
    InvalidHyperparameter {
        /// Hyperparameter name.
        name: &'static str,
        /// The value passed (widened to `f64`).
        value: f64,
        /// The rule it breaks.
        reason: &'static str,
    },
    /// A flat-buffer layout has a tensor that overlaps another or leaves the
    /// buffer.
    #[error("flat layout: tensor {index} at {start}..{end} {reason}")]
    BadLayout {
        /// Tensor index.
        index: usize,
        /// First element.
        start: usize,
        /// One past the last element.
        end: usize,
        /// What is wrong.
        reason: &'static str,
    },
    /// A schedule description is inconsistent.
    #[error("invalid schedule: {0}")]
    InvalidSchedule(&'static str),
    /// Restored state does not match the registered tensors.
    #[error("state of tensor {index} is inconsistent: {reason}")]
    CorruptState {
        /// Tensor index.
        index: usize,
        /// What is wrong.
        reason: &'static str,
    },
    /// The matrix multiply failed (only for malformed shapes, which are
    /// validated earlier, so this should not occur).
    #[error("matrix multiply: {0}")]
    Gemm(#[from] GemmError),
}

/// Fails with [`OptimError::InvalidHyperparameter`] unless `value` is finite.
pub(crate) const fn finite(name: &'static str, value: f64) -> Result<(), OptimError> {
    if value.is_finite() {
        Ok(())
    } else {
        Err(OptimError::InvalidHyperparameter {
            name,
            value,
            reason: "must be finite",
        })
    }
}

/// Fails unless `value` is finite and `>= 0`.
pub(crate) fn non_negative(name: &'static str, value: f64) -> Result<(), OptimError> {
    finite(name, value)?;
    if value >= 0.0 {
        Ok(())
    } else {
        Err(OptimError::InvalidHyperparameter {
            name,
            value,
            reason: "must be >= 0",
        })
    }
}

/// Fails unless `value` is finite and `> 0`.
pub(crate) fn positive(name: &'static str, value: f64) -> Result<(), OptimError> {
    finite(name, value)?;
    if value > 0.0 {
        Ok(())
    } else {
        Err(OptimError::InvalidHyperparameter {
            name,
            value,
            reason: "must be > 0",
        })
    }
}

/// Fails unless `0 <= value < 1`.
pub(crate) fn unit(name: &'static str, value: f64) -> Result<(), OptimError> {
    finite(name, value)?;
    if (0.0..1.0).contains(&value) {
        Ok(())
    } else {
        Err(OptimError::InvalidHyperparameter {
            name,
            value,
            reason: "must be in [0, 1)",
        })
    }
}
