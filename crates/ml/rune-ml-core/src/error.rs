//! The crate error type, [`MlError`].

/// Errors shared by the ML runes.
///
/// Algorithm crates keep their own error enum (one per crate, per the rune
/// contract) and wrap this one with `#[error(transparent)] Core(#[from] MlError)`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MlError {
    /// A flat buffer does not hold exactly `rows * cols` elements.
    #[error("buffer of length {len} does not match shape {rows}x{cols}")]
    BufferLength {
        /// Requested number of rows.
        rows: usize,
        /// Requested number of columns.
        cols: usize,
        /// Actual buffer length.
        len: usize,
    },
    /// `rows * cols` overflows `usize`.
    #[error("shape {rows}x{cols} overflows usize")]
    ShapeOverflow {
        /// Requested number of rows.
        rows: usize,
        /// Requested number of columns.
        cols: usize,
    },
    /// A row of nested input has a different length from the first row.
    #[error("row {row} has {found} columns, expected {expected}")]
    RaggedRows {
        /// Index of the offending row.
        row: usize,
        /// Length of the first row.
        expected: usize,
        /// Length of the offending row.
        found: usize,
    },
    /// Two operands have incompatible dimensions.
    #[error("dimension mismatch: expected {expected}, found {found}")]
    DimensionMismatch {
        /// Dimension the operation requires.
        expected: usize,
        /// Dimension it received.
        found: usize,
    },
    /// An index is out of bounds.
    #[error("index {index} out of bounds for length {len}")]
    IndexOutOfBounds {
        /// The offending index.
        index: usize,
        /// The length it was checked against.
        len: usize,
    },
    /// The input has no samples, or too few for the operation.
    #[error("not enough samples: need at least {needed}, got {got}")]
    TooFewSamples {
        /// Minimum number of samples required.
        needed: usize,
        /// Number of samples received.
        got: usize,
    },
    /// The input contains `NaN` or an infinity.
    #[error("non-finite value at row {row}, column {col}")]
    NonFinite {
        /// Row of the first non-finite value.
        row: usize,
        /// Column of the first non-finite value.
        col: usize,
    },
    /// A hyper-parameter is outside its valid range.
    #[error("invalid parameter `{name}`: {reason}")]
    InvalidParameter {
        /// Parameter name.
        name: &'static str,
        /// Why the value was rejected.
        reason: String,
    },
    /// An iterative method stopped before converging.
    #[error("did not converge within {iterations} iterations")]
    NoConvergence {
        /// Number of iterations performed.
        iterations: usize,
    },
}

impl MlError {
    /// Shorthand for [`MlError::InvalidParameter`].
    pub fn invalid_parameter(name: &'static str, reason: impl Into<String>) -> Self {
        Self::InvalidParameter {
            name,
            reason: reason.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::MlError;

    #[test]
    fn messages() {
        let e = MlError::BufferLength {
            rows: 2,
            cols: 3,
            len: 5,
        };
        assert_eq!(e.to_string(), "buffer of length 5 does not match shape 2x3");
        let e = MlError::invalid_parameter("k", "must be positive");
        assert_eq!(e.to_string(), "invalid parameter `k`: must be positive");
    }
}
