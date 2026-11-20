//! The crate error type, [`LowpError`].

/// Errors returned by the fallible APIs of this crate.
///
/// Scalar conversions are total (every `f32` maps to some code), so they
/// never fail. Slice, tensor and recipe APIs validate their inputs and report
/// problems through these variants instead of panicking.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LowpError {
    /// Two slices that must have the same length (or a slice and a shape)
    /// disagree.
    #[error("length mismatch: expected {expected}, found {found}")]
    LengthMismatch {
        /// The length implied by the other arguments.
        expected: usize,
        /// The length that was passed.
        found: usize,
    },
    /// A shape or block size is zero, or a product of dimensions overflows.
    #[error("invalid shape: {0}")]
    InvalidShape(&'static str),
    /// A parameter is out of its documented range.
    #[error("invalid parameter: {0}")]
    InvalidParameter(&'static str),
    /// A [`Format`](crate::Format) description cannot be represented.
    #[error("invalid format: {0}")]
    InvalidFormat(&'static str),
    /// A raw bit pattern has bits set above the width of the type.
    #[error("bit pattern {bits:#x} does not fit in {width} bits")]
    InvalidBits {
        /// The offending pattern.
        bits: u16,
        /// Width of the target type in bits.
        width: u32,
    },
}

/// Shorthand for `Result<T, LowpError>`.
pub type Result<T, E = LowpError> = std::result::Result<T, E>;
