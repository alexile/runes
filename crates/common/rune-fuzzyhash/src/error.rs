//! The crate's error type.

/// Errors returned by this crate.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The input is too short for the algorithm.
    #[error("{algorithm} needs at least {min} bytes, got {len}")]
    TooShort {
        /// `"TLSH"` or `"ssdeep"`.
        algorithm: &'static str,
        /// Length of the input.
        len: u64,
        /// Minimum length.
        min: usize,
    },
    /// The input is too long for the algorithm's length encoding.
    #[error("{algorithm} accepts at most {max} bytes, got {len}")]
    TooLong {
        /// `"TLSH"` or `"ssdeep"`.
        algorithm: &'static str,
        /// Length of the input.
        len: u64,
        /// Maximum length.
        max: u64,
    },
    /// The input has too little variety for a TLSH digest (half or more of
    /// the buckets are empty), e.g. a run of a single byte.
    #[error("input has too little byte variety for TLSH")]
    LowVariation,
    /// A digest string is malformed.
    #[error("invalid {algorithm} digest: {reason}")]
    InvalidDigest {
        /// `"TLSH"` or `"ssdeep"`.
        algorithm: &'static str,
        /// What is wrong with it.
        reason: &'static str,
    },
}
