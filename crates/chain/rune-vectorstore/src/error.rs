//! The crate's error type.

/// Errors returned by indexes and stores in this crate.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// A vector has a different number of dimensions than the store expects.
    #[error("vector has {actual} dimensions, but the store expects {expected}")]
    DimensionMismatch {
        /// Dimension fixed by the store options or by the first inserted vector.
        expected: usize,
        /// Dimension of the offending vector.
        actual: usize,
    },
    /// A vector cannot be indexed or queried (empty, NaN, infinite, or a zero
    /// vector under the cosine metric).
    #[error("invalid vector: {0}")]
    InvalidVector(&'static str),
    /// A query parameter is unusable, such as a NaN `min_score`.
    #[error("invalid query: {0}")]
    InvalidQuery(&'static str),
    /// A metadata filter is malformed, such as a range bound that is neither a
    /// number nor a string.
    #[error("invalid filter: {0}")]
    InvalidFilter(String),
    /// A record id is empty.
    #[error("record id must not be empty")]
    EmptyId,
    /// The same id appears more than once in a single upsert batch.
    #[error("duplicate id {0:?} in one upsert batch")]
    DuplicateId(String),
    /// A lock guarding an in-memory store was poisoned by a panicking writer.
    #[error("store lock poisoned")]
    Poisoned,
    /// Reading or writing a snapshot file failed.
    #[error("I/O error ({kind:?}): {message}")]
    Io {
        /// The underlying error kind.
        kind: std::io::ErrorKind,
        /// The underlying error message.
        message: String,
    },
    /// A snapshot is truncated, corrupt, from an unknown format version, or
    /// otherwise not decodable.
    #[error("invalid snapshot: {0}")]
    InvalidSnapshot(String),
    /// Input is larger than a configured limit (see [`LoadLimits`](crate::LoadLimits)).
    #[error("{what} is {actual}, above the limit of {limit}")]
    LimitExceeded {
        /// What was measured.
        what: &'static str,
        /// The configured limit.
        limit: u64,
        /// The measured value (or a lower bound of it).
        actual: u64,
    },
    /// A backend-specific failure (network, database, …) from an external store.
    #[error("backend error: {0}")]
    Backend(String),
}

impl From<std::io::Error> for StoreError {
    fn from(err: std::io::Error) -> Self {
        Self::Io {
            kind: err.kind(),
            message: err.to_string(),
        }
    }
}
