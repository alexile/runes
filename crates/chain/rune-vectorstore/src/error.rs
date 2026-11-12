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
    /// A vector cannot be indexed or queried.
    #[error("invalid vector: {0}")]
    InvalidVector(&'static str),
    /// A record id is empty.
    #[error("record id must not be empty")]
    EmptyId,
    /// The same id appears more than once in a single upsert batch.
    #[error("duplicate id {0:?} in one upsert batch")]
    DuplicateId(String),
    /// A lock guarding an in-memory store was poisoned by a panicking writer.
    #[error("store lock poisoned")]
    Poisoned,
    /// A backend-specific failure (network, database, …) from an external store.
    #[error("backend error: {0}")]
    Backend(String),
}
