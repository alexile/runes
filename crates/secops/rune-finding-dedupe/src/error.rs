//! The crate's error type.

/// Errors returned by this crate.
///
/// Deduplication and tracking cannot fail; only restoring a serialized
/// [`Tracker`](crate::Tracker) whose state does not add up can.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// An issue is filed under an id other than its own.
    #[error("issue filed under id {0} has a different id")]
    IdMismatch(String),
    /// Two issues claim the same key.
    #[error("key {0} belongs to two issues")]
    SharedKey(String),
    /// An alias is also a live issue, or points at an issue that does not
    /// list it among its aliases.
    #[error("alias {0} is a live issue or points at a missing one")]
    BadAlias(String),
}
