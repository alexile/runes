//! The crate's error type.

/// Errors returned by this crate.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The payload is longer than [`Options::max_payload_len`](crate::Options::max_payload_len).
    #[error("payload is {len} bytes, more than the limit of {max} bytes")]
    PayloadTooLong {
        /// Length of the payload in bytes.
        len: usize,
        /// The configured limit.
        max: usize,
    },
    /// A name did not match any [`Context`](crate::Context).
    #[error("unknown evasion context: {0:?}")]
    UnknownContext(String),
    /// A name did not match any [`Technique`](crate::Technique).
    #[error("unknown evasion technique: {0:?}")]
    UnknownTechnique(String),
    /// A stacked variant was requested with no techniques in it.
    #[error("a technique stack must name at least one technique")]
    EmptyStack,
    /// A transform failed, or the registry is missing a transform the
    /// evasion transforms are built on.
    #[error(transparent)]
    Transform(#[from] rune_transform::Error),
}

impl Error {
    /// Stable, machine-readable kind of this error, such as
    /// `"payload_encode.payload_too_long"`.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::PayloadTooLong { .. } => "payload_encode.payload_too_long",
            Self::UnknownContext(_) => "payload_encode.unknown_context",
            Self::UnknownTechnique(_) => "payload_encode.unknown_technique",
            Self::EmptyStack => "payload_encode.empty_stack",
            Self::Transform(inner) => inner.code(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_and_codes() {
        let error = Error::PayloadTooLong { len: 9, max: 4 };
        assert_eq!(
            error.to_string(),
            "payload is 9 bytes, more than the limit of 4 bytes"
        );
        assert_eq!(error.code(), "payload_encode.payload_too_long");
        assert_eq!(Error::EmptyStack.code(), "payload_encode.empty_stack");
        let inner = rune_transform::Error::not_reversible("x");
        assert_eq!(Error::from(inner.clone()).code(), inner.code());
    }
}
