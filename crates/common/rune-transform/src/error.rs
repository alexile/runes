//! The crate's error type.

use std::fmt;

/// Errors returned by transforms, chains and the registry.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The input is not well-formed for the transform (bad base64, a
    /// truncated escape, a corrupt gzip stream, a malformed JWT, …).
    #[error("{transform}: malformed input: {reason}")]
    Malformed {
        /// Id of the transform that rejected the input.
        transform: String,
        /// What was wrong with it.
        reason: String,
    },
    /// The transform works on text and the input is not valid UTF-8.
    #[error("{transform}: input is not valid UTF-8")]
    NotUtf8 {
        /// Id of the transform that rejected the input.
        transform: String,
    },
    /// Decompressed output would exceed the transform's size limit.
    #[error("{transform}: output exceeds the limit of {limit} bytes")]
    OutputTooLarge {
        /// Id of the transform that hit the limit.
        transform: String,
        /// The limit, in bytes.
        limit: usize,
    },
    /// A decode was requested from a one-way transform.
    #[error("transform is not reversible: {id}")]
    NotReversible {
        /// Id of the one-way transform.
        id: String,
    },
    /// No transform with this id is registered.
    #[error("unknown transform: {id}")]
    UnknownTransform {
        /// The id that was looked up.
        id: String,
    },
    /// A transform with this id is already registered.
    #[error("duplicate transform id: {id}")]
    DuplicateId {
        /// The id that was registered twice.
        id: String,
    },
    /// A transform id or chain spec is not well-formed.
    #[error("invalid transform spec {spec:?}: {reason}")]
    InvalidSpec {
        /// The offending id or spec.
        spec: String,
        /// Why it was rejected.
        reason: &'static str,
    },
}

impl Error {
    /// A [`Error::Malformed`] for `transform`, for use by custom
    /// [`Transform`](crate::Transform) implementations.
    #[must_use]
    pub fn malformed(transform: &str, reason: impl fmt::Display) -> Self {
        Self::Malformed {
            transform: transform.to_owned(),
            reason: reason.to_string(),
        }
    }

    /// A [`Error::NotUtf8`] for `transform`.
    #[must_use]
    pub fn not_utf8(transform: &str) -> Self {
        Self::NotUtf8 {
            transform: transform.to_owned(),
        }
    }

    /// A [`Error::NotReversible`] for the transform `id`.
    #[must_use]
    pub fn not_reversible(id: &str) -> Self {
        Self::NotReversible { id: id.to_owned() }
    }

    /// Stable, machine-readable kind of this error, such as
    /// `"transform.malformed"`.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Malformed { .. } => "transform.malformed",
            Self::NotUtf8 { .. } => "transform.utf8",
            Self::OutputTooLarge { .. } => "transform.output_too_large",
            Self::NotReversible { .. } => "transform.not_reversible",
            Self::UnknownTransform { .. } => "transform.unknown_transform",
            Self::DuplicateId { .. } => "transform.duplicate_id",
            Self::InvalidSpec { .. } => "transform.invalid_spec",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_and_codes() {
        let error = Error::malformed("hex", "odd length");
        assert_eq!(error.to_string(), "hex: malformed input: odd length");
        assert_eq!(error.code(), "transform.malformed");
        assert_eq!(Error::not_utf8("html").code(), "transform.utf8");
        assert_eq!(
            Error::not_reversible("md5").to_string(),
            "transform is not reversible: md5"
        );
    }
}
