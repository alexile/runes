//! Configuration and restore errors.

use std::error::Error;
use std::fmt;

/// A deduplicator could not be built from the given settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConfigError {
    /// `max_keys` was zero.
    ZeroMaxKeys,
    /// `max_keys` was set together with approximate mode, which bounds memory
    /// through [`ApproxConfig`](crate::ApproxConfig) instead.
    MaxKeysWithApproximate,
    /// [`ApproxConfig`](crate::ApproxConfig) expected zero keys.
    ZeroExpectedKeys,
    /// The false-positive rate was not strictly between 0 and 1.
    InvalidFalsePositiveRate,
    /// Fewer than two generations were requested.
    TooFewGenerations,
    /// The requested filter would exceed 2 GiB per generation.
    FilterTooLarge,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ZeroMaxKeys => "max_keys must be at least 1",
            Self::MaxKeysWithApproximate => {
                "max_keys applies to exact mode only; size approximate mode with ApproxConfig"
            }
            Self::ZeroExpectedKeys => "expected_keys must be at least 1",
            Self::InvalidFalsePositiveRate => "false_positive_rate must be in (0, 1)",
            Self::TooFewGenerations => "at least 2 generations are needed",
            Self::FilterTooLarge => "filter would exceed 2 GiB per generation",
        })
    }
}

impl Error for ConfigError {}

/// A snapshot could not be turned back into a deduplicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RestoreError {
    /// The snapshot was written by a newer, incompatible format version.
    UnsupportedVersion(u32),
    /// The settings stored in the snapshot are invalid.
    Config(ConfigError),
    /// The stored state contradicts the stored settings (wrong filter size,
    /// more entries than `max_keys`, a key recorded twice, ...).
    Inconsistent(&'static str),
}

impl fmt::Display for RestoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion(v) => write!(f, "unsupported snapshot version {v}"),
            Self::Config(e) => write!(f, "invalid snapshot settings: {e}"),
            Self::Inconsistent(why) => write!(f, "inconsistent snapshot: {why}"),
        }
    }
}

impl Error for RestoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Config(e) => Some(e),
            _ => None,
        }
    }
}

impl From<ConfigError> for RestoreError {
    fn from(e: ConfigError) -> Self {
        Self::Config(e)
    }
}
