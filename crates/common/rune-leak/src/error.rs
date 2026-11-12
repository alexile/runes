//! The crate error type.

use std::path::PathBuf;

/// Errors from compiling rules and running scans.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The scan path was empty.
    #[error("scan path is empty")]
    EmptyPath,
    /// The scan root could not be read.
    #[error("cannot read {path}: {source}")]
    Io {
        /// The path that failed.
        path: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },
    /// A rule is malformed.
    #[error("invalid rule {id:?}: {reason}")]
    InvalidRule {
        /// The rule id.
        id: String,
        /// What is wrong.
        reason: &'static str,
    },
    /// A rule's pattern does not compile.
    #[error("invalid regex in rule {id:?}: {source}")]
    InvalidRegex {
        /// The rule id.
        id: String,
        /// The compile error.
        source: regex::Error,
    },
    /// A git command failed while reading history.
    #[error("git: {0}")]
    Git(String),
    /// A TOML rule file could not be parsed.
    #[cfg(feature = "toml")]
    #[error("invalid rule file: {0}")]
    Toml(Box<toml::de::Error>),
}

impl Error {
    /// A stable, machine-readable kind to branch on.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::EmptyPath => "empty_path",
            Self::Io { .. } => "io",
            Self::InvalidRule { .. } => "invalid_rule",
            Self::InvalidRegex { .. } => "invalid_regex",
            Self::Git(_) => "git",
            #[cfg(feature = "toml")]
            Self::Toml(_) => "invalid_toml",
        }
    }
}
