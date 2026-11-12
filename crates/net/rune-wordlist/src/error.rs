//! The crate's error type.

use std::io;
use std::path::PathBuf;

use crate::Version;

/// Errors returned by this crate.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A file of the pack or store could not be read or written.
    #[error("I/O error on {}: {source}", path.display())]
    Io {
        /// The file or directory involved.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
    /// Reading a list's bytes failed.
    #[error("I/O error reading list {list:?}: {source}")]
    ReadList {
        /// The list's name in the manifest.
        list: String,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
    /// The manifest is not valid TOML or does not match the manifest schema.
    #[error("invalid manifest: {0}")]
    Manifest(String),
    /// The manifest is larger than [`Options::max_manifest_len`](crate::Options::max_manifest_len).
    #[error("manifest is larger than the limit of {max} bytes")]
    ManifestTooLarge {
        /// The configured limit.
        max: u64,
    },
    /// The manifest declares a format this version of the crate cannot read.
    #[error("unsupported manifest format {0} (this reader supports format {supported})", supported = crate::FORMAT)]
    UnsupportedFormat(u32),
    /// A pack or list name contains characters outside `[a-z0-9._-]`.
    #[error(
        "invalid name {0:?}: use 1-64 characters from [a-z0-9._-], starting with a letter or digit"
    )]
    InvalidName(String),
    /// A version is not `MAJOR.MINOR.PATCH`.
    #[error("invalid version {0:?}: expected MAJOR.MINOR.PATCH")]
    InvalidVersion(String),
    /// A list path is absolute, escapes the pack directory or is not portable.
    #[error("unsafe list path {0:?}: use a relative path with '/' separators and no '..'")]
    UnsafePath(String),
    /// A hex field (hash, key, key id or signature) is malformed.
    #[error("invalid {what}: expected {len} lowercase hex digits")]
    InvalidHex {
        /// Which field.
        what: &'static str,
        /// The expected number of hex digits.
        len: usize,
    },
    /// The bytes are not a valid Ed25519 public key.
    #[error("invalid Ed25519 public key")]
    InvalidKey,
    /// The signature file is missing or malformed.
    #[error("invalid signature file: {0}")]
    SignatureFormat(String),
    /// The key id is not in the [`Keyring`](crate::Keyring), or the
    /// manifest's `key-id` does not name the key that signed it.
    #[error("manifest names key {0}, which is not the trusted key that signed it")]
    UnknownKey(String),
    /// The signature does not verify with any trusted key: the manifest was
    /// modified, or signed by a key the caller does not trust.
    #[error(
        "signature verification failed: the manifest was modified or signed by an untrusted key"
    )]
    BadSignature,
    /// Two lists share a name.
    #[error("duplicate list name {0:?}")]
    DuplicateList(String),
    /// The pack has no list with this name.
    #[error("pack has no list named {0:?}")]
    NoSuchList(String),
    /// A list's contents do not match the signed manifest.
    #[error("list {list:?} was tampered with: {reason}")]
    Tampered {
        /// The list's name.
        list: String,
        /// What did not match.
        reason: String,
    },
    /// A line is longer than [`ReadOptions::max_line_len`](crate::ReadOptions::max_line_len).
    #[error("list {list:?} line {line} is longer than {max} bytes")]
    LineTooLong {
        /// The list's name.
        list: String,
        /// 1-based line number.
        line: u64,
        /// The configured limit.
        max: usize,
    },
    /// An update would not move the installed pack forward.
    #[error("{name} {candidate} is not newer than the installed {installed}")]
    NotNewer {
        /// The pack's name.
        name: String,
        /// The installed version.
        installed: Version,
        /// The candidate version.
        candidate: Version,
    },
    /// The store has no installed pack with this name.
    #[error("pack {0:?} is not installed")]
    NotInstalled(String),
}

impl Error {
    pub(crate) fn io(path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}

/// Shorthand for `Result<T, rune_wordlist::Error>`.
pub type Result<T, E = Error> = std::result::Result<T, E>;
