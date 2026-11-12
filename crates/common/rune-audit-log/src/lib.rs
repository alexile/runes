//! Append-only, hash-chained, tamper-evident audit log.
//!
//! Every [`Record`] says who did what to which target and when
//! ([`Entry`]), carries its position (`seq`), the hash of the record
//! before it (`prev`) and a SHA-256 hash over all of that (`hash`).
//! Changing, inserting, reordering or removing any record breaks the
//! chain at that point, and [`Verifier`] reports where. Records can also
//! be signed ([`Signer`], [`HmacSha256`]), so that rewriting the whole
//! chain needs a key the log's writer does not hold.
//!
//! - [`Chain`] and [`Verifier`] are the sans-I/O core: seal entries into
//!   records, and check a stream of records in constant memory.
//! - [`AuditLog`] binds a chain to a [`Store`]: [`MemoryStore`],
//!   [`FileStore`] (JSON lines), or your own backend.
//! - [`JsonlReader`] reads an exported log back, one bounded line at a
//!   time.
//!
//! A chain cannot tell that its newest records were deleted: the shorter
//! log is still a valid chain. Save [`AuditLog::head`] somewhere the
//! writer cannot change and check against it with
//! [`AuditLog::verify_against`] or [`Verifier::expect_head`].
//!
//! # Example
//!
//! ```
//! use rune_audit_log::{AuditLog, Entry, Error, MemoryStore, Tamper};
//!
//! let mut log = AuditLog::open(MemoryStore::new())?;
//! log.append_at(Entry::new("alice", "login").with_field("ip", "10.0.0.7"), 1_000)?;
//! log.append_at(Entry::new("alice", "policy.update").with_target("sandbox"), 2_000)?;
//! log.append_at(Entry::new("alice", "logout"), 3_000)?;
//! let checkpoint = log.head();
//! assert_eq!(log.verify()?.count, 3);
//!
//! // Rewrite the second record's action.
//! let mut store = log.into_store();
//! store.records_mut()[1].entry.action = "noop".into();
//! let log = AuditLog::open(store)?;
//! match log.verify_against(&checkpoint) {
//!     Err(Error::Tampered { seq: 1, kind: Tamper::HashMismatch }) => {}
//!     other => panic!("unexpected: {other:?}"),
//! }
//! # Ok::<(), Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod chain;
mod log;
mod record;
mod signer;
mod store;

use std::path::PathBuf;

pub use chain::{Chain, Verified, Verifier};
pub use log::AuditLog;
pub use record::{Digest, Entry, ParseDigestError, Record};
pub use signer::{HmacSha256, Signer};
pub use store::{DEFAULT_MAX_LINE_LEN, FileStore, JsonlReader, MemoryStore, Records, Store};

/// What is wrong with a record that failed verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Tamper {
    /// The record's sequence number is not the next one: a record was
    /// removed, inserted or moved.
    Sequence {
        /// The sequence number that should have come next.
        expected: u64,
    },
    /// The record's `prev` is not the previous record's hash.
    BrokenLink,
    /// The record's hash does not match its contents: it was edited.
    HashMismatch,
    /// A signer was configured but the record has no signature.
    MissingSignature,
    /// The record's signature is not valid for its hash.
    BadSignature,
    /// The log ends at a different hash than expected: records were
    /// removed from (or added to) its end.
    HeadMismatch,
}

impl std::fmt::Display for Tamper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sequence { expected } => write!(f, "out of sequence (expected {expected})"),
            Self::BrokenLink => f.write_str("does not link to the previous record"),
            Self::HashMismatch => f.write_str("hash does not match its contents"),
            Self::MissingSignature => f.write_str("is not signed"),
            Self::BadSignature => f.write_str("has an invalid signature"),
            Self::HeadMismatch => f.write_str("the log does not end at the expected head"),
        }
    }
}

/// Errors returned by this crate.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Verification failed at record `seq`.
    #[error("audit log tampered at record {seq}: {kind}")]
    Tampered {
        /// The failing record's sequence number (for
        /// [`Tamper::HeadMismatch`], the one after the last record).
        seq: u64,
        /// What is wrong.
        kind: Tamper,
    },
    /// The log reached `u64::MAX` records.
    #[error("audit log sequence numbers exhausted")]
    SequenceExhausted,
    /// A stored line could not be parsed as a record.
    #[error("corrupt audit record{}: {reason}", line.map(|n| format!(" on line {n}")).unwrap_or_default())]
    Corrupt {
        /// The 1-based line number, when known.
        line: Option<u64>,
        /// What the parser reported.
        reason: String,
    },
    /// A record is larger than the store's line bound.
    #[error("audit record is {len} bytes, more than the limit of {max}")]
    TooLarge {
        /// Its length in bytes.
        len: usize,
        /// The limit.
        max: usize,
    },
    /// Serializing a record failed.
    #[error("cannot serialize audit record: {0}")]
    Json(#[source] serde_json::Error),
    /// Reading or writing failed.
    #[error("audit log I/O error{}: {source}", path.as_ref().map(|p| format!(" on {}", p.display())).unwrap_or_default())]
    Io {
        /// The file involved, when there is one.
        path: Option<PathBuf>,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
    /// A custom [`Store`] backend failed.
    #[error("audit log storage error: {0}")]
    Storage(#[source] Box<dyn std::error::Error + Send + Sync>),
}
