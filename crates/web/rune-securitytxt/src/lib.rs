//! Parse and validate `security.txt` files
//! ([RFC 9116](https://www.rfc-editor.org/rfc/rfc9116)), reporting problems
//! as [`rune_finding`] findings.
//!
//! - [`SecurityTxt::parse`] reads a file the way clients should: field
//!   names are case-insensitive, unknown fields are kept, and lines that
//!   break the grammar are listed rather than fatal. A PGP cleartext
//!   signature ([RFC 4880 §7](https://www.rfc-editor.org/rfc/rfc4880#section-7))
//!   is unwrapped into a [`Signature`] whose canonical text and armored
//!   block can be handed to a PGP verifier; text outside the signed
//!   part is an [`Error`].
//! - [`run`] / [`analyze`] check the RFC requirements — `Contact` present,
//!   exactly one valid `Expires` and not in the past, URIs well formed and
//!   `https://`, `Canonical` matching where the file was retrieved, at most
//!   one `Preferred-Languages` with valid tags — plus recommendations
//!   (expiry under a year, a signature, `Canonical` in signed files).
//!   [`Report::is_valid`] says whether the file follows the RFC (signatures
//!   are not verified, only their framing is checked), and
//!   [`Report::to_findings`] maps weaknesses to findings with check ids
//!   `securitytxt.<kind>`.
//! - [`Timestamp`] parses RFC 3339 date-times.
//!
//! The crate is sans-I/O: it works on the text of the file and never
//! fetches anything or reads the clock. Pass the current time in
//! [`Options::now`] to check expiry.
//!
//! # Example
//!
//! ```
//! use rune_finding::Location;
//! use rune_securitytxt::{Options, SecurityTxt, Timestamp, WeaknessKind, run};
//!
//! let text = "\
//! # Our security address
//! Contact: mailto:security@example.com
//! Contact: https://example.com/security-contact.html
//! Expires: 2026-12-31T18:37:07.000Z
//! Preferred-Languages: en, fr
//! Canonical: https://example.com/.well-known/security.txt
//! ";
//! let doc = SecurityTxt::parse(text)?;
//! assert_eq!(doc.contacts()[0], "mailto:security@example.com");
//! assert_eq!(doc.preferred_languages(), ["en", "fr"]);
//!
//! let options = Options::default()
//!     .with_now(Timestamp::parse("2026-06-01T00:00:00Z")?)
//!     .with_retrieved_from("https://example.com/.well-known/security.txt");
//! let report = run(text, &options);
//! assert!(report.is_valid());
//!
//! // Half a year later the file is stale.
//! let later = options.with_now(Timestamp::parse("2027-01-01T00:00:00Z")?);
//! let report = run(text, &later);
//! assert!(!report.is_valid());
//! let findings = report.to_findings::<()>(&Location::url("https://example.com/.well-known/security.txt"));
//! assert!(findings.iter().any(|f| f.check_id == "securitytxt.expired"));
//! # Ok::<(), rune_securitytxt::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod analyze;
mod document;
mod timestamp;

pub use analyze::{MAX_VALIDITY_SECONDS, Options, Report, Weakness, WeaknessKind, analyze, run};
pub use document::{Field, FieldKind, Malformed, MalformedLine, SecurityTxt, Signature};
pub use timestamp::Timestamp;

/// The path a security.txt file is served at (RFC 9116 §3).
pub const WELL_KNOWN_PATH: &str = "/.well-known/security.txt";

/// Errors from parsing a file or a timestamp.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The PGP cleartext signature framing is broken, or text follows
    /// the signature.
    #[error("invalid signed message at line {line}: {message}")]
    InvalidSignature {
        /// 1-based line number.
        line: usize,
        /// What is wrong.
        message: String,
    },
    /// A value is not an RFC 3339 date-time.
    #[error("{value:?} is not an RFC 3339 date-time")]
    InvalidTimestamp {
        /// The value as written.
        value: String,
    },
}
