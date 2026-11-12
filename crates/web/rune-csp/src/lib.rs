//! Parse, analyze and canonicalize `Content-Security-Policy` headers,
//! reporting weaknesses as [`rune_finding`] findings.
//!
//! Implements the parsing algorithm and source-expression grammar of
//! [Content Security Policy Level 3](https://www.w3.org/TR/CSP3/):
//!
//! - [`parse_header`] splits a header value into [`Policy`]s (comma
//!   separated); [`Policy::parse`] reads one policy leniently, as browsers do,
//!   recording skipped directives as [`ParseIssue`]s. `str::parse::<Policy>()`
//!   is the strict variant and returns an [`Error`].
//! - [`Directive::sources`] parses source lists into [`Source`] expressions
//!   (keywords, nonces, hashes, schemes and hosts).
//! - [`Display`](std::fmt::Display) on [`Policy`] and [`serialize_header`]
//!   write the canonical form: lowercase names, keywords, schemes and hosts,
//!   single spaces and `"; "` separators, duplicates removed.
//! - [`run`] and [`analyze`] flag weaknesses — `'unsafe-inline'`,
//!   `'unsafe-eval'`, wildcard and `data:` sources, missing `object-src` /
//!   `base-uri`, short nonces, malformed hashes, misplaced nonces and more —
//!   and [`Report::to_findings`] maps them to [`rune_finding::Finding`]s with
//!   check ids `csp.<kind>`.
//!
//! The crate is sans-I/O: it works on header strings and never fetches
//! anything.
//!
//! # Example
//!
//! ```
//! use rune_csp::{Options, WeaknessKind, run};
//! use rune_finding::{Location, Severity};
//!
//! let report = run(
//!     "Script-Src 'self' 'unsafe-inline' https:; object-src 'none'",
//!     &Options::default(),
//! );
//! assert_eq!(
//!     report.canonical(),
//!     "script-src 'self' 'unsafe-inline' https:; object-src 'none'"
//! );
//! assert_eq!(report.max_severity(), Some(Severity::High));
//! assert!(report.weaknesses.iter().any(|w| w.kind == WeaknessKind::UnsafeInline));
//! assert!(report.weaknesses.iter().any(|w| w.kind == WeaknessKind::MissingBaseUri));
//!
//! let findings = report.to_findings::<()>(&Location::url("https://example.com/"));
//! assert!(findings.iter().any(|f| f.check_id == "csp.wildcard_source"));
//!
//! // A strict nonce-based policy leaves only informational notes.
//! let strict = run(
//!     "script-src 'nonce-rAnd0mRAnd0mRAnd0mRAnd0m' 'strict-dynamic'; \
//!      object-src 'none'; base-uri 'none'; frame-ancestors 'self'; report-to csp",
//!     &Options::default(),
//! );
//! assert!(strict.weaknesses.is_empty());
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod analyze;
mod policy;
mod source;

pub use analyze::{Options, Report, Weakness, WeaknessKind, analyze, run};
pub use policy::{Directive, ParseIssue, Policy, parse_header, serialize_header};
pub use source::{HashAlgorithm, HostSource, Keyword, Port, Source};

/// Errors from strict parsing (`str::parse::<Policy>()`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The policy has no directives.
    #[error("policy has no directives")]
    Empty,
    /// The text contains a comma, so it is a list of policies; use
    /// [`parse_header`].
    #[error("text contains several comma-separated policies")]
    MultiplePolicies,
    /// A directive appears twice.
    #[error("directive {name} appears more than once")]
    DuplicateDirective {
        /// Lowercase directive name.
        name: String,
    },
    /// A directive name has characters outside `ALPHA / DIGIT / "-"`.
    #[error("invalid directive name {name:?}")]
    InvalidDirectiveName {
        /// The name as written.
        name: String,
    },
    /// A source list holds a token that is not a source expression.
    #[error("invalid source {token:?} in {directive}")]
    InvalidSource {
        /// Lowercase directive name.
        directive: String,
        /// The token as written.
        token: String,
    },
}
