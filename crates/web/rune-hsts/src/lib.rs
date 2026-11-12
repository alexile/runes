//! Parse and analyze `Strict-Transport-Security` (HSTS) headers, and check
//! HSTS preload-list eligibility and membership, reporting problems as
//! [`rune_finding`] findings.
//!
//! Implements [RFC 6797](https://www.rfc-editor.org/rfc/rfc6797) and the
//! [preload list submission requirements](https://hstspreload.org/#submission-requirements):
//!
//! - [`Hsts::parse`] reads a header value the way browsers do (RFC 6797
//!   §6.1, §8.1) and returns an [`Error`] for a header they would ignore.
//!   [`Display`](std::fmt::Display) writes the canonical form,
//!   `max-age=N; includeSubDomains; preload`.
//! - [`run`] / [`run_fields`] and [`analyze`] flag weaknesses — a missing or
//!   ignored header, `max-age=0`, a short `max-age`, no `includeSubDomains`,
//!   `preload` without the requirements behind it, misspelled, valued,
//!   repeated and unknown directives — and [`Report::to_findings`] maps them
//!   to [`rune_finding::Finding`]s with check ids `hsts.<kind>`.
//! - [`check_preload`] checks a [`Site`] (domain, HTTPS header, HTTP
//!   redirect) against the submission requirements; [`Eligibility`] reports
//!   each unmet one as `hsts.preload_<kind>`.
//! - [`PreloadList`] answers membership against a list the caller loads —
//!   a plain domain list, or Chromium's `transport_security_state_static.json`
//!   with the `chromium` feature.
//!
//! The crate is sans-I/O: it works on header strings and caller-supplied
//! observations and lists, and never fetches anything.
//!
//! # Example
//!
//! ```
//! use rune_finding::{Location, Severity};
//! use rune_hsts::{Options, PreloadEntry, PreloadList, Site, WeaknessKind, check_preload, run};
//!
//! let report = run("max-age=3600; Preload", &Options::default());
//! assert_eq!(report.canonical().as_deref(), Some("max-age=3600; preload"));
//! assert_eq!(report.max_severity(), Some(Severity::Medium));
//! assert!(report.weaknesses.iter().any(|w| w.kind == WeaknessKind::PreloadIneligible));
//!
//! let findings = report.to_findings::<()>(&Location::url("https://example.com/"));
//! assert!(findings.iter().any(|f| f.check_id == "hsts.short_max_age"));
//!
//! // Preload eligibility, from observations the caller gathered.
//! let site = Site::new("example.com")
//!     .with_https_header("max-age=63072000; includeSubDomains; preload")
//!     .with_http_redirect("https://example.com/");
//! assert!(check_preload(&site).is_eligible());
//!
//! // Membership, against a list the caller supplies.
//! let mut list = PreloadList::new();
//! list.insert(PreloadEntry::new("example.com", true));
//! assert!(list.is_preloaded("www.example.com"));
//! assert!(!list.is_preloaded("example.org"));
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod analyze;
mod header;
mod preload;

pub use analyze::{Options, Report, Weakness, WeaknessKind, analyze, run, run_fields};
pub use header::{Extension, Hsts};
pub use preload::{
    Eligibility, HttpBehavior, PRELOAD_MIN_MAX_AGE, PreloadEntry, PreloadIssue, PreloadIssueKind,
    PreloadList, PreloadMatch, Site, check_preload, header_issues,
};

/// Errors from parsing a header ([`Hsts::parse`]) or a preload list.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The header has no directives.
    #[error("header has no directives")]
    Empty,
    /// The required `max-age` directive is missing.
    #[error("max-age is missing")]
    MissingMaxAge,
    /// `max-age` is not a non-negative integer.
    #[error("max-age value {value:?} is not a number of seconds")]
    InvalidMaxAge {
        /// The value as written (unquoted).
        value: String,
    },
    /// `max-age` or `includeSubDomains` appears more than once.
    #[error("directive {name} appears more than once")]
    DuplicateDirective {
        /// Lowercase directive name.
        name: String,
    },
    /// A directive has `=` but no value, or `max-age` has no value.
    #[error("directive {name} has no value")]
    MissingValue {
        /// Lowercase directive name.
        name: String,
    },
    /// `includeSubDomains` has a value.
    #[error("directive {name} takes no value")]
    UnexpectedValue {
        /// Lowercase directive name.
        name: String,
    },
    /// A character the grammar does not allow here.
    #[error("unexpected {found:?} at byte {offset}")]
    UnexpectedChar {
        /// Byte offset in the header value.
        offset: usize,
        /// The character found (`'\0'` at the end of input).
        found: char,
    },
    /// A quoted string is not closed.
    #[error("unterminated quoted string at byte {offset}")]
    UnterminatedQuote {
        /// Byte offset of the opening quote.
        offset: usize,
    },
    /// A preload list is malformed.
    #[error("invalid preload list at line {line}: {message}")]
    InvalidList {
        /// 1-based line number (0 when unknown).
        line: usize,
        /// What is wrong.
        message: String,
    },
}
