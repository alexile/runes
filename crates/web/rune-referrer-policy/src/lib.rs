//! Parse and analyze `Referrer-Policy` headers and `<meta name="referrer">`
//! values, reporting leak-prone policies as [`rune_finding`] findings.
//!
//! Implements [Referrer Policy](https://www.w3.org/TR/referrer-policy/) and
//! the referrer rules of [Fetch](https://fetch.spec.whatwg.org/):
//!
//! - [`Header::parse`] splits a header into tokens; [`Header::policy`] is
//!   the policy browsers apply, the last one they recognise.
//!   [`parse_meta`] reads a meta `content`, legacy keywords included.
//! - [`ReferrerPolicy::referrer`] says what a request carries (nothing, the
//!   origin, the full URL) for each [`RequestKind`], and
//!   [`ReferrerPolicy::verdict`] rates the policy.
//! - [`run`], [`run_fields`], [`run_meta`] and [`analyze`] flag
//!   `unsafe-url`, `no-referrer-when-downgrade`, origins sent over plain
//!   HTTP, a missing or unrecognised policy, unknown tokens and fallbacks
//!   that end weaker than they start, and [`Report::to_findings`] maps them
//!   to [`rune_finding::Finding`]s with check ids `referrer_policy.<kind>`.
//!
//! The crate is sans-I/O: it works on header strings and never fetches
//! anything.
//!
//! # Example
//!
//! ```
//! use rune_finding::{Location, Severity};
//! use rune_referrer_policy::{
//!     Options, Referrer, ReferrerPolicy, RequestKind, Verdict, WeaknessKind, run,
//! };
//!
//! let report = run("no-referrer, unsafe-url", &Options::default());
//! assert_eq!(report.policy, Some(ReferrerPolicy::UnsafeUrl));
//! assert_eq!(report.max_severity(), Some(Severity::High));
//! assert!(report.weaknesses.iter().any(|w| w.kind == WeaknessKind::WeakerFallback));
//!
//! let findings = report.to_findings::<()>(&Location::url("https://example.com/"));
//! assert!(findings.iter().any(|f| f.check_id == "referrer_policy.unsafe_url"));
//!
//! // The browser default sends only the origin to other sites.
//! let default = ReferrerPolicy::default();
//! assert_eq!(default.referrer(RequestKind::CrossOrigin), Referrer::Origin);
//! assert_eq!(default.verdict(), Verdict::Safe);
//! assert!(run("strict-origin-when-cross-origin", &Options::default()).weaknesses.is_empty());
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod analyze;
mod policy;

pub use analyze::{Options, Report, Weakness, WeaknessKind, analyze, run, run_fields, run_meta};
pub use policy::{
    Header, MetaValue, Referrer, ReferrerPolicy, RequestKind, Token, Verdict, parse_meta,
};

/// Errors from parsing a single policy keyword or a meta value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The text names no referrer policy.
    #[error("unknown referrer policy {token:?}")]
    UnknownPolicy {
        /// The text, trimmed.
        token: String,
    },
}
