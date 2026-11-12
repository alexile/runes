//! Parse, analyze and canonicalize `Permissions-Policy` and legacy
//! `Feature-Policy` headers, reporting over-permissive grants as
//! [`rune_finding`] findings.
//!
//! Implements [Permissions Policy](https://www.w3.org/TR/permissions-policy/)
//! on top of [RFC 8941](https://www.rfc-editor.org/rfc/rfc8941) structured
//! field dictionaries, and the legacy
//! [Feature Policy](https://wicg.github.io/feature-policy/) syntax:
//!
//! - [`PermissionsPolicy::parse`] reads a `Permissions-Policy` value
//!   strictly, as browsers do: a syntax error is an [`Error`] because the
//!   whole header is then ignored. [`PermissionsPolicy::parse_feature_policy`]
//!   reads `Feature-Policy`. Both give a feature → [`Allowlist`] map
//!   ([`Directive`]s of [`Member`]s: `*`, `self`, `src`, origins, and
//!   members browsers ignore).
//! - [`Display`](std::fmt::Display) writes the canonical form in the
//!   policy's [`Syntax`], which parses back to an equal policy;
//!   [`PermissionsPolicy::to_permissions_policy`] migrates a legacy policy.
//! - [`run`], [`run_feature_policy`], [`run_fields`] and [`analyze`] flag
//!   weaknesses — `*` grants of powerful features (rated by the
//!   [`FEATURES`] registry), `http://` origins, ignored members (`"self"`,
//!   `none`), `src` in a header, duplicate, unknown and deprecated features,
//!   the legacy header — and [`Report::to_findings`] maps them to
//!   [`rune_finding::Finding`]s with check ids `permissions_policy.<kind>`.
//!
//! The crate is sans-I/O: it works on header strings and never fetches
//! anything.
//!
//! # Example
//!
//! ```
//! use rune_finding::{Location, Severity};
//! use rune_permissions_policy::{Options, PermissionsPolicy, WeaknessKind, run};
//!
//! let report = run(
//!     "camera=*, geolocation=self, microphone=(\"self\")",
//!     &Options::default(),
//! );
//! assert_eq!(
//!     report.canonical().as_deref(),
//!     Some("camera=*, geolocation=(self), microphone=(\"self\")")
//! );
//! assert_eq!(report.max_severity(), Some(Severity::Medium));
//! assert!(report.weaknesses.iter().any(|w| w.kind == WeaknessKind::AllowAll));
//!
//! let findings = report.to_findings::<()>(&Location::url("https://example.com/"));
//! assert!(findings.iter().any(|f| f.check_id == "permissions_policy.invalid_member"));
//!
//! // Legacy Feature-Policy, migrated.
//! let legacy = PermissionsPolicy::parse_feature_policy("camera 'none'; usb 'self'").unwrap();
//! assert_eq!(legacy.to_permissions_policy().to_string(), "camera=(), usb=(self)");
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod analyze;
mod features;
mod policy;
mod sf;

pub use analyze::{
    Options, RECOMMENDED_RESTRICTED, Report, Weakness, WeaknessKind, analyze, run,
    run_feature_policy, run_fields,
};
pub use features::{FEATURES, Feature, Sensitivity, Status, feature};
pub use policy::{Allowlist, Directive, Member, PermissionsPolicy, Syntax, is_origin};

/// Errors from parsing a header.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A character the grammar does not allow here.
    #[error("unexpected {found:?} at byte {offset}")]
    UnexpectedChar {
        /// Byte offset in the header value.
        offset: usize,
        /// The character found (`'\0'` at the end of input).
        found: char,
    },
    /// A string is not closed.
    #[error("unterminated string at byte {offset}")]
    UnterminatedString {
        /// Byte offset of the opening quote.
        offset: usize,
    },
    /// An integer or decimal has too many digits.
    #[error("number out of range at byte {offset}")]
    NumberOutOfRange {
        /// Byte offset of the number.
        offset: usize,
    },
    /// A `Feature-Policy` feature name with characters outside the HTTP
    /// token set.
    #[error("invalid feature name {name:?}")]
    InvalidFeatureName {
        /// The name as written.
        name: String,
    },
}
