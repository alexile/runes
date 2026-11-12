//! Analyze CORS response headers for dangerous origin, credential and
//! allowlist combinations, reporting weaknesses as [`rune_finding`]
//! findings.
//!
//! Follows the CORS protocol of the
//! [Fetch standard](https://fetch.spec.whatwg.org/#http-cors-protocol):
//!
//! - [`CorsHeaders`] collects `Access-Control-*` and `Vary` response headers
//!   from name/value pairs or a raw header block; [`AllowOrigin`] interprets
//!   `Access-Control-Allow-Origin` the way browsers do.
//! - [`cors_check`] runs the Fetch CORS check and returns the [`Exposure`]:
//!   whether a page at the request origin can read the response, with or
//!   without credentials.
//! - [`classify`] places a request origin relative to the site under test
//!   ([`Options::target`]) and its [`Options::trusted`] origins: same origin,
//!   subdomain, plain-`http` variant, unanchored-suffix and -prefix
//!   lookalikes, `null`, or arbitrary. [`probes`] lists one origin of each
//!   class to send.
//! - [`run`] turns a table of (request origin, response headers)
//!   [`Exchange`]s into a [`Report`]: a verdict [`Row`] per exchange and the
//!   [`Weakness`]es found — reflected origins with credentials, `*` with
//!   credentials, the `null` origin, over-broad allowlists, missing
//!   `Vary: Origin`, private network access and invalid header values.
//!   [`Report::to_findings`] maps them to [`rune_finding::Finding`]s with
//!   check ids `cors.<kind>`.
//!
//! The crate is sans-I/O: it never sends requests. Send the [`probes`]
//! yourself and feed the responses back in.
//!
//! # Example
//!
//! ```
//! use rune_cors::{CorsHeaders, Exchange, Exposure, Options, WeaknessKind, run};
//! use rune_finding::{Location, Severity};
//!
//! let options = Options::for_target("https://bank.example".parse()?);
//! let reflect = |origin: &str| {
//!     Exchange::new(
//!         Some(origin),
//!         CorsHeaders::from_pairs([
//!             ("Access-Control-Allow-Origin", origin),
//!             ("Access-Control-Allow-Credentials", "true"),
//!             ("Vary", "Origin"),
//!         ]),
//!     )
//! };
//! let report = run(
//!     &[reflect("https://bank.example"), reflect("https://evil.example")],
//!     &options,
//! );
//! assert_eq!(report.rows[1].exposure, Exposure::Credentialed);
//! assert_eq!(report.max_severity(), Some(Severity::Critical));
//! assert_eq!(report.weaknesses[0].kind, WeaknessKind::OriginReflection);
//!
//! let findings = report.to_findings::<()>(&Location::url("https://bank.example/api"));
//! assert_eq!(findings[0].check_id, "cors.origin_reflection");
//!
//! // `*` without credentials is only noted.
//! let public = Exchange::new(
//!     Some("https://evil.example"),
//!     CorsHeaders::from_pairs([("Access-Control-Allow-Origin", "*")]),
//! );
//! let report = run(&[public], &options);
//! assert_eq!(report.max_severity(), Some(Severity::Informational));
//! # Ok::<(), rune_cors::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod analyze;
mod headers;
mod origin;

pub use analyze::{
    Exchange, Exposure, Options, OriginClass, Probe, Report, Row, Weakness, WeaknessKind, analyze,
    classify, cors_check, probes, run,
};
pub use headers::{AllowOrigin, CorsHeaders};
pub use origin::Origin;

/// Errors from this crate.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The text is not a serialized tuple origin.
    #[error("invalid origin {input:?}: {reason}")]
    InvalidOrigin {
        /// The text as given.
        input: String,
        /// What is wrong with it.
        reason: &'static str,
    },
}
