//! Analyze `Set-Cookie` headers for weak security attributes, reporting
//! problems as [`rune_finding`] findings.
//!
//! Builds on [`rune_cookie`], which parses each header with the user-agent
//! algorithm of [RFC 6265 §5.2](https://www.rfc-editor.org/rfc/rfc6265#section-5.2)
//! and keeps every raw attribute in wire order. On top of that this crate
//! applies the [RFC 6265bis](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis)
//! rules browsers enforce and the
//! [OWASP session management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
//! recommendations:
//!
//! - **Missing protections**: no `Secure`, `HttpOnly` or `SameSite`,
//!   `SameSite=None`, a cookie set over plain HTTP.
//! - **Scope**: a `Domain` attribute (shared with every subdomain), and —
//!   given the request URL — a `Domain` that is a public suffix or does not
//!   cover the host; no valid `Path`.
//! - **Session cookies**: names that look like sessions or credentials
//!   (configurable, see [`Options::sensitive_patterns`]) get stricter
//!   severities, a shorter lifetime limit and a hint to use `__Host-`.
//! - **Prefixes**: `__Secure-` and `__Host-` cookies that browsers reject.
//! - **Syntax**: names and values outside the strict RFC 6265 §4.1.1
//!   grammar, ignored attribute values, misspelled, repeated and unknown
//!   attributes, unparseable headers, a cookie set twice.
//!
//! [`run`], [`run_fields`] and [`run_response`] return a [`Report`];
//! [`Report::to_findings`] maps its weaknesses to
//! [`rune_finding::Finding`]s with check ids `cookie.<kind>`
//! ([`WeaknessKind::check_id`]). Rejections from `rune-cookie`'s jar map
//! through [`WeaknessKind::from_rejection`].
//!
//! The crate is sans-I/O: it works on header strings or a
//! [`rune_http_model::HttpResponse`], and never reads the clock (pass
//! [`Options::now`] to judge `Expires`).
//!
//! # Example
//!
//! ```
//! use rune_cookie_sec::{Options, WeaknessKind, run, run_fields};
//! use rune_finding::{Location, Severity};
//!
//! let report = run("sessionid=abc; Path=/; SameSite=None", &Options::default());
//! assert_eq!(report.max_severity(), Some(Severity::Medium));
//! let kinds: Vec<_> = report.weaknesses.iter().map(|w| w.kind).collect();
//! assert!(kinds.contains(&WeaknessKind::MissingSecure));
//! assert!(kinds.contains(&WeaknessKind::MissingHttpOnly));
//! assert!(kinds.contains(&WeaknessKind::SameSiteNoneWithoutSecure));
//!
//! let findings = report.to_findings::<()>(&Location::url("https://example.com/"));
//! assert!(findings.iter().any(|f| f.check_id == "cookie.missing_secure"));
//!
//! // A hardened session cookie is clean.
//! let good = run_fields(
//!     ["__Host-sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax"],
//!     &Options::default(),
//! );
//! assert!(good.is_clean());
//!
//! // With the request URL, Domain is checked against the host and the PSL.
//! let options = Options::default().with_request_url("https://shop.example.co.uk/".parse()?);
//! let report = run("pref=1; Domain=co.uk; Path=/; Secure; HttpOnly; SameSite=Lax", &options);
//! assert!(report.weaknesses.iter().any(|w| w.kind == WeaknessKind::PublicSuffixDomain));
//! # Ok::<(), url::ParseError>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod analyze;

pub use analyze::{
    DEFAULT_SENSITIVE_PATTERNS, Options, Report, Weakness, WeaknessKind, analyze, run, run_fields,
    run_response,
};
/// Why a `Set-Cookie` header did not parse (from `rune-cookie`).
pub use rune_cookie::Error;
