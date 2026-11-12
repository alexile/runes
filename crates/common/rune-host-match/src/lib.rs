//! Hostname pattern matching, for the two places it goes wrong most often:
//! egress allowlists and TLS certificate names.
//!
//! The two use different rules, so they get different types:
//!
//! | `*.example.com` against | [`HostPattern`] (allowlist) | [`CertName`] (certificate) |
//! | ----------------------- | --------------------------- | -------------------------- |
//! | `api.example.com`       | matches                     | matches                    |
//! | `a.b.example.com`       | matches (any depth)         | no (one label only)        |
//! | `example.com` (apex)    | no                          | no                         |
//! | `evilexample.com`       | no                          | no                         |
//!
//! - [`Hostname`] validates and normalizes a name: ASCII lowercase, one
//!   trailing dot dropped, RFC 1123 label syntax, length limits from
//!   RFC 1035 §2.3.4. IP literals are rejected; use `rune-cidr` for those.
//! - [`HostPattern`] and [`HostAllowlist`] implement allowlist semantics:
//!   exact names, `*.suffix` for every subdomain (never the apex), and
//!   whole-label wildcards (`api.*.example.com`).
//! - [`CertName`], [`cert_name_matches`] and [`cert_names_match`] implement
//!   certificate semantics per
//!   [RFC 6125 §6.4.3](https://www.rfc-editor.org/rfc/rfc6125#section-6.4.3)
//!   and [RFC 9525 §6.3](https://www.rfc-editor.org/rfc/rfc9525#section-6.3):
//!   a single left-most wildcard label covering exactly one label.
//!
//! Matching is sans-I/O and allocation-light. Malformed patterns are errors
//! when parsed; a malformed host simply never matches.
//!
//! Neither type knows the Public Suffix List by default, so `*.co.uk` is a
//! valid certificate name and allowlist pattern. The `psl` feature adds
//! checks against [`rune-psl`](https://docs.rs/rune-psl):
//! `CertName::parse_with_psl`, `cert_names_match_with_psl` and
//! `HostPattern::is_public_suffix_wildcard`.
//!
//! # Example
//!
//! ```
//! use rune_host_match::{cert_name_matches, HostAllowlist};
//!
//! // Egress allowlist.
//! let allow = HostAllowlist::parse_all(["api.anthropic.com", "*.github.com"])?;
//! assert!(allow.allows("API.Anthropic.com."));
//! assert!(allow.allows("codeload.github.com"));
//! assert!(!allow.allows("github.com"));
//! assert!(!allow.allows("evilgithub.com"));
//!
//! // Certificate names.
//! assert!(cert_name_matches("*.github.com", "api.github.com"));
//! assert!(!cert_name_matches("*.github.com", "a.b.github.com"));
//! # Ok::<(), rune_host_match::Error>(())
//! ```
//!
//! # Features
//!
//! - `serde`: (de)serialize [`Hostname`], [`HostPattern`], [`CertName`] as
//!   strings and [`HostAllowlist`] as a list of strings, validating on input.
//! - `psl`: Public Suffix List checks for wildcards, through `rune-psl`
//!   (re-exported as `rune_host_match::rune_psl`).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod cert;
mod error;
mod hostname;
mod pattern;
#[cfg(feature = "serde")]
mod serde_impl;

#[cfg(feature = "psl")]
pub use cert::cert_names_match_with_psl;
pub use cert::{CertName, cert_name_matches, cert_names_match};
pub use error::Error;
pub use hostname::Hostname;
pub use pattern::{HostAllowlist, HostPattern, PatternKind};
/// The Public Suffix List crate the `psl` checks take a list from.
#[cfg(feature = "psl")]
pub use rune_psl;
