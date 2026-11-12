//! IP reputation behind one interface: a [`ReputationProvider`] trait,
//! adapters for `AbuseIPDB`, `GreyNoise`, Shodan `InternetDB` and Censys, and an
//! [`Enricher`] that merges their answers.
//!
//! - Every provider turns an address into an [`HttpRequest`] and the
//!   answer into a normalized [`Verdict`]: [`Classification`], 0-100
//!   score, categories, tags, last-seen time, open ports, host names,
//!   CVEs, AS and country, plus the provider's raw JSON.
//! - The crate has no HTTP client and does no I/O. A [`Transport`] moves
//!   the bytes: implement it over the client you already use (a closure
//!   works), or call [`ReputationProvider::request`] and
//!   [`ReputationProvider::parse`] around an async client.
//! - API keys are [`SecretValue`](rune_secret_ref::SecretValue)s (resolve
//!   them with `rune-secret-ref`); they travel only in redacted headers.
//! - [`Enricher`] asks several providers, caches verdicts, paces each
//!   provider and backs off on 429s, refuses non-global addresses
//!   (`rune-ip`), and merges everything into a [`Summary`].
//!
//! | Adapter | Feature | Key | Endpoint |
//! | --- | --- | --- | --- |
//! | [`AbuseIpDb`] | `abuseipdb` | required | [`/api/v2/check`](https://docs.abuseipdb.com/#check-endpoint) |
//! | [`GreyNoise`] | `greynoise` | optional | [Community API v3](https://docs.greynoise.io/reference/get_v3-community-ip) |
//! | [`ShodanInternetDb`] | `shodan` | none | [InternetDB](https://internetdb.shodan.io/docs) |
//! | [`Censys`] | `censys` | API ID + secret | [Search v2 hosts](https://search.censys.io/api#/hosts/viewHost) |
//!
//! # Example
//!
//! ```
//! use std::time::Instant;
//! use rune_ip_intel::{
//!     AbuseIpDb, Classification, Enricher, HttpRequest, HttpResponse, Options,
//!     ShodanInternetDb, TransportError,
//! };
//! use rune_secret_ref::SecretValue;
//! # use std::time::Duration;
//!
//! // In production the key comes from `SecretRef::resolve`.
//! // Documentation addresses (203.0.113.0/24) are not global, so this
//! // example lets them through; by default they are refused.
//! let mut enricher = Enricher::new(Options::default().with_allow_non_global(true))
//!     .with_provider(AbuseIpDb::new(SecretValue::new("abuse-key")), Duration::from_secs(1))
//!     .with_provider(ShodanInternetDb::new(), Duration::ZERO);
//!
//! // Any `Fn(&HttpRequest) -> Result<HttpResponse, TransportError>` is a
//! // transport; this one answers like the providers, offline.
//! let transport = |request: &HttpRequest| -> Result<HttpResponse, TransportError> {
//!     let body = if request.url.starts_with("https://api.abuseipdb.com/") {
//!         r#"{"data":{"abuseConfidenceScore":100,"totalReports":42,
//!             "reports":[{"categories":[18,22]}]}}"#
//!     } else {
//!         r#"{"ip":"203.0.113.7","ports":[22,80],"tags":["scanner"],"vulns":[],
//!             "hostnames":[],"cpes":[]}"#
//!     };
//!     Ok(HttpResponse::new(200).with_body(body))
//! };
//!
//! let summary = enricher.enrich("203.0.113.7".parse()?, &transport, Instant::now())?;
//! assert_eq!(summary.classification, Classification::Malicious);
//! assert_eq!(summary.score, Some(100));
//! assert_eq!(summary.categories, ["Brute-Force", "SSH"]);
//! assert_eq!(summary.verdict("shodan").unwrap().open_ports, [22, 80]);
//! assert!(summary.errors.is_empty());
//!
//! // With the default options, private addresses never leave the process.
//! let mut strict = Enricher::default().with_provider(ShodanInternetDb::new(), Duration::ZERO);
//! assert!(strict.enrich("10.0.0.1".parse()?, &transport, Instant::now()).is_err());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "abuseipdb")]
mod abuseipdb;
#[cfg(feature = "censys")]
mod censys;
mod enricher;
#[cfg(feature = "greynoise")]
mod greynoise;
mod http;
mod provider;
#[cfg(feature = "shodan")]
mod shodan;
mod verdict;

use std::net::IpAddr;
use std::time::Duration;

#[cfg(feature = "abuseipdb")]
pub use abuseipdb::{AbuseIpDb, category_name as abuseipdb_category};
#[cfg(feature = "censys")]
pub use censys::Censys;
pub use enricher::{Enricher, Options};
#[cfg(feature = "greynoise")]
pub use greynoise::GreyNoise;
pub use http::{HeaderValue, HttpRequest, HttpResponse, Method, Transport, TransportError};
pub use provider::{ReputationProvider, parse_time};
#[cfg(feature = "shodan")]
pub use shodan::ShodanInternetDb;
pub use verdict::{Classification, Summary, Verdict};

/// Errors returned by this crate.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// No response arrived (from the [`Transport`]).
    #[error("transport error: {message}")]
    Transport {
        /// The transport's description.
        message: String,
        /// Whether a later attempt may succeed.
        retryable: bool,
    },
    /// The provider rejected the credentials (401 or 403).
    #[error("{provider}: authentication failed (HTTP {status})")]
    Auth {
        /// Provider name.
        provider: &'static str,
        /// HTTP status.
        status: u16,
    },
    /// The provider answered 429, or the [`Enricher`] held the request
    /// back to respect its pacing.
    #[error("{provider}: rate limited")]
    RateLimited {
        /// Provider name.
        provider: &'static str,
        /// How long to wait, when known.
        retry_after: Option<Duration>,
    },
    /// The provider answered with another error status.
    #[error("{provider}: HTTP {status}: {message}")]
    Status {
        /// Provider name.
        provider: &'static str,
        /// HTTP status.
        status: u16,
        /// The start of the response body.
        message: String,
    },
    /// The answer could not be read.
    #[error("{provider}: invalid response: {reason}")]
    InvalidResponse {
        /// Provider name.
        provider: &'static str,
        /// What was wrong.
        reason: String,
    },
    /// The address is not globally routable (see
    /// [`Options::allow_non_global`]).
    #[error("{0} is not a global address")]
    NonGlobalAddress(IpAddr),
}

impl Error {
    /// Whether a later attempt may succeed (transport failures marked
    /// retryable, rate limits, 5xx statuses).
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Transport { retryable, .. } => *retryable,
            Self::RateLimited { .. } => true,
            Self::Status { status, .. } => *status >= 500,
            _ => false,
        }
    }
}
