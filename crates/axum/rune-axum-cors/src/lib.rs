//! Safe-by-default CORS middleware — Tower middleware for Axum.
//!
//! A [`tower::Layer`] implementing the server side of the
//! [Fetch CORS protocol](https://fetch.spec.whatwg.org/#http-cors-protocol):
//! it answers preflight requests and adds `Access-Control-*` headers to
//! responses for allowed origins. It is the writing side of
//! [`rune_cors`], which analyses CORS response headers.
//!
//! Every policy is audited before it serves a request.
//! [`CorsLayer::new()`] runs the headers the middleware would send for a
//! set of attacker-style probe origins through [`rune_cors::run`] and
//! refuses the policy when the analyzer rates it insecure:
//!
//! - `*` with credentials, always;
//! - the `null` origin;
//! - an origin predicate that reflects arbitrary origins, accepts
//!   lookalikes such as `evilexample.com` or `example.com.evil.net`, or
//!   plain-`http` variants of a secure origin;
//! - Private Network Access granted to any origin.
//!
//! Weaknesses below the threshold ([`Cors::reject_at`], default `Low`) are
//! kept in [`CorsLayer::report`] so they can be logged as
//! [`rune_finding`] findings.
//!
//! # Features
//!
//! - Exact origin allowlist by default, with opt-in subdomains that keep
//!   the scheme and port, and an audited predicate escape hatch.
//! - Preflights answered directly (`204`, or `403` when refused) with
//!   method and header checks; they never reach handlers.
//! - `Vary: Origin` on every response whose CORS headers depend on the
//!   request.
//! - Credentials, exposed headers, `Access-Control-Max-Age` and Private
//!   Network Access.
//! - Works with Axum, Hyper, and any Tower-compatible framework.
//!
//! # Quick Start
//!
//! ```rust
//! use http::{HeaderName, Method};
//! use rune_axum_cors::{Cors, CorsLayer, Error, WeaknessKind};
//!
//! let cors = Cors::new()
//!     .site("https://example.com")
//!     .allow_origins(["https://app.example.com", "https://admin.example.com"])
//!     .allow_credentials(true)
//!     .allow_methods([Method::GET, Method::POST, Method::PUT])
//!     .allow_headers([HeaderName::from_static("content-type")]);
//! assert!(cors.is_allowed("https://app.example.com"));
//! assert!(!cors.is_allowed("https://evil.example"));
//! let layer = CorsLayer::new(cors)?;
//! assert!(layer.report().weaknesses.is_empty());
//!
//! // The credentialed-wildcard foot-gun is refused at build time.
//! let err = CorsLayer::new(Cors::new().allow_any_origin().allow_credentials(true))
//!     .unwrap_err();
//! assert!(matches!(
//!     &err,
//!     Error::Insecure { weaknesses } if weaknesses[0].kind == WeaknessKind::WildcardWithCredentials
//! ));
//!
//! // So is a "suffix match" predicate that lets lookalike domains in.
//! let err = CorsLayer::new(
//!     Cors::new()
//!         .site("https://example.com")
//!         .allow_origin_fn(|origin| origin.ends_with("example.com"))
//!         .allow_credentials(true),
//! )
//! .unwrap_err();
//! assert!(err.to_string().contains("cors.unanchored_allowlist"));
//! # Ok::<(), Error>(())
//! ```
//!
//! # Axum
//!
//! ```rust
//! use std::time::Duration;
//! use axum::{routing::get, Router};
//! use rune_axum_cors::{Cors, CorsLayer};
//!
//! let app: Router = Router::new()
//!     .route("/api/items", get(|| async { "[]" }))
//!     .layer(CorsLayer::new(
//!         Cors::new()
//!             .allow_origin("https://app.example.com")
//!             .max_age(Duration::from_secs(600)),
//!     )?);
//! # Ok::<(), rune_axum_cors::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub use config::Cors;
pub use layer::{CorsLayer, CorsService};
pub use rune_cors::{Report, Weakness, WeaknessKind};
pub use rune_finding::Severity;

mod config;
mod layer;

/// Errors from building a [`CorsLayer`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// An origin passed to [`Cors::allow_origin`] or [`Cors::site`] is not
    /// a valid serialized origin.
    #[error(transparent)]
    InvalidOrigin(#[from] rune_cors::Error),
    /// The `rune-cors` audit rated the policy insecure.
    #[error("insecure CORS policy: {}", summary(.weaknesses))]
    Insecure {
        /// The weaknesses that rejected the policy: the most severe
        /// instance of each kind, most severe first.
        weaknesses: Vec<Weakness>,
    },
}

/// `check_id (severity): message; …`, one entry per weakness.
fn summary(weaknesses: &[Weakness]) -> String {
    weaknesses
        .iter()
        .map(|w| format!("{} ({}): {}", w.kind.check_id(), w.severity, w.message))
        .collect::<Vec<_>>()
        .join("; ")
}
