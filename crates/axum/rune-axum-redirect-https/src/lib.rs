//! HTTP-to-HTTPS redirect middleware for Axum and Tower.
//!
//! A [`tower::Layer`] that detects incoming HTTP requests and issues a
//! permanent redirect to the HTTPS equivalent. HTTPS requests are forwarded
//! to the inner service unchanged.
//!
//! Detection follows this priority order:
//!
//! 1. `X-Forwarded-Proto: http` — set by most reverse proxies when the
//!    upstream connection is plain HTTP.
//! 2. URI scheme of `http` — present when the request line carries an
//!    absolute URI. Plain HTTP/1.1 requests served by `axum::serve` use the
//!    origin form (`GET /path`) and have no scheme, so without a proxy that
//!    sets `X-Forwarded-Proto` most requests are not detected.
//!
//! If neither indicator is present the request passes through unchanged,
//! which is the safe default when the protocol cannot be determined.
//!
//! # Features
//!
//! - Configurable redirect status: `308 Permanent Redirect` (default,
//!   method-preserving) or `301 Moved Permanently` (legacy compatibility).
//! - Optional HTTPS port override for non-standard port setups.
//! - Graceful fallback: if no `Host` header is present the request is
//!   forwarded rather than returning a malformed redirect without `Location`.
//! - A `Host` header that is not a plain host name or IP literal with an
//!   optional port gets `400 Bad Request`, so a forged host never turns into
//!   an open redirect.
//!
//! # Quick Start
//!
//! ```rust
//! use axum::{routing::get, Router};
//! use rune_axum_redirect_https::RedirectHttpsLayer;
//!
//! let app: Router = Router::new()
//!     .route("/", get(|| async { "hello" }))
//!     .layer(RedirectHttpsLayer::default());
//! ```
//!
//! # Custom Configuration
//!
//! ```rust
//! use axum::{routing::get, Router};
//! use http::StatusCode;
//! use rune_axum_redirect_https::{RedirectHttps, RedirectHttpsLayer};
//!
//! // HTTP on :8080 → HTTPS on :8443, using 301 for legacy clients
//! let layer = RedirectHttpsLayer::new(
//!     RedirectHttps::new()
//!         .status(StatusCode::MOVED_PERMANENTLY)
//!         .https_port(8443),
//! );
//!
//! let app: Router = Router::new()
//!     .route("/", get(|| async { "hello" }))
//!     .layer(layer);
//! ```

pub use layer::{RedirectHttps, RedirectHttpsLayer};

mod layer;
