//! Security headers middleware for Axum, in the spirit of
//! [Helmet.js](https://helmetjs.github.io/).
//!
//! [`HelmetLayer`] is a [`tower::Layer`] that sets the response headers the
//! [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
//! recommends. It works with Axum, Hyper and any other Tower stack.
//!
//! - A **Content-Security-Policy** on by default, a [`CspBuilder`] with
//!   per-request nonces ([`CspNonce`] in the request extensions) and
//!   `'strict-dynamic'`, and report-only mode.
//! - **HSTS** that is not sent on plain-HTTP requests, with preload checks
//!   from `rune-hsts`.
//! - A restrictive **Permissions-Policy**, cross-origin isolation headers
//!   (COOP, CORP, opt-in COEP with report-only), `Reporting-Endpoints`.
//! - Headers a handler sets itself are kept, and [`HelmetOverride`] changes
//!   the configuration per route.
//! - Everything is validated when the layer is built: a misspelt CSP
//!   directive is an [`Error`] at startup, not a header browsers ignore.
//!
//! # Default headers
//!
//! [`HelmetLayer::default()`] (and [`Helmet::new()`]) sends:
//!
//! | Header | Value |
//! |--------|-------|
//! | `Content-Security-Policy` | [`CspBuilder::recommended`]: `default-src 'self'; base-uri 'self'; font-src 'self' https: data:; form-action 'self'; frame-ancestors 'none'; img-src 'self' data:; object-src 'none'; script-src 'self'; script-src-attr 'none'; style-src 'self' https: 'unsafe-inline'; upgrade-insecure-requests` |
//! | `Strict-Transport-Security` | `max-age=31536000; includeSubDomains`, not on plain-HTTP requests ([`HstsMode`]) |
//! | `X-Content-Type-Options` | `nosniff` |
//! | `X-Frame-Options` | `DENY` |
//! | `Referrer-Policy` | `strict-origin-when-cross-origin` |
//! | `Cross-Origin-Opener-Policy` | `same-origin` |
//! | `Cross-Origin-Resource-Policy` | `same-origin` |
//! | `Origin-Agent-Cluster` | `?1` |
//! | `Permissions-Policy` | [`DEFAULT_PERMISSIONS_POLICY`]: camera, microphone, geolocation, payment, USB and other powerful features off |
//! | `X-DNS-Prefetch-Control` | `off` |
//! | `X-Permitted-Cross-Domain-Policies` | `none` |
//! | `X-XSS-Protection` | `0` (turns the legacy, exploitable XSS auditor off) |
//!
//! `Server` and `X-Powered-By` are removed. `Cross-Origin-Embedder-Policy`
//! is opt-in, since it blocks cross-origin subresources that do not opt in.
//!
//! # Quick start
//!
//! ```rust
//! use axum::{routing::get, Router};
//! use rune_axum_helmet::HelmetLayer;
//!
//! let app: Router = Router::new()
//!     .route("/", get(|| async { "hello" }))
//!     .layer(HelmetLayer::default());
//! ```
//!
//! # Nonce-based CSP
//!
//! ```rust
//! use axum::{Extension, Router, response::Html, routing::get};
//! use rune_axum_helmet::{CspBuilder, CspNonce, Helmet};
//!
//! async fn page(Extension(nonce): Extension<CspNonce>) -> Html<String> {
//!     Html(format!(r#"<script nonce="{nonce}" src="/app.js"></script>"#))
//! }
//!
//! let helmet = Helmet::new().csp_from(
//!     CspBuilder::recommended().script_nonce().strict_dynamic(),
//! );
//! let app: Router = Router::new()
//!     .route("/", get(page))
//!     .layer(helmet.build()?);
//! # Ok::<(), rune_axum_helmet::Error>(())
//! ```
//!
//! # Trying a stricter policy in report-only mode
//!
//! ```rust
//! use rune_axum_helmet::{CrossOriginEmbedderPolicy, CspBuilder, Helmet};
//!
//! let layer = Helmet::new()
//!     .reporting_endpoint("csp", "https://reports.example/csp")
//!     .report_only_csp_from(CspBuilder::strict().report_to("csp"))
//!     .reporting_endpoint("coep", "https://reports.example/coep")
//!     .report_only_cross_origin_embedder_policy(CrossOriginEmbedderPolicy::RequireCorp)
//!     .cross_origin_embedder_policy_report_to("coep")
//!     .build()?;
//! # Ok::<(), rune_axum_helmet::Error>(())
//! ```
//!
//! # Handler headers and per-route overrides
//!
//! A header the handler sets itself is left alone (turn this off with
//! [`Helmet::overwrite`]). For bigger changes, put a [`HelmetOverride`] in
//! the response extensions or wrap the route with it.

pub use crate::config::{
    CrossOriginEmbedderPolicy, CrossOriginOpenerPolicy, CrossOriginResourcePolicy,
    DEFAULT_PERMISSIONS_POLICY, Helmet, Hsts, HstsMode, PermittedCrossDomainPolicies,
    ReferrerPolicy, XFrameOptions,
};
pub use crate::csp::{CspBuilder, CspNonce};
pub use crate::error::Error;
pub use crate::layer::{HelmetLayer, HelmetOverride, HelmetOverrideService, HelmetService};

mod config;
mod csp;
mod error;
mod layer;
