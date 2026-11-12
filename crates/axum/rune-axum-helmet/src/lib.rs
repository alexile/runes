//! Security headers middleware for Axum.
//!
//! A [`tower::Layer`] that injects security-related HTTP response headers on
//! every request. Inspired by [Helmet.js](https://helmetjs.github.io/). Works
//! with any Tower-compatible framework (Axum, Hyper, etc.).
//!
//! # Default headers
//!
//! [`HelmetLayer::default()`] sets the following headers:
//!
//! | Header | Default value |
//! |--------|---------------|
//! | `X-Content-Type-Options` | `nosniff` |
//! | `X-XSS-Protection` | `0` |
//! | `X-Frame-Options` | `SAMEORIGIN` |
//! | `Referrer-Policy` | `strict-origin-when-cross-origin` |
//! | `Cross-Origin-Opener-Policy` | `same-origin` |
//! | `Cross-Origin-Resource-Policy` | `same-origin` |
//!
//! HSTS, CSP, and `Cross-Origin-Embedder-Policy` are **opt-in** — they are
//! too application-specific to be safe defaults.
//!
//! # Quick Start
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
//! # Custom Configuration
//!
//! ```rust
//! use axum::{routing::get, Router};
//! use rune_axum_helmet::{CspBuilder, Helmet, HelmetLayer, Hsts, XFrameOptions};
//!
//! let helmet = Helmet::new()
//!     .frame_options(XFrameOptions::Deny)
//!     .hsts(Hsts::new().max_age(63_072_000).include_subdomains())
//!     .csp_from(
//!         CspBuilder::new()
//!             .default_src(&["'self'"])
//!             .script_src(&["'self'", "'strict-dynamic'"])
//!             .upgrade_insecure_requests(),
//!     );
//!
//! let app: Router = Router::new()
//!     .route("/", get(|| async { "hello" }))
//!     .layer(HelmetLayer::new(helmet));
//! ```
//!
//! # Testing a new CSP with Report-Only mode
//!
//! ```rust
//! use axum::{routing::get, Router};
//! use rune_axum_helmet::{CspBuilder, Helmet, HelmetLayer};
//!
//! let helmet = Helmet::new().report_only_csp_from(
//!     CspBuilder::new()
//!         .default_src(&["'self'"])
//!         .report_to("csp-endpoint"),
//! );
//!
//! let app: Router = Router::new()
//!     .route("/", get(|| async { "ok" }))
//!     .layer(HelmetLayer::new(helmet));
//! ```

pub use crate::config::{
    CrossOriginEmbedderPolicy, CrossOriginOpenerPolicy, CrossOriginResourcePolicy, CspBuilder,
    Helmet, Hsts, ReferrerPolicy, XFrameOptions,
};
pub use crate::layer::HelmetLayer;

mod config;
mod layer;
