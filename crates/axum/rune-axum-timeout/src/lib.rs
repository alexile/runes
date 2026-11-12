//! Request timeout middleware — Tower middleware for Axum.
//!
//! A [`tower::Layer`] that gives every request a deadline. When the inner
//! service does not produce a response in time, its future is dropped
//! (cancelling the handler at its next `.await`) and the client receives a
//! configurable error response (default: `504 Gateway Timeout`) instead of a
//! hung connection.
//!
//! The deadline is configurable per route in two ways:
//!
//! - **Path overrides on one layer.** [`Timeout::path`] sets a different
//!   deadline for a path prefix; the longest matching prefix wins. The
//!   decision is a pure function, [`Timeout::duration_for`].
//! - **Per-route layers.** Axum's `MethodRouter::layer` / `Router::route_layer`
//!   accept a [`TimeoutLayer`] like any other Tower layer.
//!
//! # Features
//!
//! - Configurable default deadline (default: 30 seconds).
//! - Configurable error status code (default: `504 Gateway Timeout`).
//! - Longest-prefix path overrides, matched on `/` segment boundaries.
//! - Works with Axum, Hyper, and any Tower-compatible framework running on
//!   the Tokio runtime.
//!
//! # Quick Start
//!
//! ```rust
//! use std::time::Duration;
//! use rune_axum_timeout::Timeout;
//!
//! // The deadline decision itself is pure and needs no runtime.
//! let config = Timeout::new()
//!     .duration(Duration::from_secs(10))
//!     .path("/reports", Duration::from_secs(120));
//!
//! assert_eq!(config.duration_for("/users/42"), Duration::from_secs(10));
//! assert_eq!(config.duration_for("/reports/2026/q3"), Duration::from_secs(120));
//! assert_eq!(config.duration_for("/reportsx"), Duration::from_secs(10));
//! ```
//!
//! # Axum
//!
//! ```rust
//! use std::time::Duration;
//! use axum::{routing::get, Router};
//! use http::StatusCode;
//! use rune_axum_timeout::{Timeout, TimeoutLayer};
//!
//! let app: Router = Router::new()
//!     .route("/", get(|| async { "ok" }))
//!     .route("/export", get(|| async { "big" }))
//!     // A tighter per-route deadline, applied with axum's own per-route layering.
//!     .route(
//!         "/ping",
//!         get(|| async { "pong" }).layer(TimeoutLayer::new(
//!             Timeout::new().duration(Duration::from_millis(250)),
//!         )),
//!     )
//!     .layer(TimeoutLayer::new(
//!         Timeout::new()
//!             .duration(Duration::from_secs(5))
//!             .status(StatusCode::SERVICE_UNAVAILABLE)
//!             .path("/export", Duration::from_secs(60)),
//!     ));
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub use layer::{Timeout, TimeoutLayer, TimeoutService};

mod layer;
