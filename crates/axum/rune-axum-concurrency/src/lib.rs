//! Concurrency limit and load-shedding middleware — Tower middleware for Axum.
//!
//! A [`tower::Layer`] that bounds how many requests are processed at once.
//! Within the limit, requests pass through untouched. Beyond it, they are
//! **shed**: answered immediately with a configurable error response
//! (default: `503 Service Unavailable`, optionally with `Retry-After`)
//! without reaching the handler. Nothing queues, so latency stays bounded
//! under overload and a traffic spike cannot pile up unbounded work.
//!
//! Admission is a sans-I/O [`Limiter`]: a lock-free counter with no runtime
//! dependency, which also keeps the [`Metrics`] (in flight, peak, admitted,
//! shed) for export.
//!
//! # Features
//!
//! - Configurable limit (default: 1024 in-flight requests).
//! - Configurable shed status code (default: `503 Service Unavailable`).
//! - Optional `Retry-After` header on shed responses.
//! - Live metrics: current and peak in-flight count, admitted and shed totals.
//! - Runtime-agnostic: works with Axum, Hyper, and any Tower-compatible
//!   framework.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_axum_concurrency::Limiter;
//!
//! // The admission decision itself is pure and needs no runtime.
//! let limiter = Limiter::new(2);
//! let a = limiter.try_acquire().expect("within the limit");
//! let b = limiter.try_acquire().expect("within the limit");
//! assert!(limiter.try_acquire().is_none(), "beyond the limit: shed");
//!
//! drop(a); // a request finished
//! assert!(limiter.try_acquire().is_some());
//! # drop(b);
//!
//! let m = limiter.metrics();
//! assert_eq!((m.admitted, m.shed, m.peak), (3, 1, 2));
//! ```
//!
//! # Axum
//!
//! ```rust
//! use std::time::Duration;
//! use axum::{routing::get, Router};
//! use rune_axum_concurrency::{ConcurrencyLimit, ConcurrencyLimitLayer};
//!
//! let global = ConcurrencyLimitLayer::new(
//!     ConcurrencyLimit::new()
//!         .max_in_flight(512)
//!         .retry_after(Duration::from_secs(1)),
//! );
//! let metrics = global.limiter().clone();
//!
//! let app: Router = Router::new()
//!     .route("/", get(|| async { "ok" }))
//!     // An independent, tighter budget for one expensive route.
//!     .route(
//!         "/export",
//!         get(|| async { "big" }).layer(ConcurrencyLimitLayer::new(
//!             ConcurrencyLimit::new().max_in_flight(4),
//!         )),
//!     )
//!     .layer(global);
//!
//! assert_eq!(metrics.metrics().limit, 512);
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub use layer::{ConcurrencyLimit, ConcurrencyLimitLayer, ConcurrencyLimitService, ResponseFuture};
pub use limiter::{Limiter, Metrics, Permit};

mod layer;
mod limiter;
