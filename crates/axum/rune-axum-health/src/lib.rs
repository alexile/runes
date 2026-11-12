//! Health and readiness probes plus graceful shutdown — Tower middleware
//! for Axum.
//!
//! Three pieces work together:
//!
//! - [`HealthState`]: shared liveness, readiness, shutdown and in-flight
//!   state. Its decisions ([`HealthState::status`]) are plain functions of
//!   the state and need no runtime.
//! - [`HealthLayer`]: a [`tower::Layer`] that answers liveness (`/livez`)
//!   and readiness (`/readyz`) probes and counts every other request as in
//!   flight until its response is ready.
//! - [`HealthState::graceful_shutdown`]: a future for
//!   `axum::serve(..).with_graceful_shutdown(..)`. When the shutdown signal
//!   arrives, readiness flips to `503` at once, a grace period lets load
//!   balancers drain traffic away, and then the server stops accepting
//!   connections and lets in-flight requests finish.
//!
//! [`HealthState::drain`] waits for tracked requests with a timeout, so a
//! stuck request cannot hold the process forever.
//!
//! # Features
//!
//! - `signal` (off by default): [`shutdown_signal`], which resolves on
//!   Ctrl-C or, on Unix, `SIGTERM`.
//!
//! # Quick Start
//!
//! ```rust
//! use http::StatusCode;
//! use rune_axum_health::{HealthState, Probe};
//!
//! let state = HealthState::new();
//! assert_eq!(state.status(Probe::Readiness), StatusCode::OK);
//!
//! // A request in flight...
//! let request = state.track();
//!
//! // ...when shutdown begins: readiness fails, liveness holds.
//! state.begin_shutdown();
//! assert_eq!(state.status(Probe::Readiness), StatusCode::SERVICE_UNAVAILABLE);
//! assert_eq!(state.status(Probe::Liveness), StatusCode::OK);
//! assert_eq!(state.in_flight(), 1);
//!
//! // The request completes; the server has drained.
//! drop(request);
//! assert_eq!(state.in_flight(), 0);
//! ```
//!
//! # Axum
//!
//! ```rust,no_run
//! use std::time::Duration;
//! use axum::{routing::get, Router};
//! use rune_axum_health::{HealthLayer, HealthState};
//!
//! # async fn run() -> std::io::Result<()> {
//! let state = HealthState::new();
//! let app = Router::new()
//!     .route("/", get(|| async { "ok" }))
//!     .layer(HealthLayer::new(state.clone()));
//!
//! // With the `signal` feature: `rune_axum_health::shutdown_signal()`.
//! let signal = async { tokio::signal::ctrl_c().await.ok(); };
//!
//! let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
//! axum::serve(listener, app)
//!     .with_graceful_shutdown(state.graceful_shutdown(signal, Duration::from_secs(5)))
//!     .await?;
//!
//! // Bound the wait for any work tracked outside the server's connections.
//! if let Err(err) = state.drain(Duration::from_secs(30)).await {
//!     eprintln!("exiting anyway: {err}");
//! }
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub use error::Error;
pub use layer::{Health, HealthLayer, HealthService, Probe};
#[cfg(feature = "signal")]
pub use signal::shutdown_signal;
pub use state::{HealthState, InFlightGuard};

mod error;
mod layer;
#[cfg(feature = "signal")]
mod signal;
mod state;
