//! Request body size limiter — Tower middleware for Axum.
//!
//! A [`tower::Layer`] that caps how many request body bytes reach your
//! handlers. Oversized requests receive an empty error response (default:
//! `413 Payload Too Large`).
//!
//! The limit is enforced twice:
//!
//! - **Fast path:** a declared `Content-Length` over the limit is rejected
//!   before the body is read.
//! - **On the stream:** the body is wrapped in a [`LimitedBody`] that counts
//!   the bytes actually received and errors once they exceed the limit (or the
//!   declared `Content-Length`, if smaller). Chunked uploads without a
//!   `Content-Length` and clients that under-declare it cannot slip past, and
//!   handlers that stream the body see the error. The handler's response is
//!   then replaced by the rejection.
//!
//! # Features
//!
//! - Configurable byte limit (default: 1 MiB), enforced on the real byte count.
//! - Configurable error status code (default: `413 Payload Too Large`).
//! - `400 Bad Request` for malformed or conflicting `Content-Length` values,
//!   and for bodies longer than their declared `Content-Length`.
//! - Optional header-count and header-size limits (`431`).
//! - Empty rejection bodies: no limit or parser detail is disclosed.
//! - Works with Axum, Hyper, and any Tower-compatible framework.
//!
//! # Quick Start
//!
//! ```rust
//! use axum::{routing::post, Router};
//! use rune_axum_size::BodyLimitLayer;
//!
//! let app: Router = Router::new()
//!     .route("/upload", post(|| async { "ok" }))
//!     .layer(BodyLimitLayer::default());
//! ```
//!
//! # Custom Configuration
//!
//! ```rust
//! use axum::{routing::post, Router};
//! use http::StatusCode;
//! use rune_axum_size::{BodyLimit, BodyLimitLayer};
//!
//! // Allow up to 10 MiB; return 422 instead of 413
//! let layer = BodyLimitLayer::new(
//!     BodyLimit::new()
//!         .limit(10 * 1024 * 1024)
//!         .status(StatusCode::UNPROCESSABLE_ENTITY),
//! );
//!
//! let app: Router = Router::new()
//!     .route("/upload", post(|| async { "ok" }))
//!     .layer(layer);
//! ```
//!
//! # Migrating from 0.1
//!
//! [`BodyLimitService`] now hands the inner service a
//! `Request<LimitedBody<ReqBody>>` instead of `Request<ReqBody>`, and requires
//! `ReqBody: http_body::Body`. Axum `Router`s and method routers accept any
//! body type, so `.layer(BodyLimitLayer::...)` code is unchanged. A plain
//! Tower service written against a concrete body type must accept
//! [`LimitedBody`] (or be generic over the body). [`BodyLimit`] and
//! [`BodyLimitLayer`] are now `Copy`.
//!
//! Behaviour changes: requests without `Content-Length` are now limited too;
//! malformed or conflicting `Content-Length` values get `400`; a body that
//! outgrows its `Content-Length` gets `400`.

pub use body::{BoxError, LimitedBody};
pub use layer::{BodyLimit, BodyLimitLayer, BodyLimitService};

mod body;
mod layer;
