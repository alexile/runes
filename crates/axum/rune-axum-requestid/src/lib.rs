//! Request-id and W3C `traceparent` propagation layer for Axum.
//!
//! [`RequestIdLayer`] gives every request a correlation id and a
//! [W3C Trace Context](https://www.w3.org/TR/trace-context/) and makes both
//! visible everywhere they are needed:
//!
//! - **Propagated or generated.** A valid incoming `x-request-id` (header
//!   configurable) is kept; otherwise a random UUID v4 is minted. A valid
//!   incoming `traceparent` is continued with a fresh span id; otherwise a
//!   new trace starts.
//! - **Request extensions.** Handlers extract [`RequestId`] and
//!   [`TraceContext`] directly (both also work as `Option<_>`). The request
//!   headers are rewritten too, so code that reads headers sees the
//!   effective values and can forward them downstream.
//! - **Response.** The id is echoed in the response header (unless the
//!   handler set it) and inserted into the response extensions for outer
//!   logging layers.
//! - **Tracing span** (`tracing` feature, on by default). The inner service
//!   runs inside an `INFO` span named `request` with the fields
//!   `request_id`, `method`, `path`, `trace_id`, `span_id` and
//!   `parent_span_id`, so every log line emitted while handling the request
//!   carries them.
//!
//! Incoming ids are untrusted input: a request id must be 1 to 128 bytes of
//! visible ASCII (no spaces, line breaks or escapes), and `traceparent` is
//! parsed strictly per the specification. Anything else is replaced, never
//! echoed. Use [`RequestIdConfig::with_trust_incoming`] to always mint ids
//! at an edge that faces untrusted clients.
//!
//! The decision logic is sans-I/O: [`RequestIdConfig::resolve`] works on a
//! [`HeaderMap`](http::HeaderMap) and is usable without Tower.
//!
//! # Example
//!
//! ```
//! use axum::{body::Body, routing::get, Router};
//! use http::Request;
//! use rune_axum_requestid::{RequestId, RequestIdLayer, TraceContext};
//! use tower::ServiceExt;
//!
//! # tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(async {
//! let app: Router = Router::new()
//!     .route(
//!         "/",
//!         get(|id: RequestId, trace: TraceContext| async move {
//!             format!("{id} {}", trace.trace_id_hex())
//!         }),
//!     )
//!     .layer(RequestIdLayer::default());
//!
//! let req = Request::builder()
//!     .uri("/")
//!     .header("x-request-id", "req-1")
//!     .header("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
//!     .body(Body::empty())
//!     .unwrap();
//! let res = app.oneshot(req).await.unwrap();
//! assert_eq!(res.headers()["x-request-id"], "req-1");
//!
//! let body = axum::body::to_bytes(res.into_body(), 1024).await.unwrap();
//! assert_eq!(&body[..], b"req-1 4bf92f3577b34da6a3ce929d0e0e4736");
//! # });
//! ```
//!
//! # Configuration
//!
//! ```
//! use axum::{routing::get, Router};
//! use http::HeaderName;
//! use rune_axum_requestid::{RequestIdConfig, RequestIdLayer};
//!
//! let layer = RequestIdLayer::new(
//!     RequestIdConfig::default()
//!         .with_header(HeaderName::from_static("x-correlation-id"))
//!         .with_trust_incoming(false)
//!         .with_trace_id_as_request_id(true),
//! );
//! let app: Router = Router::new().route("/", get(|| async { "ok" })).layer(layer);
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod error;
mod extract;
mod id;
mod layer;
mod traceparent;

pub use error::Error;
pub use id::{DEFAULT_MAX_ID_LEN, RequestId};
pub use layer::{
    RequestIdConfig, RequestIdLayer, RequestIdService, Resolved, TRACEPARENT, TRACESTATE,
    TraceContext, X_REQUEST_ID,
};
pub use traceparent::{FLAG_SAMPLED, TraceParent};
