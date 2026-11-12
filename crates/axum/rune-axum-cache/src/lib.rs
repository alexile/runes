//! Cache-Control and conditional-request middleware — Tower middleware for
//! Axum.
//!
//! Two halves, usable together or apart:
//!
//! - **[`CacheLayer`]**, a [`tower::Layer`] that sets `Cache-Control` on
//!   successful `GET`/`HEAD` responses (per-path, longest prefix wins) and
//!   answers conditional requests: when the handler's `ETag` or
//!   `Last-Modified` shows the client's copy is current, the response
//!   becomes an empty `304 Not Modified`; a failed `If-Match` /
//!   `If-Unmodified-Since` becomes `412 Precondition Failed`.
//! - **A sans-I/O core** for handlers: [`CacheControl`] directives,
//!   [`EntityTag`] (with a stable content-hash constructor), [`HttpDate`],
//!   and [`Validators`] / [`evaluate`], the RFC 9110 §13.2.2 precondition
//!   algorithm. Handlers use it to set validators and to answer `304` / `412`
//!   before doing expensive or state-changing work.
//!
//! Specifications: [RFC 9110] (validators, conditional requests,
//! HTTP-date), [RFC 9111] (`Cache-Control`), [RFC 8246] (`immutable`) and
//! [RFC 5861] (`stale-while-revalidate`, `stale-if-error`).
//!
//! [RFC 9110]: https://www.rfc-editor.org/rfc/rfc9110
//! [RFC 9111]: https://www.rfc-editor.org/rfc/rfc9111
//! [RFC 8246]: https://www.rfc-editor.org/rfc/rfc8246
//! [RFC 5861]: https://www.rfc-editor.org/rfc/rfc5861
//!
//! # Quick Start
//!
//! ```rust
//! use http::{HeaderMap, Method, header};
//! use rune_axum_cache::{EntityTag, Precondition, Validators};
//!
//! let body = b"{\"id\":42}";
//! let validators = Validators::new().with_etag(EntityTag::from_content(body));
//!
//! // A revalidation request carrying the tag we handed out earlier.
//! let mut request = HeaderMap::new();
//! request.insert(header::IF_NONE_MATCH, validators.etag().unwrap().to_header_value());
//!
//! assert_eq!(validators.evaluate(&Method::GET, &request), Precondition::NotModified);
//! assert_eq!(validators.evaluate(&Method::GET, &HeaderMap::new()), Precondition::Proceed);
//! ```
//!
//! # Axum
//!
//! ```rust
//! use std::time::Duration;
//! use axum::{http::header, routing::get, Router};
//! use rune_axum_cache::{Cache, CacheControl, CacheLayer, EntityTag};
//!
//! async fn report() -> ([(header::HeaderName, header::HeaderValue); 1], &'static str) {
//!     let body = "quarterly numbers";
//!     ([(header::ETAG, EntityTag::from_content(body.as_bytes()).to_header_value())], body)
//! }
//!
//! let app: Router = Router::new()
//!     .route("/report", get(report))
//!     .route("/assets/app.3f9a.js", get(|| async { "console.log(1)" }))
//!     .layer(CacheLayer::new(
//!         Cache::new()
//!             .cache_control(CacheControl::revalidate())
//!             .path("/assets", CacheControl::immutable_asset(Duration::from_secs(31_536_000))),
//!     ));
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub use conditional::{Precondition, Validators, evaluate};
pub use date::HttpDate;
pub use directives::CacheControl;
pub use etag::{EntityTag, EntityTagList};
pub use layer::{Cache, CacheLayer, CacheService};

mod conditional;
mod date;
mod directives;
mod etag;
mod layer;

/// Errors returned by this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The text is not an HTTP-date in any of the three accepted forms.
    #[error("invalid HTTP-date")]
    InvalidDate,
    /// The date lies before 1970 or after 9999.
    #[error("date out of range (1970-01-01 to 9999-12-31)")]
    DateOutOfRange,
    /// The text is not a valid entity tag or entity-tag list.
    #[error("invalid entity tag")]
    InvalidEntityTag,
}

/// Builds a header value from text this crate rendered itself, which is
/// always visible ASCII.
fn ascii_header_value(text: &str) -> http::HeaderValue {
    http::HeaderValue::from_str(text).unwrap_or_else(|_| http::HeaderValue::from_static(""))
}
