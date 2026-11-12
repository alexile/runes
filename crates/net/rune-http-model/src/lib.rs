//! Shared HTTP model: requests, responses, byte-exact bodies, headers,
//! timings and exchanges.
//!
//! Every tool that sends, proxies, imports or analyses HTTP traffic can
//! record it with these types, so producers (clients, proxies, HAR and
//! `OpenAPI` importers) and consumers (matchers, cookie jars, auth helpers,
//! reports) share one shape. The crate is sans-I/O: there is no client,
//! only values.
//!
//! - [`HttpRequest`] and [`HttpResponse`] keep every field verbatim, with
//!   [`HeaderEntry`] lists in wire order. Header names compare
//!   case-insensitively ([RFC 9110 §5.1]); see [`header_value`],
//!   [`set_header`] and friends.
//! - [`HttpBody`] holds the exact bytes plus capture metadata (content
//!   coding, truncation). [`BodyKind`] turns text given by a user or agent
//!   into body bytes.
//! - [`HttpExchange`] ties a request to its response or error, with
//!   [`Timings`], followed [`RedirectHop`]s and an [`ExchangeId`].
//! - [`HttpVersion`] names the protocol version.
//!
//! Nothing is validated or normalised: security tooling must be able to
//! record and replay malformed methods, URLs and headers.
//!
//! # Features
//!
//! - `serde`: `Serialize`/`Deserialize` for every type. Bodies serialize as
//!   `{"encoding": "utf8" | "base64", "data": …, …}`, so binary bodies
//!   survive JSON; a bare string also deserializes as a UTF-8 body.
//! - `schemars`: `JsonSchema` for every type (implies `serde`).
//!
//! # Example
//!
//! ```
//! use rune_http_model::{
//!     ExchangeId, HttpBody, HttpExchange, HttpRequest, HttpResponse, Timings,
//! };
//!
//! let request = HttpRequest::post("https://shop.example.test/login")
//!     .with_header("Content-Type", "application/x-www-form-urlencoded")
//!     .with_body("user=alice&pass=hunter2");
//! let response = HttpResponse::new(302)
//!     .with_header("Location", "/account")
//!     .with_header("Set-Cookie", "session=abc; HttpOnly")
//!     .with_header("set-cookie", "theme=dark")
//!     .with_body(HttpBody::new(vec![0x1f, 0x8b]).with_content_encoding("gzip"));
//!
//! let exchange = HttpExchange::new(ExchangeId(1), "workbench", request)
//!     .with_response(response)
//!     .with_timings(Timings::new(42).with_time_to_headers(30));
//!
//! let response = exchange.response.as_ref().unwrap();
//! assert!(response.is_redirect());
//! assert_eq!(response.location(), Some("/account"));
//! assert_eq!(response.header_values("SET-COOKIE").count(), 2);
//! assert_eq!(response.body.as_utf8(), None); // binary, kept byte-exact
//! assert_eq!(exchange.status(), Some(302));
//! ```
//!
//! [RFC 9110 §5.1]: https://www.rfc-editor.org/rfc/rfc9110#section-5.1

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod body;
mod error;
mod exchange;
mod header;
mod message;
mod version;

pub use body::{BodyKind, HttpBody};
pub use error::HttpModelError;
pub use exchange::{ExchangeId, HttpExchange, RedirectHop, Timings};
pub use header::{
    HeaderEntry, has_header, header_value, header_values, headers_from_pairs, headers_to_pairs,
    remove_header, set_header,
};
pub use message::{HttpRequest, HttpResponse};
pub use version::HttpVersion;

/// The byte buffer [`HttpBody`] stores, re-exported so callers need not
/// depend on `bytes` themselves.
pub use bytes::Bytes;
/// The parsed URL type returned by [`HttpRequest::parsed_url`].
pub use url::{ParseError as UrlParseError, Url};
