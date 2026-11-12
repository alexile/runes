//! HAR 1.2 (HTTP Archive) reader and writer over [`rune_http_model`].
//!
//! Browsers (Chrome, Firefox, Safari), proxies (Charles, Fiddler, mitmproxy,
//! Burp) and test tools export captured traffic as [HAR 1.2]. This crate
//! reads such files into [`HttpExchange`](rune_http_model::HttpExchange)s and writes exchanges back out.
//! It works on bytes and strings only: callers bring their own files.
//!
//! Two layers:
//!
//! - **Document**: [`parse()`] reads a [`Har`], a typed model of every HAR
//!   object that keeps unknown fields (Chrome's `_initiator`, Charles's
//!   `_charlesStatus`, …) in [`Extensions`], so
//!   `parse → Har::to_json → parse` is lossless. [`HarWriter`] streams a
//!   document one entry at a time.
//! - **Exchanges**: [`read()`] (or [`Har::to_exchanges`]) maps entries to
//!   [`HttpExchange`](rune_http_model::HttpExchange)s; [`write()`] (or [`Har::from_exchanges`] /
//!   [`Entry::from_exchange`]) maps them back.
//!
//! # Tolerance
//!
//! Real exporters bend the specification, and reading bends with them:
//!
//! - `null` anywhere reads as the field's absent value; numbers written as
//!   strings, fractional sizes and `0`/`1` booleans are accepted.
//! - A byte-order mark and a bare `log` object without the `{"log": …}`
//!   wrapper are accepted.
//! - An entry or page with a field of the wrong shape is skipped with a
//!   [`Warning`]; the rest of the file still reads.
//! - Base64 bodies may contain line breaks (Charles); `postData` may be
//!   flagged with `encoding` or `_encoding`; form bodies given only as
//!   `params` are re-encoded.
//! - HTTP/2 and HTTP/3 pseudo-headers (`:authority`, …) are dropped unless
//!   [`ReadOptions::keep_pseudo_headers`] is set.
//! - Timestamps with offsets (`+01:00`, `+0100`), any fraction length and
//!   versions such as `http/2.0`, `h2` or `HTTP/2` are understood.
//!
//! # Mapping
//!
//! | `HttpExchange` | HAR entry |
//! | --- | --- |
//! | `request.method`, `url`, `http_version`, `headers` | `request.*` verbatim |
//! | `request.body` | `request.postData.text` (base64 with `"encoding": "base64"` when binary) |
//! | `response` | `response`; status `0` means no response |
//! | `response.reason` | `response.statusText` (empty means none) |
//! | `response.body` | `response.content.text`, `size` (a larger `size` marks the body truncated) |
//! | `error` | `response._error` (Chrome's spelling); else, with no response, `response.comment` (Charles) |
//! | `started_at_unix_milliseconds` | `startedDateTime` |
//! | `timings.total_milliseconds` | `time` |
//! | `timings.time_to_headers_milliseconds` | `blocked + dns + connect + send + wait` |
//! | `remote_address` | `serverIPAddress` |
//! | `notes` | `comment` |
//! | `id`, `tool`, `label`, `tags`, `redirect_chain` | `_id`, `_tool`, `_label`, `_tags`, `_redirectChain` |
//! | body `content_encoding`, `truncated`, `total_len` | `_contentEncoding`, `_truncated`, `size` / `_totalLen` |
//!
//! Without `_id` and `_tool`, an exchange's id is its entry index and its
//! tool is [`ReadOptions::tool`]. Writing also fills in `queryString` and
//! `cookies` from the URL and the `Cookie` / `Set-Cookie` headers.
//!
//! Exchanges written by this crate read back equal, except that: the
//! `raw` wire bytes are not stored; a response with status `0` reads back
//! as no response; and an unknown protocol version reads as HTTP/1.1. An
//! unknown time to headers is written as `wait = time` with
//! `"_waitEstimated": true`, which reads back as unknown.
//!
//! # Example
//!
//! ```
//! use rune_har::{ReadOptions, WriteOptions};
//! use rune_http_model::{ExchangeId, HttpExchange, HttpRequest, HttpResponse, Timings};
//!
//! let input = br#"{"log": {"version": "1.2", "creator": {"name": "x", "version": "1"},
//!   "entries": [{
//!     "startedDateTime": "2024-01-02T03:04:05.678+01:00", "time": 42.4,
//!     "request": {"method": "GET", "url": "https://h.test/?q=1", "httpVersion": "http/2.0",
//!       "headers": [{"name": ":authority", "value": "h.test"}, {"name": "Accept", "value": "*/*"}],
//!       "cookies": [], "queryString": [], "headersSize": -1, "bodySize": 0},
//!     "response": {"status": 200, "statusText": "", "httpVersion": "h2", "headers": [],
//!       "cookies": [], "content": {"size": 2, "mimeType": "text/plain", "text": "hi"},
//!       "redirectURL": "", "headersSize": -1, "bodySize": null, "_transferSize": 99},
//!     "cache": {}, "timings": {"send": 1, "wait": 30.2, "receive": 11}
//!   }]}}"#;
//!
//! let report = rune_har::read(input, &ReadOptions::default())?;
//! let exchange = &report.exchanges[0];
//! assert_eq!(exchange.request.headers.len(), 1); // `:authority` dropped
//! assert_eq!(exchange.status(), Some(200));
//! assert_eq!(exchange.response.as_ref().unwrap().body.as_utf8(), Some("hi"));
//! assert_eq!(exchange.started_at_unix_milliseconds, 1_704_161_045_678);
//! assert_eq!(exchange.timings, Timings::new(42).with_time_to_headers(31));
//!
//! // Write exchanges out and read them back.
//! let more = HttpExchange::new(ExchangeId(9), "proxy", HttpRequest::get("http://h.test/"))
//!     .with_response(HttpResponse::new(204));
//! let har = rune_har::write([exchange, &more], &WriteOptions::default())?;
//! let again = rune_har::read(har.as_bytes(), &ReadOptions::default())?;
//! assert_eq!(again.exchanges[1], more);
//!
//! // The document layer keeps fields this crate does not know.
//! let parsed = rune_har::parse(input)?;
//! assert_eq!(parsed.har.log.entries[0].response.extra["_transferSize"], 99);
//! # Ok::<(), rune_har::HarError>(())
//! ```
//!
//! [HAR 1.2]: http://www.softwareishard.com/blog/har-12-spec/

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod error;
pub mod ext;
mod lenient;
mod model;
mod query;
mod read;
mod time;
mod write;

pub use error::HarError;
pub use model::{
    Cache, CacheEntry, Content, Cookie, Creator, Entry, Extensions, Har, Log, NameValue, Page,
    PageTimings, Param, PostData, Request, Response, Timings,
};
pub use read::{Parsed, ReadOptions, ReadReport, Warning, parse, read};
pub use write::{HarWriter, WriteOptions, write};

/// The HAR format version this crate writes.
pub const HAR_VERSION: &str = "1.2";

/// Parses an ISO 8601 / RFC 3339 timestamp, as found in `startedDateTime`,
/// to milliseconds since the Unix epoch.
///
/// Accepts `Z`, `±hh:mm`, `±hhmm` and `±hh` offsets, no offset (UTC), any
/// number of fraction digits and a space instead of `T`. Returns `None` for
/// anything else and for instants before 1970 or after the year 9999.
///
/// ```
/// assert_eq!(
///     rune_har::parse_timestamp("2024-01-02T04:04:05.678+01:00"),
///     Some(1_704_164_645_678),
/// );
/// ```
#[must_use]
pub fn parse_timestamp(text: &str) -> Option<u64> {
    time::parse_unix_millis(text)
}

/// Formats milliseconds since the Unix epoch as a HAR timestamp,
/// `YYYY-MM-DDThh:mm:ss.sssZ`. Instants past the year 9999 are clamped.
///
/// ```
/// assert_eq!(rune_har::format_timestamp(0), "1970-01-01T00:00:00.000Z");
/// ```
#[must_use]
pub fn format_timestamp(unix_milliseconds: u64) -> String {
    time::format_unix_millis(unix_milliseconds)
}
