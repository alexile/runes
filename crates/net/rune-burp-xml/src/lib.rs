//! Burp Suite XML export reader and writer over [`rune_http_model`].
//!
//! Burp Suite saves selected proxy-history or site-map entries ("Save
//! items") as XML: one `<item>` per request, with the raw request and
//! response bytes (usually base64) next to the URL, host, port, protocol
//! and time. Scanner issue reports use the same request/response elements
//! inside `<issue>`. This crate reads both into
//! [`HttpExchange`](rune_http_model::HttpExchange)s, and writes exchanges
//! back out as an items export. It works on bytes and strings only:
//! callers bring their own files.
//!
//! # Reading
//!
//! [`read()`] streams the document, so memory stays bounded by one item
//! beyond the input itself. It is tolerant:
//!
//! - Payloads may be base64 (`base64="true"`, line breaks allowed) or
//!   plain text in CDATA.
//! - Raw messages may use bare `\n` line ends, folded headers, a request
//!   target with spaces or no version; HTTP/2 messages in Burp's text form
//!   read with version `HTTP/2`. Chunked bodies are de-chunked when the
//!   framing is valid ([`ReadOptions::decode_chunked`]).
//! - An item whose request cannot be decoded or parsed is skipped with a
//!   [`Warning`]; an unreadable response is dropped with one. Malformed or
//!   truncated XML ends reading with a warning, keeping what was read.
//! - Times are Java's `Date.toString()` form (`Tue Jan 02 03:04:05 UTC
//!   2024`); common zone abbreviations and `GMT+hh:mm` are understood, and
//!   an unknown zone is read as UTC with a warning.
//!
//! Burp exports cannot be read in their binary project (`.burp`) form;
//! export the items as XML first.
//!
//! # Mapping
//!
//! | `HttpExchange` | Burp item |
//! | --- | --- |
//! | `id` | item index in the file |
//! | `tool` | [`ReadOptions::tool`] (`burp`) |
//! | `started_at_unix_milliseconds` | `<time>` (whole seconds) |
//! | `request` | `<request>`, parsed; `url` from `<url>` (else `<protocol>`, `<host>`, `<port>` or the `Host` header, and the request target) |
//! | `request.raw`, `response.raw` | the decoded `<request>` / `<response>` bytes ([`ReadOptions::keep_raw`]) |
//! | `response` | `<response>`, parsed; absent when empty |
//! | response body `truncated`, `total_len` | `<responselength>` beyond the captured bytes |
//! | body `content_encoding` | the `Content-Encoding` header |
//! | `remote_address` | `<host ip="…">` |
//! | `notes` | `<comment>` |
//! | `label` | the enclosing `<issue>`'s `<name>` (issues exports) |
//!
//! Exchanges written by [`write()`] read back equal when read without
//! `raw` bytes ([`ReadOptions::with_raw`] set to `false`), except for what Burp has no place
//! for: `error`, `timings`, `redirect_chain`, `label`, `tags` and the
//! milliseconds of the start time are not written; ids are renumbered
//! in file order; and `tool` comes from [`ReadOptions::tool`].
//!
//! # Example
//!
//! ```
//! use rune_burp_xml::ReadOptions;
//! use rune_http_model::HttpVersion;
//!
//! let input = br#"<?xml version="1.0"?>
//! <items burpVersion="2024.1.1" exportTime="Tue Jan 02 03:04:10 UTC 2024">
//!   <item>
//!     <time>Tue Jan 02 03:04:05 UTC 2024</time>
//!     <url><![CDATA[https://shop.test/cart?id=7]]></url>
//!     <host ip="192.0.2.10">shop.test</host>
//!     <port>443</port>
//!     <protocol>https</protocol>
//!     <request base64="true"><![CDATA[R0VUIC9jYXJ0P2lkPTcgSFRUUC8yDQpIb3N0OiBzaG9wLnRlc3QNCg0K]]></request>
//!     <status>200</status>
//!     <responselength>31</responselength>
//!     <response base64="false"><![CDATA[HTTP/2 200 OK
//! Content-Length: 2
//!
//! ok]]></response>
//!     <comment>checkout</comment>
//!   </item>
//! </items>"#;
//!
//! let report = rune_burp_xml::read(input, &ReadOptions::default())?;
//! let exchange = &report.exchanges[0];
//! assert_eq!(exchange.request.url, "https://shop.test/cart?id=7");
//! assert_eq!(exchange.request.http_version, HttpVersion::Http2);
//! assert_eq!(exchange.request.header("Host"), Some("shop.test"));
//! assert_eq!(exchange.status(), Some(200));
//! assert_eq!(exchange.response.as_ref().unwrap().body.as_utf8(), Some("ok"));
//! assert_eq!(exchange.started_at_unix_milliseconds, 1_704_164_645_000);
//! assert_eq!(exchange.remote_address.as_deref(), Some("192.0.2.10"));
//! assert_eq!(exchange.notes.as_deref(), Some("checkout"));
//! assert_eq!(report.burp_version.as_deref(), Some("2024.1.1"));
//!
//! // Write the exchanges back out and read them again.
//! let xml = rune_burp_xml::write(&report.exchanges, &Default::default());
//! let again = rune_burp_xml::read(xml.as_bytes(), &ReadOptions::default())?;
//! assert_eq!(again.exchanges, report.exchanges);
//! # Ok::<(), rune_burp_xml::BurpError>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod error;
mod message;
mod read;
mod time;
mod write;
mod xml;

pub use error::BurpError;
pub use read::{ExportKind, ReadOptions, ReadReport, Warning, read};
pub use write::{WriteOptions, write};

/// Parses a Burp `<time>` value (Java's `EEE MMM dd HH:mm:ss zzz yyyy`) to
/// milliseconds since the Unix epoch.
///
/// Unknown zone abbreviations read as UTC. Returns `None` for anything
/// else and for years outside 1970–9999.
///
/// ```
/// assert_eq!(
///     rune_burp_xml::parse_time("Tue Jan 02 04:04:05 CET 2024"),
///     Some(1_704_164_645_000),
/// );
/// ```
#[must_use]
pub fn parse_time(text: &str) -> Option<u64> {
    time::parse(text).map(|parsed| parsed.unix_milliseconds)
}

/// Formats milliseconds since the Unix epoch as Burp writes `<time>`, in
/// UTC. Milliseconds are dropped; instants past the year 9999 are clamped.
///
/// ```
/// assert_eq!(rune_burp_xml::format_time(0), "Thu Jan 01 00:00:00 UTC 1970");
/// ```
#[must_use]
pub fn format_time(unix_milliseconds: u64) -> String {
    time::format(unix_milliseconds)
}
