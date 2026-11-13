//! Incremental sans-I/O Server-Sent Events (`text/event-stream`) parser.
//!
//! Implements the event-stream interpretation algorithm of the
//! [WHATWG HTML Living Standard, §9.2 "Server-sent events"][spec]:
//!
//! - `event`, `data` (multi-line), `id` and `retry` fields, and comments;
//! - CRLF, LF and CR line endings, including a CRLF split across two chunks;
//! - a leading UTF-8 byte order mark, and invalid UTF-8 (decoded to U+FFFD);
//! - chunk boundaries anywhere, even inside a multi-byte character;
//! - the persistent last event ID, and the end-of-stream rule that an event
//!   without its terminating blank line is never dispatched.
//!
//! The core is [`Parser`]: [`push`](Parser::push) bytes as they arrive and
//! pull complete [`Item`]s with [`next_item`](Parser::next_item) (or only
//! events with [`next_event`](Parser::next_event)). It does no I/O. Two thin
//! adapters sit on top: [`Reader`] for any [`std::io::Read`], and
//! `SseStream` for a `futures::Stream` of byte chunks (feature `stream`).
//! [`encode`] goes the other way, for servers and proxies that re-emit
//! events.
//!
//! Buffering is bounded by [`Options`]: an over-long line or event is
//! reported as an error and skipped, and parsing resumes at the next event.
//!
//! [spec]: https://html.spec.whatwg.org/multipage/server-sent-events.html#event-stream-interpretation
//!
//! # Example
//!
//! ```
//! use rune_sse::{Item, Parser};
//!
//! let mut parser = Parser::new();
//! // Bytes arrive in arbitrary chunks; this one ends mid-event.
//! parser.push(b"event: delta\ndata: {\"text\":");
//! assert!(parser.next_item().is_none());
//!
//! parser.push(b"\"hi\"}\nid: 7\n\n: keep-alive\nretry: 3000\n");
//! let event = parser.next_event().unwrap()?;
//! assert_eq!(event.event, "delta");
//! assert_eq!(event.data, "{\"text\":\"hi\"}");
//! assert_eq!(event.id, "7");
//!
//! // The `retry` field is reported as soon as it is parsed.
//! assert!(matches!(
//!     parser.next_item(),
//!     Some(Ok(Item::Retry(d))) if d.as_millis() == 3000
//! ));
//! # Ok::<(), rune_sse::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod encode;
mod event;
mod parser;
mod reader;
#[cfg(feature = "stream")]
mod stream;

pub use encode::{encode, encode_comment, encode_retry};
pub use event::{Event, Item};
pub use parser::{DEFAULT_MAX_ID_LEN, Options, Parser};
pub use reader::Reader;
#[cfg(feature = "stream")]
pub use stream::SseStream;

/// The MIME type of an event stream: `text/event-stream`.
pub const MIME_TYPE: &str = "text/event-stream";

/// Errors returned by this crate.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A line was longer than [`Options::max_line_len`]. The line and the
    /// event it belongs to were discarded.
    #[error("line exceeds the limit of {limit} bytes")]
    LineTooLong {
        /// The configured limit.
        limit: usize,
    },
    /// An event's data was larger than [`Options::max_event_len`]. The event
    /// was discarded.
    #[error("event data exceeds the limit of {limit} bytes")]
    EventTooLarge {
        /// The configured limit.
        limit: usize,
    },
    /// [`encode`] was given a field value that cannot be represented on the
    /// wire (a line break, or a NUL in an `id`).
    #[error("the `{field}` value cannot be encoded: it contains a forbidden character")]
    InvalidField {
        /// The name of the offending field.
        field: &'static str,
    },
    /// Reading from the underlying [`std::io::Read`] failed.
    #[error("I/O error reading the event stream")]
    Io(#[source] std::io::Error),
    /// The underlying byte stream returned an error (feature `stream`).
    #[error("transport error reading the event stream")]
    Transport(#[source] Box<dyn std::error::Error + Send + Sync>),
}
