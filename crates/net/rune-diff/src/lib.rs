//! Response differ: Myers line/word diffs, volatile-field masking and a
//! structural diff of HTTP messages from
//! [`rune-http-model`](rune_http_model).
//!
//! - [`diff_slices`] is Myers' O(ND) algorithm ("An O(ND) Difference
//!   Algorithm and Its Variations", 1986) in its linear-space form, with a
//!   cost cap that keeps hostile inputs bounded.
//! - [`TextDiff`] diffs text by [`Granularity`] (lines, words, characters)
//!   and renders `diff -u` style [unified](TextDiff::unified) hunks.
//! - [`Masker`] replaces volatile content (dates, epochs, UUIDs, tokens,
//!   nonces, CSRF/hidden input values, payload reflections, custom regexes)
//!   with placeholders so that two otherwise-equal responses compare equal.
//! - [`HttpDiffer`] compares status, version, headers (case-insensitive,
//!   multi-valued, volatile ones skipped) and bodies: JSON structurally with
//!   RFC 6901 pointers, text with a masked Myers diff, anything else by
//!   bytes. The result has a similarity score for differential oracles and a
//!   readable `Display` for comparers.
//!
//! Everything is sans-I/O.
//!
//! # Example
//!
//! ```
//! use rune_diff::{Granularity, HttpDiffOptions, HttpDiffer, TextDiff};
//! use rune_http_model::HttpResponse;
//!
//! // Text: line diff with unified output.
//! let diff = TextDiff::new("a\nb\n", "a\nc\n", Granularity::Line);
//! assert_eq!(diff.unified(3).to_string(), "@@ -1,2 +1,2 @@\n a\n-b\n+c\n");
//!
//! // HTTP: volatile headers and CSRF tokens are ignored, real changes are not.
//! let page = |token: &str, msg: &str| {
//!     HttpResponse::new(200)
//!         .with_header("Date", "Tue, 10 Nov 2026 08:12:31 GMT")
//!         .with_header("Content-Type", "text/html")
//!         .with_body(format!(
//!             "<form><input type=\"hidden\" name=\"csrf\" value=\"{token}\"></form>\n<p>{msg}</p>\n"
//!         ))
//! };
//! let differ = HttpDiffer::new(&HttpDiffOptions::default())?;
//! assert!(differ.diff_responses(&page("k1x9", "hi"), &page("q8z2", "hi")).is_equivalent());
//! let diff = differ.diff_responses(&page("k1x9", "hi"), &page("q8z2", "error"));
//! assert!(!diff.is_equivalent());
//! assert!(diff.similarity() > 0.0 && diff.similarity() < 1.0);
//! # Ok::<(), rune_diff::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod error;
mod http;
mod json;
mod mask;
mod myers;
mod text;

pub use error::Error;
pub use http::{
    BodyDiff, ExchangeDiff, FieldChange, HeaderChange, HeaderChangeKind, HttpDiffOptions,
    HttpDiffer, RequestDiff, ResponseDiff, TextBodyDiff, VOLATILE_HEADERS, diff_responses,
};
pub use json::{JsonChange, JsonChangeKind};
pub use mask::{MaskOptions, Masker};
pub use myers::{DiffOp, DiffOptions, EditScript, diff_slices};
pub use text::{Change, ChangeTag, Granularity, TextDiff, Unified};
