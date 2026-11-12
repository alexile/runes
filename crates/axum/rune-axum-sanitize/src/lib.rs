//! Defence-in-depth input sanitization for Axum.
//!
//! [`SanitizeLayer`] cleans string data before handlers see it: query
//! parameters, URL-encoded form fields, every string in a JSON body, and
//! `text/*` bodies. Each string goes through a [`Sanitizer`]: control
//! characters removed, optional bidi/invisible stripping and Unicode
//! normalisation, then one [`Mode`]: strip tags (tokenizer based), HTML
//! escape, or an allowlist cleaner (feature `allowlist`, via ammonia).
//!
//! **This is not your XSS defence.** Encode output for its context (HTML
//! text, attribute, URL, JavaScript) and set a Content-Security-Policy. Input
//! filtering can't know where data will end up, and data also arrives
//! through paths it does not see (headers, path segments, multipart, other
//! services). Use this crate to cut down what reaches storage and logs, not
//! as a substitute. The README has the full list of limits.
//!
//! # Quick start
//!
//! ```rust
//! use rune_axum_sanitize::{Mode, Sanitizer, escape_html, strip_html};
//!
//! assert_eq!(strip_html("<b>bold</b> <script>x()</script>text"), "bold text");
//! assert_eq!(escape_html("<a href=\"x\">"), "&lt;a href=&quot;x&quot;&gt;");
//!
//! let sanitizer = Sanitizer::new().strip_invisible(true);
//! assert_eq!(sanitizer.clean("hi\0\u{202E}<i>!</i>"), "hi!");
//! ```
//!
//! As middleware:
//!
//! ```rust,no_run
//! use axum::{routing::post, Json, Router};
//! use rune_axum_sanitize::{SanitizeConfig, SanitizeLayer};
//!
//! async fn echo(Json(body): Json<serde_json::Value>) -> Json<serde_json::Value> {
//!     Json(body)
//! }
//!
//! #[tokio::main]
//! async fn main() {
//!     let app: Router = Router::new()
//!         .route("/posts", post(echo))
//!         .layer(SanitizeLayer::new(
//!             SanitizeConfig::new()
//!                 .max_body_bytes(256 * 1024)
//!                 .exempt_field("/posts", "/markdown"),
//!         ));
//!
//!     let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();
//!     axum::serve(listener, app).await.unwrap();
//! }
//! ```

mod config;
mod json;
mod middleware;
mod sanitizer;
mod strip;
mod urlencoded;

#[cfg(feature = "allowlist")]
pub use ammonia;
pub use config::{DEFAULT_MAX_BODY_BYTES, DEFAULT_MAX_JSON_DEPTH, OtherBodies, SanitizeConfig};
pub use json::JsonError;
pub use middleware::{SanitizeFuture, SanitizeLayer, SanitizeService};
pub use sanitizer::{Mode, Normalization, Sanitizer};
pub use strip::strip_html;

/// HTML-encodes `& < > " '` so the string is inert in HTML text and quoted
/// attribute values.
///
/// This is output encoding, the real fix for XSS; do it where you render.
/// It is not enough on its own for unquoted attributes, URLs, JavaScript or
/// CSS contexts.
///
/// # Examples
///
/// ```rust
/// use rune_axum_sanitize::escape_html;
///
/// assert_eq!(escape_html("<b>&"), "&lt;b&gt;&amp;");
/// assert_eq!(escape_html("say \"hi\""), "say &quot;hi&quot;");
/// assert_eq!(escape_html("it's"), "it&#x27;s");
/// ```
#[must_use]
pub fn escape_html(input: &str) -> String {
    rune_html_encode::encode(input)
}

/// Removes all null bytes (`0x00`) from a byte slice.
///
/// Safe on UTF-8: no multi-byte sequence contains a zero byte.
///
/// # Examples
///
/// ```rust
/// use rune_axum_sanitize::strip_null_bytes;
///
/// assert_eq!(strip_null_bytes(b"hel\x00lo"), b"hello");
/// assert_eq!(strip_null_bytes(b"\x00\x00"), b"");
/// ```
#[must_use]
pub fn strip_null_bytes(input: &[u8]) -> Vec<u8> {
    input.iter().copied().filter(|&byte| byte != 0x00).collect()
}

/// Cleans every name and value in a URL query string with the default
/// [`Sanitizer`].
///
/// Values are percent-decoded first (as axum's `Query` extractor does), so
/// `%3Cscript%3E` is caught. Changed pairs are re-encoded; others are kept
/// as written.
///
/// # Examples
///
/// ```rust
/// use rune_axum_sanitize::sanitize_query;
///
/// assert_eq!(sanitize_query("q=%3Cb%3Ehi%3C/b%3E&page=1"), "q=hi&page=1");
/// assert_eq!(sanitize_query("q=<script>x</script>ok"), "q=ok");
/// assert_eq!(sanitize_query("clean=yes"), "clean=yes");
/// ```
#[must_use]
pub fn sanitize_query(query: &str) -> String {
    Sanitizer::new().clean_urlencoded(query).into_owned()
}
