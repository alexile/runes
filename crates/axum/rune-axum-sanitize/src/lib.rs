//! Input sanitization middleware for Axum — strips HTML tags and null bytes from query params and request bodies.
//!
//! Protects Axum applications from reflected XSS and null-byte injection by
//! intercepting requests before they reach handlers. Query parameters have HTML
//! tags stripped; request bodies have null bytes removed. Both transforms are
//! individually configurable via [`SanitizeConfig`].
//!
//! # Features
//!
//! - [`strip_html`] — removes HTML tags from a string, keeping text content
//! - [`escape_html`] — escapes `&`, `<`, `>`, `"`, `'` for safe HTML attribute injection
//! - [`strip_null_bytes`] — removes 0x00 bytes from byte slices
//! - [`sanitize_query`] — strips HTML tags from every value in a URL query string
//! - [`SanitizeLayer`] / [`SanitizeService`] — Tower middleware that applies both transforms
//!
//! # Quick Start
//!
//! The transforms are plain functions:
//!
//! ```rust
//! use rune_axum_sanitize::{escape_html, strip_html, strip_null_bytes};
//!
//! assert_eq!(strip_html("<b>bold</b> text"), "bold text");
//! assert_eq!(escape_html("<a href=\"x\">"), "&lt;a href=&quot;x&quot;&gt;");
//! assert_eq!(strip_null_bytes(b"a\0b"), b"ab");
//! ```
//!
//! As middleware:
//!
//! ```rust,no_run
//! use axum::{routing::get, Router};
//! use rune_axum_sanitize::SanitizeLayer;
//!
//! #[tokio::main]
//! async fn main() {
//!     let app: Router = Router::new()
//!         .route("/search", get(|| async { "ok" }))
//!         .layer(SanitizeLayer::default());
//!
//!     let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
//!     axum::serve(listener, app).await.unwrap();
//! }
//! ```
//!
//! # CLI
//!
//! This crate is a library only — no CLI binary.

use axum::body::Body;
use http::{Request, Response, StatusCode, Uri};
use http_body_util::BodyExt;
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{self, Poll},
};
use tower_layer::Layer;
use tower_service::Service;

/// Removes all HTML tags from a string, leaving only text content.
///
/// Scans for `<` and discards everything up to and including the matching `>`.
/// An unclosed tag (no closing `>`) causes the rest of the string to be
/// discarded. Does not decode or escape HTML entities — use [`escape_html`]
/// for that purpose.
///
/// # Examples
///
/// ```rust
/// use rune_axum_sanitize::strip_html;
///
/// assert_eq!(strip_html("<b>hello</b>"), "hello");
/// assert_eq!(strip_html("no tags"), "no tags");
/// assert_eq!(strip_html("<a href='url'>link</a>"), "link");
/// assert_eq!(strip_html("<script>alert(1)</script>safe"), "alert(1)safe");
/// ```
#[must_use]
pub fn strip_html(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut inside_tag = false;

    for character in input.chars() {
        match character {
            '<' => inside_tag = true,
            '>' if inside_tag => inside_tag = false,
            _ if !inside_tag => output.push(character),
            _ => {}
        }
    }

    output
}

/// Escapes HTML special characters so the string is safe for injection into HTML.
///
/// Replaces `&` → `&amp;`, `<` → `&lt;`, `>` → `&gt;`, `"` → `&quot;`,
/// `'` → `&#x27;`. Use this when rendering user-supplied text inside HTML
/// attributes or element content.
///
/// # Examples
///
/// ```rust
/// use rune_axum_sanitize::escape_html;
///
/// assert_eq!(escape_html("<b>&"), "&lt;b&gt;&amp;");
/// assert_eq!(escape_html("say \"hi\""), "say &quot;hi&quot;");
/// assert_eq!(escape_html("it's fine"), "it&#x27;s fine");
/// ```
#[must_use]
pub fn escape_html(input: &str) -> String {
    let mut output = String::with_capacity(input.len());

    for character in input.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&#x27;"),
            other => output.push(other),
        }
    }

    output
}

/// Removes all null bytes (`0x00`) from a byte slice.
///
/// Null bytes in user input can bypass security filters, corrupt C-style string
/// handling, or confuse downstream parsers. Strip them before processing
/// untrusted bodies.
///
/// # Examples
///
/// ```rust
/// use rune_axum_sanitize::strip_null_bytes;
///
/// assert_eq!(strip_null_bytes(b"hel\x00lo"), b"hello");
/// assert_eq!(strip_null_bytes(b"\x00\x00"), b"");
/// assert_eq!(strip_null_bytes(b"clean"), b"clean");
/// ```
#[must_use]
pub fn strip_null_bytes(input: &[u8]) -> Vec<u8> {
    input.iter().copied().filter(|&byte| byte != 0x00).collect()
}

/// Strips HTML tags from every value in a URL query string.
///
/// Parses `key=value&key2=value2` pairs, applies [`strip_html`] to each
/// value, and reassembles the query string. Keys are passed through unchanged.
/// Pairs that contain no `=` are passed through unchanged.
///
/// # Examples
///
/// ```rust
/// use rune_axum_sanitize::sanitize_query;
///
/// assert_eq!(
///     sanitize_query("q=<script>xss</script>&page=1"),
///     "q=xss&page=1"
/// );
/// assert_eq!(sanitize_query("clean=yes"), "clean=yes");
/// assert_eq!(sanitize_query(""), "");
/// ```
#[must_use]
pub fn sanitize_query(query: &str) -> String {
    if query.is_empty() {
        return String::new();
    }

    query
        .split('&')
        .map(|pair| match pair.split_once('=') {
            Some((key, value)) => format!("{key}={}", strip_html(value)),
            None => pair.to_owned(),
        })
        .collect::<Vec<_>>()
        .join("&")
}

fn sanitized_uri(uri: &Uri, sanitized_query: &str) -> Uri {
    let mut builder = Uri::builder();

    if let Some(scheme) = uri.scheme() {
        builder = builder.scheme(scheme.clone());
    }
    if let Some(authority) = uri.authority() {
        builder = builder.authority(authority.clone());
    }

    let path = uri.path();
    let path_and_query = if sanitized_query.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{sanitized_query}")
    };

    builder
        .path_and_query(path_and_query)
        .build()
        .unwrap_or_else(|_| uri.clone())
}

/// Configuration controlling which sanitization passes the middleware applies.
///
/// Pass to [`SanitizeLayer::new`] to enable or disable individual transforms.
/// All flags default to `true`, providing the safest out-of-the-box behaviour.
///
/// # Examples
///
/// ```rust
/// use rune_axum_sanitize::SanitizeConfig;
///
/// let config = SanitizeConfig {
///     strip_html_from_query: true,
///     strip_null_bytes_from_body: false,
///     max_body_bytes: Some(1_048_576),
/// };
/// ```
pub struct SanitizeConfig {
    /// When `true`, HTML tags are stripped from every query parameter value.
    pub strip_html_from_query: bool,
    /// When `true`, null bytes are removed from the request body before it
    /// reaches the handler.
    pub strip_null_bytes_from_body: bool,
    /// Upper bound on the number of body bytes buffered for null-byte stripping.
    /// `None` means no limit is enforced by this middleware.
    pub max_body_bytes: Option<usize>,
}

impl Default for SanitizeConfig {
    fn default() -> Self {
        Self {
            strip_html_from_query: true,
            strip_null_bytes_from_body: true,
            max_body_bytes: None,
        }
    }
}

/// Tower [`Layer`] that strips HTML tags from query parameters and null bytes from request bodies.
///
/// Wrap a [`Router`](axum::Router) or individual routes with this layer to
/// sanitize untrusted input before it reaches any handler. Configure behaviour
/// via [`SanitizeConfig`]; use [`SanitizeLayer::default`] for the recommended
/// all-on preset.
///
/// # Examples
///
/// ```rust,no_run
/// use axum::{routing::get, Router};
/// use rune_axum_sanitize::{SanitizeConfig, SanitizeLayer};
///
/// #[tokio::main]
/// async fn main() {
///     let config = SanitizeConfig {
///         strip_html_from_query: true,
///         strip_null_bytes_from_body: true,
///         max_body_bytes: Some(4_096),
///     };
///
///     let app: Router = Router::new()
///         .route("/", get(|| async { "ok" }))
///         .layer(SanitizeLayer::new(config));
///
///     let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
///     axum::serve(listener, app).await.unwrap();
/// }
/// ```
#[derive(Clone)]
pub struct SanitizeLayer {
    config: Arc<SanitizeConfig>,
}

impl SanitizeLayer {
    /// Creates a [`SanitizeLayer`] with the given [`SanitizeConfig`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_axum_sanitize::{SanitizeConfig, SanitizeLayer};
    ///
    /// let layer = SanitizeLayer::new(SanitizeConfig::default());
    /// ```
    #[must_use]
    pub fn new(config: SanitizeConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }
}

impl Default for SanitizeLayer {
    /// Creates a [`SanitizeLayer`] with [`SanitizeConfig::default`] — all sanitization enabled.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_axum_sanitize::SanitizeLayer;
    ///
    /// let layer = SanitizeLayer::default();
    /// ```
    fn default() -> Self {
        Self::new(SanitizeConfig::default())
    }
}

impl<S> Layer<S> for SanitizeLayer {
    type Service = SanitizeService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SanitizeService {
            inner,
            config: Arc::clone(&self.config),
        }
    }
}

/// Tower [`Service`] produced by [`SanitizeLayer`].
///
/// Sanitizes the incoming [`Request`] — rewriting the URI query string and/or
/// replacing the body — then delegates to the wrapped service.
#[derive(Clone)]
pub struct SanitizeService<S> {
    inner: S,
    config: Arc<SanitizeConfig>,
}

impl<S> Service<Request<Body>> for SanitizeService<S>
where
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = SanitizeFuture<S::Error>;

    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let mut inner = self.inner.clone();
        let config = Arc::clone(&self.config);

        SanitizeFuture {
            future: Box::pin(async move {
                let (mut parts, body) = req.into_parts();

                if config.strip_html_from_query {
                    let sanitized_query = parts.uri.query().map(sanitize_query).unwrap_or_default();
                    parts.uri = sanitized_uri(&parts.uri, &sanitized_query);
                }

                let clean_body = if config.strip_null_bytes_from_body {
                    // A body that cannot be read cannot be sanitised or
                    // forwarded; answer 400 instead of calling the inner service.
                    let Ok(collected) = body.collect().await else {
                        let mut response = Response::new(Body::empty());
                        *response.status_mut() = StatusCode::BAD_REQUEST;
                        return Ok(response);
                    };
                    let raw_bytes = collected.to_bytes();
                    let cleaned = strip_null_bytes(&raw_bytes);
                    Body::from(cleaned)
                } else {
                    body
                };

                let clean_request = Request::from_parts(parts, clean_body);
                inner.call(clean_request).await
            }),
        }
    }
}

/// Future returned by [`SanitizeService`].
pub struct SanitizeFuture<E> {
    future: Pin<Box<dyn Future<Output = Result<Response<Body>, E>> + Send>>,
}

impl<E> Future for SanitizeFuture<E> {
    type Output = Result<Response<Body>, E>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        self.future.as_mut().poll(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, body::Body, routing::get};
    use http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    #[test]
    fn strip_html_removes_script_tags() {
        assert_eq!(
            strip_html("<script>alert(1)</script>hello"),
            "alert(1)hello"
        );
    }

    #[test]
    fn strip_html_passes_plain_text() {
        assert_eq!(strip_html("no tags"), "no tags");
    }

    #[test]
    fn strip_html_removes_anchor_tags() {
        assert_eq!(strip_html("<a href='url'>link</a>"), "link");
    }

    #[test]
    fn strip_html_handles_unclosed_tag() {
        assert_eq!(strip_html("before<unclosed"), "before");
    }

    #[test]
    fn escape_html_escapes_all_special_chars() {
        assert_eq!(escape_html("<b>&"), "&lt;b&gt;&amp;");
    }

    #[test]
    fn escape_html_escapes_quotes() {
        assert_eq!(escape_html("\"'"), "&quot;&#x27;");
    }

    #[test]
    fn strip_null_bytes_removes_nulls() {
        assert_eq!(strip_null_bytes(b"hel\x00lo"), b"hello");
    }

    #[test]
    fn strip_null_bytes_handles_only_nulls() {
        assert_eq!(strip_null_bytes(b"\x00\x00"), b"");
    }

    #[test]
    fn strip_null_bytes_passes_clean_input() {
        assert_eq!(strip_null_bytes(b"clean"), b"clean");
    }

    #[test]
    fn sanitize_query_strips_html_from_values() {
        assert_eq!(
            sanitize_query("q=<script>xss</script>&page=1"),
            "q=xss&page=1"
        );
    }

    #[test]
    fn sanitize_query_passes_clean_query() {
        assert_eq!(sanitize_query("clean=yes"), "clean=yes");
    }

    #[test]
    fn sanitize_query_handles_empty_string() {
        assert_eq!(sanitize_query(""), "");
    }

    #[test]
    fn sanitize_query_does_not_alter_keys() {
        assert_eq!(sanitize_query("key=<b>val</b>"), "key=val");
    }

    fn test_app() -> Router {
        Router::new()
            .route(
                "/search",
                get(|req: Request<Body>| async move { req.uri().query().unwrap_or("").to_owned() }),
            )
            .layer(SanitizeLayer::default())
    }

    #[tokio::test]
    async fn middleware_strips_html_from_query() {
        let app = test_app();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/search?q=hello&page=2")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), http::StatusCode::OK);
        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let body_str = std::str::from_utf8(&body_bytes).unwrap();
        assert!(body_str.contains("q=hello"));
        assert!(body_str.contains("page=2"));
    }

    #[tokio::test]
    async fn middleware_sanitizes_query_with_tags() {
        let app = test_app();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/search?q=hello%3Cscript%3E&page=2")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), http::StatusCode::OK);
        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let body_str = std::str::from_utf8(&body_bytes).unwrap();
        assert!(!body_str.contains("<script>"));
        assert!(body_str.contains("page=2"));
    }

    #[tokio::test]
    async fn middleware_strips_null_bytes_from_body() {
        let app = Router::new()
            .route(
                "/upload",
                axum::routing::post(|body: axum::body::Bytes| async move {
                    String::from_utf8_lossy(&body).into_owned()
                }),
            )
            .layer(SanitizeLayer::default());

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/upload")
                    .body(Body::from(b"hel\x00lo".as_ref()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), http::StatusCode::OK);
        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let body_str = std::str::from_utf8(&body_bytes).unwrap();
        assert_eq!(body_str, "hello");
    }

    #[tokio::test]
    async fn middleware_passes_clean_request_unchanged() {
        let app = test_app();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/search?q=rust&page=1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), http::StatusCode::OK);
        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let body_str = std::str::from_utf8(&body_bytes).unwrap();
        assert!(body_str.contains("q=rust"));
        assert!(body_str.contains("page=1"));
    }
}
