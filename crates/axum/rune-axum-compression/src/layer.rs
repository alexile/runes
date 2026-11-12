//! Configuration, eligibility decision and the Tower layer.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use http::header::{
    ACCEPT_ENCODING, ACCEPT_RANGES, CACHE_CONTROL, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_RANGE,
    CONTENT_TYPE, ETAG, VARY,
};
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode};
use http_body::Body;
use pin_project_lite::pin_project;
use tower::{Layer, Service};

use crate::body::CompressionBody;
use crate::codec::{Encoder, Level};
use crate::encoding::{Encoding, negotiate};

/// Default minimum body size, in bytes, worth compressing.
const DEFAULT_MIN_SIZE: u64 = 1024;

/// Content types compressed by default. `type/*` matches a whole top-level
/// type and `+suffix` a structured-syntax suffix (RFC 6838 §4.2.8).
const DEFAULT_CONTENT_TYPES: [&str; 9] = [
    "text/*",
    "application/json",
    "application/javascript",
    "application/xml",
    "application/wasm",
    "application/x-ndjson",
    "image/svg+xml",
    "+json",
    "+xml",
];

/// Configuration for the compression middleware.
///
/// Build with [`Compression::new()`] and chain methods, then pass it to
/// [`CompressionLayer::new()`]. The two decisions the middleware makes are
/// pure functions you can call directly: [`Compression::negotiate`] picks a
/// coding from `Accept-Encoding`, and [`Compression::should_compress`]
/// decides whether a response is eligible.
///
/// # Examples
///
/// ```rust
/// use http::{header, HeaderMap, StatusCode};
/// use rune_axum_compression::{Compression, Encoding, Level};
///
/// let config = Compression::new()
///     .min_size(256)
///     .level(Level::Fastest)
///     .content_type("application/x-yaml");
///
/// let mut headers = HeaderMap::new();
/// headers.insert(header::CONTENT_TYPE, "application/x-yaml".parse().unwrap());
/// assert!(config.should_compress(StatusCode::OK, &headers, Some(4096)));
/// assert!(!config.should_compress(StatusCode::OK, &headers, Some(100)));
/// assert_eq!(config.negotiate("gzip"), Encoding::Gzip);
/// ```
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Compression {
    encodings: Vec<Encoding>,
    level: Level,
    min_size: u64,
    content_types: Vec<String>,
}

impl Default for Compression {
    fn default() -> Self {
        Self {
            encodings: Encoding::PREFERENCE
                .into_iter()
                .filter(|e| e.is_enabled())
                .collect(),
            level: Level::Default,
            min_size: DEFAULT_MIN_SIZE,
            content_types: DEFAULT_CONTENT_TYPES.map(str::to_owned).to_vec(),
        }
    }
}

impl Compression {
    /// Creates a configuration with defaults: every enabled coding in the
    /// order zstd, br, gzip, deflate; [`Level::Default`]; a 1024-byte
    /// minimum; and the default text-like content-type allowlist.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the codings the server offers, most preferred first. Codings not
    /// compiled into this build and `identity` are dropped; duplicates keep
    /// their first position. An empty list disables compression.
    #[must_use]
    pub fn encodings(mut self, encodings: impl IntoIterator<Item = Encoding>) -> Self {
        self.encodings.clear();
        for enc in encodings {
            if enc != Encoding::Identity && enc.is_enabled() && !self.encodings.contains(&enc) {
                self.encodings.push(enc);
            }
        }
        self
    }

    /// Sets the compression level. Defaults to [`Level::Default`].
    #[must_use]
    pub const fn level(mut self, level: Level) -> Self {
        self.level = level;
        self
    }

    /// Sets the smallest body, in bytes, that is compressed. Bodies whose
    /// exact size is known and below this are sent as is; streaming bodies of
    /// unknown size are always compressed. Defaults to 1024.
    #[must_use]
    pub const fn min_size(mut self, bytes: u64) -> Self {
        self.min_size = bytes;
        self
    }

    /// Adds a pattern to the content-type allowlist: an exact media type
    /// (`application/json`), a top-level wildcard (`text/*`) or a suffix
    /// (`+json`). Matching ignores ASCII case and parameters.
    #[must_use]
    pub fn content_type(mut self, pattern: impl Into<String>) -> Self {
        let pattern = pattern.into().trim().to_ascii_lowercase();
        if !self.content_types.contains(&pattern) {
            self.content_types.push(pattern);
        }
        self
    }

    /// Replaces the content-type allowlist. See [`content_type`](Self::content_type)
    /// for the pattern syntax.
    #[must_use]
    pub fn content_types<I, P>(mut self, patterns: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: Into<String>,
    {
        self.content_types.clear();
        patterns.into_iter().fold(self, Self::content_type)
    }

    /// The codings offered, most preferred first.
    #[must_use]
    pub fn offered(&self) -> &[Encoding] {
        &self.encodings
    }

    /// The configured compression level.
    #[must_use]
    pub const fn level_value(&self) -> Level {
        self.level
    }

    /// The configured minimum body size.
    #[must_use]
    pub const fn min_size_value(&self) -> u64 {
        self.min_size
    }

    /// Picks the coding for an `Accept-Encoding` header value among the
    /// offered codings. See [`negotiate`].
    #[must_use]
    pub fn negotiate(&self, accept_encoding: &str) -> Encoding {
        negotiate(accept_encoding, &self.encodings)
    }

    /// Whether `content_type` (a `Content-Type` value, parameters allowed)
    /// is on the allowlist. `text/event-stream` never is: compressing it
    /// would hold events back in the encoder's buffer.
    #[must_use]
    pub fn is_compressible_type(&self, content_type: &str) -> bool {
        let essence = content_type
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        let Some((top, sub)) = essence.split_once('/') else {
            return false;
        };
        if top.is_empty() || sub.is_empty() || essence == "text/event-stream" {
            return false;
        }
        self.content_types.iter().any(|pattern| {
            if let Some(suffix) = pattern.strip_prefix('+') {
                return sub
                    .strip_suffix(suffix)
                    .is_some_and(|rest| rest.len() > 1 && rest.ends_with('+'));
            }
            pattern
                .strip_suffix("/*")
                .map_or_else(|| *pattern == essence, |wild_top| wild_top == top)
        })
    }

    /// Whether a response is eligible for compression.
    ///
    /// `body_len` is the exact body size when known. A response is skipped
    /// when it is informational, `204 No Content`, `206 Partial Content` (or
    /// has `Content-Range`) or `304 Not Modified`; already has a
    /// `Content-Encoding`; carries `Cache-Control: no-transform`; has a
    /// missing or non-allowlisted `Content-Type`; or is known to be smaller
    /// than [`min_size`](Self::min_size).
    #[must_use]
    pub fn should_compress(
        &self,
        status: StatusCode,
        headers: &HeaderMap,
        body_len: Option<u64>,
    ) -> bool {
        if self.encodings.is_empty()
            || status.is_informational()
            || matches!(
                status,
                StatusCode::NO_CONTENT | StatusCode::PARTIAL_CONTENT | StatusCode::NOT_MODIFIED
            )
            || headers.contains_key(CONTENT_RANGE)
            || headers
                .get_all(CONTENT_ENCODING)
                .iter()
                .any(|v| !v.as_bytes().eq_ignore_ascii_case(b"identity"))
            || has_no_transform(headers)
            || body_len.is_some_and(|n| n < self.min_size)
        {
            return false;
        }
        headers
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|ct| self.is_compressible_type(ct))
    }
}

fn has_no_transform(headers: &HeaderMap) -> bool {
    headers
        .get_all(CACHE_CONTROL)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|d| d.trim().eq_ignore_ascii_case("no-transform"))
}

/// Joins every `Accept-Encoding` field line into one list.
fn accept_encoding(headers: &HeaderMap) -> Option<String> {
    let mut values = headers
        .get_all(ACCEPT_ENCODING)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .peekable();
    values.peek()?;
    Some(values.collect::<Vec<_>>().join(","))
}

/// Adds `Accept-Encoding` to `Vary` unless it (or `*`) is already there.
fn add_vary(headers: &mut HeaderMap) {
    let present = headers
        .get_all(VARY)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|f| {
            let f = f.trim();
            f == "*" || f.eq_ignore_ascii_case("accept-encoding")
        });
    if !present {
        headers.append(VARY, HeaderValue::from_static("accept-encoding"));
    }
}

/// A strong `ETag` names the uncompressed bytes; weaken it so caches do not
/// treat the two representations as byte-identical.
fn weaken_etag(headers: &mut HeaderMap) {
    if let Some(tag) = headers.get(ETAG)
        && !tag.as_bytes().starts_with(b"W/")
    {
        let mut weak = b"W/".to_vec();
        weak.extend_from_slice(tag.as_bytes());
        if let Ok(value) = HeaderValue::from_bytes(&weak) {
            headers.insert(ETAG, value);
        }
    }
}

/// Tower [`Layer`] that compresses eligible responses with the coding the
/// client prefers.
///
/// Apply with Axum's `.layer()` for a whole router, or per route with
/// `MethodRouter::layer` / `Router::route_layer`. Requests without
/// `Accept-Encoding`, and `HEAD` requests, are passed through.
///
/// On a compressed response the layer sets `Content-Encoding`, removes
/// `Content-Length` and `Accept-Ranges`, and weakens a strong `ETag`. On
/// every eligible response it adds `Vary: accept-encoding`.
///
/// # Examples
///
/// ```rust
/// use axum::{routing::get, Router};
/// use rune_axum_compression::CompressionLayer;
///
/// let app: Router = Router::new()
///     .route("/", get(|| async { "ok" }))
///     .layer(CompressionLayer::default());
/// ```
#[derive(Clone, Debug, Default)]
pub struct CompressionLayer {
    config: Arc<Compression>,
}

impl CompressionLayer {
    /// Creates a `CompressionLayer` from a custom [`Compression`] configuration.
    #[must_use]
    pub fn new(config: Compression) -> Self {
        Self {
            config: Arc::new(config),
        }
    }

    /// The layer's configuration.
    #[must_use]
    pub fn config(&self) -> &Compression {
        &self.config
    }
}

impl<S> Layer<S> for CompressionLayer {
    type Service = CompressionService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        CompressionService {
            inner,
            config: Arc::clone(&self.config),
        }
    }
}

/// Tower [`Service`] produced by [`CompressionLayer`].
#[derive(Clone, Debug)]
pub struct CompressionService<S> {
    inner: S,
    config: Arc<Compression>,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for CompressionService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    ResBody: Body,
{
    type Response = Response<CompressionBody<ResBody>>;
    type Error = S::Error;
    type Future = ResponseFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let encoding = if req.method() == Method::HEAD {
            None
        } else {
            Some(
                accept_encoding(req.headers())
                    .map_or(Encoding::Identity, |ae| self.config.negotiate(&ae)),
            )
        };
        ResponseFuture {
            inner: self.inner.call(req),
            encoding,
            config: Arc::clone(&self.config),
        }
    }
}

pin_project! {
    /// Response future of [`CompressionService`].
    pub struct ResponseFuture<F> {
        #[pin]
        inner: F,
        // `None` for HEAD requests: pass through untouched.
        encoding: Option<Encoding>,
        config: Arc<Compression>,
    }
}

impl<F> fmt::Debug for ResponseFuture<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResponseFuture")
            .field("encoding", &self.encoding)
            .finish_non_exhaustive()
    }
}

impl<F, B, E> Future for ResponseFuture<F>
where
    F: Future<Output = Result<Response<B>, E>>,
    B: Body,
{
    type Output = Result<Response<CompressionBody<B>>, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let response = ready!(this.inner.poll(cx))?;
        let Some(encoding) = *this.encoding else {
            return Poll::Ready(Ok(response.map(CompressionBody::identity)));
        };

        let (mut parts, body) = response.into_parts();
        if !this
            .config
            .should_compress(parts.status, &parts.headers, body.size_hint().exact())
        {
            return Poll::Ready(Ok(Response::from_parts(
                parts,
                CompressionBody::identity(body),
            )));
        }
        add_vary(&mut parts.headers);

        let encoder = match encoding {
            Encoding::Identity => None,
            enc => Encoder::new(enc, this.config.level).ok(),
        };
        let body = match encoder {
            // Encoder setup failed or identity was negotiated: send as is.
            None => CompressionBody::identity(body),
            Some(encoder) => {
                parts.headers.remove(CONTENT_ENCODING);
                parts.headers.insert(
                    CONTENT_ENCODING,
                    HeaderValue::from_static(encoding.as_str()),
                );
                parts.headers.remove(CONTENT_LENGTH);
                parts.headers.remove(ACCEPT_RANGES);
                weaken_etag(&mut parts.headers);
                CompressionBody::encoded(body, encoder)
            }
        };
        Poll::Ready(Ok(Response::from_parts(parts, body)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(http::HeaderName, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(name.clone(), HeaderValue::from_str(value).unwrap());
        }
        map
    }

    fn json() -> HeaderMap {
        headers(&[(CONTENT_TYPE, "application/json")])
    }

    #[test]
    fn default_allowlist() {
        let c = Compression::new();
        for ct in [
            "text/html; charset=utf-8",
            "TEXT/PLAIN",
            "text/css",
            "application/json",
            "application/problem+json",
            "application/vnd.api+json; charset=utf-8",
            "application/atom+xml",
            "image/svg+xml",
            "application/javascript",
            "application/wasm",
        ] {
            assert!(c.is_compressible_type(ct), "{ct}");
        }
        for ct in [
            "image/png",
            "image/jpeg",
            "video/mp4",
            "application/octet-stream",
            "application/zip",
            "application/gzip",
            "font/woff2",
            "text/event-stream",
            "text",
            "",
            "/json",
            "application/json5",
            "application/+json",
        ] {
            assert!(!c.is_compressible_type(ct), "{ct}");
        }
    }

    #[test]
    fn custom_allowlist_replaces_default() {
        let c = Compression::new().content_types(["Application/X-Yaml"]);
        assert!(c.is_compressible_type("application/x-yaml"));
        assert!(!c.is_compressible_type("text/html"));
        let c = c.content_type("text/*").content_type("text/*");
        assert!(c.is_compressible_type("text/html"));
        assert_eq!(c.content_types.len(), 2);
    }

    #[test]
    fn min_size_threshold() {
        let c = Compression::new();
        assert!(!c.should_compress(StatusCode::OK, &json(), Some(1023)));
        assert!(c.should_compress(StatusCode::OK, &json(), Some(1024)));
        // Unknown size (streaming) is compressed.
        assert!(c.should_compress(StatusCode::OK, &json(), None));
        assert!(
            Compression::new()
                .min_size(0)
                .should_compress(StatusCode::OK, &json(), Some(0))
        );
    }

    #[test]
    fn skips_by_status() {
        let c = Compression::new().min_size(0);
        for s in [
            StatusCode::CONTINUE,
            StatusCode::NO_CONTENT,
            StatusCode::PARTIAL_CONTENT,
            StatusCode::NOT_MODIFIED,
        ] {
            assert!(!c.should_compress(s, &json(), None), "{s}");
        }
        assert!(c.should_compress(StatusCode::NOT_FOUND, &json(), None));
    }

    #[test]
    fn skips_by_headers() {
        let c = Compression::new();
        let ok = |h: &HeaderMap| c.should_compress(StatusCode::OK, h, None);
        assert!(!ok(&HeaderMap::new()));
        assert!(!ok(&headers(&[
            (CONTENT_TYPE, "application/json"),
            (CONTENT_ENCODING, "br")
        ])));
        assert!(ok(&headers(&[
            (CONTENT_TYPE, "application/json"),
            (CONTENT_ENCODING, "identity")
        ])));
        assert!(!ok(&headers(&[
            (CONTENT_TYPE, "application/json"),
            (CACHE_CONTROL, "public, No-Transform")
        ])));
        assert!(!ok(&headers(&[
            (CONTENT_TYPE, "text/plain"),
            (CONTENT_RANGE, "bytes 0-1/2")
        ])));
    }

    #[test]
    fn no_encodings_disables() {
        let c = Compression::new().encodings([]);
        assert_eq!(c.offered(), []);
        assert!(!c.should_compress(StatusCode::OK, &json(), None));
        assert_eq!(c.negotiate("gzip"), Encoding::Identity);
    }

    #[test]
    fn encodings_dedup_and_filter() {
        let c = Compression::new().encodings([
            Encoding::Deflate,
            Encoding::Identity,
            Encoding::Deflate,
            Encoding::Gzip,
        ]);
        assert_eq!(c.offered(), [Encoding::Deflate, Encoding::Gzip]);
        assert_eq!(c.negotiate("gzip, deflate"), Encoding::Deflate);
    }

    #[test]
    fn vary_is_added_once() {
        let mut h = HeaderMap::new();
        add_vary(&mut h);
        add_vary(&mut h);
        assert_eq!(h.get_all(VARY).iter().count(), 1);
        let mut h = headers(&[(VARY, "Origin, Accept-Encoding")]);
        add_vary(&mut h);
        assert_eq!(h.get_all(VARY).iter().count(), 1);
        let mut h = headers(&[(VARY, "*")]);
        add_vary(&mut h);
        assert_eq!(h.get_all(VARY).iter().count(), 1);
        let mut h = headers(&[(VARY, "origin")]);
        add_vary(&mut h);
        assert_eq!(h.get_all(VARY).iter().count(), 2);
    }

    #[test]
    fn etag_weakened_once() {
        let mut h = headers(&[(ETAG, "\"abc\"")]);
        weaken_etag(&mut h);
        assert_eq!(h[ETAG], "W/\"abc\"");
        weaken_etag(&mut h);
        assert_eq!(h[ETAG], "W/\"abc\"");
    }

    #[test]
    fn accept_encoding_lines_are_joined() {
        assert_eq!(accept_encoding(&HeaderMap::new()), None);
        let h = headers(&[(ACCEPT_ENCODING, "br"), (ACCEPT_ENCODING, "gzip;q=0.5")]);
        assert_eq!(accept_encoding(&h).as_deref(), Some("br,gzip;q=0.5"));
    }
}
