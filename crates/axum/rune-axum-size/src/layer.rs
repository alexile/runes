use crate::body::{BoxError, LimitedBody};
use http::{HeaderMap, Request, Response, StatusCode, header::CONTENT_LENGTH};
use http_body::Body;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use tower::{Layer, Service};

/// Configuration for the request body size limit middleware.
///
/// Build with [`BodyLimit::new()`] and chain methods to set the byte limit,
/// the rejection status code and optional header limits, then pass to
/// [`BodyLimitLayer::new()`].
///
/// # Examples
///
/// ```rust
/// use http::StatusCode;
/// use rune_axum_size::BodyLimit;
///
/// let config = BodyLimit::new()
///     .limit(10 * 1024 * 1024) // 10 MiB
///     .status(StatusCode::PAYLOAD_TOO_LARGE)
///     .max_headers(64)
///     .max_header_bytes(16 * 1024);
/// ```
#[derive(Clone, Copy, Debug)]
pub struct BodyLimit {
    limit_bytes: u64,
    status: StatusCode,
    max_headers: Option<usize>,
    max_header_bytes: Option<usize>,
}

impl Default for BodyLimit {
    fn default() -> Self {
        Self {
            limit_bytes: 1_048_576,
            status: StatusCode::PAYLOAD_TOO_LARGE,
            max_headers: None,
            max_header_bytes: None,
        }
    }
}

/// Outcome of the checks made before the body is touched.
enum Precheck {
    /// Forward the request, streaming at most this many body bytes.
    Forward { budget: u64, declared: bool },
    /// Reject immediately with this status.
    Reject(StatusCode),
}

impl BodyLimit {
    /// Creates a `BodyLimit` with defaults: 1 MiB limit, `413 Payload Too Large`,
    /// no header limits.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the maximum allowed body size in bytes.
    ///
    /// The limit applies to the bytes actually received, whether or not the
    /// request declares a `Content-Length`. Defaults to 1 MiB (1,048,576 bytes).
    #[must_use]
    pub const fn limit(mut self, bytes: u64) -> Self {
        self.limit_bytes = bytes;
        self
    }

    /// Sets the HTTP status code returned when the body limit is exceeded.
    ///
    /// Defaults to `413 Payload Too Large`.
    #[must_use]
    pub const fn status(mut self, status: StatusCode) -> Self {
        self.status = status;
        self
    }

    /// Rejects requests carrying more than `count` header fields with
    /// `431 Request Header Fields Too Large`.
    ///
    /// Repeated header names count once per value. Off by default. This is a
    /// policy check on already-parsed headers; the server's own parser limits
    /// (for example hyper's `max_headers` / `max_buf_size`) still bound how
    /// much is read off the wire.
    #[must_use]
    pub const fn max_headers(mut self, count: usize) -> Self {
        self.max_headers = Some(count);
        self
    }

    /// Rejects requests whose header names plus values exceed `bytes` in
    /// total with `431 Request Header Fields Too Large`.
    ///
    /// Off by default. See [`max_headers`](Self::max_headers) for how this
    /// relates to the server's parser limits.
    #[must_use]
    pub const fn max_header_bytes(mut self, bytes: usize) -> Self {
        self.max_header_bytes = Some(bytes);
        self
    }

    /// Returns the configured body limit in bytes.
    #[must_use]
    pub const fn limit_bytes(&self) -> u64 {
        self.limit_bytes
    }

    fn headers_too_large(&self, headers: &HeaderMap) -> bool {
        if self.max_headers.is_some_and(|max| headers.len() > max) {
            return true;
        }
        self.max_header_bytes.is_some_and(|max| {
            headers
                .iter()
                .map(|(name, value)| name.as_str().len() + value.len())
                .try_fold(0usize, |acc, n| acc.checked_add(n).filter(|&t| t <= max))
                .is_none()
        })
    }

    fn precheck<B: Body>(&self, req: &Request<B>) -> Precheck {
        if self.headers_too_large(req.headers()) {
            return Precheck::Reject(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE);
        }

        let Ok(declared) = declared_length(req.headers()) else {
            return Precheck::Reject(StatusCode::BAD_REQUEST);
        };

        match declared {
            Some(len) if len > self.limit_bytes => Precheck::Reject(self.status),
            Some(len) => Precheck::Forward {
                budget: len,
                declared: len < self.limit_bytes,
            },
            None if req.body().size_hint().lower() > self.limit_bytes => {
                Precheck::Reject(self.status)
            }
            None => Precheck::Forward {
                budget: self.limit_bytes,
                declared: false,
            },
        }
    }
}

/// Parses every `Content-Length` value. `Ok(None)` when absent; `Err` when a
/// value is malformed or the values disagree (RFC 9110 §8.6).
fn declared_length(headers: &HeaderMap) -> Result<Option<u64>, ()> {
    let mut declared = None;
    for value in headers.get_all(CONTENT_LENGTH) {
        let text = value.to_str().map_err(|_| ())?;
        for part in text.split(',') {
            let part = part.trim();
            if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
                return Err(());
            }
            let len = part.parse::<u64>().map_err(|_| ())?;
            match declared {
                Some(prev) if prev != len => return Err(()),
                _ => declared = Some(len),
            }
        }
    }
    Ok(declared)
}

/// Tower [`Layer`] that enforces a request body size limit.
///
/// Apply with Axum's `.layer()` call. Use [`BodyLimitLayer::default()`] for a
/// 1 MiB limit with a `413` response, or [`BodyLimitLayer::new()`] to supply a
/// custom [`BodyLimit`].
///
/// Enforcement happens in two places:
///
/// 1. **Before the body is read.** A declared `Content-Length` over the limit
///    is rejected at once. Malformed or conflicting `Content-Length` values get
///    `400 Bad Request`, and the optional header limits get `431`.
/// 2. **While the body streams.** The body is wrapped in a [`LimitedBody`]
///    that errors once the bytes received exceed the limit, or exceed the
///    declared `Content-Length` when that is smaller. Chunked uploads and
///    clients that under-declare their length are caught here. If that
///    happens, the handler's response is discarded and replaced by the
///    rejection: the configured status for an oversized body, `400` for a body
///    longer than its `Content-Length`.
///
/// Rejections have an empty body, so no limit or parsing detail is disclosed.
///
/// For per-route or per-method limits, attach a layer to that route or method
/// router (`post(handler).layer(...)`) instead of the whole `Router`. Axum's
/// own `DefaultBodyLimit` (2 MiB) still applies to its buffering extractors;
/// raise or disable it if this layer's limit is higher.
///
/// # Examples
///
/// ```rust,no_run
/// use axum::{routing::post, Router};
/// use rune_axum_size::{BodyLimit, BodyLimitLayer};
///
/// let app: Router = Router::new()
///     // 10 MiB for uploads, POST only
///     .route(
///         "/upload",
///         post(|| async { "ok" })
///             .layer(BodyLimitLayer::new(BodyLimit::new().limit(10 * 1024 * 1024))),
///     )
///     // 1 MiB everywhere else
///     .layer(BodyLimitLayer::default());
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct BodyLimitLayer {
    config: BodyLimit,
}

impl BodyLimitLayer {
    /// Creates a `BodyLimitLayer` from a custom [`BodyLimit`] configuration.
    #[must_use]
    pub const fn new(config: BodyLimit) -> Self {
        Self { config }
    }
}

impl<S> Layer<S> for BodyLimitLayer {
    type Service = BodyLimitService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        BodyLimitService {
            inner,
            config: self.config,
        }
    }
}

/// Tower [`Service`] produced by [`BodyLimitLayer`].
///
/// The inner service receives `Request<LimitedBody<ReqBody>>`.
#[derive(Clone, Debug)]
pub struct BodyLimitService<S> {
    inner: S,
    config: BodyLimit,
}

fn rejection<B: Default>(status: StatusCode) -> Response<B> {
    let mut response = Response::new(B::default());
    *response.status_mut() = status;
    response
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for BodyLimitService<S>
where
    S: Service<Request<LimitedBody<ReqBody>>, Response = Response<ResBody>>,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    ReqBody: Body,
    ReqBody::Error: Into<BoxError>,
    ResBody: Default + Send + 'static,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let (budget, declared) = match self.config.precheck(&req) {
            Precheck::Reject(status) => {
                return Box::pin(async move { Ok(rejection(status)) });
            }
            Precheck::Forward { budget, declared } => (budget, declared),
        };
        let over_status = if declared {
            StatusCode::BAD_REQUEST
        } else {
            self.config.status
        };

        let tripped = Arc::new(AtomicBool::new(false));
        let req = req.map(|body| LimitedBody::new(body, budget, Arc::clone(&tripped)));
        let fut = self.inner.call(req);
        Box::pin(async move {
            let response = fut.await?;
            if tripped.load(Ordering::Acquire) {
                Ok(rejection(over_status))
            } else {
                Ok(response)
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, body::Body, routing::post};
    use bytes::Bytes;
    use http::StatusCode;
    use http_body_util::BodyExt;
    use std::convert::Infallible;
    use tower::ServiceExt;

    fn build_app(config: BodyLimit) -> Router {
        Router::new()
            .route("/upload", post(|| async { "ok" }))
            .layer(BodyLimitLayer::new(config))
    }

    /// Echoes the body length; uses the buffering `Bytes` extractor.
    fn buffering_app(config: BodyLimit) -> Router {
        Router::new()
            .route(
                "/upload",
                post(|body: Bytes| async move { body.len().to_string() }),
            )
            .layer(BodyLimitLayer::new(config))
    }

    async fn send(app: Router, req: http::Request<Body>) -> http::Response<Body> {
        app.oneshot(req).await.unwrap()
    }

    async fn body_text(resp: http::Response<Body>) -> String {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    fn post_with_length(content_length: u64) -> http::Request<Body> {
        http::Request::builder()
            .method("POST")
            .uri("/upload")
            .header(CONTENT_LENGTH, content_length)
            .body(Body::empty())
            .unwrap()
    }

    fn post_without_length() -> http::Request<Body> {
        http::Request::builder()
            .method("POST")
            .uri("/upload")
            .body(Body::empty())
            .unwrap()
    }

    /// A chunked body: no `Content-Length`, no exact size hint.
    fn chunked(chunks: usize, chunk_size: usize) -> Body {
        let stream = futures::stream::iter(
            (0..chunks).map(move |_| Ok::<_, Infallible>(Bytes::from(vec![b'x'; chunk_size]))),
        );
        Body::from_stream(stream)
    }

    fn post_chunked(body: Body, content_length: Option<u64>) -> http::Request<Body> {
        let mut builder = http::Request::builder().method("POST").uri("/upload");
        if let Some(len) = content_length {
            builder = builder.header(CONTENT_LENGTH, len);
        }
        builder.body(body).unwrap()
    }

    #[tokio::test]
    async fn rejects_when_content_length_exceeds_limit() {
        let response = send(
            build_app(BodyLimit::new().limit(1024)),
            post_with_length(2048),
        )
        .await;
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn passes_when_content_length_within_limit() {
        let response = send(
            build_app(BodyLimit::new().limit(1024)),
            post_with_length(512),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn passes_at_exact_limit() {
        let response = send(
            build_app(BodyLimit::new().limit(1024)),
            post_with_length(1024),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn rejects_one_byte_over_limit() {
        let response = send(
            build_app(BodyLimit::new().limit(1024)),
            post_with_length(1025),
        )
        .await;
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn passes_when_no_content_length_header() {
        let response = send(
            build_app(BodyLimit::new().limit(1024)),
            post_without_length(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn custom_status_code() {
        let config = BodyLimit::new()
            .limit(512)
            .status(StatusCode::UNPROCESSABLE_ENTITY);
        let response = send(build_app(config), post_with_length(1024)).await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn default_layer_uses_413_and_one_mib_limit() {
        let app = Router::new()
            .route("/upload", post(|| async { "ok" }))
            .layer(BodyLimitLayer::default());

        let within = send(app.clone(), post_with_length(1_048_576)).await;
        assert_eq!(within.status(), StatusCode::OK);

        let over = send(app, post_with_length(1_048_577)).await;
        assert_eq!(over.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn zero_limit_rejects_any_body() {
        let response = send(build_app(BodyLimit::new().limit(0)), post_with_length(1)).await;
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn chunked_body_over_limit_is_rejected() {
        let app = buffering_app(BodyLimit::new().limit(1024));
        let response = send(app, post_chunked(chunked(5, 256), None)).await;
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(body_text(response).await, "", "no detail leaked");
    }

    #[tokio::test]
    async fn chunked_body_over_limit_uses_configured_status() {
        let app = buffering_app(
            BodyLimit::new()
                .limit(10)
                .status(StatusCode::UNPROCESSABLE_ENTITY),
        );
        let response = send(app, post_chunked(chunked(3, 4), None)).await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn chunked_body_at_exact_limit_is_accepted() {
        let app = buffering_app(BodyLimit::new().limit(1024));
        let response = send(app, post_chunked(chunked(4, 256), None)).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_text(response).await, "1024");
    }

    #[tokio::test]
    async fn full_body_at_exact_limit_is_accepted() {
        let app = buffering_app(BodyLimit::new().limit(1024));
        let req = http::Request::builder()
            .method("POST")
            .uri("/upload")
            .header(CONTENT_LENGTH, 1024)
            .body(Body::from(vec![0u8; 1024]))
            .unwrap();
        let response = send(app, req).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_text(response).await, "1024");
    }

    #[tokio::test]
    async fn full_body_over_limit_without_header_is_rejected_up_front() {
        let app = buffering_app(BodyLimit::new().limit(1024));
        let req = post_chunked(Body::from(vec![0u8; 1025]), None);
        assert_eq!(send(app, req).await.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn lying_content_length_is_rejected() {
        // Declares 10 bytes (well under the limit) but sends 2 KiB.
        let app = buffering_app(BodyLimit::new().limit(1024));
        let response = send(app, post_chunked(chunked(8, 256), Some(10))).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_text(response).await, "");
    }

    #[tokio::test]
    async fn content_length_at_limit_with_longer_body_is_413() {
        let app = buffering_app(BodyLimit::new().limit(1024));
        let response = send(app, post_chunked(chunked(5, 256), Some(1024))).await;
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn malformed_content_length_is_rejected() {
        for value in ["abc", "-1", "+5", "", "1, 2"] {
            let req = http::Request::builder()
                .method("POST")
                .uri("/upload")
                .header(CONTENT_LENGTH, value)
                .body(Body::empty())
                .unwrap();
            let response = send(build_app(BodyLimit::new()), req).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{value:?}");
        }
    }

    #[tokio::test]
    async fn conflicting_content_length_headers_are_rejected() {
        let req = http::Request::builder()
            .method("POST")
            .uri("/upload")
            .header(CONTENT_LENGTH, "5")
            .header(CONTENT_LENGTH, "6")
            .body(Body::empty())
            .unwrap();
        let response = send(build_app(BodyLimit::new()), req).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn repeated_identical_content_length_is_accepted() {
        let req = http::Request::builder()
            .method("POST")
            .uri("/upload")
            .header(CONTENT_LENGTH, "5, 5")
            .body(Body::from("hello"))
            .unwrap();
        let response = send(build_app(BodyLimit::new()), req).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn streaming_handler_sees_the_error() {
        let saw_error = Arc::new(AtomicBool::new(false));
        let seen = Arc::clone(&saw_error);
        let app = Router::new()
            .route(
                "/upload",
                post(move |body: Body| {
                    let seen = Arc::clone(&seen);
                    async move {
                        let mut body = body;
                        let mut total = 0usize;
                        while let Some(frame) = body.frame().await {
                            let Ok(frame) = frame else {
                                seen.store(true, Ordering::SeqCst);
                                break;
                            };
                            total += frame.data_ref().map_or(0, Bytes::len);
                        }
                        // A careless handler that answers 200 regardless.
                        format!("streamed {total}")
                    }
                }),
            )
            .layer(BodyLimitLayer::new(BodyLimit::new().limit(1000)));

        let response = send(app, post_chunked(chunked(10, 300), None)).await;
        assert!(saw_error.load(Ordering::SeqCst), "handler saw the error");
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(body_text(response).await, "");
    }

    #[tokio::test]
    async fn limited_body_error_is_length_limit_error() {
        let tripped = Arc::new(AtomicBool::new(false));
        let body = LimitedBody::new(chunked(2, 8), 10, Arc::clone(&tripped));
        let err = body.collect().await.unwrap_err();
        assert!(err.is::<http_body_util::LengthLimitError>());
        assert!(tripped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn per_method_layer_applies_only_to_that_method() {
        let app = Router::new()
            .route(
                "/upload",
                post(|body: Bytes| async move { body.len().to_string() })
                    .layer(BodyLimitLayer::new(BodyLimit::new().limit(4)))
                    .put(|body: Bytes| async move { body.len().to_string() }),
            )
            .layer(BodyLimitLayer::new(BodyLimit::new().limit(100)));

        let post_req = post_chunked(chunked(1, 8), None);
        assert_eq!(
            send(app.clone(), post_req).await.status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );

        let put_req = http::Request::builder()
            .method("PUT")
            .uri("/upload")
            .body(chunked(1, 8))
            .unwrap();
        assert_eq!(send(app, put_req).await.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn header_count_limit() {
        let app = build_app(BodyLimit::new().max_headers(2));
        let ok = http::Request::builder()
            .method("POST")
            .uri("/upload")
            .header("a", "1")
            .header("b", "2")
            .body(Body::empty())
            .unwrap();
        assert_eq!(send(app.clone(), ok).await.status(), StatusCode::OK);

        let too_many = http::Request::builder()
            .method("POST")
            .uri("/upload")
            .header("a", "1")
            .header("a", "2")
            .header("b", "3")
            .body(Body::empty())
            .unwrap();
        let response = send(app, too_many).await;
        assert_eq!(
            response.status(),
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
        );
        assert_eq!(body_text(response).await, "");
    }

    #[tokio::test]
    async fn header_bytes_limit() {
        let app = build_app(BodyLimit::new().max_header_bytes(10));
        let ok = http::Request::builder()
            .method("POST")
            .uri("/upload")
            .header("abcd", "123456")
            .body(Body::empty())
            .unwrap();
        assert_eq!(send(app.clone(), ok).await.status(), StatusCode::OK);

        let big = http::Request::builder()
            .method("POST")
            .uri("/upload")
            .header("abcd", "1234567")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            send(app, big).await.status(),
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
        );
    }

    #[test]
    fn limit_bytes_getter() {
        assert_eq!(BodyLimit::new().limit(7).limit_bytes(), 7);
        assert_eq!(BodyLimit::default().limit_bytes(), 1_048_576);
    }
}
