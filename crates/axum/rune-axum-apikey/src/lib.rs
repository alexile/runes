//! API key extractor and middleware layer for Axum.
//!
//! Validates API keys sourced from any combination of three locations —
//! a configurable header (default `X-Api-Key`), an `Authorization: Bearer`
//! token, or a configurable query parameter (default `api_key`) — using
//! constant-time comparison to prevent timing attacks.
//!
//! # Features
//!
//! - Checks three key sources in priority order: custom header → bearer token
//!   → query parameter. The header and query parameter names are configurable
//!   and the bearer source can be turned off.
//! - [`ApiKeyLayer`] validates the key against a configured secret with
//!   [`subtle::ConstantTimeEq`], returning `401 Unauthorized` on mismatch.
//! - [`ApiKey`] extractor for handlers that need the raw key value.
//! - Builder API for customising header name, query param name, and which
//!   sources are active.
//!
//! # Quick Start
//!
//! ## Middleware
//!
//! ```rust,no_run
//! use axum::{routing::get, Router};
//! use rune_axum_apikey::ApiKeyLayer;
//!
//! #[tokio::main]
//! async fn main() {
//!     let app: Router = Router::new()
//!         .route("/data", get(|| async { "secret" }))
//!         .route_layer(ApiKeyLayer::new("super-secret-key"));
//!
//!     let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
//!     axum::serve(listener, app).await.unwrap();
//! }
//! ```
//!
//! ## Extractor
//!
//! ```rust
//! use axum::{routing::get, Router};
//! use rune_axum_apikey::ApiKey;
//!
//! async fn handler(ApiKey(key): ApiKey) -> String {
//!     format!("authenticated with key ending: ...{}", &key[key.len().saturating_sub(4)..])
//! }
//!
//! let app: Router = Router::new().route("/", get(handler));
//! ```

use axum::{
    extract::FromRequestParts,
    response::{IntoResponse, Response},
};
use http::{StatusCode, header, request::Parts};
use pin_project_lite::pin_project;
use std::{
    fmt,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{self, Poll},
};
use subtle::ConstantTimeEq;
use tower_layer::Layer;
use tower_service::Service;

const DEFAULT_HEADER: &str = "x-api-key";
const DEFAULT_QUERY_PARAM: &str = "api_key";

/// An API key extracted from the request.
///
/// Checks three sources in priority order: `X-Api-Key` header,
/// `Authorization: Bearer <key>`, then `?api_key=<value>` query parameter.
/// Returns [`ApiKeyRejection`] (`401 Unauthorized`) if no key is present.
///
/// Use [`ApiKeyLayer`] when you want the middleware to validate the key for you.
///
/// # Examples
///
/// ```rust,no_run
/// use axum::{routing::get, Router};
/// use rune_axum_apikey::ApiKey;
///
/// async fn handler(ApiKey(key): ApiKey) -> String {
///     format!("key length: {}", key.len())
/// }
///
/// let app: Router = Router::new().route("/", get(handler));
/// ```
///
/// `Debug` output redacts the key.
#[derive(Clone)]
pub struct ApiKey(pub String);

impl fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ApiKey").field(&REDACTED).finish()
    }
}

const REDACTED: &str = "[redacted]";

/// Rejection returned when no API key is found in the request.
///
/// Responds with `401 Unauthorized`.
#[derive(Debug)]
pub struct ApiKeyRejection;

impl IntoResponse for ApiKeyRejection {
    fn into_response(self) -> Response {
        StatusCode::UNAUTHORIZED.into_response()
    }
}

impl<S> FromRequestParts<S> for ApiKey
where
    S: Send + Sync,
{
    type Rejection = ApiKeyRejection;

    #[allow(
        clippy::unused_async_trait_impl,
        reason = "the extractor trait is async; this implementation happens not to await"
    )]
    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        extract_key(
            &parts.headers,
            parts.uri.query(),
            DEFAULT_HEADER,
            DEFAULT_QUERY_PARAM,
            true,
        )
        .map(ApiKey)
        .ok_or(ApiKeyRejection)
    }
}

fn extract_key(
    headers: &http::HeaderMap,
    query: Option<&str>,
    header_name: &str,
    query_param: &str,
    check_bearer: bool,
) -> Option<String> {
    if let Some(v) = headers.get(header_name).and_then(|v| v.to_str().ok()) {
        return Some(v.to_owned());
    }

    if check_bearer
        && let Some(key) = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
    {
        return Some(key.to_owned());
    }

    query.and_then(|q| {
        q.split('&')
            .filter_map(|pair| pair.split_once('='))
            .find(|(k, _)| *k == query_param)
            .map(|(_, v)| v.to_owned())
    })
}

/// Tower [`Layer`] that validates an API key on every request.
///
/// Extracts the key from the configured sources (header, bearer token, query
/// param) and compares it against the stored secret using constant-time
/// comparison. Returns `401 Unauthorized` before the handler runs if the key
/// is missing, empty or incorrect. An empty configured key matches nothing.
/// `Debug` output redacts the key.
///
/// # Examples
///
/// ```rust,no_run
/// use axum::{routing::get, Router};
/// use rune_axum_apikey::ApiKeyLayer;
///
/// #[tokio::main]
/// async fn main() {
///     // Accept key via X-Api-Key header, Bearer token, or ?api_key= param.
///     let app: Router = Router::new()
///         .route("/", get(|| async { "ok" }))
///         .route_layer(ApiKeyLayer::new("my-secret-key"));
///
///     let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
///     axum::serve(listener, app).await.unwrap();
/// }
/// ```
#[derive(Clone)]
pub struct ApiKeyLayer {
    key: Arc<[u8]>,
    header_name: Arc<str>,
    query_param: Arc<str>,
    check_bearer: bool,
}

impl ApiKeyLayer {
    /// Creates an [`ApiKeyLayer`] that accepts the given API key from any
    /// of the three default sources.
    ///
    /// Default sources: `X-Api-Key` header, `Authorization: Bearer`, `?api_key=`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_axum_apikey::ApiKeyLayer;
    ///
    /// let layer = ApiKeyLayer::new("my-secret-key-abc123");
    /// ```
    #[must_use]
    pub fn new(key: &str) -> Self {
        Self {
            key: key.as_bytes().into(),
            header_name: DEFAULT_HEADER.into(),
            query_param: DEFAULT_QUERY_PARAM.into(),
            check_bearer: true,
        }
    }

    /// Sets a custom header name to look for (default: `x-api-key`).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_axum_apikey::ApiKeyLayer;
    ///
    /// let layer = ApiKeyLayer::new("secret").header_name("x-token");
    /// ```
    #[must_use]
    pub fn header_name(mut self, name: &str) -> Self {
        self.header_name = name.into();
        self
    }

    /// Sets a custom query parameter name (default: `api_key`).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_axum_apikey::ApiKeyLayer;
    ///
    /// let layer = ApiKeyLayer::new("secret").query_param("token");
    /// ```
    #[must_use]
    pub fn query_param(mut self, param: &str) -> Self {
        self.query_param = param.into();
        self
    }

    /// Enables or disables extraction from `Authorization: Bearer` (default: `true`).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_axum_apikey::ApiKeyLayer;
    ///
    /// let layer = ApiKeyLayer::new("secret").bearer(false);
    /// ```
    #[must_use]
    pub const fn bearer(mut self, enabled: bool) -> Self {
        self.check_bearer = enabled;
        self
    }
}

impl fmt::Debug for ApiKeyLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiKeyLayer")
            .field("key", &REDACTED)
            .field("header_name", &self.header_name)
            .field("query_param", &self.query_param)
            .field("check_bearer", &self.check_bearer)
            .finish()
    }
}

impl<S> Layer<S> for ApiKeyLayer {
    type Service = ApiKeyService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ApiKeyService {
            inner,
            key: Arc::clone(&self.key),
            header_name: Arc::clone(&self.header_name),
            query_param: Arc::clone(&self.query_param),
            check_bearer: self.check_bearer,
        }
    }
}

/// Tower [`Service`] produced by [`ApiKeyLayer`].
#[derive(Clone)]
pub struct ApiKeyService<S> {
    inner: S,
    key: Arc<[u8]>,
    header_name: Arc<str>,
    query_param: Arc<str>,
    check_bearer: bool,
}

impl<S: fmt::Debug> fmt::Debug for ApiKeyService<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiKeyService")
            .field("inner", &self.inner)
            .field("key", &REDACTED)
            .field("header_name", &self.header_name)
            .field("query_param", &self.query_param)
            .field("check_bearer", &self.check_bearer)
            .finish()
    }
}

/// Compares a presented key with the configured one in constant time.
///
/// `subtle`'s slice comparison returns early when the lengths differ, which
/// tells a client how long the key is. This walks the presented key only, so
/// the time depends on what the client sent, never on the secret. Empty keys
/// never match.
fn key_matches(given: &[u8], expected: &[u8]) -> bool {
    if given.is_empty() || expected.is_empty() {
        return false;
    }
    let diff = given
        .iter()
        .zip(expected.iter().cycle())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b));
    bool::from(diff.ct_eq(&0) & given.len().ct_eq(&expected.len()))
}

impl<S, ReqB> Service<http::Request<ReqB>> for ApiKeyService<S>
where
    S: Service<http::Request<ReqB>, Response = Response>,
{
    type Response = Response;
    type Error = S::Error;
    type Future = ApiKeyFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: http::Request<ReqB>) -> Self::Future {
        let extracted = extract_key(
            req.headers(),
            req.uri().query(),
            &self.header_name,
            &self.query_param,
            self.check_bearer,
        );

        let authorized = extracted
            .as_ref()
            .is_some_and(|k| key_matches(k.as_bytes(), &self.key));

        if authorized {
            ApiKeyFuture {
                kind: FutureKind::Allow {
                    future: self.inner.call(req),
                },
            }
        } else {
            ApiKeyFuture {
                kind: FutureKind::Reject {
                    response: Some(StatusCode::UNAUTHORIZED.into_response()),
                },
            }
        }
    }
}

pin_project! {
    /// Future returned by [`ApiKeyService`].
    pub struct ApiKeyFuture<F> {
        #[pin]
        kind: FutureKind<F>,
    }
}

pin_project! {
    #[project = FutureKindProj]
    enum FutureKind<F> {
        Reject { response: Option<Response> },
        Allow { #[pin] future: F },
    }
}

impl<F, E> Future for ApiKeyFuture<F>
where
    F: Future<Output = Result<Response, E>>,
{
    type Output = Result<Response, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        match self.project().kind.project() {
            FutureKindProj::Reject { response } => {
                // Polling again after `Ready` breaks the `Future` contract; stay pending.
                response
                    .take()
                    .map_or(Poll::Pending, |r| Poll::Ready(Ok(r)))
            }
            FutureKindProj::Allow { future } => future.poll(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, body::Body, routing::get};
    use http::StatusCode;
    use tower::ServiceExt;

    const SECRET: &str = "test-key-abc123";

    fn make_app() -> Router {
        Router::new()
            .route("/data", get(|| async { "ok" }))
            .route_layer(ApiKeyLayer::new(SECRET))
    }

    async fn send(app: Router, req: http::Request<Body>) -> http::Response<Body> {
        app.oneshot(req).await.unwrap()
    }

    #[tokio::test]
    async fn key_in_header_allowed() {
        let resp = send(
            make_app(),
            http::Request::builder()
                .uri("/data")
                .header("x-api-key", SECRET)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn key_as_bearer_allowed() {
        let resp = send(
            make_app(),
            http::Request::builder()
                .uri("/data")
                .header(header::AUTHORIZATION, format!("Bearer {SECRET}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn key_in_query_allowed() {
        let resp = send(
            make_app(),
            http::Request::builder()
                .uri(format!("/data?api_key={SECRET}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn wrong_key_rejected() {
        let resp = send(
            make_app(),
            http::Request::builder()
                .uri("/data")
                .header("x-api-key", "wrong-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn missing_key_rejected() {
        let resp = send(
            make_app(),
            http::Request::builder()
                .uri("/data")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn custom_header_name_works() {
        let app = Router::new()
            .route("/", get(|| async { "ok" }))
            .route_layer(ApiKeyLayer::new(SECRET).header_name("x-token"));
        let resp = send(
            app,
            http::Request::builder()
                .uri("/")
                .header("x-token", SECRET)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn custom_query_param_works() {
        let app = Router::new()
            .route("/", get(|| async { "ok" }))
            .route_layer(ApiKeyLayer::new(SECRET).query_param("token"));
        let resp = send(
            app,
            http::Request::builder()
                .uri(format!("/?token={SECRET}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn bearer_disabled_rejects_bearer_key() {
        let app = Router::new()
            .route("/", get(|| async { "ok" }))
            .route_layer(ApiKeyLayer::new(SECRET).bearer(false));
        let resp = send(
            app,
            http::Request::builder()
                .uri("/")
                .header(header::AUTHORIZATION, format!("Bearer {SECRET}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn extractor_returns_key() {
        async fn handler(ApiKey(key): ApiKey) -> String {
            key
        }
        let app = Router::new().route("/", get(handler));
        let resp = send(
            app,
            http::Request::builder()
                .uri("/")
                .header("x-api-key", SECRET)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn extractor_rejects_missing_key() {
        async fn handler(ApiKey(_): ApiKey) -> &'static str {
            "ok"
        }
        let app = Router::new().route("/", get(handler));
        let resp = send(
            app,
            http::Request::builder()
                .uri("/")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn debug_never_prints_the_key() {
        let layer = ApiKeyLayer::new(SECRET);
        let rendered = format!("{layer:?}");
        let bytes = format!("{:?}", SECRET.as_bytes());
        assert!(!rendered.contains(&bytes[1..bytes.len() - 1]), "{rendered}");
        let service = layer.layer(());
        let rendered = format!("{service:?}");
        assert!(!rendered.contains(&bytes[1..bytes.len() - 1]), "{rendered}");
        assert!(!format!("{:?}", ApiKey(SECRET.to_owned())).contains(SECRET));
    }

    #[tokio::test]
    async fn empty_key_never_authorizes() {
        let app = Router::new()
            .route("/", get(|| async { "ok" }))
            .route_layer(ApiKeyLayer::new(""));
        for req in [
            http::Request::builder()
                .uri("/?api_key=")
                .body(Body::empty())
                .unwrap(),
            http::Request::builder()
                .uri("/")
                .header("x-api-key", "")
                .body(Body::empty())
                .unwrap(),
        ] {
            assert_eq!(
                send(app.clone(), req).await.status(),
                StatusCode::UNAUTHORIZED
            );
        }
    }

    #[test]
    fn key_comparison() {
        assert!(key_matches(b"abc", b"abc"));
        assert!(!key_matches(b"abd", b"abc"));
        assert!(!key_matches(b"ab", b"abc"));
        assert!(!key_matches(b"abcabc", b"abc"));
        assert!(!key_matches(b"", b"abc"));
        assert!(!key_matches(b"", b""));
        assert!(!key_matches(b"a", b""));
    }
}
