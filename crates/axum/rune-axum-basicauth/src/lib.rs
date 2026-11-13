//! HTTP Basic authentication extractor and middleware layer for Axum.
//!
//! Provides two complementary tools for RFC 7617 Basic authentication:
//! [`BasicAuth`] decodes `Authorization: Basic` credentials from a request and
//! returns `401 Unauthorized` if the header is absent or malformed.
//! [`BasicAuthLayer`] validates those credentials against a configured
//! username and password using constant-time comparison before the handler runs.
//!
//! # Features
//!
//! - RFC 7617 `Authorization: Basic` header parsing with base64 decoding.
//! - `WWW-Authenticate: Basic realm="protected"` on every `401` response.
//! - Constant-time credential comparison via [`subtle`] — prevents timing attacks.
//! - Extractor-only mode: use [`BasicAuth`] in a handler when you need the
//!   credentials but want to validate them yourself.
//!
//! > [!WARNING]
//! > Basic authentication encodes credentials in base64, which is trivially
//! > reversible. Always serve over HTTPS in production.
//!
//! # Quick Start
//!
//! ## Middleware
//!
//! ```rust,no_run
//! use axum::{routing::get, Router};
//! use rune_axum_basicauth::BasicAuthLayer;
//!
//! #[tokio::main]
//! async fn main() {
//!     let app: Router = Router::new()
//!         .route("/admin", get(|| async { "dashboard" }))
//!         .route_layer(BasicAuthLayer::new("admin", "s3cr3t"));
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
//! use rune_axum_basicauth::BasicAuth;
//!
//! async fn handler(auth: BasicAuth) -> String {
//!     format!("Hello, {}!", auth.username)
//! }
//!
//! let app: Router = Router::new().route("/", get(handler));
//! ```

use axum::{
    extract::FromRequestParts,
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use http::{HeaderValue, StatusCode, header, request::Parts};
use pin_project_lite::pin_project;
use std::{
    fmt,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{self, Poll},
};
use subtle::{Choice, ConstantTimeEq};
use tower_layer::Layer;
use tower_service::Service;

/// Decoded HTTP Basic authentication credentials extracted from the request.
///
/// Use as an Axum extractor to access the username and password sent by the
/// client. Returns [`BasicAuthRejection`] (`401 Unauthorized`) if the
/// `Authorization: Basic` header is absent or malformed.
///
/// For transparent middleware validation, see [`BasicAuthLayer`].
///
/// # Examples
///
/// ```rust,no_run
/// use axum::{routing::get, Router};
/// use rune_axum_basicauth::BasicAuth;
///
/// async fn handler(auth: BasicAuth) -> String {
///     format!("Hello, {}!", auth.username)
/// }
///
/// let app: Router = Router::new().route("/", get(handler));
/// ```
///
/// `Debug` output redacts the password.
#[derive(Clone)]
pub struct BasicAuth {
    /// The username from the `Authorization: Basic` header.
    pub username: String,
    /// The password from the `Authorization: Basic` header.
    pub password: String,
}

impl fmt::Debug for BasicAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BasicAuth")
            .field("username", &self.username)
            .field("password", &REDACTED)
            .finish()
    }
}

const REDACTED: &str = "[redacted]";

/// Rejection returned when [`BasicAuth`] extraction fails.
///
/// Both variants respond with `401 Unauthorized` and
/// `WWW-Authenticate: Basic realm="protected"`.
#[derive(Debug)]
pub enum BasicAuthRejection {
    /// The `Authorization` header was absent.
    Missing,
    /// The header value was not valid RFC 7617 Basic credentials.
    Malformed,
}

impl IntoResponse for BasicAuthRejection {
    fn into_response(self) -> Response {
        unauthorized()
    }
}

impl<S> FromRequestParts<S> for BasicAuth
where
    S: Send + Sync,
{
    type Rejection = BasicAuthRejection;

    #[allow(
        clippy::unused_async_trait_impl,
        reason = "the extractor trait is async; this implementation happens not to await"
    )]
    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let value = parts
            .headers
            .get(header::AUTHORIZATION)
            .ok_or(BasicAuthRejection::Missing)?;

        decode_basic(value).ok_or(BasicAuthRejection::Malformed)
    }
}

fn decode_basic(value: &HeaderValue) -> Option<BasicAuth> {
    let s = value.to_str().ok()?;
    let encoded = s.strip_prefix("Basic ")?;
    let bytes = STANDARD.decode(encoded).ok()?;
    let decoded = std::str::from_utf8(&bytes).ok()?;
    let (username, password) = decoded.split_once(':')?;
    Some(BasicAuth {
        username: username.to_owned(),
        password: password.to_owned(),
    })
}

fn unauthorized() -> Response {
    let mut resp = StatusCode::UNAUTHORIZED.into_response();
    resp.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static(r#"Basic realm="protected""#),
    );
    resp
}

/// Tower [`Layer`] that validates HTTP Basic credentials before every request.
///
/// Extracts `Authorization: Basic` credentials and compares them against the
/// configured username and password using constant-time byte comparison.
/// Requests with missing, malformed, or incorrect credentials receive
/// `401 Unauthorized` before reaching the handler. `Debug` output redacts the
/// configured credentials.
///
/// # Examples
///
/// ```rust,no_run
/// use axum::{routing::get, Router};
/// use rune_axum_basicauth::BasicAuthLayer;
///
/// #[tokio::main]
/// async fn main() {
///     let app: Router = Router::new()
///         .route("/admin", get(|| async { "dashboard" }))
///         .route_layer(BasicAuthLayer::new("admin", "hunter2"));
///
///     let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
///     axum::serve(listener, app).await.unwrap();
/// }
/// ```
#[derive(Clone)]
pub struct BasicAuthLayer {
    username: Arc<[u8]>,
    password: Arc<[u8]>,
}

impl BasicAuthLayer {
    /// Creates a [`BasicAuthLayer`] that accepts exactly one username and password.
    ///
    /// Credentials are stored as bytes and compared in constant time on every
    /// request using [`subtle::ConstantTimeEq`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_axum_basicauth::BasicAuthLayer;
    ///
    /// let layer = BasicAuthLayer::new("alice", "correct-horse-battery-staple");
    /// ```
    #[must_use]
    pub fn new(username: &str, password: &str) -> Self {
        Self {
            username: username.as_bytes().into(),
            password: password.as_bytes().into(),
        }
    }
}

impl fmt::Debug for BasicAuthLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BasicAuthLayer")
            .field("username", &REDACTED)
            .field("password", &REDACTED)
            .finish()
    }
}

impl<S> Layer<S> for BasicAuthLayer {
    type Service = BasicAuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        BasicAuthService {
            inner,
            username: Arc::clone(&self.username),
            password: Arc::clone(&self.password),
        }
    }
}

/// Tower [`Service`] produced by [`BasicAuthLayer`].
#[derive(Clone)]
pub struct BasicAuthService<S> {
    inner: S,
    username: Arc<[u8]>,
    password: Arc<[u8]>,
}

impl<S: fmt::Debug> fmt::Debug for BasicAuthService<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BasicAuthService")
            .field("inner", &self.inner)
            .field("username", &REDACTED)
            .field("password", &REDACTED)
            .finish()
    }
}

/// Compares presented bytes with the configured ones in constant time.
///
/// `subtle`'s slice comparison returns early when the lengths differ, which
/// tells a client how long the password is. This walks the presented bytes
/// only, so the time depends on what the client sent, never on the secret.
fn ct_matches(given: &[u8], expected: &[u8]) -> Choice {
    let diff = given
        .iter()
        .zip(expected.iter().cycle())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b));
    diff.ct_eq(&0) & given.len().ct_eq(&expected.len())
}

impl<S, ReqB> Service<http::Request<ReqB>> for BasicAuthService<S>
where
    S: Service<http::Request<ReqB>, Response = Response>,
{
    type Response = Response;
    type Error = S::Error;
    type Future = BasicAuthFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: http::Request<ReqB>) -> Self::Future {
        let credentials = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(decode_basic);

        let authorized = credentials.as_ref().is_some_and(|creds| {
            let user_ok = ct_matches(creds.username.as_bytes(), &self.username);
            let pass_ok = ct_matches(creds.password.as_bytes(), &self.password);
            bool::from(user_ok & pass_ok)
        });

        if authorized {
            BasicAuthFuture {
                kind: FutureKind::Allow {
                    future: self.inner.call(req),
                },
            }
        } else {
            BasicAuthFuture {
                kind: FutureKind::Reject {
                    response: Some(unauthorized()),
                },
            }
        }
    }
}

pin_project! {
    /// Future returned by [`BasicAuthService`].
    pub struct BasicAuthFuture<F> {
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

impl<F, E> Future for BasicAuthFuture<F>
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

    fn basic_header(user: &str, pass: &str) -> String {
        format!("Basic {}", STANDARD.encode(format!("{user}:{pass}")))
    }

    fn make_app() -> Router {
        Router::new()
            .route("/secret", get(|| async { "ok" }))
            .route_layer(BasicAuthLayer::new("alice", "p4ssw0rd"))
    }

    async fn send(app: Router, req: http::Request<Body>) -> http::Response<Body> {
        app.oneshot(req).await.unwrap()
    }

    #[tokio::test]
    async fn correct_credentials_allowed() {
        let resp = send(
            make_app(),
            http::Request::builder()
                .uri("/secret")
                .header(header::AUTHORIZATION, basic_header("alice", "p4ssw0rd"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn wrong_password_rejected() {
        let resp = send(
            make_app(),
            http::Request::builder()
                .uri("/secret")
                .header(header::AUTHORIZATION, basic_header("alice", "wrong"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn wrong_username_rejected() {
        let resp = send(
            make_app(),
            http::Request::builder()
                .uri("/secret")
                .header(header::AUTHORIZATION, basic_header("bob", "p4ssw0rd"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn missing_header_rejected() {
        let resp = send(
            make_app(),
            http::Request::builder()
                .uri("/secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn malformed_header_rejected() {
        let resp = send(
            make_app(),
            http::Request::builder()
                .uri("/secret")
                .header(header::AUTHORIZATION, "Basic !!!not-base64!!!")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn www_authenticate_set_on_rejection() {
        let resp = send(
            make_app(),
            http::Request::builder()
                .uri("/secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert!(resp.headers().contains_key(header::WWW_AUTHENTICATE));
    }

    #[tokio::test]
    async fn extractor_returns_credentials() {
        async fn handler(auth: BasicAuth) -> String {
            auth.username
        }
        let app = Router::new().route("/", get(handler));
        let resp = send(
            app,
            http::Request::builder()
                .uri("/")
                .header(header::AUTHORIZATION, basic_header("carol", "pass"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn extractor_rejects_missing_header() {
        async fn handler(auth: BasicAuth) -> String {
            auth.username
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
    fn debug_never_prints_the_password() {
        let layer = BasicAuthLayer::new("alice", "p4ssw0rd");
        let bytes = format!("{:?}", b"p4ssw0rd");
        let bytes = &bytes[1..bytes.len() - 1];
        assert!(!format!("{layer:?}").contains(bytes), "{layer:?}");
        let service = layer.layer(());
        assert!(!format!("{service:?}").contains(bytes), "{service:?}");
        let creds = BasicAuth {
            username: "alice".to_owned(),
            password: "p4ssw0rd".to_owned(),
        };
        let rendered = format!("{creds:?}");
        assert!(rendered.contains("alice") && !rendered.contains("p4ssw0rd"));
    }

    #[test]
    fn credential_comparison() {
        let eq = |a: &[u8], b: &[u8]| bool::from(ct_matches(a, b));
        assert!(eq(b"abc", b"abc"));
        assert!(eq(b"", b""));
        assert!(!eq(b"abd", b"abc"));
        assert!(!eq(b"ab", b"abc"));
        assert!(!eq(b"abcabc", b"abc"));
        assert!(!eq(b"", b"abc"));
        assert!(!eq(b"a", b""));
    }
}
