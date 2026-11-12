//! A Tower layer that turns bare error statuses into problem details.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use http::{HeaderMap, HeaderValue, Request, Response, StatusCode};
use http_body::Body;
use pin_project_lite::pin_project;
use tower::{Layer, Service};

use crate::problem::{CONTENT_TYPE_PROBLEM_JSON, Problem};

type MapFn = Arc<dyn Fn(Problem) -> Problem + Send + Sync>;

/// Configuration for [`ProblemLayer`].
///
/// By default every `4xx` and `5xx` response with an empty body and no
/// `Content-Type` is replaced by an `about:blank` problem for its status.
///
/// # Examples
///
/// ```rust
/// use http::{HeaderMap, StatusCode};
/// use rune_axum_problem::Problems;
///
/// let config = Problems::new().client_errors(false);
/// let empty = HeaderMap::new();
/// assert!(config.should_convert(StatusCode::BAD_GATEWAY, &empty, Some(0)));
/// assert!(!config.should_convert(StatusCode::NOT_FOUND, &empty, Some(0)));
/// assert!(!config.should_convert(StatusCode::BAD_GATEWAY, &empty, Some(12)));
/// ```
#[derive(Clone)]
#[non_exhaustive]
pub struct Problems {
    client_errors: bool,
    server_errors: bool,
    instance_from_path: bool,
    map: Option<MapFn>,
}

impl Default for Problems {
    fn default() -> Self {
        Self {
            client_errors: true,
            server_errors: true,
            instance_from_path: false,
            map: None,
        }
    }
}

impl fmt::Debug for Problems {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Problems")
            .field("client_errors", &self.client_errors)
            .field("server_errors", &self.server_errors)
            .field("instance_from_path", &self.instance_from_path)
            .field("map", &self.map.is_some())
            .finish()
    }
}

impl Problems {
    /// Creates the default configuration: convert `4xx` and `5xx`, no
    /// `instance`, no customisation.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether bare `4xx` responses are converted. Defaults to `true`.
    #[must_use]
    pub const fn client_errors(mut self, enabled: bool) -> Self {
        self.client_errors = enabled;
        self
    }

    /// Whether bare `5xx` responses are converted. Defaults to `true`.
    #[must_use]
    pub const fn server_errors(mut self, enabled: bool) -> Self {
        self.server_errors = enabled;
        self
    }

    /// Whether the request path is put in the `instance` member. Defaults to
    /// `false`. The query string is never included.
    #[must_use]
    pub const fn instance_from_path(mut self, enabled: bool) -> Self {
        self.instance_from_path = enabled;
        self
    }

    /// Customises every generated problem, for example to set a `type` URI
    /// or a `detail` per status.
    #[must_use]
    pub fn map(mut self, f: impl Fn(Problem) -> Problem + Send + Sync + 'static) -> Self {
        self.map = Some(Arc::new(f));
        self
    }

    /// Whether a response is a bare error status to convert: an enabled
    /// error class, no `Content-Type`, and a body known to be empty.
    #[must_use]
    pub fn should_convert(
        &self,
        status: StatusCode,
        headers: &HeaderMap,
        body_len: Option<u64>,
    ) -> bool {
        let class_enabled = (status.is_client_error() && self.client_errors)
            || (status.is_server_error() && self.server_errors);
        class_enabled && !headers.contains_key(CONTENT_TYPE) && body_len == Some(0)
    }

    /// The problem generated for `status` on a request for `path`.
    #[must_use]
    pub fn problem_for(&self, status: StatusCode, path: &str) -> Problem {
        let mut problem = Problem::new(status);
        if self.instance_from_path {
            problem = problem.with_instance(path);
        }
        match &self.map {
            Some(f) => f(problem),
            None => problem,
        }
    }
}

/// Tower [`Layer`] that replaces bare error responses with
/// `application/problem+json`.
///
/// A bare error response has an error status, an empty body and no
/// `Content-Type`, as produced by `StatusCode` handlers or by timeout and
/// load-shedding layers.
///
/// The response status and other headers (`Retry-After`,
/// `WWW-Authenticate`, ...) are kept. Responses that already have a body
/// pass through untouched. Place it outside the layers whose bare errors it
/// should convert.
///
/// # Examples
///
/// ```rust
/// use axum::{http::StatusCode, routing::get, Router};
/// use rune_axum_problem::{ProblemLayer, Problems};
///
/// let app: Router = Router::new()
///     .route("/", get(|| async { StatusCode::SERVICE_UNAVAILABLE }))
///     .layer(ProblemLayer::new(Problems::new().map(|p| {
///         p.with_type("https://example.com/probs/unavailable")
///     })));
/// ```
#[derive(Clone, Debug, Default)]
pub struct ProblemLayer {
    config: Arc<Problems>,
}

impl ProblemLayer {
    /// Creates a `ProblemLayer` from a custom [`Problems`] configuration.
    #[must_use]
    pub fn new(config: Problems) -> Self {
        Self {
            config: Arc::new(config),
        }
    }
}

impl<S> Layer<S> for ProblemLayer {
    type Service = ProblemService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ProblemService {
            inner,
            config: Arc::clone(&self.config),
        }
    }
}

/// Tower [`Service`] produced by [`ProblemLayer`].
#[derive(Clone, Debug)]
pub struct ProblemService<S> {
    inner: S,
    config: Arc<Problems>,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for ProblemService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    ResBody: Body + From<Vec<u8>>,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future = ResponseFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let path = self
            .config
            .instance_from_path
            .then(|| req.uri().path().to_owned());
        ResponseFuture {
            inner: self.inner.call(req),
            path,
            config: Arc::clone(&self.config),
        }
    }
}

pin_project! {
    /// Response future of [`ProblemService`].
    pub struct ResponseFuture<F> {
        #[pin]
        inner: F,
        path: Option<String>,
        config: Arc<Problems>,
    }
}

impl<F> fmt::Debug for ResponseFuture<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResponseFuture").finish_non_exhaustive()
    }
}

impl<F, B, E> Future for ResponseFuture<F>
where
    F: Future<Output = Result<Response<B>, E>>,
    B: Body + From<Vec<u8>>,
{
    type Output = Result<Response<B>, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let response = ready!(this.inner.poll(cx))?;
        let status = response.status();
        if !this.config.should_convert(
            status,
            response.headers(),
            response.body().size_hint().exact(),
        ) {
            return Poll::Ready(Ok(response));
        }
        let problem = this
            .config
            .problem_for(status, this.path.as_deref().unwrap_or_default());
        let body = problem.to_json();
        let (mut parts, _) = response.into_parts();
        parts.headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static(CONTENT_TYPE_PROBLEM_JSON),
        );
        parts
            .headers
            .insert(CONTENT_LENGTH, HeaderValue::from(body.len()));
        Poll::Ready(Ok(Response::from_parts(parts, B::from(body))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classes() {
        let empty = HeaderMap::new();
        let c = Problems::new();
        assert!(c.should_convert(StatusCode::NOT_FOUND, &empty, Some(0)));
        assert!(c.should_convert(StatusCode::GATEWAY_TIMEOUT, &empty, Some(0)));
        assert!(!c.should_convert(StatusCode::OK, &empty, Some(0)));
        assert!(!c.should_convert(StatusCode::NOT_MODIFIED, &empty, Some(0)));
        assert!(!c.should_convert(StatusCode::NOT_FOUND, &empty, None));
        let c = Problems::new().server_errors(false);
        assert!(!c.should_convert(StatusCode::GATEWAY_TIMEOUT, &empty, Some(0)));
        assert!(c.should_convert(StatusCode::NOT_FOUND, &empty, Some(0)));
    }

    #[test]
    fn content_type_blocks_conversion() {
        let mut h = HeaderMap::new();
        h.insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        assert!(!Problems::new().should_convert(StatusCode::NOT_FOUND, &h, Some(0)));
    }

    #[test]
    fn problem_for_applies_instance_and_map() {
        let c = Problems::new()
            .instance_from_path(true)
            .map(|p| p.with_detail("try later"));
        let p = c.problem_for(StatusCode::SERVICE_UNAVAILABLE, "/x");
        assert_eq!(p.instance(), Some("/x"));
        assert_eq!(p.detail(), Some("try later"));
        assert_eq!(p.title(), Some("Service Unavailable"));
        assert!(format!("{c:?}").contains("map: true"));
        assert_eq!(
            Problems::new()
                .problem_for(StatusCode::NOT_FOUND, "/x")
                .instance(),
            None
        );
    }
}
