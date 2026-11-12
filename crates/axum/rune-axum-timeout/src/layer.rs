use http::{Request, Response, StatusCode};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tower::{Layer, Service};

/// Default per-request deadline: 30 seconds.
const DEFAULT_DURATION: Duration = Duration::from_secs(30);

/// A deadline override for every path under `prefix`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct PathOverride {
    /// Normalised prefix: starts with `/`, no trailing `/` unless it is `/`.
    prefix: String,
    duration: Duration,
}

/// Configuration for the request timeout middleware.
///
/// Build with [`Timeout::new()`] and chain methods to set the default
/// deadline, the error status code and per-path overrides, then pass it to
/// [`TimeoutLayer::new()`].
///
/// # Examples
///
/// ```rust
/// use std::time::Duration;
/// use http::StatusCode;
/// use rune_axum_timeout::Timeout;
///
/// let config = Timeout::new()
///     .duration(Duration::from_secs(5))
///     .status(StatusCode::REQUEST_TIMEOUT)
///     .path("/uploads", Duration::from_secs(300));
///
/// assert_eq!(config.duration_for("/uploads/big.iso"), Duration::from_secs(300));
/// assert_eq!(config.duration_for("/"), Duration::from_secs(5));
/// assert_eq!(config.status_code(), StatusCode::REQUEST_TIMEOUT);
/// ```
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Timeout {
    duration: Duration,
    status: StatusCode,
    /// Shared so that per-request service clones stay cheap.
    overrides: Arc<Vec<PathOverride>>,
}

impl Default for Timeout {
    fn default() -> Self {
        Self {
            duration: DEFAULT_DURATION,
            status: StatusCode::GATEWAY_TIMEOUT,
            overrides: Arc::new(Vec::new()),
        }
    }
}

impl Timeout {
    /// Creates a `Timeout` with defaults: 30 second deadline,
    /// `504 Gateway Timeout`, no path overrides.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the default deadline applied to every request that matches no
    /// path override.
    ///
    /// Defaults to 30 seconds. A zero duration lets a request through only
    /// if the inner service completes on its first poll.
    #[must_use]
    pub const fn duration(mut self, duration: Duration) -> Self {
        self.duration = duration;
        self
    }

    /// Sets the HTTP status code returned when a request times out.
    ///
    /// Defaults to `504 Gateway Timeout`.
    #[must_use]
    pub const fn status(mut self, status: StatusCode) -> Self {
        self.status = status;
        self
    }

    /// Overrides the deadline for every request whose path is `prefix` or
    /// lies below it.
    ///
    /// Matching is on `/` segment boundaries: `/api` matches `/api` and
    /// `/api/users` but not `/apis`. A missing leading `/` is added and a
    /// trailing `/` is ignored, so `"api/"` is the same as `"/api"`. When
    /// several prefixes match, the longest one wins; setting the same prefix
    /// twice keeps the last duration.
    #[must_use]
    pub fn path(mut self, prefix: impl AsRef<str>, duration: Duration) -> Self {
        let prefix = normalize_prefix(prefix.as_ref());
        let overrides = Arc::make_mut(&mut self.overrides);
        if let Some(existing) = overrides.iter_mut().find(|o| o.prefix == prefix) {
            existing.duration = duration;
        } else {
            overrides.push(PathOverride { prefix, duration });
        }
        self
    }

    /// Returns the deadline that applies to a request for `path`.
    ///
    /// This is the longest matching [`path`](Self::path) override, or the
    /// default [`duration`](Self::duration) when none matches.
    #[must_use]
    pub fn duration_for(&self, path: &str) -> Duration {
        self.overrides
            .iter()
            .filter(|o| prefix_matches(&o.prefix, path))
            .max_by_key(|o| o.prefix.len())
            .map_or(self.duration, |o| o.duration)
    }

    /// Returns the status code sent when a request times out.
    #[must_use]
    pub const fn status_code(&self) -> StatusCode {
        self.status
    }
}

fn normalize_prefix(raw: &str) -> String {
    let trimmed = raw.trim_end_matches('/');
    let trimmed = trimmed.strip_prefix('/').unwrap_or(trimmed);
    format!("/{trimmed}")
}

fn prefix_matches(prefix: &str, path: &str) -> bool {
    if prefix == "/" {
        return true;
    }
    path.strip_prefix(prefix)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// Tower [`Layer`] that answers with an error response when the inner
/// service does not respond before the deadline.
///
/// Apply with Axum's `.layer()` for the whole router, or with
/// `MethodRouter::layer` / `Router::route_layer` for individual routes. Use
/// [`TimeoutLayer::default()`] for a 30 second deadline with a `504`
/// response, or [`TimeoutLayer::new()`] to supply a custom [`Timeout`].
///
/// The deadline covers the inner service's response future, that is, the
/// time until response headers are ready. It does not limit how long a
/// streaming response body takes to send.
///
/// # Examples
///
/// ```rust
/// use axum::{routing::get, Router};
/// use rune_axum_timeout::TimeoutLayer;
///
/// let app: Router = Router::new()
///     .route("/", get(|| async { "ok" }))
///     .layer(TimeoutLayer::default());
/// ```
#[derive(Clone, Debug, Default)]
pub struct TimeoutLayer {
    config: Timeout,
}

impl TimeoutLayer {
    /// Creates a `TimeoutLayer` from a custom [`Timeout`] configuration.
    #[must_use]
    pub const fn new(config: Timeout) -> Self {
        Self { config }
    }
}

impl<S> Layer<S> for TimeoutLayer {
    type Service = TimeoutService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TimeoutService {
            inner,
            config: self.config.clone(),
        }
    }
}

/// Tower [`Service`] produced by [`TimeoutLayer`].
///
/// Must be driven on a Tokio runtime with the time driver enabled.
#[derive(Clone, Debug)]
pub struct TimeoutService<S> {
    inner: S,
    config: Timeout,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for TimeoutService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    ResBody: Default + Send + 'static,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let deadline = self.config.duration_for(req.uri().path());
        let status = self.config.status;
        let fut = self.inner.call(req);
        Box::pin(async move {
            match tokio::time::timeout(deadline, fut).await {
                Ok(result) => result,
                Err(_elapsed) => {
                    let mut response = Response::new(ResBody::default());
                    *response.status_mut() = status;
                    Ok(response)
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, body::Body, routing::get};
    use tower::ServiceExt;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    fn get_req(path: &str) -> Request<Body> {
        Request::builder().uri(path).body(Body::empty()).unwrap()
    }

    #[test]
    fn defaults() {
        let t = Timeout::default();
        assert_eq!(t.duration_for("/anything"), DEFAULT_DURATION);
        assert_eq!(t.status_code(), StatusCode::GATEWAY_TIMEOUT);
    }

    #[test]
    fn normalizes_prefixes() {
        assert_eq!(normalize_prefix("api"), "/api");
        assert_eq!(normalize_prefix("/api/"), "/api");
        assert_eq!(normalize_prefix("/api///"), "/api");
        assert_eq!(normalize_prefix(""), "/");
        assert_eq!(normalize_prefix("/"), "/");
    }

    #[test]
    fn matches_on_segment_boundaries() {
        assert!(prefix_matches("/api", "/api"));
        assert!(prefix_matches("/api", "/api/"));
        assert!(prefix_matches("/api", "/api/users"));
        assert!(!prefix_matches("/api", "/apis"));
        assert!(!prefix_matches("/api", "/"));
        assert!(prefix_matches("/", "/anything/at/all"));
    }

    #[test]
    fn longest_prefix_wins_regardless_of_order() {
        let t = Timeout::new()
            .duration(secs(1))
            .path("/api/reports", secs(60))
            .path("/api", secs(5));
        assert_eq!(t.duration_for("/api/reports/x"), secs(60));
        assert_eq!(t.duration_for("/api/users"), secs(5));
        assert_eq!(t.duration_for("/health"), secs(1));
    }

    #[test]
    fn root_override_replaces_default() {
        let t = Timeout::new().duration(secs(1)).path("/", secs(9));
        assert_eq!(t.duration_for("/x"), secs(9));
    }

    #[test]
    fn repeated_prefix_keeps_last() {
        let t = Timeout::new().path("/a", secs(2)).path("/a/", secs(3));
        assert_eq!(t.duration_for("/a"), secs(3));
        assert_eq!(t.overrides.len(), 1);
    }

    #[test]
    fn builder_does_not_mutate_clones() {
        let base = Timeout::new().path("/a", secs(2));
        let derived = base.clone().path("/b", secs(3));
        assert_eq!(base.duration_for("/b"), DEFAULT_DURATION);
        assert_eq!(derived.duration_for("/b"), secs(3));
    }

    #[tokio::test(start_paused = true)]
    async fn fast_handler_passes_through() {
        let app = Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(TimeoutLayer::new(Timeout::new().duration(secs(1))));
        let res = app.oneshot(get_req("/")).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test(start_paused = true)]
    async fn slow_handler_times_out_with_default_504() {
        let app = Router::new()
            .route(
                "/",
                get(|| async {
                    tokio::time::sleep(secs(31)).await;
                    "late"
                }),
            )
            .layer(TimeoutLayer::default());
        let res = app.oneshot(get_req("/")).await.unwrap();
        assert_eq!(res.status(), StatusCode::GATEWAY_TIMEOUT);
    }

    #[tokio::test(start_paused = true)]
    async fn propagates_inner_status() {
        let app = Router::new()
            .route("/", get(|| async { StatusCode::IM_A_TEAPOT }))
            .layer(TimeoutLayer::default());
        let res = app.oneshot(get_req("/")).await.unwrap();
        assert_eq!(res.status(), StatusCode::IM_A_TEAPOT);
    }
}
