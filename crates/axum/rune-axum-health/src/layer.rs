use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use http::header::{CACHE_CONTROL, HeaderValue};
use http::{Method, Request, Response};
use tower::{Layer, Service};

use crate::HealthState;

/// Default liveness probe path.
const DEFAULT_LIVENESS_PATH: &str = "/livez";
/// Default readiness probe path.
const DEFAULT_READINESS_PATH: &str = "/readyz";

/// The kind of health probe a request asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Probe {
    /// Is the process alive? A failing liveness probe gets the process
    /// restarted. Stays healthy during shutdown.
    Liveness,
    /// Should the process receive traffic? A failing readiness probe takes
    /// it out of load balancing. Fails from the moment shutdown begins.
    Readiness,
}

/// Configuration for [`HealthLayer`]: where the probes are served.
///
/// # Examples
///
/// ```rust
/// use http::Method;
/// use rune_axum_health::{Health, Probe};
///
/// let config = Health::new().readiness_path("/health/ready");
///
/// assert_eq!(config.probe_for(&Method::GET, "/livez"), Some(Probe::Liveness));
/// assert_eq!(config.probe_for(&Method::HEAD, "/health/ready"), Some(Probe::Readiness));
/// assert_eq!(config.probe_for(&Method::POST, "/livez"), None);
/// assert_eq!(config.probe_for(&Method::GET, "/readyz"), None);
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Health {
    liveness_path: String,
    readiness_path: String,
}

impl Default for Health {
    fn default() -> Self {
        Self {
            liveness_path: DEFAULT_LIVENESS_PATH.to_owned(),
            readiness_path: DEFAULT_READINESS_PATH.to_owned(),
        }
    }
}

impl Health {
    /// Creates a `Health` with the default probe paths, `/livez` and
    /// `/readyz`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the path that answers the liveness probe. Defaults to `/livez`.
    ///
    /// A missing leading `/` is added.
    #[must_use]
    pub fn liveness_path(mut self, path: impl AsRef<str>) -> Self {
        self.liveness_path = normalize_path(path.as_ref());
        self
    }

    /// Sets the path that answers the readiness probe. Defaults to
    /// `/readyz`.
    ///
    /// A missing leading `/` is added.
    #[must_use]
    pub fn readiness_path(mut self, path: impl AsRef<str>) -> Self {
        self.readiness_path = normalize_path(path.as_ref());
        self
    }

    /// Returns the probe a request asks for, or `None` if the request is
    /// ordinary traffic.
    ///
    /// Only `GET` and `HEAD` requests whose path equals a probe path
    /// exactly are probes. Other methods on a probe path pass through to
    /// the inner service. If both paths are the same, liveness wins.
    #[must_use]
    pub fn probe_for(&self, method: &Method, path: &str) -> Option<Probe> {
        if method != Method::GET && method != Method::HEAD {
            return None;
        }
        if path == self.liveness_path {
            Some(Probe::Liveness)
        } else if path == self.readiness_path {
            Some(Probe::Readiness)
        } else {
            None
        }
    }
}

fn normalize_path(raw: &str) -> String {
    if raw.starts_with('/') {
        raw.to_owned()
    } else {
        format!("/{raw}")
    }
}

/// Tower [`Layer`] that answers health probes and tracks in-flight
/// requests for graceful shutdown.
///
/// - `GET`/`HEAD` on the liveness path answers `200 OK` while the
///   [`HealthState`] is live, `503 Service Unavailable` otherwise.
/// - `GET`/`HEAD` on the readiness path answers `200 OK` while the state is
///   ready and not shutting down, `503` otherwise.
/// - Every other request goes to the inner service and counts as in flight
///   until its response headers are ready, so
///   [`HealthState::drained`] waits for it. Probes are not counted.
///
/// Probe responses have an empty body and `Cache-Control: no-store`.
/// Apply the layer outermost, so that probes skip authentication, rate
/// limiting and the like, and so that every request is tracked.
///
/// # Examples
///
/// ```rust
/// use axum::{routing::get, Router};
/// use rune_axum_health::{HealthLayer, HealthState};
///
/// let state = HealthState::new();
/// let app: Router = Router::new()
///     .route("/", get(|| async { "ok" }))
///     .layer(HealthLayer::new(state.clone()));
/// ```
#[derive(Clone, Debug)]
pub struct HealthLayer {
    config: Health,
    state: HealthState,
}

impl HealthLayer {
    /// Creates a layer with the default probe paths that reports `state`.
    #[must_use]
    pub fn new(state: HealthState) -> Self {
        Self::with_config(Health::default(), state)
    }

    /// Creates a layer with custom probe paths that reports `state`.
    #[must_use]
    pub const fn with_config(config: Health, state: HealthState) -> Self {
        Self { config, state }
    }

    /// Returns the state this layer reports and tracks requests in.
    #[must_use]
    pub const fn state(&self) -> &HealthState {
        &self.state
    }
}

impl<S> Layer<S> for HealthLayer {
    type Service = HealthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        HealthService {
            inner,
            config: self.config.clone(),
            state: self.state.clone(),
        }
    }
}

/// Tower [`Service`] produced by [`HealthLayer`].
#[derive(Clone, Debug)]
pub struct HealthService<S> {
    inner: S,
    config: Health,
    state: HealthState,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for HealthService<S>
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
        if let Some(probe) = self.config.probe_for(req.method(), req.uri().path()) {
            let mut response = Response::new(ResBody::default());
            *response.status_mut() = self.state.status(probe);
            response
                .headers_mut()
                .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
            return Box::pin(std::future::ready(Ok(response)));
        }
        let guard = self.state.track();
        let fut = self.inner.call(req);
        Box::pin(async move {
            let result = fut.await;
            drop(guard);
            result
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_paths() {
        let h = Health::default();
        assert_eq!(h.probe_for(&Method::GET, "/livez"), Some(Probe::Liveness));
        assert_eq!(h.probe_for(&Method::GET, "/readyz"), Some(Probe::Readiness));
        assert_eq!(h.probe_for(&Method::GET, "/livez/"), None);
        assert_eq!(h.probe_for(&Method::GET, "/"), None);
    }

    #[test]
    fn only_get_and_head_are_probes() {
        let h = Health::default();
        assert_eq!(h.probe_for(&Method::HEAD, "/livez"), Some(Probe::Liveness));
        for m in [Method::POST, Method::PUT, Method::DELETE, Method::OPTIONS] {
            assert_eq!(h.probe_for(&m, "/livez"), None);
            assert_eq!(h.probe_for(&m, "/readyz"), None);
        }
    }

    #[test]
    fn custom_paths_are_normalized() {
        let h = Health::new()
            .liveness_path("healthz")
            .readiness_path("/ready");
        assert_eq!(h.probe_for(&Method::GET, "/healthz"), Some(Probe::Liveness));
        assert_eq!(h.probe_for(&Method::GET, "/ready"), Some(Probe::Readiness));
        assert_eq!(h.probe_for(&Method::GET, "/livez"), None);
    }

    #[test]
    fn liveness_wins_on_shared_path() {
        let h = Health::new().liveness_path("/h").readiness_path("/h");
        assert_eq!(h.probe_for(&Method::GET, "/h"), Some(Probe::Liveness));
    }
}
