//! Tower middleware for HTTP server metrics and the `/metrics` endpoint.

use std::convert::Infallible;
use std::fmt;
use std::future::{Future, Ready, ready};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

use http::header::{ACCEPT, CACHE_CONTROL, CONTENT_TYPE, HeaderValue};
use http::{Extensions, Method, Request, Response, StatusCode};
use pin_project_lite::pin_project;
use tower_layer::Layer;
use tower_service::Service;

use crate::{CounterVec, DEFAULT_BUCKETS, Error, Format, GaugeVec, HistogramVec, Opts, Registry};

/// A `/metrics` endpoint: a Tower [`Service`] that encodes a [`Registry`]
/// on every request.
///
/// The format is negotiated from the `Accept` header
/// ([`Format::negotiate`]). `GET` and `HEAD` are answered with `200 OK`;
/// other methods get `405 Method Not Allowed`. Mount it with Axum's
/// `route_service`:
///
/// ```
/// use axum::Router;
/// use rune_metrics::{MetricsEndpoint, Registry};
///
/// let registry = Registry::new();
/// let app: Router = Router::new().route_service("/metrics", MetricsEndpoint::new(registry));
/// ```
#[derive(Debug, Clone)]
pub struct MetricsEndpoint {
    registry: Registry,
}

impl MetricsEndpoint {
    /// Creates an endpoint serving `registry`.
    #[must_use]
    pub const fn new(registry: Registry) -> Self {
        Self { registry }
    }

    /// Builds the response for a request with this method and `Accept`
    /// header, without going through [`Service`].
    #[must_use]
    pub fn respond(&self, method: &Method, accept: Option<&str>) -> Response<String> {
        let mut response = Response::new(String::new());
        if method != Method::GET && method != Method::HEAD {
            *response.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
            response
                .headers_mut()
                .insert(http::header::ALLOW, HeaderValue::from_static("GET, HEAD"));
            return response;
        }
        let format = accept.map_or(Format::Prometheus, Format::negotiate);
        if method == Method::GET {
            *response.body_mut() = self.registry.encode(format);
        }
        let headers = response.headers_mut();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static(format.content_type()),
        );
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
    }
}

impl<B> Service<Request<B>> for MetricsEndpoint {
    type Response = Response<String>;
    type Error = Infallible;
    type Future = Ready<Result<Response<String>, Infallible>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let accept = req.headers().get(ACCEPT).and_then(|v| v.to_str().ok());
        ready(Ok(self.respond(req.method(), accept)))
    }
}

/// Extracts the route template for the `route` label from request
/// extensions.
type RouteFn = dyn Fn(&Extensions) -> Option<String> + Send + Sync;

/// HTTP server metric instruments shared by every [`HttpMetricsService`].
#[derive(Clone)]
struct Instruments {
    requests: CounterVec,
    duration: HistogramVec,
    in_flight: GaugeVec,
    route: Option<Arc<RouteFn>>,
}

/// Tower [`Layer`] that records HTTP server metrics:
///
/// | Metric                                 | Type      | Labels                       |
/// | -------------------------------------- | --------- | ---------------------------- |
/// | `http_server_requests_total`           | counter   | `method`, `status`[, `route`] |
/// | `http_server_request_duration_seconds` | histogram | `method`, `status`[, `route`] |
/// | `http_server_requests_in_flight`       | gauge     | `method`                     |
///
/// `status` is the numeric response code, or `error` if the inner service
/// failed. Duration is measured until the response headers are ready.
/// Methods outside the standard set are recorded as `_OTHER` to bound
/// cardinality.
///
/// The URI path is never used as a label: it is unbounded. Pass a route
/// extractor with [`HttpMetricsLayer::with_route`] to add a `route` label
/// from a bounded template, such as Axum's `MatchedPath`.
///
/// # Examples
///
/// ```
/// use axum::{Router, extract::MatchedPath, routing::get};
/// use rune_metrics::{HttpMetricsLayer, MetricsEndpoint, Registry};
///
/// let registry = Registry::new();
/// let layer = HttpMetricsLayer::with_route(&registry, |ext| {
///     ext.get::<MatchedPath>().map(|p| p.as_str().to_owned())
/// })?;
/// let app: Router = Router::new()
///     .route("/users/{id}", get(|| async { "user" }))
///     .route_service("/metrics", MetricsEndpoint::new(registry))
///     .layer(layer);
/// # Ok::<(), rune_metrics::Error>(())
/// ```
#[derive(Clone)]
pub struct HttpMetricsLayer {
    instruments: Instruments,
}

impl fmt::Debug for HttpMetricsLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpMetricsLayer")
            .field("route_label", &self.instruments.route.is_some())
            .finish_non_exhaustive()
    }
}

impl HttpMetricsLayer {
    /// Registers the HTTP metrics in `registry`, without a `route` label.
    ///
    /// # Errors
    ///
    /// [`Error::AlreadyRegistered`] if the metric names are taken.
    pub fn new(registry: &Registry) -> Result<Self, Error> {
        Self::build(registry, None)
    }

    /// Registers the HTTP metrics in `registry` with a `route` label taken
    /// from `route`. Requests for which it returns `None` get an empty
    /// `route`.
    ///
    /// # Errors
    ///
    /// [`Error::AlreadyRegistered`] if the metric names are taken.
    pub fn with_route<F>(registry: &Registry, route: F) -> Result<Self, Error>
    where
        F: Fn(&Extensions) -> Option<String> + Send + Sync + 'static,
    {
        Self::build(registry, Some(Arc::new(route)))
    }

    fn build(registry: &Registry, route: Option<Arc<RouteFn>>) -> Result<Self, Error> {
        let labels: &[&str] = if route.is_some() {
            &["method", "status", "route"]
        } else {
            &["method", "status"]
        };
        let requests = registry.counter_vec(
            Opts::new(
                "http_server_requests_total",
                "Total HTTP requests handled by the server.",
            ),
            labels,
        )?;
        let duration = registry.histogram_vec(
            Opts::new(
                "http_server_request_duration_seconds",
                "Time until HTTP response headers were ready, in seconds.",
            )
            .with_unit("seconds"),
            labels,
            DEFAULT_BUCKETS,
        )?;
        let in_flight = registry.gauge_vec(
            Opts::new(
                "http_server_requests_in_flight",
                "HTTP requests currently being handled.",
            ),
            &["method"],
        )?;
        Ok(Self {
            instruments: Instruments {
                requests,
                duration,
                in_flight,
                route,
            },
        })
    }
}

impl<S> Layer<S> for HttpMetricsLayer {
    type Service = HttpMetricsService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        HttpMetricsService {
            inner,
            instruments: self.instruments.clone(),
        }
    }
}

/// Tower [`Service`] produced by [`HttpMetricsLayer`].
#[derive(Clone)]
pub struct HttpMetricsService<S> {
    inner: S,
    instruments: Instruments,
}

impl<S: fmt::Debug> fmt::Debug for HttpMetricsService<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpMetricsService")
            .field("inner", &self.inner)
            .finish_non_exhaustive()
    }
}

/// Maps a method to a bounded label value.
const fn method_label(method: &Method) -> &'static str {
    match *method {
        Method::GET => "GET",
        Method::HEAD => "HEAD",
        Method::POST => "POST",
        Method::PUT => "PUT",
        Method::DELETE => "DELETE",
        Method::CONNECT => "CONNECT",
        Method::OPTIONS => "OPTIONS",
        Method::TRACE => "TRACE",
        Method::PATCH => "PATCH",
        _ => "_OTHER",
    }
}

/// Decrements the in-flight gauge when the request finishes or is dropped.
struct InFlight {
    gauge: Option<crate::Gauge>,
}

impl Drop for InFlight {
    fn drop(&mut self) {
        if let Some(g) = &self.gauge {
            g.dec();
        }
    }
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for HttpMetricsService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future = HttpMetricsFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let method = method_label(req.method());
        let route = self
            .instruments
            .route
            .as_ref()
            .map(|f| f(req.extensions()).unwrap_or_default());
        let gauge = self.instruments.in_flight.with_label_values(&[method]).ok();
        if let Some(g) = &gauge {
            g.inc();
        }
        HttpMetricsFuture {
            inner: self.inner.call(req),
            state: Some(Pending {
                instruments: self.instruments.clone(),
                method,
                route,
                start: Instant::now(),
                _in_flight: InFlight { gauge },
            }),
        }
    }
}

struct Pending {
    instruments: Instruments,
    method: &'static str,
    route: Option<String>,
    start: Instant,
    _in_flight: InFlight,
}

impl Pending {
    fn record(self, status: &str) {
        let elapsed = self.start.elapsed().as_secs_f64();
        let mut labels = vec![self.method, status];
        if let Some(route) = &self.route {
            labels.push(route);
        }
        if let Ok(c) = self.instruments.requests.with_label_values(&labels) {
            c.inc();
        }
        if let Ok(h) = self.instruments.duration.with_label_values(&labels) {
            h.observe(elapsed);
        }
    }
}

pin_project! {
    /// Response future of [`HttpMetricsService`].
    pub struct HttpMetricsFuture<F> {
        #[pin]
        inner: F,
        state: Option<Pending>,
    }
}

impl<F> fmt::Debug for HttpMetricsFuture<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpMetricsFuture").finish_non_exhaustive()
    }
}

impl<F, ResBody, E> Future for HttpMetricsFuture<F>
where
    F: Future<Output = Result<Response<ResBody>, E>>,
{
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let result = std::task::ready!(this.inner.poll(cx));
        if let Some(pending) = this.state.take() {
            match &result {
                Ok(response) => pending.record(response.status().as_str()),
                Err(_) => pending.record("error"),
            }
        }
        Poll::Ready(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_rejects_other_methods() {
        let endpoint = MetricsEndpoint::new(Registry::new());
        let response = endpoint.respond(&Method::POST, None);
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        let head = endpoint.respond(&Method::HEAD, Some("application/openmetrics-text"));
        assert_eq!(head.status(), StatusCode::OK);
        assert_eq!(head.body(), "");
        assert_eq!(
            head.headers()[CONTENT_TYPE],
            Format::OpenMetrics.content_type()
        );
    }

    #[test]
    fn unknown_methods_are_bucketed() {
        let custom = Method::from_bytes(b"PURGE").unwrap();
        assert_eq!(method_label(&custom), "_OTHER");
        assert_eq!(method_label(&Method::PATCH), "PATCH");
    }

    #[test]
    fn layer_registration_conflicts_are_reported() {
        let registry = Registry::new();
        HttpMetricsLayer::new(&registry).unwrap();
        assert!(matches!(
            HttpMetricsLayer::new(&registry),
            Err(Error::AlreadyRegistered(_))
        ));
    }
}
