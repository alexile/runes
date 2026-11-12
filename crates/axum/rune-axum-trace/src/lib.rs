//! One Axum layer for traces, metrics and redacted access logs.
//!
//! [`TraceLayer`] instruments every HTTP request with an OpenTelemetry server
//! span, propagates incoming W3C `traceparent` / `tracestate` context, and
//! records standard HTTP semantic-convention attributes. Spans are exported via
//! OTLP/gRPC to any compatible backend: Jaeger, Grafana Tempo, Honeycomb, a
//! local `OTel` Collector, and more.
//!
//! The same layer can also record Prometheus / `OpenMetrics` HTTP server metrics
//! with [`rune_metrics`] ([`TraceLayer::with_registry`]) and emit one
//! redacted access log event per request through [`tracing`], formatted and
//! redacted again by [`rune_log`] ([`TraceLayer::with_access_log`]). Each
//! access log event carries the span's `trace_id`, so logs and traces join up.
//!
//! # Features
//!
//! - Per-request [`SpanKind::Server`] spans with HTTP semantic conventions:
//!   `http.request.method`, `http.response.status_code`, `http.route`,
//!   `url.path`, `user_agent.original`.
//! - W3C `TraceContext` propagation — reads `traceparent` / `tracestate` from
//!   incoming headers and continues the distributed trace automatically.
//! - [`TraceConfig`] builder for zero-boilerplate OTLP/gRPC pipeline setup.
//! - [`OtelGuard`] RAII type that flushes and shuts down the tracer on drop.
//! - Works with any Axum `Router<S>` via `.layer()` or `.route_layer()`.
//! - Optional `http_server_requests_total`, `http_server_request_duration_seconds`
//!   and `http_server_requests_in_flight` metrics ([`rune_metrics::HttpMetricsLayer`]).
//! - Optional access log ([`AccessLog`]): path, query and user agent pass
//!   through a [`rune_log::Redactor`] before they are logged.
//!
//! > [!NOTE]
//! > Apply with `router.route_layer(TraceLayer::new())` for accurate route template
//! > span names (e.g. `GET /users/{id}`). With `router.layer()`, Axum's `MatchedPath`
//! > extension is not yet populated and the span name falls back to the HTTP method
//! > alone (`GET`).
//!
//! > [!WARNING]
//! > Call [`TraceConfig::init`] before the Axum server starts. Spans created before
//! > a provider is installed are silently dropped by the OTel noop tracer.
//!
//! # Quick Start
//!
//! ```rust,no_run
//! use axum::{routing::get, Router};
//! use rune_axum_trace::{TraceConfig, TraceLayer};
//!
//! #[tokio::main]
//! async fn main() {
//!     let _guard = TraceConfig::new()
//!         .service_name("my-api")
//!         .endpoint("http://localhost:4317")
//!         .init()
//!         .expect("failed to init tracer");
//!
//!     let app = Router::new()
//!         .route("/users/{id}", get(|| async { "ok" }))
//!         .route_layer(TraceLayer::new());
//!
//!     let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
//!     axum::serve(listener, app).await.unwrap();
//! }
//! ```
//!
//! # Traces, metrics and logs from one layer
//!
//! ```rust
//! use axum::{body::Body, routing::get, Router};
//! use rune_axum_trace::{AccessLog, TraceLayer};
//! use rune_metrics::{Format, MetricsEndpoint, Registry};
//! use tower::ServiceExt;
//! # use std::sync::{Arc, Mutex};
//! # #[derive(Clone, Default)]
//! # struct Buf(Arc<Mutex<Vec<u8>>>);
//! # impl std::io::Write for Buf {
//! #     fn write(&mut self, b: &[u8]) -> std::io::Result<usize> { self.0.lock().unwrap().extend_from_slice(b); Ok(b.len()) }
//! #     fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
//! # }
//! # impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Buf {
//! #     type Writer = Self;
//! #     fn make_writer(&'a self) -> Self { self.clone() }
//! # }
//! # let logs = Buf::default();
//! # let sink = logs.clone();
//!
//! // In a binary: `.with_env(|k| std::env::var(k).ok())?` and `std::io::stderr`.
//! let log_config = rune_log::LogConfig::default().with_timestamps(false);
//! let _logging = tracing::subscriber::set_default(log_config.subscriber(sink));
//!
//! let registry = Registry::new();
//! let app: Router = Router::new()
//!     .route("/users/{id}", get(|| async { "user" }))
//!     .route_layer(
//!         TraceLayer::new()
//!             .with_registry(&registry)?
//!             .with_access_log(AccessLog::new().with_redactor(log_config.redactor().clone())),
//!     )
//!     .route_service("/metrics", MetricsEndpoint::new(registry.clone()));
//!
//! # tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(async {
//! let req = http::Request::get("/users/bob@example.com").body(Body::empty()).unwrap();
//! let resp = app.oneshot(req).await.unwrap();
//! assert_eq!(resp.status(), 200);
//! # });
//!
//! let metrics = registry.encode(Format::Prometheus);
//! assert!(metrics.contains(r#"route="/users/{id}""#));
//! # let logs = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
//! // The access log line has `url.path=/users/[EMAIL]`: the address is gone.
//! assert!(logs.contains("/users/[EMAIL]") && !logs.contains("bob@example.com"));
//! # Ok::<(), rune_metrics::Error>(())
//! ```
//!
//! # Without `TraceConfig` (existing `OTel` setup)
//!
//! If the application already configures a global tracer provider (e.g. via
//! `opentelemetry_sdk`), skip `TraceConfig` and add the layer directly:
//!
//! ```rust
//! use axum::{routing::get, Router};
//! use rune_axum_trace::TraceLayer;
//!
//! let app: Router = Router::new()
//!     .route("/", get(|| async { "ok" }))
//!     .route_layer(TraceLayer::new());
//! ```

use http::Request;
use opentelemetry::{
    KeyValue,
    global::{self, BoxedSpan},
    trace::{Span, SpanKind, Tracer},
};
use opentelemetry_http::HeaderExtractor;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{Resource, propagation::TraceContextPropagator, trace::SdkTracerProvider};
use opentelemetry_semantic_conventions::attribute::{
    HTTP_REQUEST_METHOD, HTTP_RESPONSE_STATUS_CODE, HTTP_ROUTE,
};
use pin_project_lite::pin_project;
use rune_metrics::{HttpMetricsFuture, HttpMetricsLayer, HttpMetricsService, Registry};
use std::{
    future::Future,
    pin::Pin,
    task::{self, Poll},
};
use tower_layer::Layer;
use tower_service::Service;

mod access;

use access::PendingLog;
pub use access::{ACCESS_LOG_TARGET, AccessLog};
/// Re-export of the redacting logging crate, for
/// [`LogConfig`](rune_log::LogConfig) and [`Redactor`](rune_log::Redactor).
pub use rune_log;
/// Re-export of the metrics crate, for [`Registry`] and
/// [`MetricsEndpoint`](rune_metrics::MetricsEndpoint).
pub use rune_metrics;

/// Configuration for the OpenTelemetry OTLP tracing pipeline.
///
/// Builds and installs a global OTLP/gRPC tracer and W3C `TraceContext`
/// propagator. Call [`init`][TraceConfig::init] once at application startup
/// and hold the returned [`OtelGuard`] for the lifetime of the process.
///
/// # Examples
///
/// ```rust,no_run
/// use rune_axum_trace::TraceConfig;
///
/// #[tokio::main]
/// async fn main() {
///     let _guard = TraceConfig::new()
///         .service_name("my-api")
///         .endpoint("http://localhost:4317")
///         .init()
///         .unwrap();
/// }
/// ```
#[derive(Debug, Clone)]
pub struct TraceConfig {
    service_name: String,
    endpoint: String,
}

impl Default for TraceConfig {
    fn default() -> Self {
        Self {
            service_name: "unknown_service".to_owned(),
            endpoint: "http://localhost:4317".to_owned(),
        }
    }
}

impl TraceConfig {
    /// Creates a `TraceConfig` with default values.
    ///
    /// Default service name is `"unknown_service"` and the default OTLP endpoint
    /// is `"http://localhost:4317"`.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use rune_axum_trace::TraceConfig;
    ///
    /// let _guard = TraceConfig::new().service_name("payments").init().unwrap();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the `service.name` resource attribute reported to the collector.
    ///
    /// Appears as the service label in Jaeger, Grafana Tempo, and other backends.
    #[must_use]
    pub fn service_name(mut self, name: impl Into<String>) -> Self {
        self.service_name = name.into();
        self
    }

    /// Sets the OTLP/gRPC collector endpoint.
    ///
    /// Defaults to `"http://localhost:4317"`. The endpoint can also be controlled
    /// via the `OTEL_EXPORTER_OTLP_ENDPOINT` environment variable, which takes
    /// precedence over this value when set.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use rune_axum_trace::TraceConfig;
    ///
    /// let _guard = TraceConfig::new()
    ///     .service_name("my-api")
    ///     .endpoint("http://otel-collector.internal:4317")
    ///     .init()
    ///     .unwrap();
    /// ```
    #[must_use]
    pub fn endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = endpoint.into();
        self
    }

    /// Installs the global OTLP tracer and W3C `TraceContext` propagator.
    ///
    /// Returns an [`OtelGuard`] that flushes pending spans and shuts down the
    /// provider on drop. Bind the guard to a variable in `main` — it must live
    /// until the server exits.
    ///
    /// # Errors
    ///
    /// Returns an error if the OTLP exporter fails to initialise, for example
    /// when the endpoint URI is malformed.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use rune_axum_trace::TraceConfig;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let _guard = TraceConfig::new()
    ///         .service_name("my-api")
    ///         .init()
    ///         .expect("tracer init failed");
    ///     // application runs; guard flushes spans on drop
    /// }
    /// ```
    pub fn init(self) -> Result<OtelGuard, Box<dyn std::error::Error + Send + Sync>> {
        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .with_endpoint(self.endpoint)
            .build()?;

        let resource = Resource::builder()
            .with_service_name(self.service_name)
            .build();

        let provider = SdkTracerProvider::builder()
            .with_batch_exporter(exporter)
            .with_resource(resource)
            .build();

        global::set_tracer_provider(provider.clone());
        global::set_text_map_propagator(TraceContextPropagator::new());

        Ok(OtelGuard { provider })
    }
}

/// RAII guard that shuts down the global tracer provider on drop.
///
/// Dropping this value flushes all buffered spans to the collector and
/// shuts down the provider. Hold it for the full lifetime of the process.
///
/// Obtained from [`TraceConfig::init`].
pub struct OtelGuard {
    provider: SdkTracerProvider,
}

impl Drop for OtelGuard {
    fn drop(&mut self) {
        let _ = self.provider.shutdown();
    }
}

/// Tower [`Layer`] that instruments each Axum request with an OpenTelemetry
/// span and, optionally, HTTP metrics and a redacted access log.
///
/// Extracts the parent trace context from incoming W3C `traceparent` /
/// `tracestate` headers, creates a [`SpanKind::Server`] span, records HTTP
/// semantic-convention attributes, and ends the span with the response status
/// code when the handler returns.
///
/// - [`with_registry`](Self::with_registry) / [`with_metrics`](Self::with_metrics)
///   also record `http_server_*` metrics in a [`rune_metrics::Registry`]
///   (see [`HttpMetricsLayer`]).
/// - [`with_access_log`](Self::with_access_log) also emits one redacted
///   `tracing` event per request (see [`AccessLog`]), carrying the span's
///   `trace_id` so logs and traces can be joined.
///
/// The layer uses the global tracer installed by [`TraceConfig::init`]. If no
/// provider is installed, spans are silently dropped by the `OTel` noop tracer —
/// the layer still passes all requests through normally, and metrics and
/// access logs are still recorded.
///
/// # Layer placement
///
/// | Method | `MatchedPath` available | Span name | `route` label / field |
/// |---|---|---|---|
/// | `router.route_layer(TraceLayer::new())` | Yes | `GET /users/{id}` | `/users/{id}` |
/// | `router.layer(TraceLayer::new())` | No | `GET` | empty |
///
/// # Examples
///
/// ```rust
/// use axum::{routing::get, Router};
/// use rune_axum_trace::{AccessLog, TraceLayer};
/// use rune_metrics::{MetricsEndpoint, Registry};
///
/// let registry = Registry::new();
/// let app: Router = Router::new()
///     .route("/orders/{id}", get(|| async { "ok" }))
///     .route_layer(
///         TraceLayer::new()
///             .with_registry(&registry)?
///             .with_access_log(AccessLog::new()),
///     )
///     .route_service("/metrics", MetricsEndpoint::new(registry));
/// # Ok::<(), rune_metrics::Error>(())
/// ```
#[derive(Clone, Debug, Default)]
pub struct TraceLayer {
    metrics: Option<HttpMetricsLayer>,
    access_log: Option<AccessLog>,
}

impl TraceLayer {
    /// Creates a new [`TraceLayer`] using the global OpenTelemetry tracer,
    /// with metrics and access logs off.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use axum::{routing::get, Router};
    /// use rune_axum_trace::{TraceConfig, TraceLayer};
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let _guard = TraceConfig::new().service_name("my-api").init().unwrap();
    ///     let _app: Router = Router::new()
    ///         .route("/", get(|| async { "ok" }))
    ///         .route_layer(TraceLayer::new());
    /// }
    /// ```
    #[must_use]
    pub const fn new() -> Self {
        Self {
            metrics: None,
            access_log: None,
        }
    }

    /// Registers the HTTP server metrics in `registry`, with a `route` label
    /// taken from Axum's [`MatchedPath`](axum::extract::MatchedPath), and
    /// records them for every request.
    ///
    /// # Errors
    ///
    /// [`rune_metrics::Error::AlreadyRegistered`] if the `http_server_*`
    /// metric names are already taken in `registry`.
    pub fn with_registry(self, registry: &Registry) -> Result<Self, rune_metrics::Error> {
        let metrics = HttpMetricsLayer::with_route(registry, |ext| {
            ext.get::<axum::extract::MatchedPath>()
                .map(|p| p.as_str().to_owned())
        })?;
        Ok(self.with_metrics(metrics))
    }

    /// Records HTTP server metrics with an already-built [`HttpMetricsLayer`]
    /// (for example one with a custom `route` extractor).
    #[must_use]
    pub fn with_metrics(mut self, metrics: HttpMetricsLayer) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Emits one redacted access log event per request; see [`AccessLog`].
    #[must_use]
    pub fn with_access_log(mut self, access_log: AccessLog) -> Self {
        self.access_log = Some(access_log);
        self
    }
}

impl<S> Layer<S> for TraceLayer {
    type Service = TraceService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        let inner = match &self.metrics {
            Some(metrics) => Inner::Metered(metrics.layer(inner)),
            None => Inner::Plain(inner),
        };
        TraceService {
            inner,
            access_log: self.access_log.clone(),
        }
    }
}

/// The wrapped service, with or without the metrics middleware.
#[derive(Clone, Debug)]
enum Inner<S> {
    Plain(S),
    Metered(HttpMetricsService<S>),
}

/// Tower [`Service`] produced by [`TraceLayer`].
#[derive(Clone, Debug)]
pub struct TraceService<S> {
    inner: Inner<S>,
    access_log: Option<AccessLog>,
}

impl<S, B, ResB> Service<Request<B>> for TraceService<S>
where
    S: Service<Request<B>, Response = http::Response<ResB>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = TraceFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        match &mut self.inner {
            Inner::Plain(s) => s.poll_ready(cx),
            Inner::Metered(s) => s.poll_ready(cx),
        }
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let method = req.method().as_str().to_owned();
        let path = req.uri().path().to_owned();
        let route = req
            .extensions()
            .get::<axum::extract::MatchedPath>()
            .map(|mp| mp.as_str().to_owned());
        let user_agent = req
            .headers()
            .get(http::header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);

        let parent_cx = global::get_text_map_propagator(|propagator| {
            propagator.extract(&HeaderExtractor(req.headers()))
        });

        let span_name = route
            .as_ref()
            .map_or_else(|| method.clone(), |r| format!("{method} {r}"));

        let log = self.access_log.as_ref().map(|access_log| {
            access_log.start(
                &method,
                route.as_deref(),
                &path,
                req.uri().query(),
                user_agent.as_deref(),
            )
        });

        let mut attrs = vec![
            KeyValue::new(HTTP_REQUEST_METHOD, method),
            KeyValue::new("url.path", path),
        ];
        if let Some(r) = route {
            attrs.push(KeyValue::new(HTTP_ROUTE, r));
        }
        if let Some(ua) = user_agent {
            attrs.push(KeyValue::new("user_agent.original", ua));
        }

        let tracer = global::tracer("rune-axum-trace");
        let span = tracer
            .span_builder(span_name)
            .with_kind(SpanKind::Server)
            .with_attributes(attrs)
            .start_with_context(&tracer, &parent_cx);

        let log = log.map(|log| log.with_ids(span.span_context()));

        let inner = match &mut self.inner {
            Inner::Plain(s) => InnerFuture::Plain { fut: s.call(req) },
            Inner::Metered(s) => InnerFuture::Metered { fut: s.call(req) },
        };

        TraceFuture {
            inner,
            span: Some(span),
            log,
        }
    }
}

pin_project! {
    #[project = InnerFutureProj]
    enum InnerFuture<F> {
        Plain { #[pin] fut: F },
        Metered { #[pin] fut: HttpMetricsFuture<F> },
    }
}

impl<F, B, E> Future for InnerFuture<F>
where
    F: Future<Output = Result<http::Response<B>, E>>,
{
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        match self.project() {
            InnerFutureProj::Plain { fut } => fut.poll(cx),
            InnerFutureProj::Metered { fut } => fut.poll(cx),
        }
    }
}

pin_project! {
    /// Future returned by [`TraceService`].
    pub struct TraceFuture<F> {
        #[pin]
        inner: InnerFuture<F>,
        span: Option<BoxedSpan>,
        log: Option<PendingLog>,
    }
}

impl<F, B, E> Future for TraceFuture<F>
where
    F: Future<Output = Result<http::Response<B>, E>>,
{
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let result = task::ready!(this.inner.poll(cx));
        let status = result.as_ref().ok().map(http::Response::status);
        if let Some(mut span) = this.span.take() {
            match status {
                Some(status) => {
                    span.set_attribute(KeyValue::new(
                        HTTP_RESPONSE_STATUS_CODE,
                        i64::from(status.as_u16()),
                    ));
                    if status.is_server_error() {
                        span.set_status(opentelemetry::trace::Status::error("server error"));
                    } else {
                        span.set_status(opentelemetry::trace::Status::Ok);
                    }
                }
                None => {
                    span.set_status(opentelemetry::trace::Status::error("handler error"));
                }
            }
            span.end();
        }
        if let Some(log) = this.log.take() {
            log.emit(status.map(|s| s.as_u16()));
        }
        Poll::Ready(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, body::Body, routing::get};
    use http::StatusCode;
    use tower::ServiceExt;

    fn make_app() -> Router {
        Router::new()
            .route("/health", get(|| async { "ok" }))
            .route("/users/{id}", get(|| async { "user" }))
            .route_layer(TraceLayer::new())
    }

    async fn send(app: Router, req: http::Request<Body>) -> http::Response<Body> {
        app.oneshot(req).await.unwrap()
    }

    #[tokio::test]
    async fn request_passes_through() {
        let resp = send(
            make_app(),
            http::Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn parameterised_route_passes_through() {
        let resp = send(
            make_app(),
            http::Request::builder()
                .uri("/users/42")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn traceparent_header_accepted() {
        let resp = send(
            make_app(),
            http::Request::builder()
                .uri("/health")
                .header(
                    "traceparent",
                    "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn unknown_route_returns_not_found() {
        let resp = send(
            make_app(),
            http::Request::builder()
                .uri("/does-not-exist")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn layer_without_otel_provider_is_transparent() {
        let app = Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(TraceLayer::new());
        let resp = send(
            app,
            http::Request::builder()
                .uri("/")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    mod observability {
        use super::*;
        use rune_log::LogConfig;
        use rune_metrics::{Format, Registry};
        use std::io;
        use std::sync::{Arc, Mutex, PoisonError};

        #[derive(Clone, Default)]
        struct Capture(Arc<Mutex<Vec<u8>>>);

        impl Capture {
            fn text(&self) -> String {
                String::from_utf8_lossy(&self.0.lock().unwrap_or_else(PoisonError::into_inner))
                    .into_owned()
            }
        }

        impl io::Write for Capture {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.0
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .extend_from_slice(buf);
                Ok(buf.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
            type Writer = Self;

            fn make_writer(&'a self) -> Self {
                self.clone()
            }
        }

        fn json_logs() -> (Capture, tracing::subscriber::DefaultGuard) {
            let capture = Capture::default();
            let config = LogConfig::default()
                .with_format(rune_log::LogFormat::Json)
                .with_timestamps(false);
            let guard = tracing::subscriber::set_default(config.subscriber(capture.clone()));
            (capture, guard)
        }

        fn lines(capture: &Capture) -> Vec<serde_json::Value> {
            capture
                .text()
                .lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .collect()
        }

        fn app(layer: TraceLayer) -> Router {
            Router::new()
                .route("/users/{id}", get(|| async { "user" }))
                .route(
                    "/boom",
                    get(|| async { (StatusCode::INTERNAL_SERVER_ERROR, "boom") }),
                )
                .route_layer(layer)
        }

        fn get_req(uri: &str) -> http::Request<Body> {
            http::Request::builder()
                .uri(uri)
                .body(Body::empty())
                .unwrap()
        }

        #[tokio::test]
        async fn records_metrics_with_route_label() {
            let registry = Registry::new();
            let app = app(TraceLayer::new().with_registry(&registry).unwrap());
            for _ in 0..2 {
                let resp = send(app.clone(), get_req("/users/7")).await;
                assert_eq!(resp.status(), StatusCode::OK);
            }
            let resp = send(app, get_req("/boom")).await;
            assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

            let text = registry.encode(Format::Prometheus);
            assert!(
                text.contains(
                    r#"http_server_requests_total{method="GET",status="200",route="/users/{id}"} 2"#
                ),
                "{text}"
            );
            assert!(
                text.contains(
                    r#"http_server_requests_total{method="GET",status="500",route="/boom"} 1"#
                ),
                "{text}"
            );
            assert!(
                text.contains(r#"http_server_requests_in_flight{method="GET"} 0"#),
                "{text}"
            );
        }

        #[tokio::test]
        async fn registering_twice_fails() {
            let registry = Registry::new();
            assert!(TraceLayer::new().with_registry(&registry).is_ok());
            assert!(matches!(
                TraceLayer::new().with_registry(&registry),
                Err(rune_metrics::Error::AlreadyRegistered { .. })
            ));
        }

        #[tokio::test]
        async fn access_log_is_redacted_and_structured() {
            let (capture, _guard) = json_logs();
            let app = app(TraceLayer::new().with_access_log(AccessLog::new()));
            let req = http::Request::builder()
                .uri("/users/bob@example.com?email=alice@example.org&page=2")
                .header("user-agent", "curl/8.0 (contact carol@example.net)")
                .body(Body::empty())
                .unwrap();
            assert_eq!(send(app, req).await.status(), StatusCode::OK);

            let out = capture.text();
            for secret in ["bob@example.com", "alice@example.org", "carol@example.net"] {
                assert!(!out.contains(secret), "{secret} leaked: {out}");
            }
            let lines = lines(&capture);
            assert_eq!(lines.len(), 1, "{out}");
            let line = &lines[0];
            assert_eq!(line["level"], "INFO");
            assert_eq!(line["target"], ACCESS_LOG_TARGET);
            let f = &line["fields"];
            assert_eq!(f["message"], "request completed");
            assert_eq!(f["http.request.method"], "GET");
            assert_eq!(f["http.route"], "/users/{id}");
            assert_eq!(f["url.path"], "/users/[EMAIL]");
            assert_eq!(f["url.query"], "email=[EMAIL]&page=2");
            assert_eq!(f["http.response.status_code"], 200);
            assert!(f["duration_ms"].as_f64().is_some_and(|d| d >= 0.0), "{out}");
            assert!(
                f.get("trace_id").is_none(),
                "no span context without a parent"
            );
        }

        #[tokio::test]
        async fn access_log_carries_propagated_trace_id() {
            let (capture, _guard) = json_logs();
            global::set_text_map_propagator(TraceContextPropagator::new());
            let app = app(TraceLayer::new().with_access_log(AccessLog::new()));
            let req = http::Request::builder()
                .uri("/users/1")
                .header(
                    "traceparent",
                    "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
                )
                .body(Body::empty())
                .unwrap();
            assert_eq!(send(app, req).await.status(), StatusCode::OK);
            let lines = lines(&capture);
            assert_eq!(
                lines[0]["fields"]["trace_id"],
                "4bf92f3577b34da6a3ce929d0e0e4736"
            );
        }

        #[tokio::test]
        async fn server_errors_log_at_error_level() {
            let (capture, _guard) = json_logs();
            let app = app(TraceLayer::new().with_access_log(AccessLog::new()));
            assert_eq!(
                send(app, get_req("/boom")).await.status(),
                StatusCode::INTERNAL_SERVER_ERROR
            );
            let lines = lines(&capture);
            assert_eq!(lines[0]["level"], "ERROR");
            assert_eq!(lines[0]["fields"]["http.response.status_code"], 500);
        }

        #[tokio::test]
        async fn query_and_user_agent_can_be_omitted() {
            let (capture, _guard) = json_logs();
            let app = app(TraceLayer::new()
                .with_access_log(AccessLog::new().with_query(false).with_user_agent(false)));
            let req = http::Request::builder()
                .uri("/users/1?q=x")
                .header("user-agent", "curl/8.0")
                .body(Body::empty())
                .unwrap();
            send(app, req).await;
            let lines = lines(&capture);
            let f = &lines[0]["fields"];
            assert!(f.get("url.query").is_none());
            assert!(f.get("user_agent.original").is_none());
        }

        #[tokio::test]
        async fn traces_metrics_and_logs_from_one_layer() {
            let (capture, _guard) = json_logs();
            let registry = Registry::new();
            let app = app(TraceLayer::new()
                .with_registry(&registry)
                .unwrap()
                .with_access_log(AccessLog::new()));
            assert_eq!(
                send(app, get_req("/users/9")).await.status(),
                StatusCode::OK
            );
            assert_eq!(lines(&capture).len(), 1);
            assert!(
                registry
                    .encode(Format::Prometheus)
                    .contains(r#"status="200",route="/users/{id}"} 1"#)
            );
        }

        #[tokio::test]
        async fn no_access_log_without_opt_in() {
            let (capture, _guard) = json_logs();
            send(app(TraceLayer::new()), get_req("/users/1")).await;
            assert_eq!(capture.text(), "");
        }
    }
}
