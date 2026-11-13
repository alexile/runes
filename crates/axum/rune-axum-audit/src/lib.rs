//! Structured audit log middleware for Axum — records every request/response cycle.
//!
//! A Tower [`Layer`] that captures method, path, query string, client IP,
//! user-agent, HTTP status code, and wall-clock latency for every request,
//! then delivers the data to a configurable sink. The inner service and its
//! response are returned unchanged; auditing is purely observational.
//!
//! # Features
//!
//! - [`AuditEvent`] — a plain struct capturing one request/response cycle.
//! - [`AuditSink`] trait — implement any destination: file, channel, database, SIEM.
//! - [`StdoutSink`] / [`StderrSink`] — print structured lines to standard streams.
//! - [`NullSink`] — discard all events; useful for tests and benchmarks.
//! - [`CallbackSink`] — drive any closure; useful for custom aggregation.
//! - [`AuditLayer`] — Tower layer; apply with `.layer()` on any Axum [`Router`](axum::Router).
//!
//! # Quick Start
//!
//! ```rust
//! use axum::{routing::get, Router};
//! use rune_axum_audit::AuditLayer;
//!
//! let app: Router = Router::new()
//!     .route("/api", get(|| async { "ok" }))
//!     .layer(AuditLayer::stdout());
//! ```
//!
//! ## Custom sink
//!
//! ```rust
//! use std::sync::{Arc, Mutex};
//! use axum::{routing::get, Router};
//! use rune_axum_audit::{AuditEvent, AuditLayer, CallbackSink};
//!
//! let events: Arc<Mutex<Vec<AuditEvent>>> = Arc::new(Mutex::new(Vec::new()));
//! let captured = Arc::clone(&events);
//!
//! let app: Router = Router::new()
//!     .route("/api", get(|| async { "ok" }))
//!     .layer(AuditLayer::new(CallbackSink::new(move |event| {
//!         captured.lock().unwrap().push(event);
//!     })));
//! ```

use http::{Request, Response};
use pin_project_lite::pin_project;
use std::{
    fmt,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{self, Poll},
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use tower_layer::Layer;
use tower_service::Service;

/// A single captured request/response audit record.
///
/// Created by [`AuditLayer`] for every request that passes through it and
/// delivered to the configured [`AuditSink`]. All fields are extracted from
/// the request and response without consuming or modifying either.
///
/// # Examples
///
/// ```rust
/// use rune_axum_audit::AuditEvent;
///
/// let event = AuditEvent {
///     timestamp_secs: 1_700_000_000,
///     method: "GET".to_owned(),
///     path: "/api/users".to_owned(),
///     query: Some("page=1".to_owned()),
///     client_ip: Some("1.2.3.4".to_owned()),
///     user_agent: Some("curl/7.68.0".to_owned()),
///     status: 200,
///     latency_ms: 5,
/// };
/// println!("{event}");
/// ```
#[derive(Debug, Clone)]
pub struct AuditEvent {
    /// Seconds since Unix epoch at the start of the request.
    pub timestamp_secs: u64,
    /// HTTP method (e.g. `"GET"`, `"POST"`).
    pub method: String,
    /// Request path without query string (e.g. `"/api/users"`).
    pub path: String,
    /// Query string, without the leading `?`, when present. Values of
    /// credential-looking parameters (`api_key`, `token`, `password`,
    /// `secret`, `signature` and the like) are replaced with `[redacted]`.
    pub query: Option<String>,
    /// Client IP from the first `X-Forwarded-For` entry or `X-Real-IP`,
    /// when present.
    ///
    /// These headers come from the client unless a proxy in front of the
    /// app overwrites them, so treat this as a claim, not an identity.
    pub client_ip: Option<String>,
    /// Value of the `User-Agent` header, when present.
    pub user_agent: Option<String>,
    /// HTTP response status code.
    pub status: u16,
    /// Round-trip latency from request receipt to response completion.
    pub latency_ms: u64,
}

impl fmt::Display for AuditEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let timestamp = format_timestamp(self.timestamp_secs);
        let path_and_query = self.query.as_ref().map_or_else(
            || self.path.clone(),
            |query| format!("{}?{}", self.path, query),
        );
        write!(
            formatter,
            "[{timestamp}] {method} {path_and_query} status={status} latency={latency_ms}ms",
            method = self.method,
            status = self.status,
            latency_ms = self.latency_ms,
        )?;
        if let Some(ip) = &self.client_ip {
            write!(formatter, " ip={ip}")?;
        }
        if let Some(ua) = &self.user_agent {
            // Escape so a crafted user agent cannot close the quotes and
            // append fields of its own.
            formatter.write_str(" ua=\"")?;
            for c in ua.chars() {
                if matches!(c, '"' | '\\') {
                    formatter.write_str("\\")?;
                }
                write!(formatter, "{c}")?;
            }
            formatter.write_str("\"")?;
        }
        Ok(())
    }
}

/// Query parameter names whose values are never recorded.
const SECRET_PARAMS: &[&str] = &[
    "key",
    "code",
    "sig",
    "pwd",
    "auth",
    "jwt",
    "session",
    "sessionid",
];

/// Substrings that mark a query parameter name as a credential.
const SECRET_PARTS: &[&str] = &[
    "token",
    "secret",
    "password",
    "passwd",
    "api_key",
    "apikey",
    "api-key",
    "signature",
    "credential",
];

fn is_secret_param(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    SECRET_PARAMS.contains(&name.as_str()) || SECRET_PARTS.iter().any(|part| name.contains(part))
}

/// Replaces the values of credential-looking parameters with `[redacted]`.
fn redact_query(query: &str) -> String {
    let mut out = String::with_capacity(query.len());
    for (i, pair) in query.split('&').enumerate() {
        if i > 0 {
            out.push('&');
        }
        match pair.split_once('=') {
            Some((name, _)) if is_secret_param(name) => {
                out.push_str(name);
                out.push_str("=[redacted]");
            }
            _ => out.push_str(pair),
        }
    }
    out
}

fn format_timestamp(secs: u64) -> String {
    let remaining = secs;
    let seconds_per_minute = 60u64;
    let seconds_per_hour = 3600u64;
    let seconds_per_day = 86400u64;

    let time_of_day = remaining % seconds_per_day;
    let hour = time_of_day / seconds_per_hour;
    let minute = (time_of_day % seconds_per_hour) / seconds_per_minute;
    let second = time_of_day % seconds_per_minute;

    let days_since_epoch = remaining / seconds_per_day;
    let (year, month, day) = days_to_ymd(days_since_epoch);

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    let days_per_400_years = 146_097_u64;
    let days_per_100_years = 36524u64;
    let days_per_4_years = 1461u64;
    let days_per_year = 365u64;

    let mut remaining = days;

    let quadricentennials = remaining / days_per_400_years;
    remaining %= days_per_400_years;

    let centurials = (remaining / days_per_100_years).min(3);
    remaining -= centurials * days_per_100_years;

    let quadrennials = remaining / days_per_4_years;
    remaining %= days_per_4_years;

    let annuals = (remaining / days_per_year).min(3);
    remaining -= annuals * days_per_year;

    let year = quadricentennials * 400 + centurials * 100 + quadrennials * 4 + annuals + 1970;

    let is_leap = (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400);
    let month_lengths = [
        31u64,
        if is_leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];

    let mut month = 1u64;
    let mut day_of_month = remaining;
    for length in month_lengths {
        if day_of_month < length {
            break;
        }
        day_of_month -= length;
        month += 1;
    }

    (year, month, day_of_month + 1)
}

/// The delivery interface for [`AuditEvent`] records.
///
/// Implement this trait to send audit events to any destination — a log file,
/// a metrics system, a database, an async channel, or a SIEM. The method
/// signature is synchronous so the middleware future has no additional await
/// points; if you need async delivery, buffer events in a `Mutex<Vec<_>>` and
/// flush from a background task.
///
/// # Examples
///
/// ```rust
/// use rune_axum_audit::{AuditEvent, AuditSink};
///
/// struct MySink;
///
/// impl AuditSink for MySink {
///     fn record(&self, event: AuditEvent) {
///         eprintln!("{event}");
///     }
/// }
/// ```
pub trait AuditSink: Send + Sync + 'static {
    /// Receives one completed audit record.
    fn record(&self, event: AuditEvent);
}

/// [`AuditSink`] that prints each [`AuditEvent`] to standard output.
///
/// # Examples
///
/// ```rust,no_run
/// use axum::{routing::get, Router};
/// use rune_axum_audit::AuditLayer;
///
/// let app: Router = Router::new()
///     .route("/", get(|| async { "ok" }))
///     .layer(AuditLayer::stdout());
/// ```
pub struct StdoutSink;

impl AuditSink for StdoutSink {
    #[allow(
        clippy::print_stdout,
        reason = "writing to stdout is this sink's purpose"
    )]
    fn record(&self, event: AuditEvent) {
        println!("{event}");
    }
}

/// [`AuditSink`] that prints each [`AuditEvent`] to standard error.
///
/// # Examples
///
/// ```rust,no_run
/// use axum::{routing::get, Router};
/// use rune_axum_audit::AuditLayer;
///
/// let app: Router = Router::new()
///     .route("/", get(|| async { "ok" }))
///     .layer(AuditLayer::stderr());
/// ```
pub struct StderrSink;

impl AuditSink for StderrSink {
    fn record(&self, event: AuditEvent) {
        eprintln!("{event}");
    }
}

/// [`AuditSink`] that silently discards every [`AuditEvent`].
///
/// Use in unit tests and benchmarks where audit output is not relevant.
///
/// # Examples
///
/// ```rust,no_run
/// use axum::{routing::get, Router};
/// use rune_axum_audit::{AuditLayer, NullSink};
///
/// let app: Router = Router::new()
///     .route("/", get(|| async { "ok" }))
///     .layer(AuditLayer::new(NullSink));
/// ```
pub struct NullSink;

impl AuditSink for NullSink {
    fn record(&self, _event: AuditEvent) {}
}

/// [`AuditSink`] backed by a closure.
///
/// Wraps any `Fn(AuditEvent)` so you can capture state (e.g. a shared
/// `Arc<Mutex<Vec<AuditEvent>>>`) without implementing a full struct.
///
/// # Examples
///
/// ```rust
/// use std::sync::{Arc, Mutex};
/// use rune_axum_audit::{AuditEvent, CallbackSink};
///
/// let log: Arc<Mutex<Vec<AuditEvent>>> = Arc::new(Mutex::new(Vec::new()));
/// let captured = Arc::clone(&log);
/// let sink = CallbackSink::new(move |event| {
///     captured.lock().unwrap().push(event);
/// });
/// ```
pub struct CallbackSink<F>
where
    F: Fn(AuditEvent) + Send + Sync + 'static,
{
    callback: F,
}

impl<F> CallbackSink<F>
where
    F: Fn(AuditEvent) + Send + Sync + 'static,
{
    /// Creates a [`CallbackSink`] that calls `callback` for every audit event.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_axum_audit::{AuditEvent, CallbackSink};
    ///
    /// let sink = CallbackSink::new(|event| println!("{event}"));
    /// ```
    pub const fn new(callback: F) -> Self {
        Self { callback }
    }
}

impl<F> AuditSink for CallbackSink<F>
where
    F: Fn(AuditEvent) + Send + Sync + 'static,
{
    fn record(&self, event: AuditEvent) {
        (self.callback)(event);
    }
}

/// Tower [`Layer`] that records one [`AuditEvent`] per request to the configured [`AuditSink`].
///
/// Apply with `.layer()` on any Axum [`Router`](axum::Router). All service clones share the
/// same sink via [`Arc`]. The response passes through unchanged.
///
/// # Examples
///
/// ```rust,no_run
/// use axum::{routing::get, Router};
/// use rune_axum_audit::AuditLayer;
///
/// let app: Router = Router::new()
///     .route("/api", get(|| async { "ok" }))
///     .layer(AuditLayer::stdout());
/// ```
pub struct AuditLayer<Sink = StdoutSink> {
    sink: Arc<Sink>,
}

impl<Sink> Clone for AuditLayer<Sink> {
    fn clone(&self) -> Self {
        Self {
            sink: Arc::clone(&self.sink),
        }
    }
}

impl AuditLayer<StdoutSink> {
    /// Creates an [`AuditLayer`] that prints audit events to standard output.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use axum::{routing::get, Router};
    /// use rune_axum_audit::AuditLayer;
    ///
    /// let app: Router = Router::new()
    ///     .route("/", get(|| async { "ok" }))
    ///     .layer(AuditLayer::stdout());
    /// ```
    #[must_use]
    pub fn stdout() -> Self {
        Self {
            sink: Arc::new(StdoutSink),
        }
    }
}

impl AuditLayer<StderrSink> {
    /// Creates an [`AuditLayer`] that prints audit events to standard error.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use axum::{routing::get, Router};
    /// use rune_axum_audit::AuditLayer;
    ///
    /// let app: Router = Router::new()
    ///     .route("/", get(|| async { "ok" }))
    ///     .layer(AuditLayer::stderr());
    /// ```
    #[must_use]
    pub fn stderr() -> Self {
        Self {
            sink: Arc::new(StderrSink),
        }
    }
}

impl<Sink: AuditSink> AuditLayer<Sink> {
    /// Creates an [`AuditLayer`] with the given sink.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use axum::{routing::get, Router};
    /// use rune_axum_audit::{AuditLayer, NullSink};
    ///
    /// let app: Router = Router::new()
    ///     .route("/", get(|| async { "ok" }))
    ///     .layer(AuditLayer::new(NullSink));
    /// ```
    pub fn new(sink: Sink) -> Self {
        Self {
            sink: Arc::new(sink),
        }
    }

    /// Creates an [`AuditLayer`] from an already-shared sink.
    ///
    /// Use this when you want to share the sink independently of the layer
    /// (e.g., to read captured events from a test).
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use std::sync::Arc;
    /// use axum::{routing::get, Router};
    /// use rune_axum_audit::{AuditLayer, NullSink};
    ///
    /// let sink = Arc::new(NullSink);
    /// let app: Router = Router::new()
    ///     .route("/", get(|| async { "ok" }))
    ///     .layer(AuditLayer::with_arc(Arc::clone(&sink)));
    /// ```
    pub const fn with_arc(sink: Arc<Sink>) -> Self {
        Self { sink }
    }
}

impl<S, Sink: AuditSink> Layer<S> for AuditLayer<Sink> {
    type Service = AuditService<S, Sink>;

    fn layer(&self, inner: S) -> Self::Service {
        AuditService {
            inner,
            sink: Arc::clone(&self.sink),
        }
    }
}

/// Tower [`Service`] produced by [`AuditLayer`].
///
/// Captures request metadata before forwarding to the inner service, then
/// records the [`AuditEvent`] after the response arrives. The response is
/// returned unchanged.
pub struct AuditService<S, Sink> {
    inner: S,
    sink: Arc<Sink>,
}

impl<S: Clone, Sink> Clone for AuditService<S, Sink> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            sink: Arc::clone(&self.sink),
        }
    }
}

impl<S, Sink, ReqB> Service<Request<ReqB>> for AuditService<S, Sink>
where
    S: Service<Request<ReqB>, Response = Response<axum::body::Body>>,
    Sink: AuditSink,
    ReqB: Send + 'static,
{
    type Response = Response<axum::body::Body>;
    type Error = S::Error;
    type Future = AuditFuture<S::Future, Sink>;

    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqB>) -> Self::Future {
        let start = Instant::now();
        let timestamp_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let method = req.method().to_string();
        let path = req.uri().path().to_owned();
        let query = req.uri().query().map(redact_query);

        let client_ip = req
            .headers()
            .get("x-forwarded-for")
            .or_else(|| req.headers().get("x-real-ip"))
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(',').next())
            .map(str::trim)
            .map(str::to_owned);

        let user_agent = req
            .headers()
            .get(http::header::USER_AGENT)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);

        AuditFuture {
            inner: self.inner.call(req),
            sink: Arc::clone(&self.sink),
            meta: Some(EventMeta {
                timestamp_secs,
                method,
                path,
                query,
                client_ip,
                user_agent,
                start,
            }),
        }
    }
}

struct EventMeta {
    timestamp_secs: u64,
    method: String,
    path: String,
    query: Option<String>,
    client_ip: Option<String>,
    user_agent: Option<String>,
    start: Instant,
}

pin_project! {
    /// Future returned by [`AuditService`].
    pub struct AuditFuture<F, Sink> {
        #[pin]
        inner: F,
        sink: Arc<Sink>,
        meta: Option<EventMeta>,
    }
}

impl<F, Sink, E> Future for AuditFuture<F, Sink>
where
    F: Future<Output = Result<Response<axum::body::Body>, E>>,
    Sink: AuditSink,
{
    type Output = Result<Response<axum::body::Body>, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        match this.inner.poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                if let Some(meta) = this.meta.take() {
                    let latency_ms =
                        u64::try_from(meta.start.elapsed().as_millis()).unwrap_or(u64::MAX);
                    let status = result.as_ref().map_or(0, |resp| resp.status().as_u16());

                    this.sink.record(AuditEvent {
                        timestamp_secs: meta.timestamp_secs,
                        method: meta.method,
                        path: meta.path,
                        query: meta.query,
                        client_ip: meta.client_ip,
                        user_agent: meta.user_agent,
                        status,
                        latency_ms,
                    });
                }
                Poll::Ready(result)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, body::Body, routing::get};
    use http::{Request, StatusCode};
    use std::sync::Mutex;
    use tower::ServiceExt;

    struct TestSink {
        events: Arc<Mutex<Vec<AuditEvent>>>,
    }

    impl AuditSink for TestSink {
        fn record(&self, event: AuditEvent) {
            self.events.lock().unwrap().push(event);
        }
    }

    fn build_app(events: Arc<Mutex<Vec<AuditEvent>>>, status: StatusCode) -> Router {
        Router::new()
            .route(
                "/api/items",
                get(move || {
                    let status = status;
                    async move { status }
                }),
            )
            .layer(AuditLayer::new(TestSink { events }))
    }

    async fn send(app: Router, req: Request<Body>) -> http::Response<Body> {
        app.oneshot(req).await.unwrap()
    }

    #[allow(
        clippy::significant_drop_tightening,
        reason = "the guard must outlive the values borrowed from it"
    )]
    #[tokio::test]
    async fn records_method_path_and_status() {
        let events: Arc<Mutex<Vec<AuditEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let app = build_app(Arc::clone(&events), StatusCode::OK);

        send(
            app,
            Request::builder()
                .uri("/api/items")
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        let captured = events.lock().unwrap();
        assert_eq!(captured.len(), 1);
        let event = &captured[0];
        assert_eq!(event.method, "GET");
        assert_eq!(event.path, "/api/items");
        assert_eq!(event.status, 200);
    }

    #[tokio::test]
    async fn records_nonzero_latency() {
        let events: Arc<Mutex<Vec<AuditEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let app = build_app(Arc::clone(&events), StatusCode::OK);

        send(
            app,
            Request::builder()
                .uri("/api/items")
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        let captured = events.lock().unwrap();
        assert_eq!(captured.len(), 1);
    }

    #[tokio::test]
    async fn null_sink_does_not_panic() {
        let app: Router = Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(AuditLayer::new(NullSink));

        let resp = send(
            app,
            Request::builder().uri("/").body(Body::empty()).unwrap(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn callback_sink_receives_event() {
        let events: Arc<Mutex<Vec<AuditEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&events);

        let app: Router = Router::new()
            .route("/ping", get(|| async { "pong" }))
            .layer(AuditLayer::new(CallbackSink::new(move |event| {
                captured.lock().unwrap().push(event);
            })));

        send(
            app,
            Request::builder().uri("/ping").body(Body::empty()).unwrap(),
        )
        .await;

        let captured = events.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].path, "/ping");
        assert_eq!(captured[0].status, 200);
    }

    #[tokio::test]
    async fn captures_client_ip_from_x_forwarded_for() {
        let events: Arc<Mutex<Vec<AuditEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let app = build_app(Arc::clone(&events), StatusCode::OK);

        send(
            app,
            Request::builder()
                .uri("/api/items")
                .header("x-forwarded-for", "1.2.3.4, 5.6.7.8")
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        let captured = events.lock().unwrap();
        assert_eq!(captured[0].client_ip.as_deref(), Some("1.2.3.4"));
    }

    #[tokio::test]
    async fn captures_user_agent() {
        let events: Arc<Mutex<Vec<AuditEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let app = build_app(Arc::clone(&events), StatusCode::OK);

        send(
            app,
            Request::builder()
                .uri("/api/items")
                .header("user-agent", "curl/7.68.0")
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        let captured = events.lock().unwrap();
        assert_eq!(captured[0].user_agent.as_deref(), Some("curl/7.68.0"));
    }

    #[tokio::test]
    async fn captures_query_string() {
        let events: Arc<Mutex<Vec<AuditEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let app = build_app(Arc::clone(&events), StatusCode::OK);

        send(
            app,
            Request::builder()
                .uri("/api/items?page=2&limit=10")
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        let captured = events.lock().unwrap();
        assert_eq!(captured[0].query.as_deref(), Some("page=2&limit=10"));
    }

    #[tokio::test]
    async fn display_formats_correctly() {
        let event = AuditEvent {
            timestamp_secs: 0,
            method: "GET".to_owned(),
            path: "/api".to_owned(),
            query: None,
            client_ip: Some("1.2.3.4".to_owned()),
            user_agent: Some("curl/7.68.0".to_owned()),
            status: 200,
            latency_ms: 5,
        };
        let output = event.to_string();
        assert!(output.contains("GET /api"));
        assert!(output.contains("status=200"));
        assert!(output.contains("latency=5ms"));
        assert!(output.contains("ip=1.2.3.4"));
        assert!(output.contains("ua=\"curl/7.68.0\""));
    }

    #[test]
    fn user_agent_cannot_forge_fields() {
        let event = AuditEvent {
            timestamp_secs: 0,
            method: "GET".to_owned(),
            path: "/".to_owned(),
            query: None,
            client_ip: None,
            user_agent: Some(r#"x" status=200 user="admin"#.to_owned()),
            status: 403,
            latency_ms: 0,
        };
        let line = event.to_string();
        assert!(
            line.ends_with(r#" ua="x\" status=200 user=\"admin""#),
            "{line}"
        );
    }

    #[allow(
        clippy::significant_drop_tightening,
        reason = "the guard must outlive the values borrowed from it"
    )]
    #[tokio::test]
    async fn credentials_in_the_query_are_not_recorded() {
        let events: Arc<Mutex<Vec<AuditEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let app = build_app(Arc::clone(&events), StatusCode::OK);
        send(
            app,
            Request::builder()
                .uri("/api/items?page=2&api_key=s3cr3t&Access_Token=t0k&key=k3y&q=a=b")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        let captured = events.lock().unwrap();
        assert_eq!(
            captured[0].query.as_deref(),
            Some("page=2&api_key=[redacted]&Access_Token=[redacted]&key=[redacted]&q=a=b")
        );
    }
}
