//! Redacted per-request access log events.

use std::time::Instant;

use opentelemetry::trace::SpanContext;
use rune_log::Redactor;

/// `tracing` target of the access log events emitted by
/// [`TraceLayer`](crate::TraceLayer).
///
/// Filter on it like any other target, for example
/// `LogConfig::default().with_filter("info,rune_axum_trace::access=warn")`.
pub const ACCESS_LOG_TARGET: &str = "rune_axum_trace::access";

/// Configuration of the access log that [`TraceLayer`](crate::TraceLayer)
/// emits when built with [`with_access_log`](crate::TraceLayer::with_access_log).
///
/// One `tracing` event is emitted per request, when the response headers are
/// ready, at target [`ACCESS_LOG_TARGET`]:
///
/// | Field                       | Value                                         |
/// | --------------------------- | --------------------------------------------- |
/// | `http.request.method`       | request method                                |
/// | `http.route`                | route template (`MatchedPath`), if known      |
/// | `url.path`                  | request path, **redacted**                    |
/// | `url.query`                 | query string, **redacted** (optional)         |
/// | `user_agent.original`       | `User-Agent`, **redacted** (optional)         |
/// | `http.response.status_code` | response status; absent if the handler failed |
/// | `duration_ms`               | time until response headers, in milliseconds  |
/// | `trace_id`, `span_id`       | ids of the request's OpenTelemetry span       |
///
/// Successful and client-error responses are logged at `INFO`; `5xx`
/// responses and handler errors at `ERROR`.
///
/// Values that come from the client are passed through the [`Redactor`]
/// *before* the event is emitted, so secrets and PII in paths, query strings
/// and user agents are masked whatever subscriber is installed. Installing a
/// [`rune_log::LogConfig`] subscriber adds a second, field-level redaction pass
/// and the text / JSON output formats.
///
/// Request and response headers other than `User-Agent`, and bodies, are
/// never logged.
///
/// # Examples
///
/// ```rust
/// use rune_axum_trace::{AccessLog, TraceLayer};
///
/// let layer = TraceLayer::new().with_access_log(AccessLog::new().with_query(false));
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct AccessLog {
    redactor: Redactor,
    query: bool,
    user_agent: bool,
}

impl Default for AccessLog {
    fn default() -> Self {
        Self {
            redactor: Redactor::default(),
            query: true,
            user_agent: true,
        }
    }
}

impl AccessLog {
    /// Access log with the default [`Redactor`] (credentials, tokens and
    /// common PII), logging the query string and user agent.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the redactor applied to path, query and user agent.
    ///
    /// Reuse the redactor of your [`rune_log::LogConfig`] to apply one
    /// policy everywhere.
    #[must_use]
    pub fn with_redactor(mut self, redactor: Redactor) -> Self {
        self.redactor = redactor;
        self
    }

    /// Logs (`true`, the default) or omits the redacted query string.
    #[must_use]
    pub const fn with_query(mut self, on: bool) -> Self {
        self.query = on;
        self
    }

    /// Logs (`true`, the default) or omits the redacted `User-Agent`.
    #[must_use]
    pub const fn with_user_agent(mut self, on: bool) -> Self {
        self.user_agent = on;
        self
    }

    /// The redactor applied to client-supplied values.
    #[must_use]
    pub const fn redactor(&self) -> &Redactor {
        &self.redactor
    }

    /// Captures what the event needs from the request. Redaction is deferred
    /// to `PendingLog::emit`, off the request path.
    pub(crate) fn start(
        &self,
        method: &str,
        route: Option<&str>,
        path: &str,
        query: Option<&str>,
        user_agent: Option<&str>,
    ) -> PendingLog {
        PendingLog {
            redactor: self.redactor.clone(),
            method: method.to_owned(),
            route: route.map(str::to_owned),
            path: path.to_owned(),
            query: query.filter(|_| self.query).map(str::to_owned),
            user_agent: user_agent.filter(|_| self.user_agent).map(str::to_owned),
            ids: None,
            start: Instant::now(),
        }
    }
}

/// An access log event waiting for the response.
pub struct PendingLog {
    redactor: Redactor,
    method: String,
    route: Option<String>,
    path: String,
    query: Option<String>,
    user_agent: Option<String>,
    ids: Option<(String, String)>,
    start: Instant,
}

impl PendingLog {
    /// Records the ids of the request's span, if it has a valid context
    /// (a real tracer, or a noop tracer continuing a propagated trace).
    pub fn with_ids(mut self, cx: &SpanContext) -> Self {
        if cx.is_valid() {
            self.ids = Some((cx.trace_id().to_string(), cx.span_id().to_string()));
        }
        self
    }

    /// Emits the event. `status` is `None` when the inner service failed.
    pub fn emit(self, status: Option<u16>) {
        // Rounded to microseconds: a full-precision float is a long digit
        // run that number-based redaction (card numbers, phones) could mask.
        let duration_ms = (self.start.elapsed().as_secs_f64() * 1_000_000.0).round() / 1000.0;
        let path = self.redactor.redact(&self.path);
        let query = self.query.as_deref().map(|q| self.redactor.redact(q));
        let user_agent = self.user_agent.as_deref().map(|u| self.redactor.redact(u));
        let (trace_id, span_id) = match &self.ids {
            Some((t, s)) => (Some(t.as_str()), Some(s.as_str())),
            None => (None, None),
        };

        macro_rules! event {
            ($level:expr, $message:literal) => {
                tracing::event!(
                    target: ACCESS_LOG_TARGET,
                    $level,
                    http.request.method = self.method.as_str(),
                    http.route = self.route.as_deref(),
                    url.path = path.as_str(),
                    url.query = query.as_deref(),
                    user_agent.original = user_agent.as_deref(),
                    http.response.status_code = status,
                    duration_ms,
                    trace_id,
                    span_id,
                    $message
                )
            };
        }

        match status {
            Some(code) if code < 500 => event!(tracing::Level::INFO, "request completed"),
            Some(_) => event!(tracing::Level::ERROR, "request completed"),
            None => event!(tracing::Level::ERROR, "request failed"),
        }
    }
}
