use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use http::header::{HeaderMap, HeaderName};
use http::{Request, Response};
use tower_layer::Layer;
use tower_service::Service;

use crate::id::{DEFAULT_MAX_ID_LEN, RequestId};
use crate::traceparent::{FLAG_SAMPLED, TraceParent};

/// The default request id header, `x-request-id`.
pub const X_REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

/// The W3C `traceparent` header.
pub const TRACEPARENT: HeaderName = HeaderName::from_static("traceparent");

/// The W3C `tracestate` header.
pub const TRACESTATE: HeaderName = HeaderName::from_static("tracestate");

type Generator = Arc<dyn Fn() -> RequestId + Send + Sync>;

/// Configuration for [`RequestIdLayer`].
///
/// Start from [`RequestIdConfig::default()`] and adjust with the `with_*`
/// builder methods.
///
/// | Setting | Default |
/// |---------|---------|
/// | header | `x-request-id` |
/// | trust incoming ids | yes |
/// | max id length | 128 bytes |
/// | `traceparent` propagation | on |
/// | sample new traces | yes |
/// | trace id as request id | no |
/// | response header | on |
/// | generator | random UUID v4 |
///
/// # Examples
///
/// ```
/// use http::HeaderName;
/// use rune_axum_requestid::{RequestId, RequestIdConfig};
///
/// let config = RequestIdConfig::default()
///     .with_header(HeaderName::from_static("x-correlation-id"))
///     .with_trust_incoming(false)
///     .with_generator(|| RequestId::new("fixed").unwrap_or_else(|_| RequestId::random()));
/// ```
#[derive(Clone)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent on/off switches, each set by its own builder method"
)]
pub struct RequestIdConfig {
    header: HeaderName,
    trust_incoming: bool,
    max_len: usize,
    traceparent: bool,
    sample_new_traces: bool,
    trace_id_as_request_id: bool,
    response_header: bool,
    generator: Generator,
}

impl Default for RequestIdConfig {
    fn default() -> Self {
        Self {
            header: X_REQUEST_ID,
            trust_incoming: true,
            max_len: DEFAULT_MAX_ID_LEN,
            traceparent: true,
            sample_new_traces: true,
            trace_id_as_request_id: false,
            response_header: true,
            generator: Arc::new(RequestId::random),
        }
    }
}

impl fmt::Debug for RequestIdConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestIdConfig")
            .field("header", &self.header)
            .field("trust_incoming", &self.trust_incoming)
            .field("max_len", &self.max_len)
            .field("traceparent", &self.traceparent)
            .field("sample_new_traces", &self.sample_new_traces)
            .field("trace_id_as_request_id", &self.trace_id_as_request_id)
            .field("response_header", &self.response_header)
            .finish_non_exhaustive()
    }
}

impl RequestIdConfig {
    /// Sets the header that carries the request id, in both directions.
    #[must_use]
    pub fn with_header(mut self, header: HeaderName) -> Self {
        self.header = header;
        self
    }

    /// Whether a valid incoming request id is propagated (`true`) or always
    /// replaced by a generated one (`false`).
    ///
    /// Turn this off on an edge service that faces untrusted clients and
    /// should mint its own ids.
    #[must_use]
    pub const fn with_trust_incoming(mut self, trust: bool) -> Self {
        self.trust_incoming = trust;
        self
    }

    /// Sets the maximum accepted length of an incoming id, in bytes.
    /// Longer ids are replaced by a generated one.
    #[must_use]
    pub const fn with_max_len(mut self, max_len: usize) -> Self {
        self.max_len = max_len;
        self
    }

    /// Whether W3C `traceparent` is read, continued and forwarded.
    ///
    /// When on, every request gets a [`TraceContext`] extension and its
    /// `traceparent` header is rewritten to this server's span.
    #[must_use]
    pub const fn with_traceparent(mut self, enabled: bool) -> Self {
        self.traceparent = enabled;
        self
    }

    /// Whether a trace started here (no valid incoming `traceparent`) has
    /// the sampled flag set.
    #[must_use]
    pub const fn with_sample_new_traces(mut self, sampled: bool) -> Self {
        self.sample_new_traces = sampled;
        self
    }

    /// When no usable request id arrives, use the trace id (32 hex digits)
    /// as the request id instead of calling the generator, so logs and
    /// traces share one key. Needs `traceparent` propagation on.
    #[must_use]
    pub const fn with_trace_id_as_request_id(mut self, enabled: bool) -> Self {
        self.trace_id_as_request_id = enabled;
        self
    }

    /// Whether the request id is echoed in the response header (unless the
    /// handler already set that header).
    #[must_use]
    pub const fn with_response_header(mut self, enabled: bool) -> Self {
        self.response_header = enabled;
        self
    }

    /// Sets the function that generates a request id when none is usable.
    #[must_use]
    pub fn with_generator<F>(mut self, generator: F) -> Self
    where
        F: Fn() -> RequestId + Send + Sync + 'static,
    {
        self.generator = Arc::new(generator);
        self
    }

    /// The configured request id header.
    #[must_use]
    pub const fn header(&self) -> &HeaderName {
        &self.header
    }

    /// Decides the request id and trace context for a request with
    /// `headers`, without touching it. This is the sans-I/O core of the
    /// middleware.
    ///
    /// # Examples
    ///
    /// ```
    /// use http::HeaderMap;
    /// use rune_axum_requestid::RequestIdConfig;
    ///
    /// let mut headers = HeaderMap::new();
    /// headers.insert("x-request-id", "abc".parse().unwrap());
    /// headers.insert(
    ///     "traceparent",
    ///     "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".parse().unwrap(),
    /// );
    ///
    /// let resolved = RequestIdConfig::default().resolve(&headers);
    /// assert_eq!(resolved.request_id.as_str(), "abc");
    /// assert!(!resolved.generated);
    /// let trace = resolved.trace.unwrap();
    /// assert_eq!(trace.trace_id_hex(), "4bf92f3577b34da6a3ce929d0e0e4736");
    /// assert_eq!(trace.incoming().unwrap().parent_id_hex(), "00f067aa0ba902b7");
    /// ```
    #[must_use]
    pub fn resolve(&self, headers: &HeaderMap) -> Resolved {
        let trace = self.traceparent.then(|| {
            let incoming = single(headers, &TRACEPARENT)
                .and_then(|v| TraceParent::parse_bytes(v.as_bytes()).ok());
            let current = incoming.map_or_else(
                || {
                    let flags = if self.sample_new_traces {
                        FLAG_SAMPLED
                    } else {
                        0
                    };
                    TraceParent::random(flags)
                },
                |tp| tp.random_child(),
            );
            TraceContext { incoming, current }
        });

        let incoming_id = if self.trust_incoming {
            headers
                .get(&self.header)
                .and_then(|v| RequestId::with_max_len(v.as_bytes(), self.max_len).ok())
        } else {
            None
        };
        let generated = incoming_id.is_none();
        let request_id = incoming_id.unwrap_or_else(|| match &trace {
            Some(ctx) if self.trace_id_as_request_id => {
                RequestId::new(ctx.trace_id_hex()).unwrap_or_else(|_| (self.generator)())
            }
            _ => (self.generator)(),
        });

        Resolved {
            request_id,
            generated,
            trace,
        }
    }

    /// Resolves `req` and applies the result to it: rewrites the request id
    /// and `traceparent` headers (dropping `tracestate` when a new trace is
    /// started) and inserts [`RequestId`] and [`TraceContext`] into the
    /// request extensions.
    pub fn apply<B>(&self, req: &mut Request<B>) -> Resolved {
        let resolved = self.resolve(req.headers());
        let headers = req.headers_mut();
        headers.insert(
            self.header.clone(),
            resolved.request_id.header_value().clone(),
        );
        if let Some(ctx) = &resolved.trace {
            headers.insert(TRACEPARENT, ctx.current.to_header_value());
            if ctx.incoming.is_none() {
                headers.remove(TRACESTATE);
            }
            req.extensions_mut().insert(*ctx);
        }
        req.extensions_mut().insert(resolved.request_id.clone());
        resolved
    }
}

/// The value of `name` if it occurs exactly once.
fn single<'a>(headers: &'a HeaderMap, name: &HeaderName) -> Option<&'a http::HeaderValue> {
    let mut values = headers.get_all(name).iter();
    let first = values.next()?;
    values.next().is_none().then_some(first)
}

/// The outcome of [`RequestIdConfig::resolve`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Resolved {
    /// The request id to use for this request.
    pub request_id: RequestId,
    /// `true` when the id was generated here rather than propagated.
    pub generated: bool,
    /// The trace context, when `traceparent` propagation is on.
    pub trace: Option<TraceContext>,
}

/// W3C trace context of one request, as stored in the request extensions.
///
/// `current` is this server's span: the incoming trace id (or a new one)
/// with a fresh span id. Forward [`TraceContext::traceparent`] on outgoing
/// calls so downstream services join the same trace.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TraceContext {
    incoming: Option<TraceParent>,
    current: TraceParent,
}

impl TraceContext {
    /// The valid `traceparent` the client sent, if any.
    #[must_use]
    pub const fn incoming(&self) -> Option<TraceParent> {
        self.incoming
    }

    /// This server's span, to send downstream as `traceparent`.
    #[must_use]
    pub const fn traceparent(&self) -> TraceParent {
        self.current
    }

    /// The trace id as 32 lowercase hex digits.
    #[must_use]
    pub fn trace_id_hex(&self) -> String {
        self.current.trace_id_hex()
    }

    /// This server's span id as 16 lowercase hex digits.
    #[must_use]
    pub fn span_id_hex(&self) -> String {
        self.current.parent_id_hex()
    }

    /// Whether this request continues a trace started upstream.
    #[must_use]
    pub const fn is_continued(&self) -> bool {
        self.incoming.is_some()
    }
}

/// Tower [`Layer`] that assigns every request an id and a W3C trace context.
///
/// For each request it:
///
/// 1. propagates a valid incoming request id, or generates one;
/// 2. continues a valid incoming `traceparent` with a new span id, or starts
///    a new trace;
/// 3. rewrites the request headers and inserts [`RequestId`] and
///    [`TraceContext`] into the request extensions;
/// 4. with the `tracing` feature, runs the inner service inside a `request`
///    span carrying `request_id`, `trace_id`, `span_id` and
///    `parent_span_id`;
/// 5. echoes the id in the response header and response extensions.
///
/// # Examples
///
/// ```
/// use axum::{routing::get, Router};
/// use rune_axum_requestid::{RequestId, RequestIdLayer};
///
/// let app: Router = Router::new()
///     .route("/", get(|id: RequestId| async move { id.to_string() }))
///     .layer(RequestIdLayer::default());
/// ```
#[derive(Clone, Debug, Default)]
pub struct RequestIdLayer {
    config: RequestIdConfig,
}

impl RequestIdLayer {
    /// Creates a layer from a custom [`RequestIdConfig`].
    #[must_use]
    pub const fn new(config: RequestIdConfig) -> Self {
        Self { config }
    }
}

impl<S> Layer<S> for RequestIdLayer {
    type Service = RequestIdService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RequestIdService {
            inner,
            config: self.config.clone(),
        }
    }
}

/// Tower [`Service`] produced by [`RequestIdLayer`].
#[derive(Clone, Debug)]
pub struct RequestIdService<S> {
    inner: S,
    config: RequestIdConfig,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for RequestIdService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    ResBody: Send + 'static,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        let resolved = self.config.apply(&mut req);

        #[cfg(feature = "tracing")]
        let span = make_span(&req, &resolved);
        #[cfg(feature = "tracing")]
        let fut = span.in_scope(|| self.inner.call(req));
        #[cfg(not(feature = "tracing"))]
        let fut = self.inner.call(req);

        let header = self
            .config
            .response_header
            .then(|| self.config.header.clone());
        let id = resolved.request_id;
        let fut = async move {
            let mut res = fut.await?;
            if let Some(header) = header
                && !res.headers().contains_key(&header)
            {
                res.headers_mut().insert(header, id.header_value().clone());
            }
            res.extensions_mut().insert(id);
            Ok(res)
        };

        #[cfg(feature = "tracing")]
        let fut = tracing::Instrument::instrument(fut, span);
        Box::pin(fut)
    }
}

#[cfg(feature = "tracing")]
fn make_span<B>(req: &Request<B>, resolved: &Resolved) -> tracing::Span {
    use tracing::field::{Empty, display};

    let span = tracing::info_span!(
        "request",
        request_id = %resolved.request_id,
        method = %req.method(),
        path = req.uri().path(),
        trace_id = Empty,
        span_id = Empty,
        parent_span_id = Empty,
    );
    if let Some(ctx) = &resolved.trace {
        span.record("trace_id", display(ctx.trace_id_hex()));
        span.record("span_id", display(ctx.span_id_hex()));
        if let Some(incoming) = ctx.incoming {
            span.record("parent_span_id", display(incoming.parent_id_hex()));
        }
    }
    span
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (k, v) in pairs {
            map.append(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        map
    }

    #[test]
    fn propagates_valid_incoming_id() {
        let r = RequestIdConfig::default().resolve(&headers(&[("x-request-id", "abc")]));
        assert_eq!(r.request_id.as_str(), "abc");
        assert!(!r.generated);
    }

    #[test]
    fn generates_when_absent_invalid_or_untrusted() {
        let config = RequestIdConfig::default();
        let r = config.resolve(&HeaderMap::new());
        assert!(r.generated);
        assert_eq!(r.request_id.as_str().len(), 36);

        let long = "a".repeat(DEFAULT_MAX_ID_LEN + 1);
        let r = config.resolve(&headers(&[("x-request-id", &long)]));
        assert!(r.generated);

        let r = config.resolve(&headers(&[("x-request-id", "a b")]));
        assert!(r.generated);

        let r = config
            .with_trust_incoming(false)
            .resolve(&headers(&[("x-request-id", "abc")]));
        assert!(r.generated);
        assert_ne!(r.request_id.as_str(), "abc");
    }

    #[test]
    fn custom_header_and_generator() {
        let config = RequestIdConfig::default()
            .with_header(HeaderName::from_static("x-correlation-id"))
            .with_generator(|| RequestId::new("gen").unwrap());
        let r = config.resolve(&headers(&[("x-request-id", "ignored")]));
        assert_eq!(r.request_id.as_str(), "gen");
        let r = config.resolve(&headers(&[("x-correlation-id", "kept")]));
        assert_eq!(r.request_id.as_str(), "kept");
    }

    #[test]
    fn max_len_is_configurable() {
        let config = RequestIdConfig::default().with_max_len(3);
        assert!(
            !config
                .resolve(&headers(&[("x-request-id", "abc")]))
                .generated
        );
        assert!(
            config
                .resolve(&headers(&[("x-request-id", "abcd")]))
                .generated
        );
    }

    #[test]
    fn continues_incoming_trace() {
        let r = RequestIdConfig::default().resolve(&headers(&[("traceparent", SPEC)]));
        let ctx = r.trace.unwrap();
        assert!(ctx.is_continued());
        assert_eq!(ctx.trace_id_hex(), "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_ne!(ctx.span_id_hex(), "00f067aa0ba902b7");
        assert!(ctx.traceparent().sampled());
    }

    #[test]
    fn starts_new_trace_when_absent_invalid_or_duplicated() {
        let config = RequestIdConfig::default();
        for h in [
            headers(&[]),
            headers(&[("traceparent", "garbage")]),
            headers(&[("traceparent", SPEC), ("traceparent", SPEC)]),
        ] {
            let ctx = config.resolve(&h).trace.unwrap();
            assert!(!ctx.is_continued());
            assert_ne!(ctx.trace_id_hex(), "4bf92f3577b34da6a3ce929d0e0e4736");
            assert!(ctx.traceparent().sampled());
        }
        let ctx = config
            .with_sample_new_traces(false)
            .resolve(&HeaderMap::new())
            .trace
            .unwrap();
        assert!(!ctx.traceparent().sampled());
    }

    #[test]
    fn traceparent_can_be_disabled() {
        let r = RequestIdConfig::default()
            .with_traceparent(false)
            .resolve(&headers(&[("traceparent", SPEC)]));
        assert!(r.trace.is_none());
    }

    #[test]
    fn trace_id_as_request_id() {
        let config = RequestIdConfig::default().with_trace_id_as_request_id(true);
        let r = config.resolve(&headers(&[("traceparent", SPEC)]));
        assert_eq!(r.request_id.as_str(), "4bf92f3577b34da6a3ce929d0e0e4736");
        assert!(r.generated);
        let r = config.resolve(&headers(&[("traceparent", SPEC), ("x-request-id", "abc")]));
        assert_eq!(r.request_id.as_str(), "abc");
    }

    #[test]
    fn apply_rewrites_headers_and_extensions() {
        let config = RequestIdConfig::default();
        let mut req = Request::builder()
            .header("tracestate", "vendor=1")
            .body(())
            .unwrap();
        let r = config.apply(&mut req);
        assert_eq!(req.headers()["x-request-id"], r.request_id.as_str());
        let ctx = req.extensions().get::<TraceContext>().copied().unwrap();
        assert_eq!(
            req.headers()["traceparent"],
            ctx.traceparent().to_string().as_str()
        );
        assert!(
            req.headers().get("tracestate").is_none(),
            "new trace drops tracestate"
        );
        assert_eq!(req.extensions().get::<RequestId>(), Some(&r.request_id));

        let mut req = Request::builder()
            .header("traceparent", SPEC)
            .header("tracestate", "vendor=1")
            .body(())
            .unwrap();
        config.apply(&mut req);
        assert_eq!(req.headers()["tracestate"], "vendor=1");
    }

    #[test]
    fn debug_omits_generator() {
        let s = format!("{:?}", RequestIdConfig::default());
        assert!(s.contains("x-request-id"));
    }
}
