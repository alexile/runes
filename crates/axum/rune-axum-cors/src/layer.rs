//! The Tower layer and service.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode, header};
use rune_cors::Report;
use tower::{Layer, Service};

use crate::Error;
use crate::config::{Cors, HeaderList, REQUEST_PRIVATE_NETWORK};

/// `Vary` on preflight responses.
const PREFLIGHT_VARY: &str =
    "Origin, Access-Control-Request-Method, Access-Control-Request-Headers";

/// Tower [`Layer`] that answers CORS preflights and adds CORS headers to
/// responses, according to a [`Cors`] policy that passed its audit.
///
/// The layer owns the CORS response headers: `Access-Control-Allow-Origin`,
/// `-Allow-Credentials` and `-Expose-Headers` set by inner services are
/// replaced, or removed when the request origin is not allowed.
///
/// # Examples
///
/// ```rust
/// use axum::{routing::get, Router};
/// use rune_axum_cors::{Cors, CorsLayer};
///
/// let layer = CorsLayer::new(Cors::new().allow_origin("https://app.example.com"))?;
/// let app: Router = Router::new()
///     .route("/", get(|| async { "ok" }))
///     .layer(layer);
/// # Ok::<(), rune_axum_cors::Error>(())
/// ```
#[derive(Clone, Debug)]
pub struct CorsLayer {
    config: Arc<Cors>,
    report: Arc<Report>,
}

impl CorsLayer {
    /// Audits `config` with [`rune_cors`] and builds the layer.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidOrigin`] when a builder input was not a valid
    /// origin, and [`Error::Insecure`] when the audit finds weaknesses at
    /// or above [`Cors::reject_at`] (always for high and critical ones and
    /// for `*` with credentials).
    pub fn new(mut config: Cors) -> Result<Self, Error> {
        if let Some(error) = config.take_error() {
            return Err(error);
        }
        let report = config.audit();
        let weaknesses = config.fatal(&report);
        if !weaknesses.is_empty() {
            return Err(Error::Insecure { weaknesses });
        }
        Ok(Self {
            config: Arc::new(config),
            report: Arc::new(report),
        })
    }

    /// The audit report of the accepted policy: weaknesses below the
    /// rejection threshold, such as `*` without credentials. Map them to
    /// findings with [`Report::to_findings`] to log or export them.
    #[must_use]
    pub fn report(&self) -> &Report {
        &self.report
    }

    /// The policy this layer enforces.
    #[must_use]
    pub fn config(&self) -> &Cors {
        &self.config
    }
}

impl TryFrom<Cors> for CorsLayer {
    type Error = Error;

    fn try_from(config: Cors) -> Result<Self, Self::Error> {
        Self::new(config)
    }
}

impl<S> Layer<S> for CorsLayer {
    type Service = CorsService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        CorsService {
            inner,
            config: Arc::clone(&self.config),
        }
    }
}

/// Tower [`Service`] produced by [`CorsLayer`].
///
/// Preflights (`OPTIONS` with `Origin` and
/// `Access-Control-Request-Method`) are answered directly, with `204 No
/// Content` when allowed and [`Cors::deny_status`] otherwise; they never
/// reach the inner service. Every other request is passed on and the
/// response gets the CORS headers for its origin.
#[derive(Clone, Debug)]
pub struct CorsService<S> {
    inner: S,
    config: Arc<Cors>,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for CorsService<S>
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
        let headers = req.headers();
        let origin = single(headers, &header::ORIGIN).map(str::to_owned);
        let request_method = single(headers, &header::ACCESS_CONTROL_REQUEST_METHOD);

        if let (true, Some(origin), Some(method)) = (
            req.method() == Method::OPTIONS,
            origin.as_deref(),
            request_method,
        ) {
            let request_headers = combined(headers, &header::ACCESS_CONTROL_REQUEST_HEADERS);
            let private_network = single(headers, &REQUEST_PRIVATE_NETWORK) == Some("true");
            let response =
                self.preflight(origin, method, request_headers.as_deref(), private_network);
            return Box::pin(async move { Ok(response) });
        }

        let cors = self.config.actual_headers(origin.as_deref());
        let vary = self.config.varies();
        let fut = self.inner.call(req);
        Box::pin(async move {
            let mut response = fut.await?;
            apply(response.headers_mut(), cors, vary);
            Ok(response)
        })
    }
}

impl<S> CorsService<S> {
    /// Answers a preflight without calling the inner service.
    fn preflight<B: Default>(
        &self,
        origin: &str,
        method: &str,
        request_headers: Option<&str>,
        private_network: bool,
    ) -> Response<B> {
        let mut response = Response::new(B::default());
        let granted =
            self.config
                .preflight_headers(origin, method, request_headers, private_network);
        *response.status_mut() = if granted.is_some() {
            StatusCode::NO_CONTENT
        } else {
            self.config.deny_status_code()
        };
        let headers = response.headers_mut();
        headers.extend(granted.unwrap_or_default());
        headers.insert(header::VARY, HeaderValue::from_static(PREFLIGHT_VARY));
        response
    }
}

/// The value of a header that appears exactly once and is visible ASCII.
fn single<'a>(headers: &'a HeaderMap, name: &header::HeaderName) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    value.to_str().ok()
}

/// All values of a header joined with `,`, as a list header is combined.
fn combined(headers: &HeaderMap, name: &header::HeaderName) -> Option<String> {
    let values: Vec<&str> = headers
        .get_all(name)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    (!values.is_empty()).then(|| values.join(","))
}

/// Replaces the CORS headers of an inner response and adds `Vary: Origin`.
fn apply(headers: &mut HeaderMap, cors: HeaderList, vary: bool) {
    for name in [
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
        header::ACCESS_CONTROL_EXPOSE_HEADERS,
    ] {
        headers.remove(name);
    }
    headers.extend(cors);
    let varies_already = headers
        .get_all(header::VARY)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .any(|v| v == "*" || v.eq_ignore_ascii_case("origin"));
    if vary && !varies_already {
        headers.append(header::VARY, HeaderValue::from_static("Origin"));
    }
}

#[cfg(test)]
#[allow(clippy::assert_is_empty, reason = "emptiness is the expectation")]
mod tests {
    use super::*;

    #[test]
    fn single_rejects_repeats() {
        let mut h = HeaderMap::new();
        assert_eq!(single(&h, &header::ORIGIN), None);
        h.append(
            header::ORIGIN,
            HeaderValue::from_static("https://a.example"),
        );
        assert_eq!(single(&h, &header::ORIGIN), Some("https://a.example"));
        h.append(
            header::ORIGIN,
            HeaderValue::from_static("https://b.example"),
        );
        assert_eq!(single(&h, &header::ORIGIN), None);
    }

    #[test]
    fn apply_keeps_existing_vary() {
        let mut h = HeaderMap::new();
        h.insert(
            header::VARY,
            HeaderValue::from_static("Accept-Encoding, origin"),
        );
        h.insert(
            header::ACCESS_CONTROL_ALLOW_ORIGIN,
            HeaderValue::from_static("*"),
        );
        apply(&mut h, Vec::new(), true);
        assert_eq!(h.get_all(header::VARY).iter().count(), 1);
        assert!(h.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none());

        let mut h = HeaderMap::new();
        h.insert(header::VARY, HeaderValue::from_static("Accept-Encoding"));
        apply(&mut h, Vec::new(), true);
        assert_eq!(h.get_all(header::VARY).iter().count(), 2);
    }
}
