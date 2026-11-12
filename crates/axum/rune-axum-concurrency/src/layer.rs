use http::header::RETRY_AFTER;
use http::{HeaderValue, Request, Response, StatusCode};
use pin_project_lite::pin_project;
use std::fmt;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::Duration;
use tower::{Layer, Service};

use crate::limiter::{Limiter, Metrics, Permit};

/// Default maximum number of in-flight requests.
const DEFAULT_MAX_IN_FLIGHT: usize = 1024;

/// Configuration for the concurrency limit middleware.
///
/// Build with [`ConcurrencyLimit::new()`] and chain methods, then pass it to
/// [`ConcurrencyLimitLayer::new()`].
///
/// # Examples
///
/// ```rust
/// use std::time::Duration;
/// use http::StatusCode;
/// use rune_axum_concurrency::ConcurrencyLimit;
///
/// let config = ConcurrencyLimit::new()
///     .max_in_flight(64)
///     .status(StatusCode::TOO_MANY_REQUESTS)
///     .retry_after(Duration::from_secs(2));
///
/// assert_eq!(config.max_in_flight_value(), 64);
/// assert_eq!(config.status_code(), StatusCode::TOO_MANY_REQUESTS);
/// ```
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ConcurrencyLimit {
    max_in_flight: usize,
    status: StatusCode,
    retry_after: Option<HeaderValue>,
}

impl Default for ConcurrencyLimit {
    fn default() -> Self {
        Self {
            max_in_flight: DEFAULT_MAX_IN_FLIGHT,
            status: StatusCode::SERVICE_UNAVAILABLE,
            retry_after: None,
        }
    }
}

impl ConcurrencyLimit {
    /// Creates a `ConcurrencyLimit` with defaults: 1024 in-flight requests,
    /// `503 Service Unavailable`, no `Retry-After` header.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the maximum number of requests processed at once. Requests
    /// beyond it are shed immediately. Zero sheds every request.
    ///
    /// Defaults to 1024.
    #[must_use]
    pub const fn max_in_flight(mut self, max: usize) -> Self {
        self.max_in_flight = max;
        self
    }

    /// Sets the HTTP status code of a shed response.
    ///
    /// Defaults to `503 Service Unavailable`.
    #[must_use]
    pub const fn status(mut self, status: StatusCode) -> Self {
        self.status = status;
        self
    }

    /// Adds a `Retry-After` header to shed responses, in whole seconds
    /// (rounded up).
    ///
    /// Not sent by default.
    #[must_use]
    pub fn retry_after(mut self, after: Duration) -> Self {
        let secs = after
            .as_secs()
            .saturating_add(u64::from(after.subsec_nanos() > 0));
        self.retry_after = Some(HeaderValue::from(secs));
        self
    }

    /// Returns the configured maximum number of in-flight requests.
    #[must_use]
    pub const fn max_in_flight_value(&self) -> usize {
        self.max_in_flight
    }

    /// Returns the status code of a shed response.
    #[must_use]
    pub const fn status_code(&self) -> StatusCode {
        self.status
    }

    /// Returns the `Retry-After` header value sent with shed responses, if
    /// any.
    #[must_use]
    pub const fn retry_after_value(&self) -> Option<&HeaderValue> {
        self.retry_after.as_ref()
    }
}

/// Tower [`Layer`] that bounds the number of in-flight requests and sheds
/// the rest with an error response (default: `503 Service Unavailable`).
///
/// Unlike `tower::limit::ConcurrencyLimit`, an over-limit request does not
/// wait for a slot: it is answered at once, without reaching the inner
/// service. This keeps latency bounded under overload instead of building
/// an unbounded queue.
///
/// The layer owns one [`Limiter`]. Every service it produces, and every
/// clone of the layer, shares that budget; build separate layers for
/// independent budgets (for example one per route with
/// `MethodRouter::layer`). Read the counters with
/// [`metrics`](Self::metrics).
///
/// A slot is held until the inner service's response future completes,
/// that is, until response headers are ready. Streaming the response body
/// afterwards does not hold a slot.
///
/// # Examples
///
/// ```rust
/// use axum::{routing::get, Router};
/// use rune_axum_concurrency::{ConcurrencyLimit, ConcurrencyLimitLayer};
///
/// let limit = ConcurrencyLimitLayer::new(ConcurrencyLimit::new().max_in_flight(256));
/// let metrics = limit.limiter().clone(); // export from a /metrics handler
///
/// let app: Router = Router::new()
///     .route("/", get(|| async { "ok" }))
///     .layer(limit);
///
/// assert_eq!(metrics.metrics().in_flight, 0);
/// ```
#[derive(Clone, Debug)]
pub struct ConcurrencyLimitLayer {
    config: ConcurrencyLimit,
    limiter: Limiter,
}

impl Default for ConcurrencyLimitLayer {
    fn default() -> Self {
        Self::new(ConcurrencyLimit::default())
    }
}

impl ConcurrencyLimitLayer {
    /// Creates a layer with a fresh [`Limiter`] sized from `config`.
    #[must_use]
    pub fn new(config: ConcurrencyLimit) -> Self {
        let limiter = Limiter::new(config.max_in_flight);
        Self { config, limiter }
    }

    /// Returns the shared [`Limiter`], for reading metrics or sharing the
    /// budget with non-HTTP work.
    #[must_use]
    pub const fn limiter(&self) -> &Limiter {
        &self.limiter
    }

    /// Returns a snapshot of the admission counters.
    #[must_use]
    pub fn metrics(&self) -> Metrics {
        self.limiter.metrics()
    }
}

impl<S> Layer<S> for ConcurrencyLimitLayer {
    type Service = ConcurrencyLimitService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ConcurrencyLimitService {
            inner,
            config: self.config.clone(),
            limiter: self.limiter.clone(),
        }
    }
}

/// Tower [`Service`] produced by [`ConcurrencyLimitLayer`].
#[derive(Clone, Debug)]
pub struct ConcurrencyLimitService<S> {
    inner: S,
    config: ConcurrencyLimit,
    limiter: Limiter,
}

impl<S> ConcurrencyLimitService<S> {
    /// Returns the shared [`Limiter`].
    #[must_use]
    pub const fn limiter(&self) -> &Limiter {
        &self.limiter
    }
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for ConcurrencyLimitService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    ResBody: Default,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future = ResponseFuture<S::Future, ResBody>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let kind = match self.limiter.try_acquire() {
            Some(permit) => Kind::Admitted {
                inner: self.inner.call(req),
                permit: Some(permit),
            },
            None => Kind::Shed {
                status: self.config.status,
                retry_after: self.config.retry_after.clone(),
                _body: PhantomData,
            },
        };
        ResponseFuture { kind }
    }
}

pin_project! {
    /// Response future of [`ConcurrencyLimitService`].
    ///
    /// Holds the request's slot while the inner future runs and frees it as
    /// soon as that future completes or is dropped. A shed request resolves
    /// immediately to the configured error response.
    pub struct ResponseFuture<F, B> {
        #[pin]
        kind: Kind<F, B>,
    }
}

impl<F, B> fmt::Debug for ResponseFuture<F, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = match self.kind {
            Kind::Admitted { .. } => "admitted",
            Kind::Shed { .. } => "shed",
        };
        f.debug_struct("ResponseFuture")
            .field("state", &state)
            .finish_non_exhaustive()
    }
}

pin_project! {
    #[project = KindProj]
    enum Kind<F, B> {
        Admitted {
            #[pin]
            inner: F,
            permit: Option<Permit>,
        },
        Shed {
            status: StatusCode,
            retry_after: Option<HeaderValue>,
            _body: PhantomData<fn() -> B>,
        },
    }
}

impl<F, B, E> Future for ResponseFuture<F, B>
where
    F: Future<Output = Result<Response<B>, E>>,
    B: Default,
{
    type Output = Result<Response<B>, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.project().kind.project() {
            KindProj::Admitted { inner, permit } => {
                let out = ready!(inner.poll(cx));
                // Free the slot now, even if the future itself lives on.
                drop(permit.take());
                Poll::Ready(out)
            }
            KindProj::Shed {
                status,
                retry_after,
                ..
            } => {
                let mut response = Response::new(B::default());
                *response.status_mut() = *status;
                if let Some(value) = retry_after {
                    response.headers_mut().insert(RETRY_AFTER, value.clone());
                }
                Poll::Ready(Ok(response))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults() {
        let c = ConcurrencyLimit::default();
        assert_eq!(c.max_in_flight_value(), DEFAULT_MAX_IN_FLIGHT);
        assert_eq!(c.status_code(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(c.retry_after_value().is_none());
    }

    #[test]
    fn retry_after_rounds_up_to_whole_seconds() {
        let v = |d| ConcurrencyLimit::new().retry_after(d).retry_after.unwrap();
        assert_eq!(v(Duration::from_secs(0)), "0");
        assert_eq!(v(Duration::from_secs(3)), "3");
        assert_eq!(v(Duration::from_millis(1)), "1");
        assert_eq!(v(Duration::from_millis(2_500)), "3");
        assert_eq!(v(Duration::MAX), u64::MAX.to_string().as_str());
    }

    #[test]
    fn layer_clones_share_limiter() {
        let a = ConcurrencyLimitLayer::new(ConcurrencyLimit::new().max_in_flight(1));
        let b = a.clone();
        let _p = a.limiter().try_acquire();
        assert!(b.limiter().try_acquire().is_none());
        assert_eq!(b.metrics().shed, 1);
    }
}
