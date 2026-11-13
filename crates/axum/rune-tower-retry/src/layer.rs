use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use http::Method;
use tower::{Layer, Service};

use crate::{Decision, Retrier, Retry, Stats};

/// A boxed timer future, as returned by [`Clock::sleep`].
pub type Sleep = Pin<Box<dyn Future<Output = ()> + Send>>;

/// A source of time and timers, so tests can drive retries without real
/// sleeps.
pub trait Clock: Send + Sync + 'static {
    /// The current instant.
    fn now(&self) -> Instant;

    /// A future that completes after `duration`.
    fn sleep(&self, duration: Duration) -> Sleep;
}

/// The Tokio clock: [`tokio::time::Instant`] and [`tokio::time::sleep`].
///
/// It follows Tokio's paused test time (`#[tokio::test(start_paused = true)]`).
#[derive(Clone, Copy, Debug, Default)]
pub struct TokioClock;

impl Clock for TokioClock {
    fn now(&self) -> Instant {
        tokio::time::Instant::now().into_std()
    }

    fn sleep(&self, duration: Duration) -> Sleep {
        Box::pin(tokio::time::sleep(duration))
    }
}

/// Decides whether a call's result is a transient failure worth retrying.
///
/// Implemented for [`ErrorsOnly`] (the default), [`TransientHttp`] and any
/// `Fn(&Result<R, E>) -> bool` closure. Everything not retriable (success
/// or a permanent failure) is returned to the caller at once.
pub trait Classify<R, E> {
    /// Whether `result` should be retried.
    fn is_retriable(&self, result: &Result<R, E>) -> bool;
}

/// Retries every `Err` from the inner service; never retries an `Ok`.
#[derive(Clone, Copy, Debug, Default)]
pub struct ErrorsOnly;

impl<R, E> Classify<R, E> for ErrorsOnly {
    fn is_retriable(&self, result: &Result<R, E>) -> bool {
        result.is_err()
    }
}

/// For HTTP: retries errors and transient gateway statuses.
///
/// Those are `502 Bad Gateway`, `503 Service Unavailable` and
/// `504 Gateway Timeout`. Other responses, `500` and `429` included, are
/// returned as they are.
#[derive(Clone, Copy, Debug, Default)]
pub struct TransientHttp;

impl<B, E> Classify<http::Response<B>, E> for TransientHttp {
    fn is_retriable(&self, result: &Result<http::Response<B>, E>) -> bool {
        result.as_ref().map_or(true, |response| {
            matches!(response.status().as_u16(), 502..=504)
        })
    }
}

impl<F, R, E> Classify<R, E> for F
where
    F: Fn(&Result<R, E>) -> bool,
{
    fn is_retriable(&self, result: &Result<R, E>) -> bool {
        self(result)
    }
}

/// Makes the copies of a request that retries and hedges send.
///
/// Returning `None` marks the request as not replayable: it is sent once,
/// never retried or hedged. Implemented for [`CloneAll`] (the default),
/// [`IdempotentHttp`], [`IdempotentBodiless`] and any
/// `Fn(&Req) -> Option<Req>` closure.
pub trait CloneRequest<Req> {
    /// A copy of `request` to send again, or `None` if it must not be.
    fn clone_request(&self, request: &Req) -> Option<Req>;
}

/// Replays any `Clone` request. Use it for calls that are safe to repeat.
///
/// It knows nothing about HTTP methods: an `http::Request` with a `Clone`
/// body is replayed whatever its method, `POST` and `PATCH` included. Use
/// [`IdempotentHttp`] or [`IdempotentBodiless`] for HTTP clients.
#[derive(Clone, Copy, Debug, Default)]
pub struct CloneAll;

impl<Req: Clone> CloneRequest<Req> for CloneAll {
    fn clone_request(&self, request: &Req) -> Option<Req> {
        Some(request.clone())
    }
}

/// Replays HTTP requests whose method is idempotent (RFC 9110 §9.2.2:
/// `GET`, `HEAD`, `OPTIONS`, `TRACE`, `PUT`, `DELETE`), cloning the body.
/// `POST`, `PATCH` and extension methods are sent once.
#[derive(Clone, Copy, Debug, Default)]
pub struct IdempotentHttp;

impl<B: Clone> CloneRequest<http::Request<B>> for IdempotentHttp {
    fn clone_request(&self, request: &http::Request<B>) -> Option<http::Request<B>> {
        is_idempotent(request.method()).then(|| copy_request(request, request.body().clone()))
    }
}

/// Replays HTTP requests with an idempotent method and a body known to be
/// empty, for streaming bodies that cannot be cloned (such as
/// `axum::body::Body`). The copy gets `B::default()` as its body.
#[derive(Clone, Copy, Debug, Default)]
pub struct IdempotentBodiless;

impl<B> CloneRequest<http::Request<B>> for IdempotentBodiless
where
    B: http_body::Body + Default,
{
    fn clone_request(&self, request: &http::Request<B>) -> Option<http::Request<B>> {
        let empty = request.body().size_hint().exact() == Some(0);
        (empty && is_idempotent(request.method())).then(|| copy_request(request, B::default()))
    }
}

impl<F, Req> CloneRequest<Req> for F
where
    F: Fn(&Req) -> Option<Req>,
{
    fn clone_request(&self, request: &Req) -> Option<Req> {
        self(request)
    }
}

fn is_idempotent(method: &Method) -> bool {
    [
        Method::GET,
        Method::HEAD,
        Method::OPTIONS,
        Method::TRACE,
        Method::PUT,
        Method::DELETE,
    ]
    .contains(method)
}

fn copy_request<B>(request: &http::Request<B>, body: B) -> http::Request<B> {
    let mut copy = http::Request::new(body);
    *copy.method_mut() = request.method().clone();
    *copy.uri_mut() = request.uri().clone();
    *copy.version_mut() = request.version();
    *copy.headers_mut() = request.headers().clone();
    *copy.extensions_mut() = request.extensions().clone();
    copy
}

/// The retrier and clock shared by a layer and every service it builds.
struct Shared {
    retrier: Mutex<Retrier>,
    clock: Arc<dyn Clock>,
}

impl Shared {
    fn new(retrier: Retrier, clock: Arc<dyn Clock>) -> Arc<Self> {
        Arc::new(Self {
            retrier: Mutex::new(retrier),
            clock,
        })
    }

    fn lock(&self) -> MutexGuard<'_, Retrier> {
        // The retrier's invariants hold between method calls, so a panic
        // elsewhere while the lock was held leaves it usable.
        self.retrier.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A handle on a layer's retry state, for metrics.
///
/// Obtained from [`RetryLayer::handle`]; cheap to clone.
#[derive(Clone)]
pub struct RetryHandle {
    shared: Arc<Shared>,
}

impl RetryHandle {
    /// Counters across every call made through the layer.
    #[must_use]
    pub fn stats(&self) -> Stats {
        self.shared.lock().stats()
    }

    /// Retries the budget would allow now, or `None` without a budget.
    #[must_use]
    pub fn budget_remaining(&self) -> Option<u64> {
        let now = self.shared.clock.now();
        self.shared.lock().budget_remaining(now)
    }
}

impl fmt::Debug for RetryHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RetryHandle")
            .field("stats", &self.stats())
            .finish_non_exhaustive()
    }
}

/// Tower [`Layer`] that retries transient failures and hedges slow calls.
///
/// **One layer is one budget.** Every service the layer builds, and every
/// clone of them, shares the retry budget, the latency window and the
/// counters, so put one layer in front of each downstream dependency.
///
/// The inner service must be `Clone`: each retry or hedge calls a clone of
/// it once that clone is ready. Errors and responses pass through
/// unchanged; when retries run out, the last failure is returned.
///
/// # Examples
///
/// ```rust
/// use std::time::Duration;
/// use rune_tower_retry::{Backoff, IdempotentHttp, Retry, RetryLayer, TransientHttp};
/// use tower::ServiceBuilder;
///
/// let layer = RetryLayer::new(
///     Retry::new()
///         .max_attempts(3)
///         .backoff(Backoff::exponential(Duration::from_millis(25))),
/// )
/// .classify(TransientHttp)
/// .clone_requests(IdempotentHttp);
/// let retries = layer.handle();
///
/// let client = ServiceBuilder::new().layer(layer).service(tower::service_fn(
///     |_req: http::Request<String>| async {
///         Ok::<_, std::convert::Infallible>(http::Response::new(()))
///     },
/// ));
/// # let _ = (client, retries.stats());
/// ```
pub struct RetryLayer<C = ErrorsOnly, R = CloneAll> {
    shared: Arc<Shared>,
    classify: Arc<C>,
    cloner: Arc<R>,
}

impl RetryLayer {
    /// Creates a layer that retries inner-service errors on `Clone`
    /// requests, timed by [`TokioClock`].
    ///
    /// The default [`CloneAll`] replays every request, so for an HTTP
    /// client add `.clone_requests(IdempotentHttp)` unless every call,
    /// `POST` included, is safe to send twice.
    #[must_use]
    pub fn new(config: Retry) -> Self {
        Self {
            shared: Shared::new(Retrier::new(config), Arc::new(TokioClock)),
            classify: Arc::new(ErrorsOnly),
            cloner: Arc::new(CloneAll),
        }
    }
}

impl Default for RetryLayer {
    fn default() -> Self {
        Self::new(Retry::default())
    }
}

impl<C, R> RetryLayer<C, R> {
    /// Replaces the classifier that decides which results are retried,
    /// such as with [`TransientHttp`] or a closure.
    #[must_use]
    pub fn classify<C2>(self, classify: C2) -> RetryLayer<C2, R> {
        RetryLayer {
            shared: self.shared,
            classify: Arc::new(classify),
            cloner: self.cloner,
        }
    }

    /// Replaces the request cloner that decides which requests may be
    /// replayed, such as with [`IdempotentHttp`] or a closure.
    #[must_use]
    pub fn clone_requests<R2>(self, cloner: R2) -> RetryLayer<C, R2> {
        RetryLayer {
            shared: self.shared,
            classify: self.classify,
            cloner: Arc::new(cloner),
        }
    }

    /// Replaces the clock. The budget, latencies and counters are reset,
    /// so call this before the layer is used.
    #[must_use]
    pub fn clock(self, clock: impl Clock) -> Self {
        let config = *self.shared.lock().config();
        self.rebuild(Retrier::new(config), Arc::new(clock))
    }

    /// Makes backoff jitter reproducible. The budget, latencies and
    /// counters are reset, so call this before the layer is used.
    #[must_use]
    pub fn seed(self, seed: u64) -> Self {
        let config = *self.shared.lock().config();
        let clock = Arc::clone(&self.shared.clock);
        self.rebuild(Retrier::with_seed(config, seed), clock)
    }

    /// A handle on this layer's counters and budget.
    #[must_use]
    pub fn handle(&self) -> RetryHandle {
        RetryHandle {
            shared: Arc::clone(&self.shared),
        }
    }

    fn rebuild(self, retrier: Retrier, clock: Arc<dyn Clock>) -> Self {
        Self {
            shared: Shared::new(retrier, clock),
            classify: self.classify,
            cloner: self.cloner,
        }
    }
}

impl<C, R> Clone for RetryLayer<C, R> {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
            classify: Arc::clone(&self.classify),
            cloner: Arc::clone(&self.cloner),
        }
    }
}

impl<C, R> fmt::Debug for RetryLayer<C, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RetryLayer")
            .field("config", self.shared.lock().config())
            .finish_non_exhaustive()
    }
}

impl<S, C, R> Layer<S> for RetryLayer<C, R> {
    type Service = RetryService<S, C, R>;

    fn layer(&self, inner: S) -> Self::Service {
        RetryService {
            inner,
            shared: Arc::clone(&self.shared),
            classify: Arc::clone(&self.classify),
            cloner: Arc::clone(&self.cloner),
        }
    }
}

/// Tower [`Service`] produced by [`RetryLayer`].
pub struct RetryService<S, C = ErrorsOnly, R = CloneAll> {
    inner: S,
    shared: Arc<Shared>,
    classify: Arc<C>,
    cloner: Arc<R>,
}

impl<S, C, R> RetryService<S, C, R> {
    /// A handle on this service's counters and budget.
    #[must_use]
    pub fn handle(&self) -> RetryHandle {
        RetryHandle {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<S: Clone, C, R> Clone for RetryService<S, C, R> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            shared: Arc::clone(&self.shared),
            classify: Arc::clone(&self.classify),
            cloner: Arc::clone(&self.cloner),
        }
    }
}

impl<S: fmt::Debug, C, R> fmt::Debug for RetryService<S, C, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RetryService")
            .field("inner", &self.inner)
            .finish_non_exhaustive()
    }
}

impl<S, C, R, Req> Service<Req> for RetryService<S, C, R>
where
    S: Service<Req> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Response: Send + 'static,
    S::Error: Send + 'static,
    C: Classify<S::Response, S::Error> + Send + Sync + 'static,
    R: CloneRequest<Req> + Send + Sync + 'static,
    Req: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Req) -> Self::Future {
        let template = self.cloner.clone_request(&req);
        let now = self.shared.clock.now();
        let call = self.shared.lock().begin(now);
        // The ready service takes this request; a fresh clone (not yet
        // ready) is kept for the attempts that follow.
        let clone = self.inner.clone();
        let mut ready = std::mem::replace(&mut self.inner, clone);
        let first = Attempt {
            future: Box::pin(ready.call(req)),
            started: now,
        };
        let mut driver = Driver {
            service: ready,
            template,
            shared: Arc::clone(&self.shared),
            classify: Arc::clone(&self.classify),
            cloner: Arc::clone(&self.cloner),
            call,
            in_flight: vec![first],
            timer: None,
            launching: false,
            last: None,
        };
        driver.arm_hedge();
        Box::pin(driver)
    }
}

/// One call to the inner service.
struct Attempt<F> {
    future: Pin<Box<F>>,
    started: Instant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TimerKind {
    Backoff,
    Hedge,
}

/// Drives one request: its attempts in flight, the backoff or hedge timer,
/// and the decisions of the shared [`Retrier`].
struct Driver<S, Req, C, R>
where
    S: Service<Req>,
{
    service: S,
    /// The copy future attempts are cloned from; `None` when the request
    /// is not replayable.
    template: Option<Req>,
    shared: Arc<Shared>,
    classify: Arc<C>,
    cloner: Arc<R>,
    call: crate::Call,
    in_flight: Vec<Attempt<S::Future>>,
    timer: Option<(Sleep, TimerKind)>,
    /// Waiting for `service` to be ready to send the next attempt.
    launching: bool,
    /// The most recent retriable failure.
    last: Option<Result<S::Response, S::Error>>,
}

// Every future the driver polls is boxed, and `service` is only used
// through `&mut`, never pinned, so moving the driver is always sound.
impl<S, Req, C, R> Unpin for Driver<S, Req, C, R> where S: Service<Req> {}

impl<S, Req, C, R> Driver<S, Req, C, R>
where
    S: Service<Req>,
    C: Classify<S::Response, S::Error>,
    R: CloneRequest<Req>,
{
    /// Arms the hedge timer for the attempt just sent, if hedging applies.
    fn arm_hedge(&mut self) {
        if self.template.is_none() {
            return;
        }
        let delay = self.shared.lock().hedge_delay(&self.call);
        if let Some(delay) = delay {
            self.timer = Some((self.shared.clock.sleep(delay), TimerKind::Hedge));
        }
    }

    /// Polls the attempts in flight. Returns a result to hand back.
    fn poll_attempts(&mut self, cx: &mut Context<'_>) -> Option<Result<S::Response, S::Error>> {
        let mut i = 0;
        while i < self.in_flight.len() {
            let Poll::Ready(result) = self.in_flight[i].future.as_mut().poll(cx) else {
                i += 1;
                continue;
            };
            let attempt = self.in_flight.swap_remove(i);
            if self.classify.is_retriable(&result) {
                self.last = Some(result);
            } else {
                let elapsed = self
                    .shared
                    .clock
                    .now()
                    .saturating_duration_since(attempt.started);
                self.shared.lock().record_latency(elapsed);
                // Returning drops the other attempts: losers are cancelled.
                return Some(result);
            }
        }
        None
    }

    /// Sends the next attempt once the service is ready. Returns whether
    /// anything changed.
    fn poll_launch(&mut self, cx: &mut Context<'_>) -> bool {
        if !self.launching {
            return false;
        }
        match self.service.poll_ready(cx) {
            Poll::Pending => false,
            Poll::Ready(Err(e)) => {
                self.launching = false;
                let failure = Err(e);
                if !self.classify.is_retriable(&failure) {
                    // A permanent readiness error ends the call once the
                    // attempts in flight are done: stop replaying.
                    self.template = None;
                }
                self.last = Some(failure);
                true
            }
            Poll::Ready(Ok(())) => {
                self.launching = false;
                let request = self
                    .template
                    .as_ref()
                    .and_then(|t| self.cloner.clone_request(t));
                if let Some(request) = request {
                    let started = self.shared.clock.now();
                    self.in_flight.push(Attempt {
                        future: Box::pin(self.service.call(request)),
                        started,
                    });
                    self.arm_hedge();
                } else {
                    // The cloner refused a copy: stop replaying.
                    self.template = None;
                }
                true
            }
        }
    }

    /// Polls the backoff or hedge timer. Returns whether it fired.
    fn poll_timer(&mut self, cx: &mut Context<'_>) -> bool {
        let Some((sleep, kind)) = &mut self.timer else {
            return false;
        };
        if sleep.as_mut().poll(cx).is_pending() {
            return false;
        }
        let kind = *kind;
        self.timer = None;
        match kind {
            TimerKind::Backoff => self.launching = true,
            TimerKind::Hedge => {
                let now = self.shared.clock.now();
                if !self.launching && self.shared.lock().try_hedge(&mut self.call, now) {
                    self.launching = true;
                }
            }
        }
        true
    }
}

impl<S, Req, C, R> Future for Driver<S, Req, C, R>
where
    S: Service<Req>,
    C: Classify<S::Response, S::Error>,
    R: CloneRequest<Req>,
{
    type Output = Result<S::Response, S::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        loop {
            if let Some(result) = this.poll_attempts(cx) {
                return Poll::Ready(result);
            }
            if this.poll_launch(cx) || this.poll_timer(cx) {
                continue;
            }
            let backing_off = matches!(this.timer, Some((_, TimerKind::Backoff)));
            if !this.in_flight.is_empty() || this.launching || backing_off {
                return Poll::Pending;
            }
            // Every attempt failed retriably: retry or give up.
            this.timer = None;
            let Some(failure) = this.last.take() else {
                // Unreachable: an attempt is always in flight, launching or
                // backing off until a failure is recorded.
                return Poll::Pending;
            };
            if this.template.is_none() {
                return Poll::Ready(failure);
            }
            let now = this.shared.clock.now();
            let decision = this.shared.lock().on_failure(&mut this.call, now);
            match decision {
                Decision::Retry { after } => {
                    // Kept in case the next attempt cannot be sent.
                    this.last = Some(failure);
                    this.timer = Some((this.shared.clock.sleep(after), TimerKind::Backoff));
                }
                Decision::GiveUp(_) => return Poll::Ready(failure),
            }
        }
    }
}
