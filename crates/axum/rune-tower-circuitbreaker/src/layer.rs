use std::fmt;
use std::future::{Future, ready};
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll};
use std::time::Instant;

use tower::{Layer, Service};

use crate::{Breaker, CircuitBreaker, Error, Permit, Snapshot, State};

/// A source of the current time, so tests can drive the breaker without
/// sleeping.
pub trait Clock: Send + Sync + 'static {
    /// The current instant.
    fn now(&self) -> Instant;
}

/// The real monotonic clock, [`Instant::now`].
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// Decides whether a call's result counts as a failure.
///
/// Implemented for [`ErrorsOnly`] (the default), [`ServerErrors`] and any
/// `Fn(&Result<R, E>) -> bool` closure.
pub trait Classify<R, E> {
    /// Whether `result` is a failure for the circuit.
    fn is_failure(&self, result: &Result<R, E>) -> bool;
}

/// Counts every `Err` from the inner service as a failure, and every `Ok`
/// as a success.
#[derive(Clone, Copy, Debug, Default)]
pub struct ErrorsOnly;

impl<R, E> Classify<R, E> for ErrorsOnly {
    fn is_failure(&self, result: &Result<R, E>) -> bool {
        result.is_err()
    }
}

/// For HTTP clients: counts errors and `5xx` responses as failures.
/// `4xx` responses are the caller's fault, not the server's, and count as
/// successes.
#[derive(Clone, Copy, Debug, Default)]
pub struct ServerErrors;

impl<B, E> Classify<http::Response<B>, E> for ServerErrors {
    fn is_failure(&self, result: &Result<http::Response<B>, E>) -> bool {
        result
            .as_ref()
            .map_or(true, |response| response.status().is_server_error())
    }
}

impl<F, R, E> Classify<R, E> for F
where
    F: Fn(&Result<R, E>) -> bool,
{
    fn is_failure(&self, result: &Result<R, E>) -> bool {
        self(result)
    }
}

/// The breaker and clock shared by a layer and every service it builds.
struct Shared {
    breaker: Mutex<Breaker>,
    clock: Arc<dyn Clock>,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, Breaker> {
        // The breaker's invariants hold between method calls, so a panic
        // elsewhere while the lock was held leaves it usable.
        self.breaker.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A handle on a circuit, for inspecting or overriding its state.
///
/// Obtained from [`CircuitBreakerLayer::handle`]; cheap to clone.
#[derive(Clone)]
pub struct CircuitHandle {
    shared: Arc<Shared>,
}

impl CircuitHandle {
    /// The current state.
    #[must_use]
    pub fn state(&self) -> State {
        let now = self.shared.clock.now();
        self.shared.lock().state(now)
    }

    /// The current state and window rates.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        let now = self.shared.clock.now();
        self.shared.lock().snapshot(now)
    }

    /// Opens the circuit now, as if the thresholds had been breached.
    pub fn trip(&self) {
        let now = self.shared.clock.now();
        self.shared.lock().trip(now);
    }

    /// Closes the circuit with an empty window.
    pub fn reset(&self) {
        self.shared.lock().reset();
    }
}

impl fmt::Debug for CircuitHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CircuitHandle")
            .field("snapshot", &self.snapshot())
            .finish()
    }
}

/// Tower [`Layer`] that wraps a service in a circuit breaker.
///
/// **One layer is one circuit.** Every service the layer builds, and every
/// clone of them, shares the same breaker, so put one layer in front of
/// each downstream dependency. While the circuit is open, calls fail fast
/// with [`Error::Open`] without reaching the inner service.
///
/// # Examples
///
/// ```rust
/// use std::time::Duration;
/// use rune_tower_circuitbreaker::{CircuitBreaker, CircuitBreakerLayer, ServerErrors};
/// use tower::ServiceBuilder;
///
/// let layer = CircuitBreakerLayer::new(
///     CircuitBreaker::new()
///         .failure_rate(0.5)
///         .slow_calls(Duration::from_secs(2), 0.8)
///         .open_duration(Duration::from_secs(15)),
/// )
/// .classify(ServerErrors);
/// let circuit = layer.handle();
///
/// let client = ServiceBuilder::new().layer(layer).service(tower::service_fn(
///     |_req: http::Request<()>| async {
///         Ok::<_, std::convert::Infallible>(http::Response::new(()))
///     },
/// ));
/// # let _ = (client, circuit.state());
/// ```
pub struct CircuitBreakerLayer<C = ErrorsOnly> {
    shared: Arc<Shared>,
    classify: Arc<C>,
}

impl CircuitBreakerLayer {
    /// Creates a layer with its own closed circuit, counting inner-service
    /// errors as failures.
    #[must_use]
    pub fn new(config: CircuitBreaker) -> Self {
        Self {
            shared: Arc::new(Shared {
                breaker: Mutex::new(Breaker::new(config)),
                clock: Arc::new(SystemClock),
            }),
            classify: Arc::new(ErrorsOnly),
        }
    }
}

impl Default for CircuitBreakerLayer {
    fn default() -> Self {
        Self::new(CircuitBreaker::default())
    }
}

impl<C> CircuitBreakerLayer<C> {
    /// Replaces the failure classifier, such as with [`ServerErrors`] or a
    /// closure over the inner service's result.
    #[must_use]
    pub fn classify<C2>(self, classify: C2) -> CircuitBreakerLayer<C2> {
        CircuitBreakerLayer {
            shared: self.shared,
            classify: Arc::new(classify),
        }
    }

    /// Replaces the clock. The circuit is reset (closed, empty window),
    /// so call this before the layer is used.
    #[must_use]
    pub fn clock(self, clock: impl Clock) -> Self {
        let config = self.shared.lock().config().clone();
        Self {
            shared: Arc::new(Shared {
                breaker: Mutex::new(Breaker::new(config)),
                clock: Arc::new(clock),
            }),
            classify: self.classify,
        }
    }

    /// A handle on this layer's circuit.
    #[must_use]
    pub fn handle(&self) -> CircuitHandle {
        CircuitHandle {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<C> Clone for CircuitBreakerLayer<C> {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
            classify: Arc::clone(&self.classify),
        }
    }
}

impl<C> fmt::Debug for CircuitBreakerLayer<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CircuitBreakerLayer")
            .field("circuit", &self.handle())
            .finish_non_exhaustive()
    }
}

impl<S, C> Layer<S> for CircuitBreakerLayer<C> {
    type Service = CircuitBreakerService<S, C>;

    fn layer(&self, inner: S) -> Self::Service {
        CircuitBreakerService {
            inner,
            shared: Arc::clone(&self.shared),
            classify: Arc::clone(&self.classify),
        }
    }
}

/// Tower [`Service`] produced by [`CircuitBreakerLayer`].
pub struct CircuitBreakerService<S, C = ErrorsOnly> {
    inner: S,
    shared: Arc<Shared>,
    classify: Arc<C>,
}

impl<S, C> CircuitBreakerService<S, C> {
    /// A handle on this service's circuit.
    #[must_use]
    pub fn handle(&self) -> CircuitHandle {
        CircuitHandle {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<S: Clone, C> Clone for CircuitBreakerService<S, C> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            shared: Arc::clone(&self.shared),
            classify: Arc::clone(&self.classify),
        }
    }
}

impl<S: fmt::Debug, C> fmt::Debug for CircuitBreakerService<S, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CircuitBreakerService")
            .field("inner", &self.inner)
            .field("circuit", &self.handle())
            .finish_non_exhaustive()
    }
}

impl<S, C, Req> Service<Req> for CircuitBreakerService<S, C>
where
    S: Service<Req>,
    S::Future: Send + 'static,
    S::Response: Send + 'static,
    S::Error: Send + 'static,
    C: Classify<S::Response, S::Error> + Send + Sync + 'static,
{
    type Response = S::Response;
    type Error = Error<S::Error>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Error::Inner)
    }

    fn call(&mut self, req: Req) -> Self::Future {
        let started = self.shared.clock.now();
        let acquired = self.shared.lock().try_acquire(started);
        let permit = match acquired {
            Ok(permit) => permit,
            Err(rejected) => {
                return Box::pin(ready(Err(Error::Open {
                    retry_after: rejected.retry_after(),
                })));
            }
        };
        let mut guard = PermitGuard {
            shared: Arc::clone(&self.shared),
            permit: Some(permit),
        };
        let classify = Arc::clone(&self.classify);
        let fut = self.inner.call(req);
        Box::pin(async move {
            let result = fut.await;
            let failed = classify.is_failure(&result);
            guard.record(failed, started);
            result.map_err(Error::Inner)
        })
    }
}

/// Records the call's outcome, or releases its permit if the future is
/// dropped first.
struct PermitGuard {
    shared: Arc<Shared>,
    permit: Option<Permit>,
}

impl PermitGuard {
    fn record(&mut self, failed: bool, started: Instant) {
        if let Some(permit) = self.permit.take() {
            let now = self.shared.clock.now();
            let elapsed = now.saturating_duration_since(started);
            self.shared.lock().record(permit, failed, elapsed, now);
        }
    }
}

impl Drop for PermitGuard {
    fn drop(&mut self) {
        if let Some(permit) = self.permit.take() {
            self.shared.lock().release(permit);
        }
    }
}
