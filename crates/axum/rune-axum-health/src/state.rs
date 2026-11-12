use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use http::StatusCode;
use tokio::sync::Notify;

use crate::{Error, Probe};

#[derive(Debug)]
struct Inner {
    live: AtomicBool,
    ready: AtomicBool,
    shutting_down: AtomicBool,
    in_flight: AtomicUsize,
    /// Woken once, when shutdown begins.
    shutdown: Notify,
    /// Woken every time the in-flight count drops to zero.
    idle: Notify,
}

/// Shared health, readiness and shutdown state of one server.
///
/// Cheap to clone: every clone refers to the same state. Hand one clone to
/// [`HealthLayer`](crate::HealthLayer), keep another to flip readiness,
/// start shutdown and wait for in-flight requests to drain.
///
/// A new state is live and ready. Call [`set_ready(false)`](Self::set_ready)
/// right away if the service needs to warm up before taking traffic.
///
/// # Lifecycle
///
/// 1. **Serving.** Liveness and readiness probes answer `200 OK`.
/// 2. **Shutdown begins** ([`begin_shutdown`](Self::begin_shutdown), or the
///    signal passed to [`graceful_shutdown`](Self::graceful_shutdown)
///    fires). Readiness answers `503` from now on, so load balancers stop
///    routing new traffic here; liveness keeps answering `200` so the
///    orchestrator does not kill the process mid-drain.
/// 3. **Drain.** Requests already in flight run to completion;
///    [`drained`](Self::drained) and [`drain`](Self::drain) wait for them.
///
/// # Examples
///
/// ```rust
/// use http::StatusCode;
/// use rune_axum_health::{HealthState, Probe};
///
/// let state = HealthState::new();
/// assert_eq!(state.status(Probe::Readiness), StatusCode::OK);
///
/// let guard = state.track();
/// assert_eq!(state.in_flight(), 1);
///
/// state.begin_shutdown();
/// assert_eq!(state.status(Probe::Readiness), StatusCode::SERVICE_UNAVAILABLE);
/// assert_eq!(state.status(Probe::Liveness), StatusCode::OK);
///
/// drop(guard);
/// assert_eq!(state.in_flight(), 0);
/// ```
#[derive(Clone, Debug)]
pub struct HealthState {
    inner: Arc<Inner>,
}

impl Default for HealthState {
    fn default() -> Self {
        Self {
            inner: Arc::new(Inner {
                live: AtomicBool::new(true),
                ready: AtomicBool::new(true),
                shutting_down: AtomicBool::new(false),
                in_flight: AtomicUsize::new(0),
                shutdown: Notify::new(),
                idle: Notify::new(),
            }),
        }
    }
}

impl HealthState {
    /// Creates a state that is live, ready, not shutting down and has no
    /// requests in flight.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Marks the process live or not live.
    ///
    /// Set it to `false` when the process is wedged beyond recovery (a
    /// deadlock detector, a poisoned critical resource) so that the
    /// orchestrator restarts it.
    pub fn set_live(&self, live: bool) {
        self.inner.live.store(live, Ordering::Release);
    }

    /// Marks the service ready or not ready to take traffic.
    ///
    /// Use it for warm-up and for temporary unavailability of a dependency.
    /// It cannot make the service ready again once shutdown has begun.
    pub fn set_ready(&self, ready: bool) {
        self.inner.ready.store(ready, Ordering::Release);
    }

    /// Returns whether the process is live.
    #[must_use]
    pub fn is_live(&self) -> bool {
        self.inner.live.load(Ordering::Acquire)
    }

    /// Returns whether the service is ready: marked ready and not shutting
    /// down.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.inner.ready.load(Ordering::Acquire) && !self.is_shutting_down()
    }

    /// Returns whether shutdown has begun.
    #[must_use]
    pub fn is_shutting_down(&self) -> bool {
        self.inner.shutting_down.load(Ordering::Acquire)
    }

    /// Begins shutdown: readiness turns `503` for good and every
    /// [`shutdown_requested`](Self::shutdown_requested) future resolves.
    ///
    /// Idempotent: later calls do nothing.
    pub fn begin_shutdown(&self) {
        if !self.inner.shutting_down.swap(true, Ordering::AcqRel) {
            self.inner.shutdown.notify_waiters();
        }
    }

    /// Returns the number of requests (and other [`track`](Self::track)ed
    /// work) currently in flight.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.inner.in_flight.load(Ordering::Acquire)
    }

    /// Returns the status code a probe answers with right now: `200 OK`
    /// when the probed condition holds, `503 Service Unavailable` otherwise.
    #[must_use]
    pub fn status(&self, probe: Probe) -> StatusCode {
        let healthy = match probe {
            Probe::Liveness => self.is_live(),
            Probe::Readiness => self.is_ready(),
        };
        if healthy {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        }
    }

    /// Counts one unit of in-flight work until the returned guard drops.
    ///
    /// [`HealthLayer`](crate::HealthLayer) does this for every request
    /// until its response headers are ready. Use it directly for work the
    /// layer cannot see, such as a streaming response body, a WebSocket
    /// session or a background task spawned by a handler, so that draining
    /// waits for it too.
    pub fn track(&self) -> InFlightGuard {
        self.inner.in_flight.fetch_add(1, Ordering::AcqRel);
        InFlightGuard {
            state: self.clone(),
        }
    }

    /// Resolves once shutdown has begun (immediately if it already has).
    pub async fn shutdown_requested(&self) {
        loop {
            let notified = self.inner.shutdown.notified();
            tokio::pin!(notified);
            // Register before checking, so a concurrent `begin_shutdown`
            // cannot slip between the check and the wait.
            notified.as_mut().enable();
            if self.is_shutting_down() {
                return;
            }
            notified.await;
        }
    }

    /// Resolves once no work is in flight (immediately if none is).
    ///
    /// This does not stop new requests from arriving; call it after the
    /// server has stopped accepting them, or after
    /// [`begin_shutdown`](Self::begin_shutdown) once load balancers have
    /// had time to react.
    pub async fn drained(&self) {
        loop {
            let notified = self.inner.idle.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.in_flight() == 0 {
                return;
            }
            notified.await;
        }
    }

    /// Waits up to `timeout` for in-flight work to drain.
    ///
    /// # Errors
    ///
    /// [`Error::DrainTimeout`] if work is still in flight when `timeout`
    /// expires. The caller decides whether to exit anyway.
    pub async fn drain(&self, timeout: Duration) -> Result<(), Error> {
        tokio::time::timeout(timeout, self.drained())
            .await
            .map_err(|_elapsed| Error::DrainTimeout {
                in_flight: self.in_flight(),
                timeout,
            })
    }

    /// Returns a future for `axum::serve(..).with_graceful_shutdown(..)`.
    ///
    /// The future waits for `signal` to resolve (its output is ignored, so
    /// an error from a signal source starts shutdown too) or for
    /// [`begin_shutdown`](Self::begin_shutdown) to be called elsewhere.
    /// It then begins shutdown, which flips readiness to `503`, and waits
    /// `grace` before resolving. The grace period lets load balancers
    /// observe the failing readiness probe and stop sending traffic while
    /// the server still accepts it. Once the future resolves, the server
    /// stops accepting connections and waits for open ones to finish.
    ///
    /// Must be driven on a Tokio runtime with the time driver enabled.
    pub fn graceful_shutdown<F>(
        &self,
        signal: F,
        grace: Duration,
    ) -> impl Future<Output = ()> + Send + 'static
    where
        F: Future + Send + 'static,
    {
        let state = self.clone();
        async move {
            tokio::select! {
                _ = signal => {}
                () = state.shutdown_requested() => {}
            }
            state.begin_shutdown();
            if !grace.is_zero() {
                tokio::time::sleep(grace).await;
            }
        }
    }
}

/// Counts one unit of in-flight work for [`HealthState`] while it lives.
///
/// Returned by [`HealthState::track`]. Dropping it ends the work; when the
/// last guard drops, [`HealthState::drained`] resolves.
#[derive(Debug)]
#[must_use = "the work counts as in flight only while the guard lives"]
pub struct InFlightGuard {
    state: HealthState,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        let inner = &self.state.inner;
        if inner.in_flight.fetch_sub(1, Ordering::AcqRel) == 1 {
            inner.idle.notify_waiters();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_state_is_live_and_ready() {
        let s = HealthState::new();
        assert!(s.is_live());
        assert!(s.is_ready());
        assert!(!s.is_shutting_down());
        assert_eq!(s.in_flight(), 0);
    }

    #[test]
    fn shutdown_flips_readiness_not_liveness() {
        let s = HealthState::new();
        s.begin_shutdown();
        s.begin_shutdown();
        assert!(!s.is_ready());
        assert!(s.is_live());
        // Readiness cannot come back once shutdown has begun.
        s.set_ready(true);
        assert_eq!(s.status(Probe::Readiness), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn set_ready_and_set_live() {
        let s = HealthState::new();
        s.set_ready(false);
        assert_eq!(s.status(Probe::Readiness), StatusCode::SERVICE_UNAVAILABLE);
        s.set_ready(true);
        assert_eq!(s.status(Probe::Readiness), StatusCode::OK);
        s.set_live(false);
        assert_eq!(s.status(Probe::Liveness), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn clones_share_state() {
        let a = HealthState::new();
        let b = a.clone();
        let g = b.track();
        assert_eq!(a.in_flight(), 1);
        a.begin_shutdown();
        assert!(b.is_shutting_down());
        drop(g);
        assert_eq!(a.in_flight(), 0);
    }

    #[tokio::test]
    async fn drained_resolves_immediately_when_idle() {
        HealthState::new().drained().await;
    }

    #[tokio::test]
    async fn shutdown_requested_resolves_after_begin() {
        let s = HealthState::new();
        let waiter = tokio::spawn({
            let s = s.clone();
            async move { s.shutdown_requested().await }
        });
        tokio::task::yield_now().await;
        s.begin_shutdown();
        waiter.await.unwrap();
        // And immediately once already begun.
        s.shutdown_requested().await;
    }

    #[tokio::test(start_paused = true)]
    async fn drain_waits_for_last_guard() {
        let s = HealthState::new();
        let g1 = s.track();
        let g2 = s.track();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            drop(g1);
            tokio::time::sleep(Duration::from_secs(1)).await;
            drop(g2);
        });
        let started = tokio::time::Instant::now();
        s.drain(Duration::from_secs(10)).await.unwrap();
        assert_eq!(started.elapsed(), Duration::from_secs(2));
    }

    #[tokio::test(start_paused = true)]
    async fn drain_times_out() {
        let s = HealthState::new();
        let _g = s.track();
        let err = s.drain(Duration::from_secs(3)).await.unwrap_err();
        assert!(matches!(
            err,
            Error::DrainTimeout { in_flight: 1, timeout } if timeout == Duration::from_secs(3)
        ));
        assert_eq!(
            err.to_string(),
            "1 request(s) still in flight after waiting 3s to drain"
        );
    }
}
