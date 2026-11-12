//! Integration tests: a flaky service trips the circuit, half-open probes
//! test it, and the circuit closes once it recovers.
//!
//! A manual clock drives time, so the tests need no real sleeps.

#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rune_tower_circuitbreaker::{
    CircuitBreaker, CircuitBreakerLayer, Clock, Error, ServerErrors, State,
};
use tower::{Layer, Service, ServiceExt, service_fn};

/// A clock that only moves when told to.
#[derive(Clone)]
struct ManualClock {
    base: Instant,
    offset_ms: Arc<AtomicU64>,
}

impl ManualClock {
    fn new() -> Self {
        Self {
            base: Instant::now(),
            offset_ms: Arc::new(AtomicU64::new(0)),
        }
    }

    fn advance(&self, d: Duration) {
        let ms = u64::try_from(d.as_millis()).unwrap();
        self.offset_ms.fetch_add(ms, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Instant {
        self.base + Duration::from_millis(self.offset_ms.load(Ordering::SeqCst))
    }
}

/// A dependency whose health and latency the test controls.
#[derive(Clone)]
struct Flaky {
    healthy: Arc<AtomicBool>,
    latency: Arc<Mutex<Duration>>,
    calls: Arc<AtomicUsize>,
    clock: ManualClock,
}

impl Flaky {
    fn new(clock: &ManualClock) -> Self {
        Self {
            healthy: Arc::new(AtomicBool::new(true)),
            latency: Arc::new(Mutex::new(Duration::from_millis(5))),
            calls: Arc::new(AtomicUsize::new(0)),
            clock: clock.clone(),
        }
    }

    fn set_healthy(&self, healthy: bool) {
        self.healthy.store(healthy, Ordering::SeqCst);
    }

    fn set_latency(&self, latency: Duration) {
        *self.latency.lock().unwrap() = latency;
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn service(
        &self,
    ) -> impl Service<u32, Response = u32, Error = &'static str, Future: Send> + Clone + use<> {
        let this = self.clone();
        service_fn(move |req: u32| {
            let this = this.clone();
            async move {
                this.calls.fetch_add(1, Ordering::SeqCst);
                let latency = *this.latency.lock().unwrap();
                this.clock.advance(latency);
                if this.healthy.load(Ordering::SeqCst) {
                    Ok(req)
                } else {
                    Err("upstream unavailable")
                }
            }
        })
    }
}

fn config() -> CircuitBreaker {
    CircuitBreaker::new()
        .failure_rate(0.5)
        .slow_calls(Duration::from_millis(500), 0.5)
        .window(10)
        .minimum_calls(10)
        .open_duration(Duration::from_secs(30))
        .half_open_probes(3)
}

async fn call<S>(svc: &mut S, req: u32) -> Result<u32, Error<&'static str>>
where
    S: Service<u32, Response = u32, Error = Error<&'static str>>,
{
    svc.ready().await?.call(req).await
}

#[tokio::test]
async fn opens_probes_and_closes_on_recovery() {
    let clock = ManualClock::new();
    let flaky = Flaky::new(&clock);
    let layer = CircuitBreakerLayer::new(config()).clock(clock.clone());
    let circuit = layer.handle();
    let mut svc = layer.layer(flaky.service());

    // Healthy traffic keeps it closed.
    for i in 0..20 {
        assert_eq!(call(&mut svc, i).await.unwrap(), i);
    }
    assert_eq!(circuit.state(), State::Closed);

    // The dependency starts failing: half the window fails -> open.
    flaky.set_healthy(false);
    for _ in 0..5 {
        assert!(matches!(call(&mut svc, 0).await, Err(Error::Inner(_))));
    }
    assert_eq!(circuit.state(), State::Open);
    let calls_when_opened = flaky.calls();

    // While open, calls fail fast and never reach the dependency.
    for _ in 0..50 {
        let err = call(&mut svc, 0).await.unwrap_err();
        assert!(err.is_open());
    }
    assert_eq!(flaky.calls(), calls_when_opened);
    match call(&mut svc, 0).await {
        Err(Error::Open { retry_after }) => assert!(retry_after <= Duration::from_secs(30)),
        other => panic!("expected open, got {other:?}"),
    }

    // Still broken when the open duration ends: the probe fails, reopen.
    clock.advance(Duration::from_secs(30));
    assert_eq!(circuit.state(), State::HalfOpen);
    assert!(matches!(call(&mut svc, 0).await, Err(Error::Inner(_))));
    assert_eq!(circuit.state(), State::Open);
    assert_eq!(flaky.calls(), calls_when_opened + 1);

    // Recovered: three successful probes close the circuit.
    flaky.set_healthy(true);
    clock.advance(Duration::from_secs(30));
    for i in 0..3 {
        assert_eq!(circuit.state(), State::HalfOpen);
        assert_eq!(call(&mut svc, i).await.unwrap(), i);
    }
    assert_eq!(circuit.state(), State::Closed);
    assert_eq!(circuit.snapshot().calls, 0);
    for i in 0..20 {
        assert_eq!(call(&mut svc, i).await.unwrap(), i);
    }
    assert_eq!(circuit.state(), State::Closed);
}

#[tokio::test]
async fn opens_on_latency_alone() {
    let clock = ManualClock::new();
    let flaky = Flaky::new(&clock);
    let layer = CircuitBreakerLayer::new(config()).clock(clock.clone());
    let circuit = layer.handle();
    let mut svc = layer.layer(flaky.service());

    flaky.set_latency(Duration::from_secs(2));
    for i in 0..10 {
        // Successful, but slow.
        assert_eq!(call(&mut svc, i).await.unwrap(), i);
    }
    assert_eq!(circuit.state(), State::Open);
    let s = circuit.snapshot();
    assert_eq!(s.state, State::Open);

    // A slow probe reopens; a fast one (after recovery) closes.
    clock.advance(Duration::from_secs(30));
    assert!(call(&mut svc, 1).await.is_ok());
    assert_eq!(circuit.state(), State::Open);
    flaky.set_latency(Duration::from_millis(10));
    clock.advance(Duration::from_secs(30));
    for i in 0..3 {
        assert!(call(&mut svc, i).await.is_ok());
    }
    assert_eq!(circuit.state(), State::Closed);
}

#[tokio::test]
async fn clones_share_one_circuit() {
    let clock = ManualClock::new();
    let flaky = Flaky::new(&clock);
    flaky.set_healthy(false);
    let layer = CircuitBreakerLayer::new(config()).clock(clock.clone());
    let mut a = layer.layer(flaky.service());
    let mut b = a.clone();
    let mut c = layer.layer(flaky.service());
    for _ in 0..5 {
        let _ = call(&mut a, 0).await;
        let _ = call(&mut b, 0).await;
    }
    assert!(call(&mut c, 0).await.unwrap_err().is_open());
    assert_eq!(a.handle().state(), State::Open);
}

#[tokio::test]
async fn cancelled_probe_frees_its_slot() {
    let clock = ManualClock::new();
    let layer = CircuitBreakerLayer::new(config().half_open_probes(1)).clock(clock.clone());
    let circuit = layer.handle();
    circuit.trip();
    clock.advance(Duration::from_secs(30));

    let mut svc = layer.layer(service_fn(|_: u32| async {
        std::future::pending::<Result<u32, &'static str>>().await
    }));
    let probe = svc.ready().await.unwrap().call(1);
    // The only probe slot is taken.
    assert!(call(&mut svc, 2).await.unwrap_err().is_open());
    drop(probe);
    // Dropping the in-flight probe released it: a new probe may start.
    let probe = svc.ready().await.unwrap().call(3);
    drop(probe);
    assert_eq!(circuit.state(), State::HalfOpen);
}

#[tokio::test]
async fn http_classifier_counts_5xx_but_not_4xx() {
    let clock = ManualClock::new();
    let status = Arc::new(Mutex::new(http::StatusCode::OK));
    let s = Arc::clone(&status);
    let inner = service_fn(move |_: http::Request<()>| {
        let code = *s.lock().unwrap();
        async move {
            let mut res = http::Response::new(());
            *res.status_mut() = code;
            Ok::<_, std::convert::Infallible>(res)
        }
    });
    let layer = CircuitBreakerLayer::new(config())
        .clock(clock)
        .classify(ServerErrors);
    let circuit = layer.handle();
    let mut svc = layer.layer(inner);

    *status.lock().unwrap() = http::StatusCode::NOT_FOUND;
    for _ in 0..10 {
        let res = svc
            .ready()
            .await
            .unwrap()
            .call(http::Request::new(()))
            .await;
        assert_eq!(res.unwrap().status(), http::StatusCode::NOT_FOUND);
    }
    assert_eq!(circuit.state(), State::Closed);

    *status.lock().unwrap() = http::StatusCode::BAD_GATEWAY;
    for _ in 0..10 {
        let _ = svc
            .ready()
            .await
            .unwrap()
            .call(http::Request::new(()))
            .await;
    }
    assert_eq!(circuit.state(), State::Open);
}

#[tokio::test]
async fn closure_classifier_and_manual_controls() {
    let layer = CircuitBreakerLayer::new(config().minimum_calls(1).window(1))
        .classify(|r: &Result<u32, &'static str>| matches!(r, Ok(0) | Err(_)));
    let circuit = layer.handle();
    let mut svc = layer.layer(service_fn(|n: u32| async move { Ok::<_, &'static str>(n) }));
    assert!(call(&mut svc, 7).await.is_ok());
    assert_eq!(circuit.state(), State::Closed);
    assert!(call(&mut svc, 0).await.is_ok());
    assert_eq!(circuit.state(), State::Open);
    circuit.reset();
    assert_eq!(circuit.state(), State::Closed);
    assert!(format!("{circuit:?}").contains("Closed"));
}
