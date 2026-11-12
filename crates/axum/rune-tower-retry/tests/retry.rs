//! Integration tests: retries, budget, request cloning, hedging, and
//! composition with the circuit breaker.
//!
//! Tokio's paused clock drives time, so the tests need no real sleeps.

#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]

use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use http::{Method, Request, Response, StatusCode};
use rune_tower_circuitbreaker::{CircuitBreaker, CircuitBreakerLayer, State};
use rune_tower_retry::{
    Backoff, Hedge, IdempotentBodiless, IdempotentHttp, Retry, RetryBudget, RetryLayer,
    TransientHttp,
};
use tokio::time::{Instant, sleep};
use tower::{Layer, Service, ServiceExt, service_fn};

const MS: fn(u64) -> Duration = Duration::from_millis;

/// A backend whose `n`-th call (0-based) answers as `script(n, req)` says,
/// after the latency it says.
#[derive(Clone)]
struct Scripted {
    calls: Arc<AtomicUsize>,
    dropped: Arc<AtomicUsize>,
}

/// Counts futures dropped before completing.
struct DropGuard(Arc<AtomicUsize>, bool);

impl DropGuard {
    const fn disarm(&mut self) {
        self.1 = true;
    }
}

impl Drop for DropGuard {
    fn drop(&mut self) {
        if !self.1 {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
}

impl Scripted {
    fn new() -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            dropped: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    /// A `u32 -> Result<u32, &str>` service.
    fn numbers<F>(
        &self,
        script: F,
    ) -> impl Service<u32, Response = u32, Error = &'static str, Future: Send> + Clone + use<F>
    where
        F: Fn(usize, u32) -> (Duration, Result<u32, &'static str>) + Clone + Send + Sync + 'static,
    {
        self.service(script)
    }

    fn cancelled(&self) -> usize {
        self.dropped.load(Ordering::SeqCst)
    }

    fn service<F, Req, T, E>(
        &self,
        script: F,
    ) -> impl Service<Req, Response = T, Error = E, Future: Send> + Clone + use<F, Req, T, E>
    where
        F: Fn(usize, Req) -> (Duration, Result<T, E>) + Clone + Send + Sync + 'static,
        Req: Send + 'static,
        T: Send + 'static,
        E: Send + 'static,
    {
        let this = self.clone();
        service_fn(move |req: Req| {
            let n = this.calls.fetch_add(1, Ordering::SeqCst);
            let (latency, out) = script(n, req);
            let mut guard = DropGuard(Arc::clone(&this.dropped), false);
            async move {
                sleep(latency).await;
                guard.disarm();
                out
            }
        })
    }
}

fn fast_retry() -> Retry {
    Retry::new().backoff(Backoff::constant(MS(10))).no_budget()
}

#[tokio::test(start_paused = true)]
async fn retries_transient_errors_until_success() {
    let backend = Scripted::new();
    let layer = RetryLayer::new(fast_retry());
    let stats = layer.handle();
    let svc = layer
        .layer(backend.numbers(|n, req: u32| (MS(1), if n < 2 { Err("reset") } else { Ok(req) })));
    let started = Instant::now();
    assert_eq!(svc.oneshot(7).await, Ok(7));
    assert_eq!(backend.calls(), 3);
    // Two 1 ms failures, two 10 ms backoffs, one 1 ms success.
    assert_eq!(started.elapsed(), MS(23));
    let s = stats.stats();
    assert_eq!((s.requests, s.retries, s.exhausted), (1, 2, 0));
}

#[tokio::test(start_paused = true)]
async fn gives_up_after_max_attempts_with_last_error() {
    let backend = Scripted::new();
    let layer = RetryLayer::new(fast_retry().max_attempts(4));
    let stats = layer.handle();
    let svc = layer.layer(backend.numbers(|n, _: u32| (MS(1), Err(["a", "b", "c", "d", "e"][n]))));
    assert_eq!(svc.oneshot(0).await, Err("d"));
    assert_eq!(backend.calls(), 4);
    assert_eq!(stats.stats().exhausted, 1);
}

#[tokio::test(start_paused = true)]
async fn permanent_failures_are_not_retried() {
    let backend = Scripted::new();
    let svc = RetryLayer::new(fast_retry())
        .classify(|r: &Result<u32, &'static str>| matches!(r, Err("timeout")))
        .layer(backend.numbers(|_, _: u32| (MS(1), Err("bad request"))));
    assert_eq!(svc.oneshot(0).await, Err("bad request"));
    assert_eq!(backend.calls(), 1);
}

#[tokio::test(start_paused = true)]
async fn budget_stops_a_retry_storm() {
    let backend = Scripted::new();
    let layer = RetryLayer::new(
        fast_retry()
            .max_attempts(5)
            .budget(RetryBudget::new().min_per_sec(0).ratio(0.5)),
    );
    let stats = layer.handle();
    let svc = layer.layer(backend.numbers(|_, _: u32| (MS(1), Err("down"))));
    for _ in 0..10 {
        assert_eq!(svc.clone().oneshot(0).await, Err("down"));
    }
    // 10 requests earn 5 retries in total, not 40.
    assert_eq!(backend.calls(), 15);
    let s = stats.stats();
    assert_eq!(s.retries, 5);
    assert!(s.budget_denied > 0);
    assert_eq!(stats.budget_remaining(), Some(0));
}

fn http_backend(
    backend: &Scripted,
    statuses: &'static [u16],
) -> impl Service<Request<String>, Response = Response<String>, Error = Infallible, Future: Send>
+ Clone
+ use<> {
    backend.service(move |n, req: Request<String>| {
        let status = statuses[n.min(statuses.len() - 1)];
        let mut res = Response::new(req.into_body());
        *res.status_mut() = StatusCode::from_u16(status).unwrap();
        (MS(1), Ok::<_, Infallible>(res))
    })
}

fn request(method: Method, body: &str) -> Request<String> {
    Request::builder()
        .method(method)
        .uri("http://svc.internal/items")
        .header("x-trace", "abc")
        .body(body.to_owned())
        .unwrap()
}

#[tokio::test(start_paused = true)]
async fn transient_http_statuses_are_retried_with_the_same_request() {
    let backend = Scripted::new();
    let svc = RetryLayer::new(fast_retry())
        .classify(TransientHttp)
        .clone_requests(IdempotentHttp)
        .layer(http_backend(&backend, &[503, 502, 200]));
    let res = svc.oneshot(request(Method::PUT, "payload")).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    // The replayed copy carried the original body.
    assert_eq!(res.body(), "payload");
    assert_eq!(backend.calls(), 3);
}

#[tokio::test(start_paused = true)]
async fn server_errors_and_client_errors_are_final() {
    for status in [500, 429, 404] {
        let backend = Scripted::new();
        let statuses: &'static [u16] = Box::leak(vec![status, 200].into_boxed_slice());
        let svc = RetryLayer::new(fast_retry())
            .classify(TransientHttp)
            .clone_requests(IdempotentHttp)
            .layer(http_backend(&backend, statuses));
        let res = svc.oneshot(request(Method::GET, "")).await.unwrap();
        assert_eq!(res.status().as_u16(), status);
        assert_eq!(backend.calls(), 1);
    }
}

#[tokio::test(start_paused = true)]
async fn non_idempotent_requests_are_sent_once() {
    for method in [Method::POST, Method::PATCH] {
        let backend = Scripted::new();
        let svc = RetryLayer::new(fast_retry())
            .classify(TransientHttp)
            .clone_requests(IdempotentHttp)
            .layer(http_backend(&backend, &[503, 200]));
        let res = svc.oneshot(request(method, "x")).await.unwrap();
        assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(backend.calls(), 1);
    }
}

#[tokio::test(start_paused = true)]
async fn bodiless_cloner_only_replays_empty_bodies() {
    for (body, calls) in [("", 2), ("streamed", 1)] {
        let backend = Scripted::new();
        let svc = RetryLayer::new(fast_retry())
            .classify(TransientHttp)
            .clone_requests(IdempotentBodiless)
            .layer(http_backend(&backend, &[503, 200]));
        let _ = svc.oneshot(request(Method::GET, body)).await.unwrap();
        assert_eq!(backend.calls(), calls, "body {body:?}");
    }
}

#[tokio::test(start_paused = true)]
async fn hedge_wins_and_cancels_the_slow_attempt() {
    let backend = Scripted::new();
    let layer = RetryLayer::new(fast_retry().hedge(Hedge::after(MS(50))));
    let stats = layer.handle();
    let svc = layer.layer(backend.numbers(|n, req: u32| {
        let latency = if n == 0 { MS(1_000) } else { MS(10) };
        (latency, Ok(req + u32::try_from(n).unwrap()))
    }));
    let started = Instant::now();
    // The hedge (call 1) answers first.
    assert_eq!(svc.oneshot(100).await, Ok(101));
    assert_eq!(started.elapsed(), MS(60));
    assert_eq!(backend.calls(), 2);
    // The loser's future was dropped, not left running.
    assert_eq!(backend.cancelled(), 1);
    assert_eq!(stats.stats().hedges, 1);
}

#[tokio::test(start_paused = true)]
async fn fast_calls_are_not_hedged() {
    let backend = Scripted::new();
    let svc = RetryLayer::new(fast_retry().hedge(Hedge::after(MS(50))))
        .layer(backend.numbers(|_, req: u32| (MS(5), Ok(req))));
    assert_eq!(svc.oneshot(1).await, Ok(1));
    assert_eq!(backend.calls(), 1);
}

#[tokio::test(start_paused = true)]
async fn hedges_respect_the_budget() {
    let backend = Scripted::new();
    let layer = RetryLayer::new(
        Retry::new()
            .budget(RetryBudget::new().min_per_sec(0).ratio(0.0))
            .hedge(Hedge::after(MS(50))),
    );
    let stats = layer.handle();
    let svc = layer.layer(backend.numbers(|_, req: u32| (MS(200), Ok(req))));
    assert_eq!(svc.oneshot(1).await, Ok(1));
    assert_eq!(backend.calls(), 1);
    assert_eq!(stats.stats().budget_denied, 1);
}

#[tokio::test(start_paused = true)]
async fn failed_hedge_waits_for_the_original() {
    let backend = Scripted::new();
    let svc = RetryLayer::new(fast_retry().max_attempts(2).hedge(Hedge::after(MS(50)))).layer(
        backend.numbers(|n, req: u32| {
            if n == 0 {
                (MS(100), Ok(req))
            } else {
                (MS(1), Err("hedge failed"))
            }
        }),
    );
    assert_eq!(svc.oneshot(9).await, Ok(9));
    assert_eq!(backend.calls(), 2);
}

#[tokio::test(start_paused = true)]
async fn hedged_then_retried() {
    // Attempt 0 and its hedge both fail; a retry succeeds.
    let backend = Scripted::new();
    let svc = RetryLayer::new(fast_retry().hedge(Hedge::after(MS(5)))).layer(backend.numbers(
        |n, req: u32| match n {
            0 => (MS(20), Err("slow failure")),
            1 => (MS(1), Err("fast failure")),
            _ => (MS(1), Ok(req)),
        },
    ));
    assert_eq!(svc.oneshot(3).await, Ok(3));
    assert_eq!(backend.calls(), 3);
}

#[tokio::test(start_paused = true)]
async fn dropping_the_call_mid_backoff_is_clean() {
    let backend = Scripted::new();
    let svc = RetryLayer::new(
        Retry::new()
            .backoff(Backoff::constant(MS(1_000)))
            .no_budget(),
    )
    .layer(backend.numbers(|_, _: u32| (MS(1), Err("down"))));
    let res = tokio::time::timeout(MS(100), svc.oneshot(0)).await;
    assert!(res.is_err());
    assert_eq!(backend.calls(), 1);
}

#[tokio::test(start_paused = true)]
async fn composes_with_the_circuit_breaker() {
    let backend = Scripted::new();
    let breaker = CircuitBreakerLayer::new(
        CircuitBreaker::new()
            .window(4)
            .minimum_calls(4)
            .open_duration(Duration::from_secs(30)),
    );
    let circuit = breaker.handle();
    // Retry outside the breaker; never retry the breaker's fast rejections.
    let retry = RetryLayer::new(fast_retry().max_attempts(3)).classify(
        |r: &Result<u32, rune_tower_circuitbreaker::Error<&'static str>>| {
            matches!(r, Err(e) if !e.is_open())
        },
    );
    let svc = retry.layer(breaker.layer(backend.numbers(|_, _: u32| (MS(1), Err("down")))));

    // Two requests × up to three attempts: the fourth attempt trips the
    // circuit, the fifth is rejected fast and not retried.
    let first = svc.clone().oneshot(0).await.unwrap_err();
    assert!(!first.is_open());
    let second = svc.clone().oneshot(0).await.unwrap_err();
    assert!(second.is_open());
    assert_eq!(backend.calls(), 4);
    assert_eq!(circuit.state(), State::Open);

    let third = svc.oneshot(0).await.unwrap_err();
    assert!(third.is_open());
    assert_eq!(backend.calls(), 4);
}
