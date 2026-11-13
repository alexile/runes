# rune-tower-retry

> Retry and hedging layer for Tower clients — backoff with jitter, a retry budget, and request hedging for idempotent calls.

[![crates.io](https://img.shields.io/crates/v/rune-tower-retry)](https://crates.io/crates/rune-tower-retry)
[![docs.rs](https://img.shields.io/docsrs/rune-tower-retry)](https://docs.rs/rune-tower-retry)
[![license](https://img.shields.io/crates/l/rune-tower-retry)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

A [`tower::Layer`](https://docs.rs/tower/latest/tower/trait.Layer.html) for outbound clients that retries transient failures and hedges slow calls, without turning an outage into a retry storm:

- **Retries on retriable failures only.** A pluggable classifier decides what is transient: `ErrorsOnly` (default), `TransientHttp` (errors, `502`, `503`, `504`) or a closure. Everything else returns at once.
- **Only replayable requests.** A request cloner makes the copies retries send, and decides which requests may be repeated at all: `CloneAll` (default), `IdempotentHttp` (idempotent methods, cloned body), `IdempotentBodiless` (idempotent methods with an empty, non-`Clone` body such as `axum::body::Body`) or a closure. `CloneAll` replays any method, `POST` included, so HTTP clients want `IdempotentHttp` or `IdempotentBodiless`.
- **Backoff with jitter** between attempts: exponential or constant, with full, equal or no jitter.
- **A retry budget** limits retries and hedges to a share of recent traffic.
- **Hedging.** A call still pending after a fixed delay, or after a latency percentile of recent calls, is sent again. The first answer wins; the loser's future is dropped, which cancels it.

The decisions live in a sans-I/O core (`Retrier`, `Budget`) driven by explicit instants, so they can be embedded anywhere and tested without sleeping. The layer takes an injectable `Clock` (Tokio's by default, which follows paused test time).

## Installation

```toml
[dependencies]
rune-tower-retry = "0.1"
```

## Usage

### HTTP client

```rust
use std::time::Duration;
use rune_tower_retry::{Backoff, Hedge, IdempotentHttp, Retry, RetryBudget, RetryLayer, TransientHttp};
use tower::ServiceBuilder;

let layer = RetryLayer::new(
    Retry::new()
        .max_attempts(3)                                        // first try, retries and hedges
        .backoff(Backoff::exponential(Duration::from_millis(50)).max(Duration::from_secs(2)))
        .budget(RetryBudget::new().min_per_sec(10).ratio(0.2))  // ≤ 10/s + 20 % of requests
        .hedge(Hedge::at_percentile(0.95, Duration::from_millis(200))),
)
.classify(TransientHttp)        // errors, 502, 503, 504
.clone_requests(IdempotentHttp); // never replays POST or PATCH
let retries = layer.handle();

let client = ServiceBuilder::new().layer(layer).service(http_client);
```

One layer is one budget: every service it builds, and every clone of them, shares the retry budget, latency window and counters. Use one layer per downstream dependency. The inner service must be `Clone`.

### With a circuit breaker

Put the retry layer outside [`rune-tower-circuitbreaker`](../rune-tower-circuitbreaker), so the breaker records every attempt, and don't retry its fail-fast rejections:

```rust
use rune_tower_circuitbreaker::{CircuitBreaker, CircuitBreakerLayer, Error};
use rune_tower_retry::{Retry, RetryLayer};

let client = ServiceBuilder::new()
    .layer(RetryLayer::new(Retry::new()).classify(
        |r: &Result<Reply, Error<MyError>>| matches!(r, Err(e) if !e.is_open()),
    ))
    .layer(CircuitBreakerLayer::new(CircuitBreaker::new()))
    .service(transport);
```

### Sans-I/O core

```rust
use std::time::{Duration, Instant};
use rune_tower_retry::{Backoff, Decision, Retrier, Retry};

let mut retrier = Retrier::new(Retry::new().backoff(Backoff::constant(Duration::from_millis(10))));
let now = Instant::now();
let mut call = retrier.begin(now);
if let Decision::Retry { after } = retrier.on_failure(&mut call, now) {
    // wait `after`, then send the next attempt
}
```

### Metrics

`layer.handle()` (or `service.handle()`) returns a `RetryHandle` with `stats()` (requests, retries, hedges, exhausted, budget-denied) and `budget_remaining()`.

## Configuration

| Method | Default | Description |
|--------|---------|-------------|
| `.max_attempts(u32)` | `3` | Calls per request to the inner service: first attempt, retries and hedges. |
| `.backoff(Backoff)` | exponential from 50 ms, ×2, ≤ 5 s, full jitter | Delay before each retry. |
| `.budget(RetryBudget)` | 10/s + 20 % of requests over 10 s | Caps retries and hedges. |
| `.no_budget()` | — | Only `max_attempts` limits retries. |
| `.hedge(Hedge)` | off | `Hedge::after(d)` or `Hedge::at_percentile(p, fallback)`, with `.max_hedges(n)`, `.latency_window(n)`, `.min_samples(n)`. |

Layer options: `.classify(c)`, `.clone_requests(r)`, `.clock(c)` (any `Clock`), `.seed(u64)` (reproducible jitter).

## Behaviour notes

- When retries run out, or the budget is spent, the last failure is returned unchanged; responses and errors are never wrapped.
- A hedge that fails retriably does not end the call while another attempt is still in flight; the call retries only after every attempt in flight has failed.
- Dropping the response future cancels every attempt in flight and any pending backoff.
- Each retry or hedge waits for a clone of the inner service to be ready (`poll_ready`) before it is sent.

## License

MIT
