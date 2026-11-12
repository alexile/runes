# rune-tower-circuitbreaker

> Circuit-breaker layer for Tower clients — opens on error-rate or slow-call-rate thresholds, probes in half-open, closes on recovery.

[![crates.io](https://img.shields.io/crates/v/rune-tower-circuitbreaker)](https://crates.io/crates/rune-tower-circuitbreaker)
[![docs.rs](https://img.shields.io/docsrs/rune-tower-circuitbreaker)](https://docs.rs/rune-tower-circuitbreaker)
[![license](https://img.shields.io/crates/l/rune-tower-circuitbreaker)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

A [`tower::Layer`](https://docs.rs/tower/latest/tower/trait.Layer.html) for outbound clients that stops calling a dependency that is failing or too slow, gives it time to recover, then probes it before sending full traffic again.

```
            failure or slow-call rate >= threshold
  Closed ─────────────────────────────────────────▶ Open ◀───┐
    ▲                                                 │       │ a probe fails
    │ all probes succeed                 open_duration│       │ or is slow
    │                                                 ▼       │
    └──────────────────────────────────────────── Half-open ──┘
```

- **Closed.** Calls flow. Outcomes go into a count-based sliding window; once it holds `minimum_calls`, a failure rate or slow-call rate at or above its threshold opens the circuit.
- **Open.** Calls fail fast with `Error::Open { retry_after }` and never reach the inner service.
- **Half-open.** After `open_duration`, up to `half_open_probes` probe calls go through. If they all succeed quickly, the circuit closes with a fresh window; the first failed or slow probe opens it again.

The state machine is a sans-I/O core (`Breaker`) driven by explicit instants, so it can be embedded anywhere and tested without sleeping. Works with any Tower service and needs no particular async runtime.

## Installation

```toml
[dependencies]
rune-tower-circuitbreaker = "0.1"
```

## Usage

### HTTP client

```rust
use std::time::Duration;
use rune_tower_circuitbreaker::{CircuitBreaker, CircuitBreakerLayer, ServerErrors};
use tower::ServiceBuilder;

let layer = CircuitBreakerLayer::new(
    CircuitBreaker::new()
        .failure_rate(0.5)                                // 50 % of the window failed
        .slow_calls(Duration::from_secs(2), 0.8)          // or 80 % took >= 2 s
        .window(100)
        .minimum_calls(20)
        .open_duration(Duration::from_secs(15))
        .half_open_probes(3),
)
.classify(ServerErrors); // errors and 5xx are failures; 4xx are not
let circuit = layer.handle();

let client = ServiceBuilder::new().layer(layer).service(http_client);
```

One layer is one circuit: every service it builds, and every clone of them, shares the same breaker. Use one layer per downstream dependency.

### Handling rejections

```rust
use rune_tower_circuitbreaker::Error;

match client.ready().await?.call(request).await {
    Ok(response) => { /* … */ }
    Err(Error::Open { retry_after }) => { /* fail fast, serve a fallback */ }
    Err(Error::Inner(e)) => { /* the dependency itself failed */ }
    Err(_) => { /* future variants */ }
}
```

### Custom classification

```rust
let layer = CircuitBreakerLayer::new(CircuitBreaker::new())
    .classify(|r: &Result<Reply, MyError>| matches!(r, Err(e) if e.is_transient()));
```

### Observing and overriding

`layer.handle()` (or `service.handle()`) returns a `CircuitHandle` with `state()`, `snapshot()` (state, window size, failure and slow-call rates), `trip()` and `reset()`.

## Configuration

| Method | Default | Description |
|--------|---------|-------------|
| `.failure_rate(f64)` | `0.5` | Failure share of the window that opens the circuit. |
| `.slow_calls(Duration, f64)` | 10 s, `0.5` | Calls at least this long are slow; this slow share opens the circuit. |
| `.no_slow_calls()` | — | Never open on latency alone. |
| `.window(usize)` | `100` | Number of most recent calls the rates cover. |
| `.minimum_calls(usize)` | `20` | Calls the window needs before it may open (capped at the window). |
| `.open_duration(Duration)` | 30 s | Time the circuit stays open before probing. |
| `.half_open_probes(u32)` | `3` | Concurrent probes allowed, and successes needed to close. |

Layer options: `.classify(c)` (`ErrorsOnly` by default, `ServerErrors`, or a closure) and `.clock(c)` (any `Clock`; `SystemClock` by default).

## Behaviour notes

- Outcomes of calls that started before a state change (for example, a slow call that finishes after the circuit opened) are ignored.
- A probe whose future is dropped before completing frees its slot, so cancellation cannot wedge the circuit half-open.
- Latency is measured from `call` until the inner future resolves, with the layer's clock.

## License

MIT
