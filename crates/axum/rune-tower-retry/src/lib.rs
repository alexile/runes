//! Retry and hedging layer for Tower clients.
//!
//! A [`tower::Layer`] that makes calls to a flaky or slow dependency more
//! reliable without overwhelming it:
//!
//! - **Retries on retriable failures only.** A pluggable [`Classify`]-er
//!   decides what is transient ([`ErrorsOnly`] by default,
//!   [`TransientHttp`] for `502`/`503`/`504`); everything else returns at
//!   once.
//! - **Only replayable requests.** A [`CloneRequest`]-er makes the copies
//!   retries send and decides which requests may be repeated at all
//!   ([`CloneAll`], [`IdempotentHttp`], [`IdempotentBodiless`]).
//! - **Backoff with jitter** ([`Backoff`], [`Jitter`]) between attempts.
//! - **A retry budget** ([`RetryBudget`]) caps retries at a share of recent
//!   traffic, so an outage does not turn into a retry storm.
//! - **Hedging** ([`Hedge`]): a call that has not answered after a fixed
//!   delay, or after a latency percentile, is sent again; the first answer
//!   wins and the loser is cancelled.
//!
//! The decisions live in a sans-I/O core, [`Retrier`] (with [`Budget`]),
//! driven by explicit instants. [`RetryLayer`] wraps it for any `Clone`
//! Tower service, with an injectable [`Clock`] ([`TokioClock`] by default).
//!
//! # Quick Start
//!
//! ```rust
//! use std::time::{Duration, Instant};
//! use rune_tower_retry::{Backoff, Decision, GiveUp, Jitter, Retrier, Retry};
//!
//! let mut retrier = Retrier::new(
//!     Retry::new()
//!         .max_attempts(3)
//!         .backoff(Backoff::exponential(Duration::from_millis(100)).jitter(Jitter::None)),
//! );
//! let now = Instant::now();
//! let mut call = retrier.begin(now);
//! assert_eq!(
//!     retrier.on_failure(&mut call, now),
//!     Decision::Retry { after: Duration::from_millis(100) },
//! );
//! assert_eq!(
//!     retrier.on_failure(&mut call, now),
//!     Decision::Retry { after: Duration::from_millis(200) },
//! );
//! assert_eq!(retrier.on_failure(&mut call, now), Decision::GiveUp(GiveUp::Attempts));
//! ```
//!
//! # Tower
//!
//! ```rust
//! use std::sync::Arc;
//! use std::sync::atomic::{AtomicU32, Ordering};
//! use std::time::Duration;
//! use rune_tower_retry::{Backoff, Retry, RetryLayer};
//! use tower::{Service, ServiceBuilder, ServiceExt};
//!
//! # tokio::runtime::Runtime::new().unwrap().block_on(async {
//! let calls = Arc::new(AtomicU32::new(0));
//! let counter = Arc::clone(&calls);
//! let mut client = ServiceBuilder::new()
//!     .layer(RetryLayer::new(Retry::new().backoff(Backoff::constant(Duration::from_millis(1)))))
//!     .service_fn(move |req: u32| {
//!         let n = counter.fetch_add(1, Ordering::SeqCst);
//!         async move { if n == 0 { Err("connection reset") } else { Ok(req * 2) } }
//!     });
//!
//! assert_eq!(client.ready().await.unwrap().call(21).await, Ok(42));
//! assert_eq!(calls.load(Ordering::SeqCst), 2);
//! # });
//! ```
//!
//! # With a circuit breaker
//!
//! Put the retry layer **outside** `rune-tower-circuitbreaker`'s layer, so
//! every attempt is recorded by the breaker, and do not retry the
//! breaker's fail-fast rejections:
//!
//! ```rust
//! use rune_tower_circuitbreaker::{CircuitBreaker, CircuitBreakerLayer, Error};
//! use rune_tower_retry::{Retry, RetryLayer};
//! use tower::ServiceBuilder;
//!
//! let client = ServiceBuilder::new()
//!     .layer(RetryLayer::new(Retry::new()).classify(
//!         |r: &Result<u32, Error<std::io::Error>>| matches!(r, Err(e) if !e.is_open()),
//!     ))
//!     .layer(CircuitBreakerLayer::new(CircuitBreaker::new()))
//!     .service_fn(|req: u32| async move { Ok::<_, std::io::Error>(req) });
//! # let _ = client;
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub use layer::{
    Classify, Clock, CloneAll, CloneRequest, ErrorsOnly, IdempotentBodiless, IdempotentHttp,
    RetryHandle, RetryLayer, RetryService, Sleep, TokioClock, TransientHttp,
};
pub use policy::{Backoff, Hedge, Jitter, Retry, RetryBudget};
pub use retrier::{Budget, Call, Decision, GiveUp, Retrier, Stats};

mod layer;
mod policy;
mod retrier;
