//! Circuit-breaker layer for Tower clients.
//!
//! A [`tower::Layer`] that stops calling a dependency that is failing or
//! too slow, gives it time to recover, and then probes it carefully before
//! sending full traffic again:
//!
//! - **Closed.** Calls flow. Outcomes go into a count-based sliding window;
//!   once it holds enough calls, a failure rate or slow-call rate at or
//!   above its threshold opens the circuit.
//! - **Open.** Calls fail fast with [`Error::Open`] (carrying a
//!   `retry_after` hint) without touching the inner service.
//! - **Half-open.** After the open duration, a few probe calls go through.
//!   If they all succeed quickly the circuit closes with a fresh window;
//!   the first failed or slow probe opens it again.
//!
//! The state machine is a sans-I/O core, [`Breaker`], driven by explicit
//! instants. [`CircuitBreakerLayer`] wraps it for any Tower service, with a
//! pluggable failure [`Classify`]-er ([`ErrorsOnly`] by default,
//! [`ServerErrors`] for HTTP clients) and an injectable [`Clock`].
//!
//! # Quick Start
//!
//! ```rust
//! use std::time::{Duration, Instant};
//! use rune_tower_circuitbreaker::{Breaker, CircuitBreaker, State};
//!
//! let mut breaker = Breaker::new(CircuitBreaker::new().window(10).minimum_calls(10));
//! let now = Instant::now();
//! for _ in 0..10 {
//!     let permit = breaker.try_acquire(now).unwrap();
//!     breaker.record(permit, true, Duration::from_millis(3), now);
//! }
//! assert_eq!(breaker.state(now), State::Open);
//! assert_eq!(
//!     breaker.try_acquire(now).unwrap_err().retry_after(),
//!     Duration::from_secs(30),
//! );
//! ```
//!
//! # Tower
//!
//! ```rust
//! use std::time::Duration;
//! use rune_tower_circuitbreaker::{CircuitBreaker, CircuitBreakerLayer, Error, State};
//! use tower::{Service, ServiceBuilder, ServiceExt};
//!
//! # tokio::runtime::Runtime::new().unwrap().block_on(async {
//! let layer = CircuitBreakerLayer::new(
//!     CircuitBreaker::new().window(4).minimum_calls(4).open_duration(Duration::from_secs(60)),
//! );
//! let circuit = layer.handle();
//! let mut client = ServiceBuilder::new()
//!     .layer(layer)
//!     .service_fn(|_: ()| async { Err::<(), _>("connection refused") });
//!
//! for _ in 0..4 {
//!     let _ = client.ready().await.unwrap().call(()).await;
//! }
//! assert_eq!(circuit.state(), State::Open);
//! let err = client.ready().await.unwrap().call(()).await.unwrap_err();
//! assert!(err.is_open());
//! # });
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::time::Duration;

pub use breaker::{Breaker, CircuitBreaker, Permit, Rejected, Snapshot, State};
pub use layer::{
    CircuitBreakerLayer, CircuitBreakerService, CircuitHandle, Classify, Clock, ErrorsOnly,
    ServerErrors, SystemClock,
};

mod breaker;
mod layer;

/// Errors returned by [`CircuitBreakerService`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error<E> {
    /// The circuit is open (or half-open with every probe slot taken); the
    /// inner service was not called.
    #[error("circuit breaker is open; retry after {retry_after:?}")]
    Open {
        /// How long until the circuit lets probes through.
        retry_after: Duration,
    },
    /// The inner service failed.
    #[error("inner service error: {0}")]
    Inner(E),
}

impl<E> Error<E> {
    /// Whether the call was rejected by the circuit.
    #[must_use]
    pub const fn is_open(&self) -> bool {
        matches!(self, Self::Open { .. })
    }

    /// The inner service's error, if the call reached it.
    #[must_use]
    pub fn into_inner(self) -> Option<E> {
        match self {
            Self::Inner(e) => Some(e),
            Self::Open { .. } => None,
        }
    }
}
