//! Observability: events emitted by [`RetryLlm`](crate::RetryLlm) and
//! [`Router`](crate::Router).

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use rune_chain_core::LlmError;

use crate::ErrorClass;

/// State of a provider's circuit breaker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BreakerState {
    /// Healthy: requests flow normally.
    Closed,
    /// Too many consecutive failures: requests skip this provider until the
    /// open period ends.
    Open,
    /// The open period ended: one probe request is let through; its outcome
    /// closes or re-opens the breaker.
    HalfOpen,
}

/// Why a [`Router`](crate::Router) did not try a provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SkipReason {
    /// Its circuit breaker is open (or half-open with a probe in flight).
    BreakerOpen,
    /// It is cooling down after a rate limit.
    CoolingDown,
    /// The estimated prompt does not fit its context window.
    ContextTooSmall,
}

/// Something that happened while serving a request.
///
/// `provider` names come from [`RetryLlm::name`](crate::RetryLlm::name) or
/// [`Provider::new`](crate::Provider::new). Attempts are numbered from 1
/// per provider.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Event {
    /// An attempt is about to be sent.
    AttemptStarted {
        /// Provider name.
        provider: Arc<str>,
        /// Attempt number (1-based).
        attempt: u32,
    },
    /// An attempt succeeded (for streams: the first chunk arrived).
    AttemptSucceeded {
        /// Provider name.
        provider: Arc<str>,
        /// Attempt number (1-based).
        attempt: u32,
        /// Time the attempt took (time to first chunk for streams).
        latency: Duration,
    },
    /// An attempt failed.
    AttemptFailed {
        /// Provider name.
        provider: Arc<str>,
        /// Attempt number (1-based).
        attempt: u32,
        /// How the error was classified.
        class: ErrorClass,
        /// The error.
        error: LlmError,
    },
    /// A retry of the same provider was scheduled after `delay`.
    RetryScheduled {
        /// Provider name.
        provider: Arc<str>,
        /// Number of the upcoming attempt.
        attempt: u32,
        /// Backoff before it.
        delay: Duration,
    },
    /// The router gave up on `from` and moves on to `to`.
    Fallback {
        /// Provider that failed.
        from: Arc<str>,
        /// Provider tried next.
        to: Arc<str>,
        /// Class of the failure that caused the fallback.
        class: ErrorClass,
    },
    /// The router skipped a provider without calling it.
    ProviderSkipped {
        /// Provider name.
        provider: Arc<str>,
        /// Why.
        reason: SkipReason,
    },
    /// A provider's circuit breaker changed state.
    BreakerStateChanged {
        /// Provider name.
        provider: Arc<str>,
        /// Previous state.
        from: BreakerState,
        /// New state.
        to: BreakerState,
    },
    /// A provider was put in a cooldown after a rate limit.
    CooldownStarted {
        /// Provider name.
        provider: Arc<str>,
        /// Length of the cooldown.
        duration: Duration,
    },
}

/// A callback receiving [`Event`]s. It runs synchronously on the request's
/// task, so keep it cheap (log, bump a metric, push to a channel).
pub type Observer = Arc<dyn Fn(&Event) + Send + Sync>;

/// A list of observers.
#[derive(Clone, Default)]
pub struct Observers(Vec<Observer>);

impl Observers {
    pub const fn new() -> Self {
        Self(Vec::new())
    }

    pub fn push(&mut self, o: Observer) {
        self.0.push(o);
    }

    pub fn emit(&self, event: impl FnOnce() -> Event) {
        if self.0.is_empty() {
            return;
        }
        let event = event();
        for o in &self.0 {
            o(&event);
        }
    }
}

impl fmt::Debug for Observers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} observer(s)", self.0.len())
    }
}
