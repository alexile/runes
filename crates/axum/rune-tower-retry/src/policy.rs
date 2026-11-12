//! Retry configuration: attempts, backoff, budget and hedging.

use std::time::Duration;

/// Default number of attempts per call, the first one included.
const DEFAULT_MAX_ATTEMPTS: u32 = 3;
/// Default delay before the first retry.
const DEFAULT_INITIAL_BACKOFF: Duration = Duration::from_millis(50);
/// Default cap on any single backoff delay.
const DEFAULT_MAX_BACKOFF: Duration = Duration::from_secs(5);
/// Default growth factor between consecutive backoff delays.
const DEFAULT_MULTIPLIER: f64 = 2.0;
/// Default time span the retry budget covers.
const DEFAULT_BUDGET_TTL: Duration = Duration::from_secs(10);
/// Default retries per second always allowed, regardless of traffic.
const DEFAULT_MIN_RETRIES_PER_SEC: u32 = 10;
/// Default share of recent requests that may be retried on top of the floor.
const DEFAULT_RETRY_RATIO: f64 = 0.2;
/// Default number of recent latencies a percentile hedge delay is computed over.
const DEFAULT_LATENCY_WINDOW: usize = 128;
/// Default number of latencies needed before a percentile hedge delay applies.
const DEFAULT_MIN_SAMPLES: usize = 20;

/// How a backoff delay is randomised, to keep many clients from retrying in
/// lock-step.
///
/// See "Exponential Backoff And Jitter" (AWS Architecture Blog, 2015).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Jitter {
    /// Exactly the computed delay.
    None,
    /// Uniform in `[0, delay)`: the best spread, the default.
    #[default]
    Full,
    /// Uniform in `[delay / 2, delay)`: never retries almost immediately.
    Equal,
}

/// The delay between a failed attempt and the next retry.
///
/// Retry `n` (1-based) waits `initial × multiplierⁿ⁻¹`, capped at `max`,
/// then randomised by the [`Jitter`].
///
/// # Examples
///
/// ```rust
/// use std::time::Duration;
/// use rune_tower_retry::{Backoff, Jitter};
///
/// let backoff = Backoff::exponential(Duration::from_millis(100))
///     .max(Duration::from_secs(1))
///     .jitter(Jitter::None);
/// assert_eq!(backoff.delay(1, 0.5), Duration::from_millis(100));
/// assert_eq!(backoff.delay(3, 0.5), Duration::from_millis(400));
/// assert_eq!(backoff.delay(10, 0.5), Duration::from_secs(1));
/// ```
#[derive(Clone, Copy, Debug, PartialEq)]
#[non_exhaustive]
pub struct Backoff {
    initial: Duration,
    max: Duration,
    multiplier: f64,
    jitter: Jitter,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            initial: DEFAULT_INITIAL_BACKOFF,
            max: DEFAULT_MAX_BACKOFF,
            multiplier: DEFAULT_MULTIPLIER,
            jitter: Jitter::Full,
        }
    }
}

impl Backoff {
    /// Exponential backoff from `initial`, doubling each retry up to 5 s,
    /// with [`Jitter::Full`].
    #[must_use]
    pub fn exponential(initial: Duration) -> Self {
        Self {
            initial,
            ..Self::default()
        }
    }

    /// The same `delay` before every retry, without jitter.
    #[must_use]
    pub const fn constant(delay: Duration) -> Self {
        Self {
            initial: delay,
            max: delay,
            multiplier: 1.0,
            jitter: Jitter::None,
        }
    }

    /// Retries immediately.
    #[must_use]
    pub const fn none() -> Self {
        Self::constant(Duration::ZERO)
    }

    /// Caps every delay at `max`.
    #[must_use]
    pub const fn max(mut self, max: Duration) -> Self {
        self.max = max;
        self
    }

    /// Sets the growth factor between consecutive delays (at least 1; `NaN`
    /// counts as 1).
    #[must_use]
    pub const fn multiplier(mut self, multiplier: f64) -> Self {
        self.multiplier = if multiplier.is_nan() {
            1.0
        } else {
            multiplier.max(1.0)
        };
        self
    }

    /// Sets the randomisation.
    #[must_use]
    pub const fn jitter(mut self, jitter: Jitter) -> Self {
        self.jitter = jitter;
        self
    }

    /// The delay before retry number `retry` (1-based), given `random`, a
    /// uniform sample from `[0, 1)` (values outside are clamped).
    #[must_use]
    pub fn delay(&self, retry: u32, random: f64) -> Duration {
        let exponent = i32::try_from(retry.saturating_sub(1)).unwrap_or(i32::MAX);
        let base = self.initial.as_secs_f64() * self.multiplier.powi(exponent);
        let base = Duration::try_from_secs_f64(base)
            .unwrap_or(self.max)
            .min(self.max);
        let random = if random.is_nan() {
            0.0
        } else {
            random.clamp(0.0, 1.0)
        };
        match self.jitter {
            Jitter::None => base,
            Jitter::Full => base.mul_f64(random),
            Jitter::Equal => base / 2 + (base / 2).mul_f64(random),
        }
    }
}

/// Limits retries to a share of recent traffic, so that a struggling
/// dependency is not hit by a retry storm.
///
/// Over a sliding window of `ttl`, retries (and hedges) are allowed while
/// they number fewer than `min_per_sec × ttl + ratio × requests`. With the
/// defaults, at most 10 retries per second plus 20 % of the requests seen in
/// the last 10 s.
///
/// # Examples
///
/// ```rust
/// use std::time::Duration;
/// use rune_tower_retry::RetryBudget;
///
/// let budget = RetryBudget::new()
///     .ttl(Duration::from_secs(30))
///     .min_per_sec(1)
///     .ratio(0.1);
/// # let _ = budget;
/// ```
#[derive(Clone, Copy, Debug, PartialEq)]
#[non_exhaustive]
pub struct RetryBudget {
    pub(crate) ttl: Duration,
    pub(crate) min_per_sec: u32,
    pub(crate) ratio: f64,
}

impl Default for RetryBudget {
    fn default() -> Self {
        Self {
            ttl: DEFAULT_BUDGET_TTL,
            min_per_sec: DEFAULT_MIN_RETRIES_PER_SEC,
            ratio: DEFAULT_RETRY_RATIO,
        }
    }
}

impl RetryBudget {
    /// A budget of 10 retries per second plus 20 % of requests over 10 s.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the window the budget covers (at least 1 ms).
    #[must_use]
    pub fn ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl.max(Duration::from_millis(1));
        self
    }

    /// Sets the retries per second allowed even without traffic.
    #[must_use]
    pub const fn min_per_sec(mut self, retries: u32) -> Self {
        self.min_per_sec = retries;
        self
    }

    /// Sets the share of requests that may be retried (`0.0..`, clamped at
    /// 0; `NaN` counts as 0). A ratio above 1 lets one request earn several
    /// retries.
    #[must_use]
    pub const fn ratio(mut self, ratio: f64) -> Self {
        self.ratio = if ratio.is_nan() { 0.0 } else { ratio.max(0.0) };
        self
    }
}

/// When hedges are sent.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum HedgeDelay {
    Fixed(Duration),
    Percentile { percentile: f64, fallback: Duration },
}

/// Request hedging: if an attempt has not answered after a delay, send
/// another copy and keep whichever answers first. The loser is cancelled
/// (its future dropped).
///
/// Hedging trades extra load for lower tail latency. Only hedge
/// idempotent calls; the request cloner decides which those are.
///
/// # Examples
///
/// ```rust
/// use std::time::Duration;
/// use rune_tower_retry::Hedge;
///
/// // A second copy after 50 ms.
/// let fixed = Hedge::after(Duration::from_millis(50));
/// // A second copy once the call is slower than 95 % of recent calls
/// // (100 ms until 20 latencies have been seen).
/// let adaptive = Hedge::at_percentile(0.95, Duration::from_millis(100)).max_hedges(2);
/// # let _ = (fixed, adaptive);
/// ```
#[derive(Clone, Copy, Debug, PartialEq)]
#[non_exhaustive]
pub struct Hedge {
    pub(crate) delay: HedgeDelay,
    pub(crate) max_hedges: u32,
    pub(crate) window: usize,
    pub(crate) min_samples: usize,
}

impl Hedge {
    /// Hedges calls still pending after `delay`, once.
    #[must_use]
    pub const fn after(delay: Duration) -> Self {
        Self {
            delay: HedgeDelay::Fixed(delay),
            max_hedges: 1,
            window: DEFAULT_LATENCY_WINDOW,
            min_samples: DEFAULT_MIN_SAMPLES,
        }
    }

    /// Hedges calls slower than the `percentile` (`0.0..=1.0`, clamped;
    /// `NaN` counts as 1) of recent successful calls, once. Until enough
    /// latencies are known, hedges after `fallback`.
    #[must_use]
    pub const fn at_percentile(percentile: f64, fallback: Duration) -> Self {
        let percentile = if percentile.is_nan() {
            1.0
        } else {
            percentile.clamp(0.0, 1.0)
        };
        Self {
            delay: HedgeDelay::Percentile {
                percentile,
                fallback,
            },
            ..Self::after(fallback)
        }
    }

    /// Sets how many hedges one call may send (at least 1). Each hedge is
    /// sent one delay after the previous attempt started.
    #[must_use]
    pub fn max_hedges(mut self, hedges: u32) -> Self {
        self.max_hedges = hedges.max(1);
        self
    }

    /// Sets how many recent latencies the percentile covers (at least 1).
    #[must_use]
    pub fn latency_window(mut self, calls: usize) -> Self {
        self.window = calls.max(1);
        self
    }

    /// Sets how many latencies are needed before the percentile replaces
    /// the fallback delay (at least 1).
    #[must_use]
    pub fn min_samples(mut self, calls: usize) -> Self {
        self.min_samples = calls.max(1);
        self
    }
}

/// Configuration for retrying and hedging calls.
///
/// [`max_attempts`] bounds every call made to the inner service for one
/// request: the first attempt, retries and hedges together.
///
/// [`max_attempts`]: Self::max_attempts
///
/// # Examples
///
/// ```rust
/// use std::time::Duration;
/// use rune_tower_retry::{Backoff, Hedge, Retry, RetryBudget};
///
/// let config = Retry::new()
///     .max_attempts(4)
///     .backoff(Backoff::exponential(Duration::from_millis(20)))
///     .budget(RetryBudget::new().ratio(0.1))
///     .hedge(Hedge::after(Duration::from_millis(80)));
/// assert_eq!(config.attempts(), 4);
/// ```
#[derive(Clone, Copy, Debug, PartialEq)]
#[non_exhaustive]
pub struct Retry {
    pub(crate) max_attempts: u32,
    pub(crate) backoff: Backoff,
    pub(crate) budget: Option<RetryBudget>,
    pub(crate) hedge: Option<Hedge>,
}

impl Default for Retry {
    fn default() -> Self {
        Self {
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            backoff: Backoff::default(),
            budget: Some(RetryBudget::default()),
            hedge: None,
        }
    }
}

impl Retry {
    /// Up to 3 attempts, exponential backoff from 50 ms with full jitter,
    /// the default [`RetryBudget`], no hedging.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the most calls one request may make to the inner service,
    /// first attempt, retries and hedges included (at least 1; 1 disables
    /// retries and hedging).
    #[must_use]
    pub fn max_attempts(mut self, attempts: u32) -> Self {
        self.max_attempts = attempts.max(1);
        self
    }

    /// Sets the delay between attempts.
    #[must_use]
    pub const fn backoff(mut self, backoff: Backoff) -> Self {
        self.backoff = backoff;
        self
    }

    /// Sets the retry budget.
    #[must_use]
    pub const fn budget(mut self, budget: RetryBudget) -> Self {
        self.budget = Some(budget);
        self
    }

    /// Retries without a budget: only [`max_attempts`](Self::max_attempts)
    /// limits them. Prefer a budget in production.
    #[must_use]
    pub const fn no_budget(mut self) -> Self {
        self.budget = None;
        self
    }

    /// Enables request hedging.
    #[must_use]
    pub const fn hedge(mut self, hedge: Hedge) -> Self {
        self.hedge = Some(hedge);
        self
    }

    /// The configured attempt limit.
    #[must_use]
    pub const fn attempts(&self) -> u32 {
        self.max_attempts
    }

    /// The configured backoff.
    #[must_use]
    pub const fn backoff_policy(&self) -> &Backoff {
        &self.backoff
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: fn(u64) -> Duration = Duration::from_millis;

    #[test]
    fn exponential_grows_and_caps() {
        let b = Backoff::exponential(MS(10))
            .max(MS(70))
            .jitter(Jitter::None);
        let delays: Vec<_> = (1..=5).map(|n| b.delay(n, 0.0)).collect();
        assert_eq!(delays, [MS(10), MS(20), MS(40), MS(70), MS(70)]);
        assert_eq!(b.delay(u32::MAX, 0.0), MS(70));
        assert_eq!(b.delay(0, 0.0), MS(10));
    }

    #[test]
    fn jitter_ranges() {
        let full = Backoff::constant(MS(100)).jitter(Jitter::Full);
        assert_eq!(full.delay(1, 0.0), Duration::ZERO);
        assert_eq!(full.delay(1, 0.5), MS(50));
        let equal = Backoff::constant(MS(100)).jitter(Jitter::Equal);
        assert_eq!(equal.delay(1, 0.0), MS(50));
        assert_eq!(equal.delay(1, 1.0), MS(100));
        assert_eq!(equal.delay(1, f64::NAN), MS(50));
        assert_eq!(equal.delay(1, 7.0), MS(100));
    }

    #[test]
    fn multiplier_and_constant() {
        let b = Backoff::exponential(MS(10))
            .multiplier(f64::NAN)
            .jitter(Jitter::None);
        assert_eq!(b.delay(5, 0.0), MS(10));
        let b = b.multiplier(0.1);
        assert_eq!(b.delay(5, 0.0), MS(10));
        assert_eq!(Backoff::none().delay(3, 0.9), Duration::ZERO);
    }

    #[test]
    fn huge_values_do_not_panic() {
        let b = Backoff::exponential(Duration::MAX)
            .max(Duration::MAX)
            .multiplier(f64::MAX)
            .jitter(Jitter::Full);
        let _ = b.delay(u32::MAX, 0.99);
    }

    #[test]
    fn config_clamps() {
        assert_eq!(Retry::new().max_attempts(0).attempts(), 1);
        assert_eq!(RetryBudget::new().ratio(-3.0).ratio, 0.0);
        assert_eq!(RetryBudget::new().ratio(f64::NAN).ratio, 0.0);
        assert_eq!(RetryBudget::new().ttl(Duration::ZERO).ttl, MS(1));
        let h = Hedge::at_percentile(f64::NAN, MS(5))
            .max_hedges(0)
            .latency_window(0)
            .min_samples(0);
        assert_eq!(
            h.delay,
            HedgeDelay::Percentile {
                percentile: 1.0,
                fallback: MS(5)
            }
        );
        assert_eq!((h.max_hedges, h.window, h.min_samples), (1, 1, 1));
    }
}
