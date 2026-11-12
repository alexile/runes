//! Retry policy: how often, how long to wait, and how long to keep trying.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// How the computed backoff delay is randomised.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum Jitter {
    /// Use the exponential delay as is (deterministic).
    None,
    /// "Full jitter": a uniformly random delay in `[0, delay]`. The default;
    /// it spreads out clients that failed together so they do not retry in
    /// lockstep.
    #[default]
    Full,
    /// "Equal jitter": half the delay, plus a random amount up to the other
    /// half. Keeps a minimum wait while still spreading clients out.
    Equal,
}

/// Backoff and budget settings for retrying one provider.
///
/// The delay before retry `n` (0-based) is
/// `min(initial_delay × multiplier^n, max_delay)`, randomised by
/// [`jitter`](Self::jitter). A provider's retry-after hint (see
/// [`retry_after`](crate::retry_after)) raises the delay to at least that
/// hint. Retrying stops after [`max_retries`](Self::max_retries), or as
/// soon as the next wait would exceed [`max_elapsed`](Self::max_elapsed).
///
/// # Example
///
/// ```rust
/// use std::time::Duration;
/// use rune_chain_retry::{Jitter, RetryPolicy};
///
/// let policy = RetryPolicy::default()
///     .with_max_retries(5)
///     .with_initial_delay(Duration::from_millis(250))
///     .with_max_elapsed(Duration::from_secs(20))
///     .with_attempt_timeout(Duration::from_secs(60))
///     .with_jitter(Jitter::Full);
/// assert_eq!(policy.max_retries, 5);
/// ```
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub struct RetryPolicy {
    /// Retries after the first attempt (default 3).
    pub max_retries: u32,
    /// Delay before the first retry (default 200 ms).
    pub initial_delay: Duration,
    /// Factor applied to the delay after each retry (default 2.0).
    pub multiplier: f64,
    /// Upper bound on a single backoff delay (default 30 s).
    pub max_delay: Duration,
    /// Randomisation of each delay (default [`Jitter::Full`]).
    pub jitter: Jitter,
    /// Total time budget, measured from the first attempt (default: none).
    pub max_elapsed: Option<Duration>,
    /// Time limit for one attempt; for streams it covers opening the stream
    /// and receiving the first chunk (default: none).
    pub attempt_timeout: Option<Duration>,
    /// Whether provider retry-after hints are honoured (default `true`).
    pub honor_retry_after: bool,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl RetryPolicy {
    /// The default policy (see the field docs).
    pub const DEFAULT: Self = Self {
        max_retries: 3,
        initial_delay: Duration::from_millis(200),
        multiplier: 2.0,
        max_delay: Duration::from_secs(30),
        jitter: Jitter::Full,
        max_elapsed: None,
        attempt_timeout: None,
        honor_retry_after: true,
    };

    /// A policy that never retries (one attempt), still applying
    /// [`attempt_timeout`](Self::attempt_timeout) if set.
    #[must_use]
    pub const fn no_retry() -> Self {
        Self {
            max_retries: 0,
            ..Self::DEFAULT
        }
    }

    /// Set [`max_retries`](Self::max_retries).
    #[must_use]
    pub const fn with_max_retries(mut self, n: u32) -> Self {
        self.max_retries = n;
        self
    }

    /// Set [`initial_delay`](Self::initial_delay).
    #[must_use]
    pub const fn with_initial_delay(mut self, d: Duration) -> Self {
        self.initial_delay = d;
        self
    }

    /// Set [`multiplier`](Self::multiplier).
    #[must_use]
    pub const fn with_multiplier(mut self, m: f64) -> Self {
        self.multiplier = m;
        self
    }

    /// Set [`max_delay`](Self::max_delay).
    #[must_use]
    pub const fn with_max_delay(mut self, d: Duration) -> Self {
        self.max_delay = d;
        self
    }

    /// Set [`jitter`](Self::jitter).
    #[must_use]
    pub const fn with_jitter(mut self, j: Jitter) -> Self {
        self.jitter = j;
        self
    }

    /// Set [`max_elapsed`](Self::max_elapsed).
    #[must_use]
    pub const fn with_max_elapsed(mut self, d: Duration) -> Self {
        self.max_elapsed = Some(d);
        self
    }

    /// Set [`attempt_timeout`](Self::attempt_timeout).
    #[must_use]
    pub const fn with_attempt_timeout(mut self, d: Duration) -> Self {
        self.attempt_timeout = Some(d);
        self
    }

    /// Set [`honor_retry_after`](Self::honor_retry_after).
    #[must_use]
    pub const fn with_honor_retry_after(mut self, yes: bool) -> Self {
        self.honor_retry_after = yes;
        self
    }

    /// The un-jittered delay before retry number `retry` (0-based), capped
    /// at [`max_delay`](Self::max_delay). Never panics: a non-finite or
    /// negative product saturates to `max_delay` or zero.
    #[must_use]
    pub fn base_delay(&self, retry: u32) -> Duration {
        let exp = i32::try_from(retry).unwrap_or(i32::MAX);
        let secs = self.initial_delay.as_secs_f64() * self.multiplier.powi(exp);
        let d = if secs.is_nan() {
            self.initial_delay
        } else if secs <= 0.0 {
            Duration::ZERO
        } else {
            Duration::try_from_secs_f64(secs).unwrap_or(self.max_delay)
        };
        d.min(self.max_delay)
    }

    /// The delay before retry `retry`, with jitter drawn from `unit`
    /// (a uniform sample in `[0, 1)`).
    #[must_use]
    pub fn delay(&self, retry: u32, unit: f64) -> Duration {
        let base = self.base_delay(retry);
        let unit = unit.clamp(0.0, 1.0);
        match self.jitter {
            Jitter::None => base,
            Jitter::Full => base.mul_f64(unit),
            Jitter::Equal => base / 2 + (base / 2).mul_f64(unit),
        }
    }
}

/// Small lock-free `SplitMix64` generator for jitter and weighted picks.
///
/// Seeded lazily from the standard library's per-process random hasher keys
/// unless a seed is given, so independent clients do not jitter in lockstep.
#[derive(Debug, Default)]
pub struct Rng {
    seed: OnceLock<u64>,
    counter: AtomicU64,
}

impl Rng {
    pub const fn new() -> Self {
        Self {
            seed: OnceLock::new(),
            counter: AtomicU64::new(0),
        }
    }

    pub fn seeded(seed: u64) -> Self {
        Self {
            seed: OnceLock::from(seed),
            counter: AtomicU64::new(0),
        }
    }

    pub fn next_u64(&self) -> u64 {
        let seed = *self.seed.get_or_init(|| {
            let mut h = RandomState::new().build_hasher();
            h.write_u64(0x5EED);
            h.finish()
        });
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        let mut z = seed.wrapping_add(n.wrapping_add(1).wrapping_mul(0x9E37_79B9_7F4A_7C15));
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in `[0, 1)`.
    #[allow(
        clippy::cast_precision_loss,
        reason = "53 random bits fit an f64 mantissa exactly"
    )]
    pub fn unit(&self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_delay_grows_and_caps() {
        let p = RetryPolicy::default()
            .with_initial_delay(Duration::from_millis(100))
            .with_max_delay(Duration::from_millis(500));
        assert_eq!(p.base_delay(0), Duration::from_millis(100));
        assert_eq!(p.base_delay(2), Duration::from_millis(400));
        assert_eq!(p.base_delay(3), Duration::from_millis(500));
        assert_eq!(p.base_delay(u32::MAX), Duration::from_millis(500));
    }

    #[test]
    fn absurd_multipliers_do_not_panic() {
        for m in [f64::NAN, -3.0, f64::INFINITY, 1e300, 0.0] {
            let p = RetryPolicy::default().with_multiplier(m);
            for n in [0, 1, 7, u32::MAX] {
                assert!(p.base_delay(n) <= p.max_delay);
            }
        }
    }

    #[test]
    fn jitter_bounds() {
        let p = RetryPolicy::default().with_initial_delay(Duration::from_secs(1));
        assert_eq!(p.delay(0, 0.5), Duration::from_millis(500));
        let p = p.with_jitter(Jitter::Equal);
        assert_eq!(p.delay(0, 0.0), Duration::from_millis(500));
        assert_eq!(p.delay(0, 1.0), Duration::from_secs(1));
        let p = p.with_jitter(Jitter::None);
        assert_eq!(p.delay(0, 0.1), Duration::from_secs(1));
    }

    #[test]
    fn rng_is_deterministic_when_seeded_and_in_range() {
        let a = Rng::seeded(7);
        let b = Rng::seeded(7);
        for _ in 0..1000 {
            let x = a.unit();
            assert!((0.0..1.0).contains(&x));
            assert_eq!(x.to_bits(), b.unit().to_bits());
        }
        assert_ne!(Rng::new().next_u64(), Rng::seeded(1).next_u64());
    }
}
