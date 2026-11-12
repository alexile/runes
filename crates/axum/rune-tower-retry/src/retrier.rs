//! The sans-I/O retry core: budget, latency tracking and per-call decisions.

use std::collections::VecDeque;
use std::hash::{BuildHasher, RandomState};
use std::time::{Duration, Instant};

use crate::policy::{HedgeDelay, Retry, RetryBudget};

/// Number of buckets the budget window is split into.
const BUDGET_BUCKETS: u32 = 10;

#[derive(Clone, Copy, Debug)]
struct Bucket {
    start: Instant,
    deposits: u64,
    withdrawals: u64,
}

/// A sliding-window retry budget, driven by explicit instants.
///
/// Every request [`deposit`](Self::deposit)s; every retry or hedge must
/// [`try_withdraw`](Self::try_withdraw). See [`RetryBudget`] for the rule.
///
/// # Examples
///
/// ```rust
/// use std::time::{Duration, Instant};
/// use rune_tower_retry::{Budget, RetryBudget};
///
/// let mut budget = Budget::new(RetryBudget::new().min_per_sec(0).ratio(0.5));
/// let now = Instant::now();
/// for _ in 0..4 {
///     budget.deposit(now);
/// }
/// assert!(budget.try_withdraw(now));
/// assert!(budget.try_withdraw(now));
/// assert!(!budget.try_withdraw(now)); // 50 % of 4 requests spent
/// ```
#[derive(Clone, Debug)]
pub struct Budget {
    config: RetryBudget,
    bucket_width: Duration,
    reserve: u64,
    buckets: VecDeque<Bucket>,
}

impl Budget {
    /// Creates an empty budget.
    #[must_use]
    pub fn new(config: RetryBudget) -> Self {
        let bucket_width = (config.ttl / BUDGET_BUCKETS).max(Duration::from_micros(100));
        let reserve = f64::from(config.min_per_sec) * config.ttl.as_secs_f64();
        Self {
            config,
            bucket_width,
            reserve: saturating_u64(reserve),
            buckets: VecDeque::with_capacity(BUDGET_BUCKETS as usize + 1),
        }
    }

    /// Records a request at `now`.
    pub fn deposit(&mut self, now: Instant) {
        self.current(now).deposits += 1;
    }

    /// Spends one retry at `now`, if the budget allows it.
    pub fn try_withdraw(&mut self, now: Instant) -> bool {
        if self.remaining(now) == 0 {
            return false;
        }
        self.current(now).withdrawals += 1;
        true
    }

    /// How many retries the budget would allow at `now`.
    #[must_use]
    pub fn remaining(&self, now: Instant) -> u64 {
        let (deposits, withdrawals) = self.live(now).fold((0_u64, 0_u64), |(d, w), b| {
            (d + b.deposits, w + b.withdrawals)
        });
        #[allow(
            clippy::cast_precision_loss,
            reason = "request counts in one window are far below 2^52"
        )]
        let earned = saturating_u64(self.config.ratio * deposits as f64);
        self.reserve
            .saturating_add(earned)
            .saturating_sub(withdrawals)
    }

    fn live(&self, now: Instant) -> impl Iterator<Item = &Bucket> {
        let ttl = self.config.ttl;
        self.buckets
            .iter()
            .filter(move |b| now.saturating_duration_since(b.start) < ttl)
    }

    fn current(&mut self, now: Instant) -> &mut Bucket {
        let ttl = self.config.ttl;
        while self
            .buckets
            .front()
            .is_some_and(|b| now.saturating_duration_since(b.start) >= ttl)
        {
            self.buckets.pop_front();
        }
        let fresh = self
            .buckets
            .back()
            .is_none_or(|b| now.saturating_duration_since(b.start) >= self.bucket_width);
        if fresh {
            self.buckets.push_back(Bucket {
                start: now,
                deposits: 0,
                withdrawals: 0,
            });
        }
        let last = self.buckets.len() - 1;
        &mut self.buckets[last]
    }
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    reason = "clamped to the u64 range first; NaN maps to 0"
)]
fn saturating_u64(x: f64) -> u64 {
    if x.is_nan() || x <= 0.0 {
        0
    } else if x >= u64::MAX as f64 {
        u64::MAX
    } else {
        x as u64
    }
}

/// The latencies of recent successful calls, for percentile hedge delays.
#[derive(Clone, Debug)]
struct Latencies {
    window: usize,
    samples: VecDeque<Duration>,
}

impl Latencies {
    fn new(window: usize) -> Self {
        Self {
            window,
            samples: VecDeque::with_capacity(window.min(1024)),
        }
    }

    fn record(&mut self, latency: Duration) {
        if self.samples.len() >= self.window {
            self.samples.pop_front();
        }
        self.samples.push_back(latency);
    }

    /// The nearest-rank percentile, or `None` below `min_samples`.
    fn percentile(&self, p: f64, min_samples: usize) -> Option<Duration> {
        if self.samples.is_empty() || self.samples.len() < min_samples {
            return None;
        }
        let mut sorted: Vec<Duration> = self.samples.iter().copied().collect();
        sorted.sort_unstable();
        #[allow(
            clippy::cast_precision_loss,
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "p is in 0..=1 and the window is small"
        )]
        let rank = (p * sorted.len() as f64).ceil() as usize;
        sorted
            .get(rank.saturating_sub(1).min(sorted.len() - 1))
            .copied()
    }
}

/// `SplitMix64`: a small, fast generator for jitter. Not cryptographic.
#[derive(Clone, Debug)]
struct SplitMix(u64);

impl SplitMix {
    const fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in `[0, 1)`.
    #[allow(
        clippy::cast_precision_loss,
        reason = "a 53-bit integer is exact in f64"
    )]
    fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 * (1.0 / (1_u64 << 53) as f64)
    }
}

/// Per-request attempt counters, from [`Retrier::begin`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Call {
    attempts: u32,
    retries: u32,
    hedges: u32,
}

impl Call {
    /// Calls made to the inner service so far, the first one included.
    #[must_use]
    pub const fn attempts(&self) -> u32 {
        self.attempts
    }

    /// Retries made so far.
    #[must_use]
    pub const fn retries(&self) -> u32 {
        self.retries
    }

    /// Hedges sent so far.
    #[must_use]
    pub const fn hedges(&self) -> u32 {
        self.hedges
    }
}

/// What to do after a retriable failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Decision {
    /// Retry after this backoff delay.
    Retry {
        /// How long to wait before the next attempt.
        after: Duration,
    },
    /// Return the failure to the caller.
    GiveUp(GiveUp),
}

/// Why a retriable failure is returned to the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum GiveUp {
    /// The call already made `max_attempts` attempts.
    Attempts,
    /// The retry budget is spent.
    Budget,
}

/// Counters across every call a [`Retrier`] has handled.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Stats {
    /// Requests started.
    pub requests: u64,
    /// Retries made after a retriable failure.
    pub retries: u64,
    /// Hedges sent.
    pub hedges: u64,
    /// Retriable failures returned because `max_attempts` was reached.
    pub exhausted: u64,
    /// Retries or hedges refused by the retry budget.
    pub budget_denied: u64,
}

/// The retry and hedging decisions, without clocks, timers or I/O.
///
/// A caller [`begin`](Self::begin)s each request, asks
/// [`on_failure`](Self::on_failure) after each retriable failure and, when
/// hedging, asks [`hedge_delay`](Self::hedge_delay) when to hedge and
/// [`try_hedge`](Self::try_hedge) whether it may.
///
/// # Examples
///
/// ```rust
/// use std::time::{Duration, Instant};
/// use rune_tower_retry::{Backoff, Decision, GiveUp, Retrier, Retry};
///
/// let mut retrier = Retrier::new(
///     Retry::new()
///         .max_attempts(3)
///         .backoff(Backoff::constant(Duration::from_millis(10)))
///         .no_budget(),
/// );
/// let now = Instant::now();
/// let mut call = retrier.begin(now);
/// assert_eq!(
///     retrier.on_failure(&mut call, now),
///     Decision::Retry { after: Duration::from_millis(10) },
/// );
/// assert!(matches!(retrier.on_failure(&mut call, now), Decision::Retry { .. }));
/// assert_eq!(retrier.on_failure(&mut call, now), Decision::GiveUp(GiveUp::Attempts));
/// assert_eq!(call.attempts(), 3);
/// ```
#[derive(Clone, Debug)]
pub struct Retrier {
    config: Retry,
    budget: Option<Budget>,
    latencies: Latencies,
    rng: SplitMix,
    stats: Stats,
}

impl Retrier {
    /// Creates a retrier with a randomly seeded jitter source.
    #[must_use]
    pub fn new(config: Retry) -> Self {
        Self::with_seed(config, RandomState::new().hash_one(0x5EED_u64))
    }

    /// Creates a retrier whose jitter is reproducible from `seed`.
    #[must_use]
    pub fn with_seed(config: Retry, seed: u64) -> Self {
        let window = config.hedge.map_or(1, |h| h.window);
        Self {
            budget: config.budget.map(Budget::new),
            latencies: Latencies::new(window),
            config,
            rng: SplitMix(seed),
            stats: Stats::default(),
        }
    }

    /// The configuration.
    #[must_use]
    pub const fn config(&self) -> &Retry {
        &self.config
    }

    /// Counters so far.
    #[must_use]
    pub const fn stats(&self) -> Stats {
        self.stats
    }

    /// Retries the budget would allow at `now`, or `None` without a budget.
    #[must_use]
    pub fn budget_remaining(&self, now: Instant) -> Option<u64> {
        self.budget.as_ref().map(|b| b.remaining(now))
    }

    /// Starts a request at `now`: deposits into the budget and counts its
    /// first attempt.
    pub fn begin(&mut self, now: Instant) -> Call {
        self.stats.requests += 1;
        if let Some(budget) = &mut self.budget {
            budget.deposit(now);
        }
        Call {
            attempts: 1,
            retries: 0,
            hedges: 0,
        }
    }

    /// Decides what follows a retriable failure of `call` at `now`. A
    /// [`Decision::Retry`] counts the next attempt and spends budget.
    pub fn on_failure(&mut self, call: &mut Call, now: Instant) -> Decision {
        if call.attempts >= self.config.max_attempts {
            self.stats.exhausted += 1;
            return Decision::GiveUp(GiveUp::Attempts);
        }
        if !self.withdraw(now) {
            return Decision::GiveUp(GiveUp::Budget);
        }
        call.attempts += 1;
        call.retries += 1;
        self.stats.retries += 1;
        let random = self.rng.next_f64();
        Decision::Retry {
            after: self.config.backoff.delay(call.retries, random),
        }
    }

    /// How long after an attempt starts to hedge it, or `None` when
    /// hedging is off or `call` may send no more hedges.
    #[must_use]
    pub fn hedge_delay(&self, call: &Call) -> Option<Duration> {
        let hedge = self.config.hedge?;
        if call.hedges >= hedge.max_hedges || call.attempts >= self.config.max_attempts {
            return None;
        }
        Some(match hedge.delay {
            HedgeDelay::Fixed(delay) => delay,
            HedgeDelay::Percentile {
                percentile,
                fallback,
            } => self
                .latencies
                .percentile(percentile, hedge.min_samples)
                .unwrap_or(fallback),
        })
    }

    /// Whether `call` may send a hedge at `now`; if so, counts it and
    /// spends budget.
    pub fn try_hedge(&mut self, call: &mut Call, now: Instant) -> bool {
        if self.hedge_delay(call).is_none() || !self.withdraw(now) {
            return false;
        }
        call.attempts += 1;
        call.hedges += 1;
        self.stats.hedges += 1;
        true
    }

    /// Records the latency of a successful attempt, for percentile hedging.
    pub fn record_latency(&mut self, latency: Duration) {
        if self.config.hedge.is_some() {
            self.latencies.record(latency);
        }
    }

    fn withdraw(&mut self, now: Instant) -> bool {
        let allowed = self.budget.as_mut().is_none_or(|b| b.try_withdraw(now));
        if !allowed {
            self.stats.budget_denied += 1;
        }
        allowed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Backoff, Hedge, Jitter};

    const MS: fn(u64) -> Duration = Duration::from_millis;

    #[test]
    fn budget_floor_and_ratio() {
        let mut b = Budget::new(
            RetryBudget::new()
                .ttl(Duration::from_secs(10))
                .min_per_sec(1)
                .ratio(0.5),
        );
        let t0 = Instant::now();
        assert_eq!(b.remaining(t0), 10);
        for _ in 0..4 {
            b.deposit(t0);
        }
        assert_eq!(b.remaining(t0), 12);
        for _ in 0..12 {
            assert!(b.try_withdraw(t0));
        }
        assert!(!b.try_withdraw(t0));
    }

    #[test]
    fn budget_window_slides() {
        let mut b = Budget::new(
            RetryBudget::new()
                .ttl(Duration::from_secs(10))
                .min_per_sec(0)
                .ratio(1.0),
        );
        let t0 = Instant::now();
        b.deposit(t0);
        assert!(b.try_withdraw(t0));
        assert!(!b.try_withdraw(t0));
        // A later deposit earns a retry while the old withdrawal is live.
        let t1 = t0 + Duration::from_secs(5);
        b.deposit(t1);
        assert_eq!(b.remaining(t1), 1);
        // Once the first bucket ages out, only the second deposit counts.
        let t2 = t0 + Duration::from_secs(10);
        assert_eq!(b.remaining(t2), 1);
        let t3 = t1 + Duration::from_secs(10);
        assert_eq!(b.remaining(t3), 0);
        assert!(b.buckets.len() <= 2);
    }

    #[test]
    fn budget_buckets_stay_bounded() {
        let mut b = Budget::new(RetryBudget::new().ttl(Duration::from_secs(1)));
        let t0 = Instant::now();
        for i in 0..10_000 {
            b.deposit(t0 + MS(i));
        }
        assert!(b.buckets.len() <= BUDGET_BUCKETS as usize + 1);
    }

    #[test]
    fn retries_until_max_attempts() {
        let mut r = Retrier::with_seed(
            Retry::new()
                .max_attempts(3)
                .backoff(Backoff::exponential(MS(10)).jitter(Jitter::None))
                .no_budget(),
            1,
        );
        let now = Instant::now();
        let mut call = r.begin(now);
        assert_eq!(
            r.on_failure(&mut call, now),
            Decision::Retry { after: MS(10) }
        );
        assert_eq!(
            r.on_failure(&mut call, now),
            Decision::Retry { after: MS(20) }
        );
        assert_eq!(
            r.on_failure(&mut call, now),
            Decision::GiveUp(GiveUp::Attempts)
        );
        let s = r.stats();
        assert_eq!((s.requests, s.retries, s.exhausted), (1, 2, 1));
        assert_eq!(r.budget_remaining(now), None);
    }

    #[test]
    fn budget_denies_retries() {
        let mut r = Retrier::with_seed(
            Retry::new()
                .max_attempts(10)
                .budget(RetryBudget::new().min_per_sec(0).ratio(0.5)),
            1,
        );
        let now = Instant::now();
        let mut a = r.begin(now);
        let mut b = r.begin(now);
        assert!(matches!(r.on_failure(&mut a, now), Decision::Retry { .. }));
        assert_eq!(r.on_failure(&mut b, now), Decision::GiveUp(GiveUp::Budget));
        assert_eq!(r.stats().budget_denied, 1);
        assert_eq!(r.budget_remaining(now), Some(0));
    }

    #[test]
    fn jitter_is_seeded() {
        let config = Retry::new().max_attempts(5).no_budget();
        let delays = |seed| {
            let mut r = Retrier::with_seed(config, seed);
            let now = Instant::now();
            let mut call = r.begin(now);
            (0..4)
                .map(|_| r.on_failure(&mut call, now))
                .collect::<Vec<_>>()
        };
        assert_eq!(delays(7), delays(7));
        assert_ne!(delays(7), delays(8));
    }

    #[test]
    fn hedging_counts_attempts() {
        let mut r = Retrier::with_seed(
            Retry::new()
                .max_attempts(3)
                .no_budget()
                .hedge(Hedge::after(MS(5)).max_hedges(5)),
            1,
        );
        let now = Instant::now();
        let mut call = r.begin(now);
        assert_eq!(r.hedge_delay(&call), Some(MS(5)));
        assert!(r.try_hedge(&mut call, now));
        assert!(r.try_hedge(&mut call, now));
        // max_attempts caps hedges too.
        assert_eq!(r.hedge_delay(&call), None);
        assert!(!r.try_hedge(&mut call, now));
        assert_eq!((call.attempts(), call.hedges()), (3, 2));
        assert_eq!(
            r.on_failure(&mut call, now),
            Decision::GiveUp(GiveUp::Attempts)
        );
    }

    #[test]
    fn no_hedge_without_config() {
        let mut r = Retrier::new(Retry::new());
        let now = Instant::now();
        let mut call = r.begin(now);
        assert_eq!(r.hedge_delay(&call), None);
        assert!(!r.try_hedge(&mut call, now));
    }

    #[test]
    fn percentile_hedge_delay() {
        let mut r = Retrier::with_seed(
            Retry::new().hedge(Hedge::at_percentile(0.9, MS(500)).min_samples(10)),
            1,
        );
        let call = r.begin(Instant::now());
        for ms in 1..=9 {
            r.record_latency(MS(ms * 10));
        }
        assert_eq!(r.hedge_delay(&call), Some(MS(500)));
        r.record_latency(MS(100));
        assert_eq!(r.hedge_delay(&call), Some(MS(90)));
    }

    #[test]
    fn latency_window_slides() {
        let mut l = Latencies::new(3);
        for ms in [100, 1, 2, 3] {
            l.record(MS(ms));
        }
        assert_eq!(l.percentile(1.0, 1), Some(MS(3)));
        assert_eq!(l.percentile(0.0, 1), Some(MS(1)));
        assert_eq!(Latencies::new(3).percentile(0.5, 0), None);
    }

    #[test]
    fn random_is_in_unit_interval() {
        let mut rng = SplitMix(0);
        for _ in 0..10_000 {
            let x = rng.next_f64();
            assert!((0.0..1.0).contains(&x));
        }
    }
}
