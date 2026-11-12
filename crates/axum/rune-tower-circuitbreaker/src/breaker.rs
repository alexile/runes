//! The sans-I/O circuit-breaker state machine.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Default share of failed calls in the window that opens the circuit.
const DEFAULT_FAILURE_RATE: f64 = 0.5;
/// Default share of slow calls in the window that opens the circuit.
const DEFAULT_SLOW_CALL_RATE: f64 = 0.5;
/// Default duration from which a call counts as slow.
const DEFAULT_SLOW_CALL_DURATION: Duration = Duration::from_secs(10);
/// Default number of recent calls the rates are computed over.
const DEFAULT_WINDOW: usize = 100;
/// Default number of calls the window needs before it may open the circuit.
const DEFAULT_MINIMUM_CALLS: usize = 20;
/// Default time the circuit stays open before probing.
const DEFAULT_OPEN_DURATION: Duration = Duration::from_secs(30);
/// Default number of successful probes that close the circuit.
const DEFAULT_HALF_OPEN_PROBES: u32 = 3;

/// The externally visible state of a circuit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum State {
    /// Calls flow; outcomes are recorded in the sliding window.
    Closed,
    /// Calls are rejected without reaching the inner service.
    Open,
    /// A limited number of probe calls test whether the service recovered.
    HalfOpen,
}

/// Configuration for a circuit breaker.
///
/// Rates are computed over a count-based sliding window of the most recent
/// calls. Once the window holds at least [`minimum_calls`] outcomes, the
/// circuit opens when the failure rate or the slow-call rate reaches its
/// threshold. After [`open_duration`] it lets [`half_open_probes`] trial
/// calls through: if all of them succeed quickly the circuit closes with a
/// fresh window, and the first failed or slow probe opens it again.
///
/// [`minimum_calls`]: Self::minimum_calls
/// [`open_duration`]: Self::open_duration
/// [`half_open_probes`]: Self::half_open_probes
///
/// # Examples
///
/// ```rust
/// use std::time::Duration;
/// use rune_tower_circuitbreaker::CircuitBreaker;
///
/// let config = CircuitBreaker::new()
///     .failure_rate(0.25)
///     .slow_calls(Duration::from_millis(500), 0.5)
///     .window(50)
///     .minimum_calls(10)
///     .open_duration(Duration::from_secs(5))
///     .half_open_probes(2);
/// assert_eq!(config.window_size(), 50);
/// ```
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct CircuitBreaker {
    failure_rate: f64,
    slow_call_rate: f64,
    slow_call_duration: Duration,
    window: usize,
    minimum_calls: usize,
    open_duration: Duration,
    half_open_probes: u32,
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self {
            failure_rate: DEFAULT_FAILURE_RATE,
            slow_call_rate: DEFAULT_SLOW_CALL_RATE,
            slow_call_duration: DEFAULT_SLOW_CALL_DURATION,
            window: DEFAULT_WINDOW,
            minimum_calls: DEFAULT_MINIMUM_CALLS,
            open_duration: DEFAULT_OPEN_DURATION,
            half_open_probes: DEFAULT_HALF_OPEN_PROBES,
        }
    }
}

impl CircuitBreaker {
    /// Creates a configuration with defaults: open at a 50 % failure rate
    /// or a 50 % rate of calls slower than 10 s, over the last 100 calls
    /// once at least 20 were seen; stay open 30 s; close after 3
    /// successful probes.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the failure rate (`0.0..=1.0`) at or above which the circuit
    /// opens. Out-of-range values are clamped; `NaN` disables the check.
    #[must_use]
    pub const fn failure_rate(mut self, rate: f64) -> Self {
        self.failure_rate = clamp_rate(rate);
        self
    }

    /// Counts calls that take `duration` or longer as slow, and opens the
    /// circuit when slow calls reach `rate` (`0.0..=1.0`, clamped; `NaN`
    /// disables the check). A call can be both slow and failed.
    #[must_use]
    pub const fn slow_calls(mut self, duration: Duration, rate: f64) -> Self {
        self.slow_call_duration = duration;
        self.slow_call_rate = clamp_rate(rate);
        self
    }

    /// Never opens on latency alone.
    #[must_use]
    pub const fn no_slow_calls(mut self) -> Self {
        self.slow_call_rate = f64::NAN;
        self
    }

    /// Sets how many of the most recent calls the rates cover (at least 1).
    #[must_use]
    pub fn window(mut self, calls: usize) -> Self {
        self.window = calls.max(1);
        self
    }

    /// Sets how many outcomes the window needs before it may open the
    /// circuit, so a single early failure cannot trip it. Capped at the
    /// window size.
    #[must_use]
    pub fn minimum_calls(mut self, calls: usize) -> Self {
        self.minimum_calls = calls.max(1);
        self
    }

    /// Sets how long the circuit stays open before it lets probes through.
    #[must_use]
    pub const fn open_duration(mut self, duration: Duration) -> Self {
        self.open_duration = duration;
        self
    }

    /// Sets how many probes run in half-open (concurrently, at most) and
    /// how many must succeed to close the circuit (at least 1).
    #[must_use]
    pub fn half_open_probes(mut self, probes: u32) -> Self {
        self.half_open_probes = probes.max(1);
        self
    }

    /// The configured window size.
    #[must_use]
    pub const fn window_size(&self) -> usize {
        self.window
    }

    /// Whether a call that took `elapsed` counts as slow.
    #[must_use]
    pub fn is_slow(&self, elapsed: Duration) -> bool {
        !self.slow_call_rate.is_nan() && elapsed >= self.slow_call_duration
    }

    fn minimum(&self) -> usize {
        self.minimum_calls.min(self.window)
    }
}

const fn clamp_rate(rate: f64) -> f64 {
    if rate.is_nan() {
        f64::NAN
    } else {
        rate.clamp(0.0, 1.0)
    }
}

/// Permission to make one call, from [`Breaker::try_acquire`].
///
/// Hand it back with [`Breaker::record`] when the call completes, or with
/// [`Breaker::release`] when it is abandoned (for example, cancelled),
/// so that half-open probe slots are not leaked.
#[derive(Debug, PartialEq, Eq)]
#[must_use = "a permit must be recorded or released"]
pub struct Permit {
    generation: u64,
    probe: bool,
}

impl Permit {
    /// Whether this call is a half-open probe.
    #[must_use]
    pub const fn is_probe(&self) -> bool {
        self.probe
    }
}

/// A call refused by an open (or saturated half-open) circuit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rejected {
    retry_after: Duration,
}

impl Rejected {
    /// How long until the circuit lets probes through. Zero while
    /// half-open probes are already in flight.
    #[must_use]
    pub const fn retry_after(self) -> Duration {
        self.retry_after
    }
}

/// A point-in-time view of a breaker.
#[derive(Clone, Copy, Debug, PartialEq)]
#[non_exhaustive]
pub struct Snapshot {
    /// The current state.
    pub state: State,
    /// Outcomes in the closed-state window.
    pub calls: usize,
    /// Share of failed calls in the window (0 when empty).
    pub failure_rate: f64,
    /// Share of slow calls in the window (0 when empty).
    pub slow_call_rate: f64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Closed,
    Open { until: Instant },
    HalfOpen { in_flight: u32, successes: u32 },
}

#[derive(Clone, Copy, Debug)]
struct Outcome {
    failed: bool,
    slow: bool,
}

/// The circuit-breaker state machine, without clocks or I/O.
///
/// Callers pass the current [`Instant`] in, ask for a [`Permit`] before
/// each call and report the outcome afterwards. Outcomes that arrive after
/// the state changed (a call started while closed that finishes after the
/// circuit opened) are ignored.
///
/// # Examples
///
/// ```rust
/// use std::time::{Duration, Instant};
/// use rune_tower_circuitbreaker::{Breaker, CircuitBreaker, State};
///
/// let mut breaker = Breaker::new(
///     CircuitBreaker::new()
///         .window(4)
///         .minimum_calls(4)
///         .open_duration(Duration::from_secs(10))
///         .half_open_probes(1),
/// );
/// let t0 = Instant::now();
/// let ms = Duration::from_millis;
///
/// // Two failures out of four calls: 50 % reaches the default threshold.
/// for failed in [false, true, false, true] {
///     let permit = breaker.try_acquire(t0).unwrap();
///     breaker.record(permit, failed, ms(5), t0);
/// }
/// assert_eq!(breaker.state(t0), State::Open);
/// assert!(breaker.try_acquire(t0).is_err());
///
/// // After the open duration a probe goes through and, succeeding, closes it.
/// let later = t0 + Duration::from_secs(10);
/// let probe = breaker.try_acquire(later).unwrap();
/// assert!(probe.is_probe());
/// breaker.record(probe, false, ms(5), later);
/// assert_eq!(breaker.state(later), State::Closed);
/// ```
#[derive(Clone, Debug)]
pub struct Breaker {
    config: CircuitBreaker,
    phase: Phase,
    /// Bumped on every transition, so stale permits can be recognised.
    generation: u64,
    window: VecDeque<Outcome>,
    failures: usize,
    slow: usize,
}

impl Breaker {
    /// Creates a closed breaker.
    #[must_use]
    pub fn new(config: CircuitBreaker) -> Self {
        Self {
            window: VecDeque::with_capacity(config.window.min(1024)),
            config,
            phase: Phase::Closed,
            generation: 0,
            failures: 0,
            slow: 0,
        }
    }

    /// The configuration.
    #[must_use]
    pub const fn config(&self) -> &CircuitBreaker {
        &self.config
    }

    /// The state at `now`. An open circuit whose open duration has passed
    /// reports [`State::HalfOpen`]: the next call will be a probe.
    #[must_use]
    pub fn state(&self, now: Instant) -> State {
        match self.phase {
            Phase::Closed => State::Closed,
            Phase::Open { until } if now < until => State::Open,
            Phase::Open { .. } | Phase::HalfOpen { .. } => State::HalfOpen,
        }
    }

    /// The state and window rates at `now`.
    #[must_use]
    pub fn snapshot(&self, now: Instant) -> Snapshot {
        let calls = self.window.len();
        Snapshot {
            state: self.state(now),
            calls,
            failure_rate: ratio(self.failures, calls),
            slow_call_rate: ratio(self.slow, calls),
        }
    }

    /// Asks to make a call at `now`.
    ///
    /// # Errors
    ///
    /// [`Rejected`] while the circuit is open, or half-open with every
    /// probe slot taken.
    pub fn try_acquire(&mut self, now: Instant) -> Result<Permit, Rejected> {
        match self.phase {
            Phase::Closed => Ok(self.permit(false)),
            Phase::Open { until } if now < until => Err(Rejected {
                retry_after: until - now,
            }),
            Phase::Open { .. } => {
                self.transition(Phase::HalfOpen {
                    in_flight: 1,
                    successes: 0,
                });
                Ok(self.permit(true))
            }
            Phase::HalfOpen {
                in_flight,
                successes,
            } => {
                if in_flight.saturating_add(successes) < self.config.half_open_probes {
                    self.phase = Phase::HalfOpen {
                        in_flight: in_flight + 1,
                        successes,
                    };
                    Ok(self.permit(true))
                } else {
                    Err(Rejected {
                        retry_after: Duration::ZERO,
                    })
                }
            }
        }
    }

    /// Records the outcome of a call made with `permit`: whether it
    /// `failed`, and how long it took (`elapsed`, compared with the
    /// slow-call duration).
    #[allow(
        clippy::needless_pass_by_value,
        reason = "taking the permit by value stops it being used twice"
    )]
    pub fn record(&mut self, permit: Permit, failed: bool, elapsed: Duration, now: Instant) {
        if permit.generation != self.generation {
            return;
        }
        let slow = self.config.is_slow(elapsed);
        match self.phase {
            Phase::Closed => {
                self.push(Outcome { failed, slow });
                if self.should_open() {
                    self.open(now);
                }
            }
            Phase::HalfOpen {
                in_flight,
                successes,
            } if permit.probe => {
                if failed || slow {
                    self.open(now);
                } else if successes + 1 >= self.config.half_open_probes {
                    self.transition(Phase::Closed);
                } else {
                    self.phase = Phase::HalfOpen {
                        in_flight: in_flight.saturating_sub(1),
                        successes: successes + 1,
                    };
                }
            }
            Phase::Open { .. } | Phase::HalfOpen { .. } => {}
        }
    }

    /// Returns a permit whose call was abandoned without an outcome, such
    /// as a cancelled future. Frees its half-open probe slot.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "taking the permit by value stops it being used twice"
    )]
    pub const fn release(&mut self, permit: Permit) {
        if permit.generation != self.generation || !permit.probe {
            return;
        }
        if let Phase::HalfOpen {
            in_flight,
            successes,
        } = self.phase
        {
            self.phase = Phase::HalfOpen {
                in_flight: in_flight.saturating_sub(1),
                successes,
            };
        }
    }

    /// Opens the circuit at `now`, regardless of the window.
    pub fn trip(&mut self, now: Instant) {
        self.open(now);
    }

    /// Closes the circuit with an empty window.
    pub fn reset(&mut self) {
        self.transition(Phase::Closed);
    }

    const fn permit(&self, probe: bool) -> Permit {
        Permit {
            generation: self.generation,
            probe,
        }
    }

    fn open(&mut self, now: Instant) {
        // An open duration too large for the platform's Instant never ends.
        let until = now
            .checked_add(self.config.open_duration)
            .unwrap_or_else(|| far_future(now));
        self.transition(Phase::Open { until });
    }

    fn transition(&mut self, phase: Phase) {
        self.phase = phase;
        self.generation = self.generation.wrapping_add(1);
        self.window.clear();
        self.failures = 0;
        self.slow = 0;
    }

    fn push(&mut self, outcome: Outcome) {
        if self.window.len() >= self.config.window
            && let Some(old) = self.window.pop_front()
        {
            self.failures -= usize::from(old.failed);
            self.slow -= usize::from(old.slow);
        }
        self.failures += usize::from(outcome.failed);
        self.slow += usize::from(outcome.slow);
        self.window.push_back(outcome);
    }

    fn should_open(&self) -> bool {
        let calls = self.window.len();
        if calls < self.config.minimum() {
            return false;
        }
        ratio(self.failures, calls) >= self.config.failure_rate
            || ratio(self.slow, calls) >= self.config.slow_call_rate
    }
}

#[allow(
    clippy::cast_precision_loss,
    reason = "window counts are far below 2^52"
)]
fn ratio(part: usize, whole: usize) -> f64 {
    if whole == 0 {
        0.0
    } else {
        part as f64 / whole as f64
    }
}

/// The latest instant reachable from `now` by halving steps, about 2^63 ns
/// ahead at most.
fn far_future(now: Instant) -> Instant {
    let mut step = Duration::from_secs(u64::MAX / 2);
    let mut t = now;
    while step > Duration::ZERO {
        if let Some(next) = t.checked_add(step) {
            t = next;
        }
        step /= 2;
    }
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAST: Duration = Duration::from_millis(1);

    fn config() -> CircuitBreaker {
        CircuitBreaker::new()
            .window(10)
            .minimum_calls(5)
            .open_duration(Duration::from_secs(10))
            .half_open_probes(2)
            .slow_calls(Duration::from_secs(1), 0.5)
    }

    fn call(b: &mut Breaker, now: Instant, failed: bool, elapsed: Duration) {
        let p = b.try_acquire(now).unwrap();
        b.record(p, failed, elapsed, now);
    }

    fn open_breaker(now: Instant) -> Breaker {
        let mut b = Breaker::new(config());
        for _ in 0..5 {
            call(&mut b, now, true, FAST);
        }
        assert_eq!(b.state(now), State::Open);
        b
    }

    #[test]
    fn stays_closed_below_minimum_calls() {
        let now = Instant::now();
        let mut b = Breaker::new(config());
        for _ in 0..4 {
            call(&mut b, now, true, FAST);
        }
        assert_eq!(b.state(now), State::Closed);
        call(&mut b, now, true, FAST);
        assert_eq!(b.state(now), State::Open);
    }

    #[test]
    fn opens_at_failure_rate_threshold() {
        let now = Instant::now();
        let mut b = Breaker::new(config());
        for failed in [false, false, false, true, true, false] {
            call(&mut b, now, failed, FAST);
        }
        assert_eq!(b.state(now), State::Closed);
        assert!((b.snapshot(now).failure_rate - 2.0 / 6.0).abs() < 1e-9);
        for _ in 0..2 {
            call(&mut b, now, true, FAST);
        }
        // 4 of 8 = 50 %.
        assert_eq!(b.state(now), State::Open);
        assert_eq!(b.snapshot(now).calls, 0);
    }

    #[test]
    fn opens_on_slow_calls_even_when_successful() {
        let now = Instant::now();
        let mut b = Breaker::new(config());
        for elapsed in [FAST, FAST, Duration::from_secs(1), Duration::from_secs(3)] {
            call(&mut b, now, false, elapsed);
        }
        assert_eq!(b.state(now), State::Closed);
        call(&mut b, now, false, Duration::from_secs(2));
        assert_eq!(b.state(now), State::Open);
    }

    #[test]
    fn slow_calls_can_be_disabled() {
        let now = Instant::now();
        let mut b = Breaker::new(config().no_slow_calls());
        for _ in 0..20 {
            call(&mut b, now, false, Duration::from_secs(60));
        }
        assert_eq!(b.state(now), State::Closed);
        assert!(!b.config().is_slow(Duration::MAX));
    }

    #[test]
    fn window_slides() {
        let now = Instant::now();
        let mut b = Breaker::new(config().failure_rate(0.6));
        for _ in 0..5 {
            call(&mut b, now, true, FAST);
        }
        // 100 % failure, but minimum 5 reached: opens.
        assert_eq!(b.state(now), State::Open);

        let mut b = Breaker::new(config().minimum_calls(10).failure_rate(0.6));
        for _ in 0..5 {
            call(&mut b, now, true, FAST);
        }
        for _ in 0..10 {
            call(&mut b, now, false, FAST);
        }
        // The five failures slid out of the 10-call window.
        assert_eq!(b.snapshot(now).failure_rate, 0.0);
        assert_eq!(b.snapshot(now).calls, 10);
    }

    #[test]
    fn rejects_while_open_with_retry_after() {
        let t0 = Instant::now();
        let mut b = open_breaker(t0);
        let r = b.try_acquire(t0 + Duration::from_secs(4)).unwrap_err();
        assert_eq!(r.retry_after(), Duration::from_secs(6));
    }

    #[test]
    fn half_open_limits_probes_and_closes_on_success() {
        let t0 = Instant::now();
        let mut b = open_breaker(t0);
        let t1 = t0 + Duration::from_secs(10);
        assert_eq!(b.state(t1), State::HalfOpen);
        let p1 = b.try_acquire(t1).unwrap();
        let p2 = b.try_acquire(t1).unwrap();
        assert!(p1.is_probe() && p2.is_probe());
        assert_eq!(b.try_acquire(t1).unwrap_err().retry_after(), Duration::ZERO);
        b.record(p1, false, FAST, t1);
        assert_eq!(b.state(t1), State::HalfOpen);
        // A successful probe does not free a slot: two successes are needed.
        assert!(b.try_acquire(t1).is_err());
        b.record(p2, false, FAST, t1);
        assert_eq!(b.state(t1), State::Closed);
        assert!(!b.try_acquire(t1).unwrap().is_probe());
    }

    #[test]
    fn failed_or_slow_probe_reopens() {
        let t0 = Instant::now();
        for (failed, elapsed) in [(true, FAST), (false, Duration::from_secs(5))] {
            let mut b = open_breaker(t0);
            let t1 = t0 + Duration::from_secs(10);
            let p = b.try_acquire(t1).unwrap();
            b.record(p, failed, elapsed, t1);
            assert_eq!(b.state(t1), State::Open);
            assert_eq!(
                b.try_acquire(t1).unwrap_err().retry_after(),
                Duration::from_secs(10)
            );
        }
    }

    #[test]
    fn stale_permits_are_ignored() {
        let t0 = Instant::now();
        let mut b = Breaker::new(config());
        let stale = b.try_acquire(t0).unwrap();
        for _ in 0..5 {
            call(&mut b, t0, true, FAST);
        }
        let t1 = t0 + Duration::from_secs(10);
        let probe = b.try_acquire(t1).unwrap();
        // A pre-open failure arriving in half-open must not reopen.
        b.record(stale, true, FAST, t1);
        assert_eq!(b.state(t1), State::HalfOpen);
        b.record(probe, false, FAST, t1);
        let probe = b.try_acquire(t1).unwrap();
        b.record(probe, false, FAST, t1);
        assert_eq!(b.state(t1), State::Closed);
    }

    #[test]
    fn release_frees_probe_slot() {
        let t0 = Instant::now();
        let mut b = open_breaker(t0);
        let t1 = t0 + Duration::from_secs(10);
        let p1 = b.try_acquire(t1).unwrap();
        let p2 = b.try_acquire(t1).unwrap();
        assert!(b.try_acquire(t1).is_err());
        b.release(p1);
        let p3 = b.try_acquire(t1).unwrap();
        b.release(p2);
        b.release(p3);
        assert_eq!(b.state(t1), State::HalfOpen);
    }

    #[test]
    fn trip_and_reset() {
        let t0 = Instant::now();
        let mut b = Breaker::new(config());
        b.trip(t0);
        assert_eq!(b.state(t0), State::Open);
        b.reset();
        assert_eq!(b.state(t0), State::Closed);
    }

    #[test]
    fn huge_open_duration_does_not_panic() {
        let t0 = Instant::now();
        let mut b = Breaker::new(config().open_duration(Duration::MAX));
        b.trip(t0);
        assert_eq!(b.state(t0 + Duration::from_secs(1_000_000)), State::Open);
    }

    #[test]
    fn config_clamps() {
        let c = CircuitBreaker::new()
            .failure_rate(7.0)
            .window(0)
            .minimum_calls(0)
            .half_open_probes(0);
        assert_eq!(c.failure_rate, 1.0);
        assert_eq!(c.window, 1);
        assert_eq!(c.minimum(), 1);
        assert_eq!(c.half_open_probes, 1);
        assert_eq!(CircuitBreaker::new().failure_rate(-1.0).failure_rate, 0.0);
        assert_eq!(CircuitBreaker::new().minimum_calls(500).minimum(), 100);
    }

    #[test]
    fn nan_rate_disables_check() {
        let now = Instant::now();
        let mut b = Breaker::new(config().failure_rate(f64::NAN));
        for _ in 0..20 {
            call(&mut b, now, true, FAST);
        }
        assert_eq!(b.state(now), State::Closed);
    }
}
