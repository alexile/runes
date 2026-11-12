//! Composable rule evaluation over a numeric stream.
//!
//! A [`Rule`] takes a value and decides whether it violates some condition,
//! returning an optional [`Violation`]. Rules are stateful (a rate-of-change rule
//! needs to remember the previous value) and trait-object friendly, so a monitoring
//! pipeline can hold a heterogeneous `Vec<Box<dyn Rule<f64>>>` and evaluate every
//! incoming value against all of them.
//!
//! # Features
//!
//! - [`Rule`] — the trait every rule implements: `evaluate(&mut self, &T) -> Option<Violation>`.
//! - [`ThresholdRule`] — flags values outside a `[min, max]` band.
//! - [`RateOfChangeRule`] — flags a jump between consecutive values larger than a delta.
//! - [`MissingHeartbeatRule`] — flags when no ping has arrived within a timeout. Its
//!   input shape (a clock tick plus a separate ping stream) doesn't fit `Rule<T>`, so
//!   it exposes its own `ping`/`check` API instead — see its docs for why.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_rate_rule::{Rule, ThresholdRule};
//!
//! let mut rule = ThresholdRule::new("temp-range").min(0.0).max(100.0);
//! assert!(rule.evaluate(&50.0).is_none());
//! assert!(rule.evaluate(&150.0).is_some());
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-rate-rule --min 0 --max 100 readings.txt
//! cat readings.txt | rune-rate-rule --min 0 --max 100 -
//! ```

use std::time::{Duration, Instant};

/// A rule violation: which rule fired and a human-readable reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// Name of the rule that produced this violation.
    pub rule: String,
    /// Human-readable description of what was violated.
    pub message: String,
}

/// A stateful rule evaluated against a stream of values of type `T`.
///
/// Implementations may hold internal state (e.g. the previous value) so that
/// `evaluate` can be called once per incoming value, in order.
pub trait Rule<T> {
    /// Evaluates one value, returning `Some(Violation)` if the rule fires.
    fn evaluate(&mut self, value: &T) -> Option<Violation>;
}

/// Flags values outside a `[min, max]` band. Either bound may be left unset,
/// in which case that side is unconstrained.
///
/// # Example
///
/// ```rust
/// use rune_rate_rule::{Rule, ThresholdRule};
///
/// let mut rule = ThresholdRule::new("humidity").min(20.0).max(80.0);
/// assert!(rule.evaluate(&50.0).is_none());
/// assert!(rule.evaluate(&10.0).is_some());
/// assert!(rule.evaluate(&90.0).is_some());
/// ```
pub struct ThresholdRule {
    name: String,
    min: Option<f64>,
    max: Option<f64>,
}

impl ThresholdRule {
    /// Creates a new threshold rule with no bounds set (evaluates to no violations
    /// until `.min()` and/or `.max()` are applied).
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            min: None,
            max: None,
        }
    }

    /// Sets the inclusive lower bound.
    #[must_use]
    pub const fn min(mut self, min: f64) -> Self {
        self.min = Some(min);
        self
    }

    /// Sets the inclusive upper bound.
    #[must_use]
    pub const fn max(mut self, max: f64) -> Self {
        self.max = Some(max);
        self
    }
}

impl Rule<f64> for ThresholdRule {
    fn evaluate(&mut self, value: &f64) -> Option<Violation> {
        if let Some(min) = self.min
            && *value < min
        {
            return Some(Violation {
                rule: self.name.clone(),
                message: format!("{value} is below minimum {min}"),
            });
        }
        if let Some(max) = self.max
            && *value > max
        {
            return Some(Violation {
                rule: self.name.clone(),
                message: format!("{value} is above maximum {max}"),
            });
        }
        None
    }
}

/// Flags a jump between consecutive values larger than `max_delta`. The first
/// observed value never violates — it only establishes the baseline.
///
/// # Example
///
/// ```rust
/// use rune_rate_rule::{Rule, RateOfChangeRule};
///
/// let mut rule = RateOfChangeRule::new("speed", 5.0);
/// assert!(rule.evaluate(&10.0).is_none(), "first value never violates");
/// assert!(rule.evaluate(&12.0).is_none(), "small jump is fine");
/// assert!(rule.evaluate(&30.0).is_some(), "large jump violates");
/// ```
pub struct RateOfChangeRule {
    name: String,
    max_delta: f64,
    previous: Option<f64>,
}

impl RateOfChangeRule {
    /// Creates a rate-of-change rule that flags jumps larger than `max_delta`.
    pub fn new(name: impl Into<String>, max_delta: f64) -> Self {
        Self {
            name: name.into(),
            max_delta,
            previous: None,
        }
    }
}

impl Rule<f64> for RateOfChangeRule {
    fn evaluate(&mut self, value: &f64) -> Option<Violation> {
        let violation = self.previous.and_then(|previous| {
            let delta = (value - previous).abs();
            if delta > self.max_delta {
                Some(Violation {
                    rule: self.name.clone(),
                    message: format!(
                        "changed by {delta} (from {previous} to {value}), exceeds max delta {}",
                        self.max_delta
                    ),
                })
            } else {
                None
            }
        });
        self.previous = Some(*value);
        violation
    }
}

/// Flags when no [`ping`](MissingHeartbeatRule::ping) has arrived within `timeout`
/// of the current time.
///
/// This does not implement [`Rule<T>`] because its input isn't a single per-evaluation
/// value: liveness depends on two independent inputs — a ping stream (`ping`) and a
/// separately-advancing clock (`check`) — that arrive on their own schedules. Forcing
/// that into `evaluate(&mut self, &T)` would require bundling a ping flag and a
/// timestamp into one synthetic `T` on every tick, which is worse than just exposing
/// the two operations directly.
///
/// # Example
///
/// ```rust
/// use rune_rate_rule::MissingHeartbeatRule;
/// use std::time::{Duration, Instant};
///
/// let start = Instant::now();
/// let mut rule = MissingHeartbeatRule::new("gateway-1", Duration::from_secs(30));
/// rule.ping(start);
///
/// assert!(rule.check(start + Duration::from_secs(10)).is_none());
/// assert!(rule.check(start + Duration::from_secs(40)).is_some());
/// ```
pub struct MissingHeartbeatRule {
    name: String,
    timeout: Duration,
    last_ping: Option<Instant>,
}

impl MissingHeartbeatRule {
    /// Creates a heartbeat rule that flags silence longer than `timeout`.
    pub fn new(name: impl Into<String>, timeout: Duration) -> Self {
        Self {
            name: name.into(),
            timeout,
            last_ping: None,
        }
    }

    /// Records a heartbeat at time `at`.
    pub const fn ping(&mut self, at: Instant) {
        self.last_ping = Some(at);
    }

    /// Checks liveness as of `now`. Returns `Some(Violation)` if no ping has ever
    /// been recorded, or the last ping is more than `timeout` behind `now`.
    pub fn check(&mut self, now: Instant) -> Option<Violation> {
        match self.last_ping {
            None => Some(Violation {
                rule: self.name.clone(),
                message: "no heartbeat received yet".to_string(),
            }),
            Some(last) if now.duration_since(last) > self.timeout => Some(Violation {
                rule: self.name.clone(),
                message: format!(
                    "no heartbeat for {:?}, exceeds timeout {:?}",
                    now.duration_since(last),
                    self.timeout
                ),
            }),
            Some(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threshold_within_bounds_is_ok() {
        let mut rule = ThresholdRule::new("t").min(0.0).max(10.0);
        assert!(rule.evaluate(&5.0).is_none());
    }

    #[test]
    fn threshold_below_min_violates() {
        let mut rule = ThresholdRule::new("t").min(0.0).max(10.0);
        let violation = rule.evaluate(&-1.0).unwrap();
        assert_eq!(violation.rule, "t");
    }

    #[test]
    fn threshold_above_max_violates() {
        let mut rule = ThresholdRule::new("t").min(0.0).max(10.0);
        assert!(rule.evaluate(&11.0).is_some());
    }

    #[test]
    fn threshold_only_min_set() {
        let mut rule = ThresholdRule::new("t").min(0.0);
        assert!(rule.evaluate(&1000.0).is_none());
        assert!(rule.evaluate(&-1.0).is_some());
    }

    #[test]
    fn threshold_only_max_set() {
        let mut rule = ThresholdRule::new("t").max(10.0);
        assert!(rule.evaluate(&-1000.0).is_none());
        assert!(rule.evaluate(&11.0).is_some());
    }

    #[test]
    fn threshold_no_bounds_never_violates() {
        let mut rule = ThresholdRule::new("t");
        assert!(rule.evaluate(&f64::MAX).is_none());
        assert!(rule.evaluate(&f64::MIN).is_none());
    }

    #[test]
    fn rate_of_change_first_value_never_violates() {
        let mut rule = RateOfChangeRule::new("r", 1.0);
        assert!(rule.evaluate(&1000.0).is_none());
    }

    #[test]
    fn rate_of_change_small_delta_is_ok() {
        let mut rule = RateOfChangeRule::new("r", 5.0);
        rule.evaluate(&10.0);
        assert!(rule.evaluate(&12.0).is_none());
    }

    #[test]
    fn rate_of_change_large_delta_violates() {
        let mut rule = RateOfChangeRule::new("r", 5.0);
        rule.evaluate(&10.0);
        assert!(rule.evaluate(&30.0).is_some());
    }

    #[test]
    fn rate_of_change_negative_delta_also_flagged() {
        let mut rule = RateOfChangeRule::new("r", 5.0);
        rule.evaluate(&30.0);
        assert!(rule.evaluate(&10.0).is_some());
    }

    #[test]
    fn heartbeat_no_ping_ever_violates() {
        let mut rule = MissingHeartbeatRule::new("h", Duration::from_secs(10));
        assert!(rule.check(Instant::now()).is_some());
    }

    #[test]
    fn heartbeat_within_timeout_is_ok() {
        let start = Instant::now();
        let mut rule = MissingHeartbeatRule::new("h", Duration::from_secs(30));
        rule.ping(start);
        assert!(rule.check(start + Duration::from_secs(5)).is_none());
    }

    #[test]
    fn heartbeat_past_timeout_violates() {
        let start = Instant::now();
        let mut rule = MissingHeartbeatRule::new("h", Duration::from_secs(30));
        rule.ping(start);
        assert!(rule.check(start + Duration::from_secs(31)).is_some());
    }

    #[test]
    fn heartbeat_resets_on_reping() {
        let start = Instant::now();
        let mut rule = MissingHeartbeatRule::new("h", Duration::from_secs(30));
        rule.ping(start);
        rule.ping(start + Duration::from_secs(20));
        assert!(rule.check(start + Duration::from_secs(40)).is_none());
    }

    #[test]
    fn composes_as_trait_objects() {
        let mut rules: Vec<Box<dyn Rule<f64>>> = vec![
            Box::new(ThresholdRule::new("range").min(0.0).max(100.0)),
            Box::new(RateOfChangeRule::new("jump", 10.0)),
        ];

        for rule in &mut rules {
            assert!(rule.evaluate(&50.0).is_none());
        }

        let violations: Vec<Violation> = rules
            .iter_mut()
            .filter_map(|rule| rule.evaluate(&500.0))
            .collect();

        assert_eq!(violations.len(), 2, "both rules should fire on 500.0");
    }
}
