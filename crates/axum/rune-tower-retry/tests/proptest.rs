//! Property tests: backoff delays stay within their bounds, the budget never
//! allows more retries than it earned, and per-call attempts never exceed
//! the configured limit.

#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "small, non-negative test values"
)]

use std::time::{Duration, Instant};

use proptest::prelude::*;
use rune_tower_retry::{
    Backoff, Budget, Decision, GiveUp, Hedge, Jitter, Retrier, Retry, RetryBudget,
};

fn jitter() -> impl Strategy<Value = Jitter> {
    prop_oneof![Just(Jitter::None), Just(Jitter::Full), Just(Jitter::Equal)]
}

proptest! {
    #[test]
    fn backoff_delay_is_bounded(
        initial_ms in 0..10_000u64,
        max_ms in 0..60_000u64,
        multiplier in 0.0..10.0f64,
        jitter in jitter(),
        retry in any::<u32>(),
        random in 0.0..1.0f64,
    ) {
        let max = Duration::from_millis(max_ms);
        let b = Backoff::exponential(Duration::from_millis(initial_ms))
            .max(max)
            .multiplier(multiplier)
            .jitter(jitter);
        let d = b.delay(retry, random);
        prop_assert!(d <= max);
        let full = b.jitter(Jitter::None).delay(retry, random);
        prop_assert!(d <= full);
        if jitter == Jitter::Equal {
            prop_assert!(d >= full / 2);
        }
    }

    #[test]
    fn budget_never_overspends(
        min_per_sec in 0..5u32,
        ratio in 0.0..2.0f64,
        steps in prop::collection::vec((any::<bool>(), 0..3_000u64), 1..300),
    ) {
        let ttl = Duration::from_secs(10);
        let mut budget = Budget::new(
            RetryBudget::new().ttl(ttl).min_per_sec(min_per_sec).ratio(ratio),
        );
        let t0 = Instant::now();
        let mut now = t0;
        // (instant, is_deposit) of every accepted event.
        let mut events: Vec<(Instant, bool)> = Vec::new();
        // The budget's buckets are a tenth of the ttl wide.
        let width = ttl / 10;
        for (deposit, advance_ms) in steps {
            now += Duration::from_millis(advance_ms);
            if deposit {
                budget.deposit(now);
                events.push((now, true));
            } else if budget.try_withdraw(now) {
                events.push((now, false));
                // Bucketing ages events out up to one bucket early, so
                // every withdrawal from the last `ttl - width` was still
                // counted, and only deposits from the last `ttl` earned.
                let count = |want: bool, span: Duration| {
                    events
                        .iter()
                        .filter(|(t, d)| *d == want && now.duration_since(*t) < span)
                        .count()
                };
                let deposits = u32::try_from(count(true, ttl)).unwrap();
                let earned = (ratio * f64::from(deposits)).floor() as usize;
                let reserve = min_per_sec as usize * 10;
                prop_assert!(count(false, ttl.checked_sub(width).unwrap()) <= reserve + earned);
            }
        }
    }

    #[test]
    fn attempts_never_exceed_the_limit(
        max_attempts in 1..8u32,
        hedges in 1..4u32,
        ops in prop::collection::vec(any::<bool>(), 0..40),
    ) {
        let mut r = Retrier::with_seed(
            Retry::new()
                .max_attempts(max_attempts)
                .no_budget()
                .hedge(Hedge::after(Duration::from_millis(1)).max_hedges(hedges)),
            42,
        );
        let now = Instant::now();
        let mut call = r.begin(now);
        let mut gave_up = false;
        for hedge in ops {
            if hedge {
                let _ = r.try_hedge(&mut call, now);
            } else if let Decision::GiveUp(reason) = r.on_failure(&mut call, now) {
                prop_assert_eq!(reason, GiveUp::Attempts);
                gave_up = true;
            }
            prop_assert!(call.attempts() <= max_attempts);
            prop_assert!(call.hedges() <= hedges);
        }
        if gave_up {
            prop_assert_eq!(call.attempts(), max_attempts);
        }
    }
}
