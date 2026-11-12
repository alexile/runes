//! Property tests: the breaker never panics, its window rates stay in
//! range, and it can only be open after the thresholds were breached.

#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]

use std::time::{Duration, Instant};

use proptest::prelude::*;
use rune_tower_circuitbreaker::{Breaker, CircuitBreaker, State};

#[derive(Clone, Debug)]
enum Step {
    Call { failed: bool, elapsed_ms: u64 },
    Advance(u64),
    Abandon,
}

fn step() -> impl Strategy<Value = Step> {
    prop_oneof![
        (any::<bool>(), 0..2_000u64)
            .prop_map(|(failed, elapsed_ms)| Step::Call { failed, elapsed_ms }),
        (0..20_000u64).prop_map(Step::Advance),
        Just(Step::Abandon),
    ]
}

proptest! {
    #[test]
    fn arbitrary_sequences_keep_invariants(
        window in 1..20usize,
        minimum in 1..25usize,
        probes in 1..4u32,
        rate in 0.0..=1.0f64,
        steps in prop::collection::vec(step(), 0..200),
    ) {
        let config = CircuitBreaker::new()
            .window(window)
            .minimum_calls(minimum)
            .failure_rate(rate)
            .slow_calls(Duration::from_millis(1_000), rate)
            .open_duration(Duration::from_secs(10))
            .half_open_probes(probes);
        let mut b = Breaker::new(config);
        let mut now = Instant::now();
        for step in steps {
            match step {
                Step::Call { failed, elapsed_ms } => {
                    let before = b.state(now);
                    match b.try_acquire(now) {
                        Ok(permit) => {
                            prop_assert_ne!(before, State::Open);
                            b.record(permit, failed, Duration::from_millis(elapsed_ms), now);
                        }
                        Err(rejected) => {
                            prop_assert_ne!(before, State::Closed);
                            prop_assert!(rejected.retry_after() <= Duration::from_secs(10));
                        }
                    }
                }
                Step::Advance(ms) => now += Duration::from_millis(ms),
                Step::Abandon => {
                    if let Ok(permit) = b.try_acquire(now) {
                        b.release(permit);
                    }
                }
            }
            let s = b.snapshot(now);
            prop_assert!(s.calls <= window);
            prop_assert!((0.0..=1.0).contains(&s.failure_rate));
            prop_assert!((0.0..=1.0).contains(&s.slow_call_rate));
            if s.state == State::Closed && s.calls >= minimum.min(window) {
                prop_assert!(s.failure_rate < rate && s.slow_call_rate < rate);
            }
        }
    }

    #[test]
    fn all_successes_never_open(n in 0..500usize, window in 1..50usize) {
        let mut b = Breaker::new(CircuitBreaker::new().window(window).minimum_calls(1));
        let now = Instant::now();
        for _ in 0..n {
            let p = b.try_acquire(now).unwrap();
            b.record(p, false, Duration::ZERO, now);
        }
        prop_assert_eq!(b.state(now), State::Closed);
    }
}
