//! Dedupe properties against straightforward reference models.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use proptest::prelude::*;
use rune_dedupe::{ApproxConfig, Dedupe, EventTimeDedupe, HashKey, Verdict};

/// Unbounded reference: key -> time of its last acceptance.
fn reference(accepted: &HashMap<u8, u64>, key: u8, now: u64, window: u64) -> bool {
    accepted.get(&key).is_none_or(|&t| now - t > window)
}

proptest! {
    /// For non-decreasing timestamps, `check` accepts a key iff it has no
    /// accepted occurrence within the trailing window, and `len` counts the
    /// keys whose last acceptance is still inside the window.
    #[test]
    fn matches_reference_model(
        window_ms in 0u64..50,
        events in prop::collection::vec((0u8..5, 0u64..20), 0..80),
    ) {
        let start = Instant::now();
        let mut dedupe = Dedupe::new(Duration::from_millis(window_ms));
        let mut accepted: HashMap<u8, u64> = HashMap::new();
        let mut now = 0u64;
        for (key, delta) in events {
            now += delta;
            let at = start + Duration::from_millis(now);
            prop_assert_eq!(dedupe.contains(&key, at), !reference(&accepted, key, now, window_ms));
            let got = dedupe.check(key, at);
            let want = reference(&accepted, key, now, window_ms);
            prop_assert_eq!(got, want, "key {} at {}ms", key, now);
            if want {
                accepted.insert(key, now);
            }
            let live = accepted.values().filter(|&&t| now - t <= window_ms).count();
            prop_assert_eq!(dedupe.len(), live);
        }
    }

    /// With a cap at least as large as the number of keys live in the window,
    /// exact mode never misses a duplicate; with any cap it never reports a
    /// key as a duplicate unless it really was accepted within the window.
    #[test]
    fn capped_exact_mode_is_exact_within_cap(
        window_ms in 0u64..50,
        cap in 1usize..12,
        events in prop::collection::vec((0u8..16, 0u64..10), 0..120),
    ) {
        let mut dedupe: Dedupe<u8, u64> = Dedupe::builder(Duration::from_millis(window_ms))
            .max_keys(cap)
            .build()
            .unwrap();
        let mut accepted: HashMap<u8, u64> = HashMap::new();
        let mut now = 0u64;
        for (key, delta) in events {
            now += delta;
            let live = accepted.values().filter(|&&t| now - t <= window_ms).count();
            let want = reference(&accepted, key, now, window_ms);
            let got = dedupe.check(key, now);
            if !got {
                prop_assert!(!want, "false positive for {} at {}", key, now);
            }
            if live < cap {
                prop_assert_eq!(got, want, "within cap, key {} at {}", key, now);
            }
            if got {
                accepted.insert(key, now);
            }
            prop_assert!(dedupe.len() <= cap);
        }
    }

    /// Approximate mode never misses a duplicate within the window when it is
    /// sized for the traffic.
    #[test]
    fn approximate_mode_has_no_false_negatives(
        window_ms in 0u64..50,
        generations in 2u32..6,
        events in prop::collection::vec((0u8..40, 0u64..10), 0..150),
    ) {
        let mut dedupe: Dedupe<u8, u64> = Dedupe::builder(Duration::from_millis(window_ms))
            .approximate(ApproxConfig::new(10_000, 0.01).generations(generations))
            .build()
            .unwrap();
        let mut accepted: HashMap<u8, u64> = HashMap::new();
        let mut now = 0u64;
        for (key, delta) in events {
            now += delta;
            let fresh_by_reference = reference(&accepted, key, now, window_ms);
            let got = dedupe.check(key, now);
            if !fresh_by_reference {
                prop_assert!(!got, "missed duplicate {} at {}", key, now);
            }
            if got {
                accepted.insert(key, now);
            }
        }
    }

    /// Snapshot then restore, in either mode, gives identical decisions on the
    /// rest of the stream.
    #[test]
    fn restore_gives_identical_decisions(
        approximate in any::<bool>(),
        cap in prop::option::of(1usize..8),
        split in 0usize..100,
        events in prop::collection::vec((0u16..300, 0u64..10), 0..100),
    ) {
        let mut builder = Dedupe::<u16, u64>::builder(Duration::from_millis(30))
            .hash_key(HashKey::new(9, 9));
        builder = if approximate {
            builder.approximate(ApproxConfig::new(20, 0.2).generations(3))
        } else if let Some(cap) = cap {
            builder.max_keys(cap)
        } else {
            builder
        };
        let mut original = builder.build().unwrap();
        let split = split.min(events.len());
        let mut now = 0u64;
        for &(key, delta) in &events[..split] {
            now += delta;
            original.check(key, now);
        }
        let mut restored = Dedupe::restore(original.snapshot()).unwrap();
        prop_assert_eq!(restored.stats(), original.stats());
        for &(key, delta) in &events[split..] {
            now += delta;
            prop_assert_eq!(original.check(key, now), restored.check(key, now));
            prop_assert_eq!(original.len(), restored.len());
        }
    }

    /// Event-time dedupe against a model that keeps every accepted occurrence
    /// and forgets those more than a window behind the watermark.
    #[test]
    fn event_time_matches_reference(
        window in 0i64..30,
        lateness in 0i64..20,
        events in prop::collection::vec((0u8..4, 0i64..100), 0..100),
    ) {
        let mut dedupe = EventTimeDedupe::new(Duration::from_millis(window.unsigned_abs()));
        let mut held: Vec<(u8, i64)> = Vec::new();
        let mut watermark: Option<i64> = None;
        let mut max_seen: Option<i64> = None;
        for (key, ts) in events {
            let got = dedupe.check(key, ts);
            let matched = held.iter().any(|&(k, t)| k == key && (t - ts).abs() <= window);
            let want = if matched {
                Verdict::Duplicate
            } else if watermark.is_some_and(|wm| ts < wm) {
                Verdict::Late
            } else {
                held.push((key, ts));
                Verdict::Fresh
            };
            prop_assert_eq!(got, want, "key {} at {}", key, ts);

            // Advance the watermark the way a lateness-bounded tracker would.
            max_seen = Some(max_seen.map_or(ts, |m| m.max(ts)));
            let wm = max_seen.unwrap_or(ts) - lateness;
            if watermark.is_none_or(|old| wm > old) {
                watermark = Some(wm);
                held.retain(|&(_, t)| wm - t <= window);
            }
            dedupe.advance_watermark(wm);
            prop_assert_eq!(dedupe.len(), held.len());
        }
    }

    /// Event-time restore gives identical decisions too.
    #[test]
    fn event_time_restore_gives_identical_decisions(
        split in 0usize..60,
        events in prop::collection::vec((0u8..6, 0i64..60, any::<bool>()), 0..60),
    ) {
        let mut original: EventTimeDedupe<u8> =
            EventTimeDedupe::builder(Duration::from_millis(10)).max_keys(5).build().unwrap();
        let split = split.min(events.len());
        for &(key, ts, advance) in &events[..split] {
            original.check(key, ts);
            if advance {
                original.advance_watermark(ts - 5);
            }
        }
        let mut restored = EventTimeDedupe::restore(original.snapshot()).unwrap();
        for &(key, ts, advance) in &events[split..] {
            prop_assert_eq!(original.check(key, ts), restored.check(key, ts));
            if advance {
                prop_assert_eq!(original.advance_watermark(ts - 5), restored.advance_watermark(ts - 5));
            }
        }
    }
}

/// Measured false-positive rate on seeded keys stays under the configured one,
/// with keys spread across the whole window so every generation is in play.
#[test]
fn approximate_false_positive_rate_is_within_bound() {
    for (fpr, generations, seed) in [(0.01, 4, 1_u64), (0.001, 4, 2), (0.05, 2, 3), (0.01, 8, 4)] {
        let n = 20_000_u64;
        let window = Duration::from_millis(n);
        let mut dedupe: Dedupe<u64, u64> = Dedupe::builder(window)
            .approximate(ApproxConfig::new(20_000, fpr).generations(generations))
            .hash_key(HashKey::new(seed, seed ^ 0xabcd))
            .build()
            .unwrap();
        // One insert per millisecond fills each generation to capacity.
        for i in 0..n {
            dedupe.check(i, i);
        }
        // Probe never-seen keys at the last instant, while everything is live.
        let probes = 50_000_u64;
        let false_positives = (0..probes)
            .filter(|&i| dedupe.contains(&(1_000_000_000 + i * 2_654_435_761), n - 1))
            .count();
        #[allow(clippy::cast_precision_loss)]
        let measured = false_positives as f64 / probes as f64;
        assert!(
            measured <= fpr,
            "fpr {fpr} gens {generations}: measured {measured}"
        );
        assert_eq!(dedupe.stats().evicted_capacity, 0);
    }
}

#[cfg(feature = "serde")]
mod serde_roundtrip {
    use super::*;
    use rune_dedupe::{Checkpoint, Snapshot};

    proptest! {
        /// A JSON round-trip of a checkpoint restores identical decisions.
        #[test]
        fn json_checkpoint_restores_identical_decisions(
            approximate in any::<bool>(),
            events in prop::collection::vec((0u16..200, 0u64..10), 1..80),
        ) {
            let mut builder = Dedupe::<String, u64>::builder(Duration::from_millis(25));
            if approximate {
                builder = builder.approximate(ApproxConfig::new(50, 0.05));
            }
            let mut original = builder.build().unwrap();
            let (head, tail) = events.split_at(events.len() / 2);
            let mut now = 0;
            for &(k, d) in head {
                now += d;
                original.check(k.to_string(), now);
            }
            let cp = Checkpoint { offset: head.len() as u64, state: original.snapshot() };
            let json = serde_json::to_string(&cp).unwrap();
            let back: Checkpoint<Snapshot<String, u64>> = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(back.offset, head.len() as u64);
            let mut restored = Dedupe::restore(back.state).unwrap();
            for &(k, d) in tail {
                now += d;
                prop_assert_eq!(original.check(k.to_string(), now), restored.check(k.to_string(), now));
            }
        }
    }

    #[test]
    fn event_time_snapshot_round_trips() {
        let mut d: EventTimeDedupe<String> = EventTimeDedupe::new(Duration::from_millis(5));
        d.check("a".into(), 10);
        d.advance_watermark(8);
        let json = serde_json::to_string(&d.snapshot()).unwrap();
        let mut r: EventTimeDedupe<String> =
            EventTimeDedupe::restore(serde_json::from_str(&json).unwrap()).unwrap();
        assert_eq!(r.watermark(), Some(8));
        assert_eq!(r.check("a".into(), 14), Verdict::Duplicate);
        assert_eq!(r.check("b".into(), 1), Verdict::Late);
    }
}

#[test]
fn deduplicators_are_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Dedupe<String>>();
    assert_send_sync::<Dedupe<String, u64>>();
    assert_send_sync::<EventTimeDedupe<String>>();
}
