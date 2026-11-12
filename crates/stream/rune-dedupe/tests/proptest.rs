//! Dedup-window properties against a straightforward reference model.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use proptest::prelude::*;
use rune_dedupe::Dedupe;

proptest! {
    /// For non-decreasing timestamps, `check` accepts a key iff it has no
    /// accepted occurrence within the trailing window, and `len` counts the
    /// keys whose last acceptance is still inside the window.
    #[test]
    fn matches_reference_model(
        window_ms in 0u64..50,
        events in prop::collection::vec((0u8..5, 0u64..20), 0..80),
    ) {
        let window = Duration::from_millis(window_ms);
        let start = Instant::now();
        let mut dedupe = Dedupe::new(window);
        let mut accepted_at: HashMap<u8, u64> = HashMap::new();
        let mut now_ms = 0u64;
        for (key, delta) in events {
            now_ms += delta;
            let got = dedupe.check(key, start + Duration::from_millis(now_ms));
            let want = accepted_at.get(&key).is_none_or(|&t| now_ms - t > window_ms);
            prop_assert_eq!(got, want, "key {} at {}ms", key, now_ms);
            if want {
                accepted_at.insert(key, now_ms);
            }
            let live = accepted_at.values().filter(|&&t| now_ms - t <= window_ms).count();
            prop_assert_eq!(dedupe.len(), live);
            prop_assert_eq!(dedupe.is_empty(), live == 0);
        }
    }

    /// Accepted occurrences of the same key are always more than `window` apart.
    #[test]
    fn accepted_occurrences_are_spaced_by_window(
        window_ms in 1u64..30,
        deltas in prop::collection::vec(0u64..10, 1..100),
    ) {
        let start = Instant::now();
        let mut dedupe = Dedupe::new(Duration::from_millis(window_ms));
        let mut t = 0u64;
        let mut last: Option<u64> = None;
        for d in deltas {
            t += d;
            if dedupe.check("k", start + Duration::from_millis(t)) {
                if let Some(prev) = last {
                    prop_assert!(t - prev > window_ms);
                }
                last = Some(t);
            }
        }
    }
}
