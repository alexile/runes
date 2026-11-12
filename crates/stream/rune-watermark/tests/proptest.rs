//! Watermark advancement properties.

use proptest::prelude::*;
use rune_watermark::{Lateness, WatermarkTracker};

proptest! {
    /// The watermark is `max_seen - lateness`, never moves backwards, and an
    /// event is late exactly when it is below the watermark it arrived at.
    #[test]
    fn classification_matches_reference(
        lateness in 0i64..1_000,
        ts in prop::collection::vec(-10_000i64..10_000, 1..100),
    ) {
        let mut tracker = WatermarkTracker::new(lateness);
        let mut max_seen: Option<i64> = None;
        let mut prev_wm: Option<i64> = None;
        for t in ts {
            let before = tracker.watermark();
            prop_assert_eq!(before, max_seen.map(|m| m - lateness));
            let want = match before {
                Some(wm) if t < wm => Lateness::Late { by_ms: wm - t },
                _ => Lateness::OnTime,
            };
            prop_assert_eq!(tracker.observe(t), want);
            max_seen = Some(max_seen.map_or(t, |m| m.max(t)));
            let after = tracker.watermark();
            if let (Some(p), Some(a)) = (prev_wm, after) {
                prop_assert!(a >= p, "watermark regressed");
            }
            prev_wm = after;
        }
    }

    /// Sorted input is never late, for any lateness >= 0.
    #[test]
    fn sorted_stream_is_always_on_time(
        lateness in 0i64..100,
        mut ts in prop::collection::vec(any::<i64>(), 0..100),
    ) {
        ts.sort_unstable();
        let mut tracker = WatermarkTracker::new(lateness);
        for t in ts {
            prop_assert_eq!(tracker.observe(t), Lateness::OnTime);
        }
    }

    /// Arbitrary i64 input never panics, and `by_ms` is always positive.
    #[test]
    fn arbitrary_input_never_panics(
        lateness in any::<i64>(),
        ts in prop::collection::vec(any::<i64>(), 0..50),
    ) {
        let mut tracker = WatermarkTracker::new(lateness);
        for t in ts {
            if let Lateness::Late { by_ms } = tracker.observe(t) {
                prop_assert!(by_ms > 0);
            }
        }
    }
}
