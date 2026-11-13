//! Hostile inputs: attacker-chosen event times and tampered snapshots.

#![allow(clippy::unwrap_used, reason = "test code")]

use std::time::{Duration, Instant};

use rune_dedupe::{EventTimeDedupe, Verdict};

#[test]
fn one_key_at_many_event_times_stays_fast() {
    // Every occurrence is a window apart from the others, so each one is
    // fresh and the key collects thousands of event times.
    let mut d: EventTimeDedupe<&str, i64> = EventTimeDedupe::new(Duration::from_millis(10));
    let start = Instant::now();
    for i in 0..30_000_i64 {
        assert_eq!(d.check("k", i * 100), Verdict::Fresh);
    }
    assert_eq!(d.check("k", 1_234_505), Verdict::Duplicate);
    assert_eq!(d.check("k", 1_234_550), Verdict::Fresh);
    let elapsed = start.elapsed();
    assert!(elapsed < Duration::from_secs(1), "{elapsed:?}");
}

#[cfg(feature = "serde")]
mod snapshots {
    use rune_dedupe::{ApproxConfig, Dedupe, EventTimeDedupe, EventTimeSnapshot, Snapshot};
    use serde_json::Value;
    use std::time::Duration;

    fn tamper<S: serde::Serialize + serde::de::DeserializeOwned>(
        snapshot: &S,
        edit: impl FnOnce(&mut Value),
    ) -> S {
        let mut json = serde_json::to_value(snapshot).unwrap();
        edit(&mut json);
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn saturated_counters_do_not_panic() {
        let window = Duration::from_millis(10);
        let mut d: Dedupe<u32, u64> = Dedupe::builder(window)
            .approximate(ApproxConfig::new(100, 0.01))
            .build()
            .unwrap();
        d.check(1, 0);
        let snap: Snapshot<u32, u64> = tamper(&d.snapshot(), |json| {
            for counter in json["stats"].as_object_mut().unwrap().values_mut() {
                *counter = Value::from(u64::MAX);
            }
            let generation = &mut json["state"]["Approximate"]["generations"][0];
            generation["count"] = Value::from(u64::MAX);
        });
        let mut d = Dedupe::restore(snap).unwrap();
        let _ = d.len();
        assert!(d.check(2, 1));
        assert!(!d.check(2, 2));
        d.check(3, 1_000);
        assert_eq!(d.stats().seen, u64::MAX);

        let mut e: EventTimeDedupe<u32, i64> = EventTimeDedupe::new(window);
        e.check(1, 0);
        let snap: EventTimeSnapshot<u32, i64> = tamper(&e.snapshot(), |json| {
            json["stats"]["late"] = Value::from(u64::MAX);
            json["stats"]["seen"] = Value::from(u64::MAX);
        });
        let mut e = EventTimeDedupe::restore(snap).unwrap();
        e.advance_watermark(100);
        e.check(1, 0);
        assert_eq!(e.stats().late, u64::MAX);
    }
}
