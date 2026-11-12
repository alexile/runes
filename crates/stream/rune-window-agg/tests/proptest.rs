//! Window-aggregation properties against brute-force grouping of sorted
//! input: every closed window has exact aggregates, windows close in start
//! order, and no event is counted twice or lost.

#![allow(clippy::float_cmp, reason = "integer-valued sums are exact in f64")]

use std::collections::BTreeMap;

use proptest::prelude::*;
use rune_window_agg::{WindowAggregator, WindowKind, WindowResult};

/// Sorted timestamps with small integer values (exact f64 arithmetic).
fn stream() -> impl Strategy<Value = Vec<(i64, f64)>> {
    prop::collection::vec((-200i64..200, -50i32..50), 0..60).prop_map(|mut v| {
        v.sort_by_key(|e| e.0);
        v.into_iter().map(|(t, x)| (t, f64::from(x))).collect()
    })
}

/// Returns (results emitted by `push`, in order) ++ (results from `flush`).
fn run(kind: WindowKind, events: &[(i64, f64)]) -> (Vec<WindowResult>, Vec<WindowResult>) {
    let mut agg = WindowAggregator::new(kind);
    let mut pushed = Vec::new();
    for &(t, v) in events {
        pushed.extend(agg.push(t, v));
    }
    (pushed, agg.flush())
}

fn reference(groups: BTreeMap<(i64, i64), Vec<f64>>) -> Vec<(i64, i64, usize, f64, f64, f64)> {
    groups
        .into_iter()
        .map(|((s, e), vs)| {
            let min = vs.iter().copied().fold(f64::INFINITY, f64::min);
            let max = vs.iter().copied().fold(f64::NEG_INFINITY, f64::max);
            (s, e, vs.len(), vs.iter().sum(), min, max)
        })
        .collect()
}

fn summary(rs: &[WindowResult]) -> Vec<(i64, i64, usize, f64, f64, f64)> {
    rs.iter()
        .map(|r| (r.start_ms, r.end_ms, r.count, r.sum, r.min, r.max))
        .collect()
}

proptest! {
    #[test]
    fn tumbling_matches_reference(events in stream(), size in 1i64..50) {
        let (pushed, flushed) = run(WindowKind::Tumbling { size_ms: size }, &events);
        let mut groups: BTreeMap<(i64, i64), Vec<f64>> = BTreeMap::new();
        for &(t, v) in &events {
            let s = t.div_euclid(size) * size;
            groups.entry((s, s + size)).or_default().push(v);
        }
        let mut all = pushed.clone();
        all.extend(flushed.iter().copied());
        // Emitted in strictly increasing start order across push + flush.
        prop_assert!(all.windows(2).all(|w| w[0].start_ms < w[1].start_ms));
        prop_assert_eq!(summary(&all), reference(groups));
        // At most one window (the latest) remains open at flush time.
        prop_assert!(flushed.len() <= 1);
        // A window is only closed by a push once an event lands past its end.
        let last = events.last().map(|e| e.0);
        for r in &pushed {
            prop_assert!(last.is_some_and(|l| l >= r.end_ms));
        }
    }

    #[test]
    fn sliding_matches_reference(events in stream(), size in 1i64..40, step in 1i64..40) {
        let kind = WindowKind::Sliding { size_ms: size, step_ms: step };
        let (pushed, flushed) = run(kind, &events);
        let mut groups: BTreeMap<(i64, i64), Vec<f64>> = BTreeMap::new();
        for &(t, v) in &events {
            // Every window [k*step, k*step + size) that contains t.
            let mut k = t.div_euclid(step);
            while k * step + size > t {
                if k * step <= t {
                    groups.entry((k * step, k * step + size)).or_default().push(v);
                }
                k -= 1;
            }
        }
        let mut all = pushed;
        all.extend(flushed.iter().copied());
        prop_assert!(all.windows(2).all(|w| w[0].start_ms < w[1].start_ms));
        prop_assert_eq!(summary(&all), reference(groups));
        // Closed-on-push windows have ended by the time they are emitted.
        let mut wm = i64::MIN;
        let mut agg = WindowAggregator::new(kind);
        for &(t, v) in &events {
            wm = wm.max(t);
            for r in agg.push(t, v) {
                prop_assert!(r.end_ms <= wm);
            }
        }
        // Still-open windows at flush time have not ended yet.
        for r in &flushed {
            prop_assert!(r.end_ms > wm);
        }
    }

    #[test]
    fn session_matches_reference(events in stream(), gap in 0i64..30) {
        let (pushed, flushed) = run(WindowKind::Session { gap_ms: gap }, &events);
        let mut sessions: Vec<Vec<(i64, f64)>> = Vec::new();
        for &(t, v) in &events {
            match sessions.last_mut() {
                Some(cur) if t - cur[cur.len() - 1].0 <= gap => cur.push((t, v)),
                _ => sessions.push(vec![(t, v)]),
            }
        }
        let want: Vec<_> = sessions
            .iter()
            .map(|s| {
                let vs: Vec<f64> = s.iter().map(|e| e.1).collect();
                let mut g = BTreeMap::new();
                g.insert((s[0].0, s[s.len() - 1].0), vs);
                reference(g)[0]
            })
            .collect();
        let mut all = pushed;
        all.extend(flushed.iter().copied());
        prop_assert_eq!(summary(&all), want);
        prop_assert!(flushed.len() <= 1);
        // Consecutive sessions are separated by more than the gap.
        prop_assert!(all.windows(2).all(|w| w[1].start_ms - w[0].end_ms > gap));
    }
}
