//! Property tests for the text encoder and histogram.

#![allow(clippy::unwrap_used, reason = "test helpers")]

use proptest::prelude::*;
use rune_metrics::{Format, Histogram, Registry};

/// Undoes label value escaping.
fn unescape(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some(other) => out.push(other),
                None => {}
            }
        } else {
            out.push(c);
        }
    }
    out
}

proptest! {
    #[test]
    fn label_values_round_trip_through_escaping(value in any::<String>()) {
        let registry = Registry::new();
        let fam = registry.gauge_vec(("g", "h"), &["v"]).unwrap();
        fam.with_label_values(&[&value]).unwrap().set(1.0);
        for format in [Format::Prometheus, Format::OpenMetrics] {
            let text = registry.encode(format);
            let line = text.lines().find(|l| l.starts_with("g{")).unwrap();
            // Exactly one sample line: escaped newlines never break lines.
            prop_assert_eq!(text.lines().filter(|l| !l.starts_with('#')).count(), 1);
            let inner = line.strip_prefix("g{v=\"").unwrap().strip_suffix("\"} 1").unwrap();
            prop_assert_eq!(unescape(inner), value.clone());
        }
    }

    #[test]
    fn histogram_buckets_are_cumulative(obs in proptest::collection::vec(-10.0f64..10.0, 0..64)) {
        let h = Histogram::new(&[-1.0, 0.0, 1.0, 5.0]).unwrap();
        for v in &obs {
            h.observe(*v);
        }
        let s = h.snapshot();
        prop_assert_eq!(s.count, obs.len() as u64);
        prop_assert!(s.buckets.windows(2).all(|w| w[0].1 <= w[1].1));
        for (bound, count) in &s.buckets {
            prop_assert_eq!(*count, obs.iter().filter(|v| **v <= *bound).count() as u64);
        }
    }

    #[test]
    fn arbitrary_names_never_panic(name in any::<String>(), label in any::<String>()) {
        let registry = Registry::new();
        let _ = registry.counter_vec((name.as_str(), "help"), &[label.as_str()]);
        let _ = registry.encode(Format::OpenMetrics);
    }
}
