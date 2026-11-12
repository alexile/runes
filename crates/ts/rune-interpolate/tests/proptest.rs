//! Property tests: both interpolators hit every knot, linear stays within the
//! bracketing values, and neither panics on arbitrary input.

use proptest::prelude::*;
use rune_interpolate::{cubic_spline, linear};

/// Strictly increasing `x` knots with arbitrary `y` values.
fn knots() -> impl Strategy<Value = Vec<(f64, f64)>> {
    prop::collection::vec((0.01..10.0f64, -1.0e3..1.0e3f64), 2..40).prop_map(|steps| {
        let mut x = 0.0;
        steps
            .into_iter()
            .map(|(dx, y)| {
                x += dx;
                (x, y)
            })
            .collect()
    })
}

proptest! {
    #[test]
    fn both_interpolators_hit_every_knot(points in knots()) {
        for &(x, y) in &points {
            prop_assert_eq!(linear(&points, x), Some(y));
            let s = cubic_spline(&points, x);
            prop_assert!(s.is_some());
            let s = s.unwrap_or(f64::NAN);
            prop_assert!((s - y).abs() <= 1e-6 * (1.0 + y.abs()), "x={x}: {s} vs {y}");
        }
    }

    #[test]
    fn linear_stays_between_bracketing_values(points in knots(), t in 0.0..1.0f64) {
        let first = points[0].0;
        let last = points[points.len() - 1].0;
        let at = t.mul_add(last - first, first);
        let v = linear(&points, at);
        prop_assert!(v.is_some());
        let v = v.unwrap_or(f64::NAN);
        let i = points.windows(2).position(|w| at >= w[0].0 && at <= w[1].0);
        prop_assert!(i.is_some());
        let i = i.unwrap_or(0);
        let (a, b) = (points[i].1, points[i + 1].1);
        prop_assert!(v >= a.min(b) - 1e-9 && v <= a.max(b) + 1e-9);
    }

    #[test]
    fn never_panics_on_arbitrary_input(
        points in prop::collection::vec((any::<f64>(), any::<f64>()), 0..20),
        at in any::<f64>(),
    ) {
        let _ = linear(&points, at);
        let _ = cubic_spline(&points, at);
    }
}
