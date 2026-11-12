//! Douglas-Peucker invariants: the output is an order-preserving subsequence
//! that keeps both endpoints, every dropped point lies within `epsilon` of
//! the chord that replaced it, and a larger `epsilon` never keeps more points.

use proptest::prelude::*;
use rune_simplify::simplify;

/// Distance from `p` to the infinite line through `a` and `b` (or to `a`
/// when they coincide), written independently of the crate.
fn line_distance(p: (f64, f64), a: (f64, f64), b: (f64, f64)) -> f64 {
    let (dx, dy) = (b.0 - a.0, b.1 - a.1);
    let len = dx.hypot(dy);
    if len == 0.0 {
        return (p.0 - a.0).hypot(p.1 - a.1);
    }
    dy.mul_add(p.0 - a.0, -dx * (p.1 - a.1)).abs() / len
}

/// Indices of `kept` within `points`, matched greedily in order, or `None`
/// if `kept` is not a subsequence of `points`.
fn subsequence_indices(points: &[(f64, f64)], kept: &[(f64, f64)]) -> Option<Vec<usize>> {
    let mut indices = Vec::with_capacity(kept.len());
    let mut next = 0;
    for k in kept {
        let found = points[next..].iter().position(|p| p == k)? + next;
        indices.push(found);
        next = found + 1;
    }
    Some(indices)
}

/// Paths with strictly increasing `x`, so every point is distinct and the
/// subsequence match is unambiguous.
fn path() -> impl Strategy<Value = Vec<(f64, f64)>> {
    prop::collection::vec((0.01..10.0f64, -50.0..50.0f64), 0..64).prop_map(|steps| {
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

#[test]
fn known_values() {
    // A square wave keeps every corner at a small tolerance.
    let wave = [(0.0, 0.0), (0.0, 1.0), (1.0, 1.0), (1.0, 0.0), (2.0, 0.0)];
    assert_eq!(simplify(&wave, 0.1), wave.to_vec());
    // Only the peak survives a moderate tolerance on a triangle with noise.
    let path = [(0.0, 0.0), (1.0, 0.1), (2.0, 4.0), (3.0, 0.1), (4.0, 0.0)];
    // (1, 0.1) is 0.85 from the chord (0, 0)-(2, 4).
    assert_eq!(
        simplify(&path, 1.0),
        vec![(0.0, 0.0), (2.0, 4.0), (4.0, 0.0)]
    );
    assert_eq!(simplify(&path, 0.8), path.to_vec());
    assert_eq!(simplify(&path, 5.0), vec![(0.0, 0.0), (4.0, 0.0)]);
    // A point exactly at distance epsilon is dropped (strict comparison).
    let path = [(0.0, 0.0), (1.0, 1.0), (2.0, 0.0)];
    assert_eq!(simplify(&path, 1.0), vec![(0.0, 0.0), (2.0, 0.0)]);
    assert_eq!(simplify(&path, 0.999), path.to_vec());
}

#[test]
fn negative_epsilon_terminates() {
    // Regression: with every interior point exactly on the chord, a negative
    // epsilon re-split the same range forever and overflowed the stack.
    let collinear = [(0.0, 0.0), (1.0, 0.0), (2.0, 0.0), (3.0, 0.0)];
    assert_eq!(simplify(&collinear, -1.0), simplify(&collinear, 0.0));
    let bent = [(0.0, 0.0), (1.0, 1.0), (2.0, 0.0)];
    assert_eq!(simplify(&bent, -1.0), bent.to_vec());
}

#[test]
fn long_paths_do_not_overflow_the_stack() {
    // Regression: the recursion was as deep as the path is long when each
    // split peels off one point, as it does on a zigzag: every interior point
    // ties for farthest and the first one wins.
    let path: Vec<(f64, f64)> = (0..5_000)
        .map(|i| (f64::from(i), f64::from(i % 2)))
        .collect();
    let handle = std::thread::Builder::new()
        .stack_size(64 * 1024)
        .spawn(move || simplify(&path, 0.0).len())
        .unwrap();
    assert_eq!(handle.join().unwrap(), 5_000);
}

proptest! {
    #[test]
    fn output_is_subsequence_with_endpoints(points in path(), epsilon in 0.0..20.0f64) {
        let kept = simplify(&points, epsilon);
        let indices = subsequence_indices(&points, &kept);
        prop_assert!(indices.is_some(), "not a subsequence");
        prop_assert!(kept.len() <= points.len());
        if points.len() < 3 {
            prop_assert_eq!(&kept, &points);
        } else {
            prop_assert_eq!(kept.first(), points.first());
            prop_assert_eq!(kept.last(), points.last());
        }
    }

    #[test]
    fn dropped_points_are_within_epsilon(points in path(), epsilon in 0.0..20.0f64) {
        let kept = simplify(&points, epsilon);
        let indices = subsequence_indices(&points, &kept).unwrap();
        for pair in indices.windows(2) {
            let (a, b) = (points[pair[0]], points[pair[1]]);
            for &p in &points[pair[0] + 1..pair[1]] {
                let d = line_distance(p, a, b);
                prop_assert!(d <= epsilon + 1e-9, "{:?} is {} from chord {:?}-{:?}", p, d, a, b);
            }
        }
    }

    #[test]
    fn larger_epsilon_keeps_a_subset(points in path(), e1 in 0.0..20.0f64, e2 in 0.0..20.0f64) {
        let (small, large) = if e1 <= e2 { (e1, e2) } else { (e2, e1) };
        let fine = simplify(&points, small);
        let coarse = simplify(&points, large);
        prop_assert!(subsequence_indices(&fine, &coarse).is_some());
    }

    #[test]
    fn second_pass_never_adds_points(points in path(), epsilon in 0.0..20.0f64) {
        let once = simplify(&points, epsilon);
        let twice = simplify(&once, epsilon);
        prop_assert!(subsequence_indices(&once, &twice).is_some());
    }

    #[test]
    fn huge_epsilon_keeps_only_endpoints(points in path()) {
        prop_assume!(points.len() >= 2);
        let kept = simplify(&points, f64::INFINITY);
        prop_assert_eq!(kept, vec![points[0], points[points.len() - 1]]);
    }

    #[test]
    fn never_panics(
        points in prop::collection::vec((any::<f64>(), any::<f64>()), 0..32),
        epsilon in any::<f64>(),
    ) {
        let kept = simplify(&points, epsilon);
        prop_assert!(kept.len() <= points.len());
    }
}
