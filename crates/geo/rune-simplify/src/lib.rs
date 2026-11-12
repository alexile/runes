//! Douglas-Peucker line simplification for coordinate paths.
//!
//! Reduces the number of points in a polyline while preserving its overall
//! shape: it recursively keeps the point with the maximum perpendicular
//! distance from the line segment between the current endpoints, as long as
//! that distance exceeds a tolerance (`epsilon`), and discards every point
//! in between otherwise.
//!
//! # Features
//!
//! - [`simplify`] — simplify a path of `(x, y)` points down to the subset
//!   needed to stay within `epsilon` of the original shape.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_simplify::simplify;
//!
//! // A near-straight line with one clearly redundant point.
//! let path = [(0.0, 0.0), (5.0, 0.01), (10.0, 0.0)];
//! let simplified = simplify(&path, 1.0);
//! assert_eq!(simplified, vec![(0.0, 0.0), (10.0, 0.0)]);
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-simplify --epsilon 0.5 points.json
//! ```

/// Simplifies `points` using the Douglas-Peucker algorithm, keeping only the
/// points needed to stay within `epsilon` of the original path.
///
/// The first and last points are always kept. Inputs of fewer than 3 points
/// are returned unchanged, since there is nothing to simplify. A point is
/// kept only when its distance strictly exceeds `epsilon`, so points exactly
/// on a chord are dropped even when `epsilon` is zero or negative.
///
/// # Example
///
/// ```rust
/// use rune_simplify::simplify;
///
/// // A real deviation large enough to matter is kept.
/// let path = [(0.0, 0.0), (5.0, 5.0), (10.0, 0.0)];
/// let simplified = simplify(&path, 1.0);
/// assert_eq!(simplified, vec![(0.0, 0.0), (5.0, 5.0), (10.0, 0.0)]);
/// ```
#[must_use]
pub fn simplify(points: &[(f64, f64)], epsilon: f64) -> Vec<(f64, f64)> {
    if points.len() < 3 {
        return points.to_vec();
    }

    let mut keep = vec![false; points.len()];
    keep[0] = true;
    keep[points.len() - 1] = true;

    // An explicit work list instead of recursion: a path whose every split
    // peels off a single point would otherwise recurse once per point and
    // overflow the stack on long inputs.
    let mut ranges = vec![(0, points.len() - 1)];
    while let Some((start, end)) = ranges.pop() {
        if let Some(split) = farthest_beyond(points, start, end, epsilon) {
            keep[split] = true;
            ranges.push((start, split));
            ranges.push((split, end));
        }
    }

    points
        .iter()
        .zip(keep.iter())
        .filter(|(_, k)| **k)
        .map(|(p, _)| *p)
        .collect()
}

/// The interior point of `start..=end` farthest from the chord between its
/// endpoints, if that distance exceeds `epsilon`.
fn farthest_beyond(points: &[(f64, f64)], start: usize, end: usize, epsilon: f64) -> Option<usize> {
    if end <= start + 1 {
        return None;
    }

    let mut max_dist = 0.0;
    let mut max_idx = start;
    for (i, &point) in points.iter().enumerate().take(end).skip(start + 1) {
        let dist = perpendicular_distance(point, points[start], points[end]);
        if dist > max_dist {
            max_dist = dist;
            max_idx = i;
        }
    }

    // `max_idx == start` means every interior point lies on the chord (or is
    // NaN); never split there, even for a negative epsilon, or the same range
    // would be split forever.
    (max_idx > start && max_dist > epsilon).then_some(max_idx)
}

fn perpendicular_distance(p: (f64, f64), a: (f64, f64), b: (f64, f64)) -> f64 {
    let (px, py) = p;
    let (ax, ay) = a;
    let (bx, by) = b;

    let dx = bx - ax;
    let dy = by - ay;

    if dx == 0.0 && dy == 0.0 {
        return (px - ax).hypot(py - ay);
    }

    let numerator = f64::mul_add(
        by,
        -ax,
        f64::mul_add(bx, ay, f64::mul_add(dx, -py, dy * px)),
    )
    .abs();
    let denominator = dx.hypot(dy);
    numerator / denominator
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drops_near_collinear_midpoint() {
        let path = [(0.0, 0.0), (5.0, 0.01), (10.0, 0.0)];
        let simplified = simplify(&path, 1.0);
        assert_eq!(simplified, vec![(0.0, 0.0), (10.0, 0.0)]);
    }

    #[test]
    fn keeps_point_with_real_deviation() {
        let path = [(0.0, 0.0), (5.0, 5.0), (10.0, 0.0)];
        let simplified = simplify(&path, 1.0);
        assert_eq!(simplified, vec![(0.0, 0.0), (5.0, 5.0), (10.0, 0.0)]);
    }

    #[test]
    fn empty_input_returns_empty() {
        let path: [(f64, f64); 0] = [];
        assert_eq!(simplify(&path, 1.0), Vec::<(f64, f64)>::new());
    }

    #[test]
    fn single_point_returns_unchanged() {
        let path = [(1.0, 2.0)];
        assert_eq!(simplify(&path, 1.0), vec![(1.0, 2.0)]);
    }

    #[test]
    fn two_points_returns_unchanged() {
        let path = [(1.0, 2.0), (3.0, 4.0)];
        assert_eq!(simplify(&path, 1.0), vec![(1.0, 2.0), (3.0, 4.0)]);
    }

    #[test]
    fn epsilon_zero_keeps_all_points_when_not_exactly_collinear() {
        // A tiny, non-zero deviation still exceeds an epsilon of exactly 0.
        let path = [(0.0, 0.0), (5.0, 0.000_000_1), (10.0, 0.0)];
        let simplified = simplify(&path, 0.0);
        assert_eq!(simplified, path.to_vec());
    }

    #[test]
    fn epsilon_zero_drops_exactly_collinear_midpoint() {
        // When the midpoint's perpendicular distance is exactly 0.0, it does
        // not exceed an epsilon of 0.0 (a strict `>` comparison), so it is
        // dropped even at epsilon=0. This is the documented, tested
        // behavior of this implementation, not an approximation artifact.
        let path = [(0.0, 0.0), (5.0, 0.0), (10.0, 0.0)];
        let simplified = simplify(&path, 0.0);
        assert_eq!(simplified, vec![(0.0, 0.0), (10.0, 0.0)]);
    }

    #[test]
    fn always_keeps_first_and_last_points() {
        let path = [(0.0, 0.0), (1.0, 0.5), (2.0, -0.5), (3.0, 0.3), (10.0, 0.0)];
        let simplified = simplify(&path, 100.0);
        assert_eq!(simplified.first(), Some(&(0.0, 0.0)));
        assert_eq!(simplified.last(), Some(&(10.0, 0.0)));
    }

    #[test]
    fn zigzag_path_retains_multiple_significant_points() {
        let path = [(0.0, 0.0), (1.0, 5.0), (2.0, 0.0), (3.0, 5.0), (4.0, 0.0)];
        let simplified = simplify(&path, 0.5);
        assert_eq!(simplified, path.to_vec());
    }

    #[test]
    fn coincident_endpoints_use_euclidean_distance_to_endpoint() {
        // start == end, so the "line" degenerates to a point; the max
        // perpendicular distance falls back to straight-line distance.
        let path = [(0.0, 0.0), (3.0, 4.0), (0.0, 0.0)];
        let simplified = simplify(&path, 1.0);
        assert_eq!(simplified, path.to_vec());
    }
}
