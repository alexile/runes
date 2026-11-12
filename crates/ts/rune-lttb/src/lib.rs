//! Largest-Triangle-Three-Buckets (LTTB) downsampling for chart-ready series.
//!
//! Naive decimation (keeping every Nth point) can silently erase sharp spikes
//! that fall on a dropped index. LTTB instead buckets the series and, within
//! each bucket, keeps the point that forms the largest triangle area against
//! the previously-kept point and the *average* of the next bucket — which
//! tends to preserve visually significant features (spikes, corners) rather
//! than an arbitrary sample.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_lttb::{downsample, Point};
//!
//! let points: Vec<Point> = (0..100)
//!     .map(|i| Point { x: i as f64, y: (i as f64).sin() })
//!     .collect();
//!
//! let reduced = downsample(&points, 10);
//! assert_eq!(reduced.len(), 10);
//! assert_eq!(reduced[0], points[0]);
//! assert_eq!(reduced[9], points[99]);
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-lttb 10 data.csv
//! ```

/// A single `(x, y)` data point.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Point {
    /// X coordinate (usually time).
    pub x: f64,
    /// Y coordinate (the sampled value).
    pub y: f64,
}

/// Downsamples `points` to `threshold` points using LTTB.
///
/// The first and last input points are always kept. If `threshold >=
/// points.len()` or `threshold < 3`, `points` is returned unchanged — there's
/// nothing meaningful to downsample in either case.
///
/// # Example
///
/// ```rust
/// use rune_lttb::{downsample, Point};
///
/// let points = vec![
///     Point { x: 0.0, y: 0.0 },
///     Point { x: 1.0, y: 1.0 },
///     Point { x: 2.0, y: 0.0 },
/// ];
/// // Fewer points than threshold: returned unchanged.
/// assert_eq!(downsample(&points, 10).len(), 3);
/// ```
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    reason = "the value is non-negative and bounded by the input size; float-to-int `as` saturates"
)]
#[must_use]
pub fn downsample(points: &[Point], threshold: usize) -> Vec<Point> {
    let n = points.len();
    if threshold >= n || threshold < 3 {
        return points.to_vec();
    }

    let mut sampled = Vec::with_capacity(threshold);
    sampled.push(points[0]);

    let bucket_count = threshold - 2;
    let every = (n - 2) as f64 / bucket_count as f64;
    let mut a = 0usize;

    for i in 0..bucket_count {
        let avg_start = (((i + 1) as f64 * every) as usize + 1).min(n - 1);
        let mut avg_end = (((i + 2) as f64 * every) as usize + 1).min(n);
        if avg_end <= avg_start {
            avg_end = (avg_start + 1).min(n);
        }

        let avg_len = (avg_end - avg_start) as f64;
        let (mut avg_x, mut avg_y) = (0.0, 0.0);
        for point in &points[avg_start..avg_end] {
            avg_x += point.x;
            avg_y += point.y;
        }
        avg_x /= avg_len;
        avg_y /= avg_len;

        let range_start = ((i as f64 * every) as usize + 1).min(n - 1);
        let range_end = (((i + 1) as f64 * every) as usize + 1)
            .min(n)
            .max(range_start + 1);

        let point_a = points[a];
        let mut max_area = -1.0;
        let mut max_area_index = range_start;

        for (offset, point) in points[range_start..range_end].iter().enumerate() {
            let area = (point_a.x - point.x)
                .mul_add(
                    -(avg_y - point_a.y),
                    (point_a.x - avg_x) * (point.y - point_a.y),
                )
                .abs()
                * 0.5;
            if area > max_area {
                max_area = area;
                max_area_index = range_start + offset;
            }
        }

        sampled.push(points[max_area_index]);
        a = max_area_index;
    }

    sampled.push(points[n - 1]);
    sampled
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(
        clippy::cast_precision_loss,
        reason = "counts and indices stay far below 2^52, so the f64 conversion is exact"
    )]
    fn line(n: usize) -> Vec<Point> {
        (0..n)
            .map(|i| Point {
                x: i as f64,
                y: i as f64,
            })
            .collect()
    }

    #[test]
    fn returns_exactly_threshold_points() {
        let points = line(1000);
        let reduced = downsample(&points, 50);
        assert_eq!(reduced.len(), 50);
    }

    #[test]
    fn preserves_first_and_last_point() {
        let points = line(1000);
        let reduced = downsample(&points, 50);
        assert_eq!(reduced.first(), points.first());
        assert_eq!(reduced.last(), points.last());
    }

    #[test]
    fn shorter_than_threshold_is_unchanged() {
        let points = line(5);
        let reduced = downsample(&points, 50);
        assert_eq!(reduced, points);
    }

    #[test]
    fn threshold_below_three_is_unchanged() {
        let points = line(100);
        let reduced = downsample(&points, 2);
        assert_eq!(reduced, points);
    }

    #[test]
    fn preserves_a_sharp_spike() {
        let mut points: Vec<Point> = (0..200)
            .map(|i| Point {
                x: f64::from(i),
                y: 0.0,
            })
            .collect();
        points[100].y = 1000.0; // one sharp spike among 200 flat points

        let reduced = downsample(&points, 20);
        assert_eq!(reduced.len(), 20);

        let max_y = reduced.iter().map(|p| p.y).fold(f64::MIN, f64::max);
        assert!(
            max_y > 100.0,
            "the spike should survive aggressive downsampling, got max_y={max_y}"
        );
    }

    #[test]
    fn exact_threshold_equal_to_length_is_unchanged() {
        let points = line(10);
        let reduced = downsample(&points, 10);
        assert_eq!(reduced, points);
    }
}
