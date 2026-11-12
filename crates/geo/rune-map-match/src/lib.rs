//! Snap a noisy position stream onto the nearest edges of a supplied road/path graph.
//!
//! GPS fixes wander off the actual path they represent — a few meters here, a
//! building canyon there. Map matching corrects for this by snapping each raw
//! point onto the nearest edge of a known graph (a road network, a factory floor
//! plan, a fixed conveyor route), so downstream consumers work with clean,
//! on-graph positions instead of raw noise.
//!
//! This crate treats coordinates as planar (flat-earth) for its nearest-point
//! projection math. That's the right tradeoff for graphs that span a small area
//! (a site, a city block, a warehouse) where the curvature of the earth is
//! negligible; for large-scale road networks spanning many degrees of latitude,
//! project coordinates into a local planar frame first.
//!
//! # Features
//!
//! - [`nearest_point_on_segment`] — closest point on a single line segment to a
//!   query point, clamped to the segment (no extrapolation past the endpoints).
//! - [`match_point`] — the best-matching edge (and snapped point) for one position,
//!   out of a candidate set.
//! - [`match_trace`] — [`match_point`] applied across a whole recorded trace.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_map_match::{Edge, match_point};
//!
//! let edges = vec![
//!     Edge { id: 0, from: (0.0, 0.0), to: (10.0, 0.0) },
//!     Edge { id: 1, from: (0.0, 5.0), to: (10.0, 5.0) },
//! ];
//!
//! let (edge_id, snapped) = match_point((3.0, 1.0), &edges).unwrap();
//! assert_eq!(edge_id, 0);
//! assert_eq!(snapped, (3.0, 0.0));
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-map-match edges.json trace.json
//! ```

/// One edge of the road/path graph: an id and its two endpoints.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Edge {
    /// Caller-assigned segment identifier.
    pub id: usize,
    /// Segment start as `(lat, lon)`.
    pub from: (f64, f64),
    /// Segment end as `(lat, lon)`.
    pub to: (f64, f64),
}

/// Returns the closest point on segment `a`-`b` to `p`, clamped to the segment
/// (never extrapolated past `a` or `b`).
///
/// # Example
///
/// ```rust
/// use rune_map_match::nearest_point_on_segment;
///
/// // Perpendicular projection onto a horizontal segment.
/// let projected = nearest_point_on_segment((5.0, 3.0), (0.0, 0.0), (10.0, 0.0));
/// assert_eq!(projected, (5.0, 0.0));
///
/// // Past the segment's end: clamps to the endpoint.
/// let clamped = nearest_point_on_segment((15.0, 0.0), (0.0, 0.0), (10.0, 0.0));
/// assert_eq!(clamped, (10.0, 0.0));
/// ```
#[must_use]
pub fn nearest_point_on_segment(p: (f64, f64), a: (f64, f64), b: (f64, f64)) -> (f64, f64) {
    let (ax, ay) = a;
    let (bx, by) = b;
    let (px, py) = p;

    let abx = bx - ax;
    let aby = by - ay;
    let len_sq = f64::mul_add(aby, aby, abx * abx);

    if len_sq == 0.0 {
        return a;
    }

    let t = f64::mul_add(py - ay, aby, (px - ax) * abx) / len_sq;
    let t_clamped = t.clamp(0.0, 1.0);

    (
        f64::mul_add(t_clamped, abx, ax),
        f64::mul_add(t_clamped, aby, ay),
    )
}

fn squared_distance(a: (f64, f64), b: (f64, f64)) -> f64 {
    let dx = a.0 - b.0;
    let dy = a.1 - b.1;
    dy.mul_add(dy, dx * dx)
}

/// Matches `p` against every edge in `edges` (brute force) and returns the id and
/// snapped point of the closest one. Returns `None` if `edges` is empty.
///
/// # Example
///
/// ```rust
/// use rune_map_match::{Edge, match_point};
///
/// let edges = vec![Edge { id: 7, from: (0.0, 0.0), to: (10.0, 0.0) }];
/// let (edge_id, snapped) = match_point((5.0, 2.0), &edges).unwrap();
/// assert_eq!(edge_id, 7);
/// assert_eq!(snapped, (5.0, 0.0));
/// ```
#[must_use]
pub fn match_point(p: (f64, f64), edges: &[Edge]) -> Option<(usize, (f64, f64))> {
    edges
        .iter()
        .map(|edge| {
            let snapped = nearest_point_on_segment(p, edge.from, edge.to);
            (edge.id, snapped, squared_distance(p, snapped))
        })
        .min_by(|(_, _, d1), (_, _, d2)| d1.total_cmp(d2))
        .map(|(id, snapped, _)| (id, snapped))
}

/// Applies [`match_point`] to each point in `points`, in order.
///
/// # Example
///
/// ```rust
/// use rune_map_match::{Edge, match_trace};
///
/// let edges = vec![Edge { id: 0, from: (0.0, 0.0), to: (10.0, 0.0) }];
/// let trace = vec![(1.0, 1.0), (5.0, -1.0)];
/// let matched = match_trace(&trace, &edges);
/// assert_eq!(matched.len(), 2);
/// assert!(matched.iter().all(Option::is_some));
/// ```
#[must_use]
pub fn match_trace(points: &[(f64, f64)], edges: &[Edge]) -> Vec<Option<(usize, (f64, f64))>> {
    points.iter().map(|&p| match_point(p, edges)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn point_on_segment_matches_itself() {
        let projected = nearest_point_on_segment((5.0, 0.0), (0.0, 0.0), (10.0, 0.0));
        assert_eq!(projected, (5.0, 0.0));
    }

    #[test]
    fn perpendicular_projection_on_horizontal_segment() {
        let projected = nearest_point_on_segment((5.0, 3.0), (0.0, 0.0), (10.0, 0.0));
        assert_eq!(projected, (5.0, 0.0));
    }

    #[test]
    fn perpendicular_projection_on_vertical_segment() {
        let projected = nearest_point_on_segment((3.0, 5.0), (0.0, 0.0), (0.0, 10.0));
        assert_eq!(projected, (0.0, 5.0));
    }

    #[test]
    fn clamps_past_far_endpoint() {
        let projected = nearest_point_on_segment((15.0, 4.0), (0.0, 0.0), (10.0, 0.0));
        assert_eq!(projected, (10.0, 0.0));
    }

    #[test]
    fn clamps_past_near_endpoint() {
        let projected = nearest_point_on_segment((-5.0, 4.0), (0.0, 0.0), (10.0, 0.0));
        assert_eq!(projected, (0.0, 0.0));
    }

    #[test]
    fn zero_length_segment_returns_the_point() {
        let projected = nearest_point_on_segment((3.0, 4.0), (1.0, 1.0), (1.0, 1.0));
        assert_eq!(projected, (1.0, 1.0));
    }

    #[test]
    fn match_point_picks_the_nearest_of_several_edges() {
        let edges = vec![
            Edge {
                id: 0,
                from: (0.0, 0.0),
                to: (10.0, 0.0),
            },
            Edge {
                id: 1,
                from: (0.0, 5.0),
                to: (10.0, 5.0),
            },
            Edge {
                id: 2,
                from: (0.0, 20.0),
                to: (10.0, 20.0),
            },
        ];
        let (edge_id, snapped) = match_point((3.0, 4.0), &edges).unwrap();
        assert_eq!(edge_id, 1);
        assert_eq!(snapped, (3.0, 5.0));
    }

    #[test]
    fn match_point_returns_none_for_no_edges() {
        assert!(match_point((0.0, 0.0), &[]).is_none());
    }

    #[test]
    fn match_trace_matches_each_point_independently() {
        let edges = vec![
            Edge {
                id: 0,
                from: (0.0, 0.0),
                to: (10.0, 0.0),
            },
            Edge {
                id: 1,
                from: (0.0, 5.0),
                to: (10.0, 5.0),
            },
        ];
        let trace = vec![(2.0, 1.0), (2.0, 4.0)];
        let matched = match_trace(&trace, &edges);
        assert_eq!(matched[0].unwrap().0, 0);
        assert_eq!(matched[1].unwrap().0, 1);
    }
}
