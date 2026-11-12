//! Point-in-shape containment checks and enter/exit event detection over a
//! stream of positions.
//!
//! Supports two fence shapes — a circle (center + radius) and an arbitrary
//! simple polygon — as standalone containment functions, plus a
//! [`GeofenceTracker`] that turns a sequence of position updates into
//! [`FenceEvent`]s by tracking the previous inside/outside state.
//!
//! # Features
//!
//! - [`point_in_circle`] — great-circle-distance-based circular containment.
//! - [`point_in_polygon`] — ray-casting containment for arbitrary simple polygons.
//! - [`GeofenceTracker`] — stateful enter/exit detection over a position stream.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_geofence::{Fence, GeofenceTracker, FenceEvent};
//!
//! let mut tracker = GeofenceTracker::new(Fence::Circle {
//!     center_lat: 60.0,
//!     center_lon: 24.0,
//!     radius_m: 1000.0,
//! });
//!
//! assert_eq!(tracker.update(60.0, 24.0), Some(FenceEvent::Enter));
//! assert_eq!(tracker.update(60.0, 24.0), None); // still inside
//! assert_eq!(tracker.update(61.0, 24.0), Some(FenceEvent::Exit));
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-geofence circle 60.0 24.0 1000 60.001 24.001
//! ```

const EARTH_RADIUS_M: f64 = 6_371_000.0;

fn distance_m(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    let phi1 = lat1.to_radians();
    let phi2 = lat2.to_radians();
    let d_phi = (lat2 - lat1).to_radians();
    let d_lambda = (lon2 - lon1).to_radians();

    let a = (d_phi / 2.0).sin().mul_add(
        (d_phi / 2.0).sin(),
        phi1.cos() * phi2.cos() * (d_lambda / 2.0).sin().powi(2),
    );
    let c = 2.0 * a.sqrt().asin();
    EARTH_RADIUS_M * c
}

/// Whether `(lat, lon)` falls within `radius_m` meters of `(center_lat, center_lon)`.
///
/// # Example
///
/// ```rust
/// use rune_geofence::point_in_circle;
///
/// assert!(point_in_circle(60.0, 24.0, 60.0, 24.0, 10.0));
/// assert!(!point_in_circle(61.0, 24.0, 60.0, 24.0, 10.0));
/// ```
#[must_use]
pub fn point_in_circle(
    lat: f64,
    lon: f64,
    center_lat: f64,
    center_lon: f64,
    radius_m: f64,
) -> bool {
    distance_m(lat, lon, center_lat, center_lon) <= radius_m
}

/// Whether `(lat, lon)` falls within the simple polygon described by `polygon`,
/// a sequence of `(lat, lon)` vertices (implicitly closed from the last vertex
/// back to the first).
///
/// Uses the standard ray-casting algorithm.
///
/// # Example
///
/// ```rust
/// use rune_geofence::point_in_polygon;
///
/// let square = [(0.0, 0.0), (0.0, 10.0), (10.0, 10.0), (10.0, 0.0)];
/// assert!(point_in_polygon(5.0, 5.0, &square));
/// assert!(!point_in_polygon(20.0, 20.0, &square));
/// ```
#[must_use]
pub fn point_in_polygon(lat: f64, lon: f64, polygon: &[(f64, f64)]) -> bool {
    if polygon.len() < 3 {
        return false;
    }

    let mut inside = false;
    let n = polygon.len();
    let mut j = n - 1;
    for i in 0..n {
        let (lat_i, lon_i) = polygon[i];
        let (lat_j, lon_j) = polygon[j];

        let straddles = (lat_i > lat) != (lat_j > lat);
        if straddles {
            let x_intersect = ((lat - lat_i) / (lat_j - lat_i)).mul_add(lon_j - lon_i, lon_i);
            if lon < x_intersect {
                inside = !inside;
            }
        }
        j = i;
    }
    inside
}

/// A geofence shape.
#[derive(Debug, Clone, Copy)]
pub enum Fence<'a> {
    /// A circle around a centre point.
    Circle {
        /// Centre latitude in degrees.
        center_lat: f64,
        /// Centre longitude in degrees.
        center_lon: f64,
        /// Radius in metres.
        radius_m: f64,
    },
    /// A polygon given by its vertices.
    Polygon {
        /// Vertices as `(lat, lon)` pairs; the ring closes implicitly.
        vertices: &'a [(f64, f64)],
    },
}

impl Fence<'_> {
    fn contains(&self, lat: f64, lon: f64) -> bool {
        match self {
            Fence::Circle {
                center_lat,
                center_lon,
                radius_m,
            } => point_in_circle(lat, lon, *center_lat, *center_lon, *radius_m),
            Fence::Polygon { vertices } => point_in_polygon(lat, lon, vertices),
        }
    }
}

/// An enter/exit transition reported by [`GeofenceTracker::update`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FenceEvent {
    /// The point moved from outside to inside the fence.
    Enter,
    /// The point moved from inside to outside the fence.
    Exit,
}

/// Tracks whether a moving point is inside or outside a [`Fence`], reporting
/// [`FenceEvent`]s only on state transitions.
pub struct GeofenceTracker<'a> {
    fence: Fence<'a>,
    inside: bool,
}

impl<'a> GeofenceTracker<'a> {
    /// Creates a tracker for `fence`, initially assuming the tracked point is outside.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_geofence::{Fence, GeofenceTracker};
    ///
    /// let tracker = GeofenceTracker::new(Fence::Circle { center_lat: 0.0, center_lon: 0.0, radius_m: 100.0 });
    /// ```
    #[must_use]
    pub const fn new(fence: Fence<'a>) -> Self {
        GeofenceTracker {
            fence,
            inside: false,
        }
    }

    /// Feeds a new position and returns `Some(FenceEvent)` only when this update
    /// changes the inside/outside state.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_geofence::{Fence, GeofenceTracker, FenceEvent};
    ///
    /// let mut tracker = GeofenceTracker::new(Fence::Circle { center_lat: 0.0, center_lon: 0.0, radius_m: 100.0 });
    /// assert_eq!(tracker.update(0.0, 0.0), Some(FenceEvent::Enter));
    /// assert_eq!(tracker.update(0.0, 0.0), None);
    /// ```
    pub fn update(&mut self, lat: f64, lon: f64) -> Option<FenceEvent> {
        let now_inside = self.fence.contains(lat, lon);
        let event = match (self.inside, now_inside) {
            (false, true) => Some(FenceEvent::Enter),
            (true, false) => Some(FenceEvent::Exit),
            _ => None,
        };
        self.inside = now_inside;
        event
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn circle_containment() {
        assert!(point_in_circle(0.0, 0.0, 0.0, 0.0, 1.0));
        assert!(!point_in_circle(10.0, 10.0, 0.0, 0.0, 1000.0));
    }

    #[test]
    fn polygon_containment_square() {
        let square = [(0.0, 0.0), (0.0, 10.0), (10.0, 10.0), (10.0, 0.0)];
        assert!(point_in_polygon(5.0, 5.0, &square));
        assert!(!point_in_polygon(50.0, 50.0, &square));
    }

    #[test]
    fn polygon_with_too_few_vertices_is_never_containing() {
        assert!(!point_in_polygon(0.0, 0.0, &[(0.0, 0.0), (1.0, 1.0)]));
    }

    #[test]
    fn tracker_reports_single_enter_then_exit() {
        let mut tracker = GeofenceTracker::new(Fence::Circle {
            center_lat: 0.0,
            center_lon: 0.0,
            radius_m: 1000.0,
        });

        assert_eq!(tracker.update(50.0, 50.0), None); // starts outside, stays outside
        assert_eq!(tracker.update(0.0, 0.0), Some(FenceEvent::Enter));
        assert_eq!(tracker.update(0.0, 0.0001), None); // still inside
        assert_eq!(tracker.update(50.0, 50.0), Some(FenceEvent::Exit));
    }

    #[test]
    fn tracker_with_polygon_fence() {
        let square = [(0.0, 0.0), (0.0, 10.0), (10.0, 10.0), (10.0, 0.0)];
        let mut tracker = GeofenceTracker::new(Fence::Polygon { vertices: &square });

        assert_eq!(tracker.update(5.0, 5.0), Some(FenceEvent::Enter));
        assert_eq!(tracker.update(5.0, 5.0), None);
        assert_eq!(tracker.update(50.0, 50.0), Some(FenceEvent::Exit));
    }

    #[test]
    fn staying_inside_across_many_updates_produces_no_repeat_events() {
        let mut tracker = GeofenceTracker::new(Fence::Circle {
            center_lat: 0.0,
            center_lon: 0.0,
            radius_m: 1000.0,
        });
        assert_eq!(tracker.update(0.0, 0.0), Some(FenceEvent::Enter));
        for _ in 0..5 {
            assert_eq!(tracker.update(0.0, 0.0), None);
        }
    }
}
