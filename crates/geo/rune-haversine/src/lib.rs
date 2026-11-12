//! Great-circle distance and initial bearing between two latitude/longitude
//! coordinates, via the haversine formula.
//!
//! # Features
//!
//! - [`distance_m`] — great-circle distance in meters, using a mean Earth
//!   radius of 6,371,000 m.
//! - [`bearing_deg`] — initial compass bearing (0..360°, 0 = north) from one
//!   point toward another along the great-circle path.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_haversine::{distance_m, bearing_deg};
//!
//! // Helsinki to Turku, roughly 150 km apart.
//! let d = distance_m(60.1699, 24.9384, 60.4518, 22.2666);
//! assert!((140_000.0..160_000.0).contains(&d));
//!
//! let bearing = bearing_deg(0.0, 0.0, 1.0, 0.0);
//! assert!((bearing - 0.0).abs() < 1e-6); // due north
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-haversine 60.1699 24.9384 60.4518 22.2666
//! ```

const EARTH_RADIUS_M: f64 = 6_371_000.0;

/// Great-circle distance between two coordinates, in meters.
///
/// # Example
///
/// ```rust
/// use rune_haversine::distance_m;
///
/// assert_eq!(distance_m(10.0, 20.0, 10.0, 20.0), 0.0);
/// ```
#[must_use]
pub fn distance_m(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
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

/// Initial compass bearing, in degrees, from `(lat1, lon1)` toward `(lat2, lon2)`.
///
/// `0` is north, `90` is east, `180` is south, `270` is west.
///
/// # Example
///
/// ```rust
/// use rune_haversine::bearing_deg;
///
/// let b = bearing_deg(0.0, 0.0, 0.0, 1.0);
/// assert!((b - 90.0).abs() < 1e-6); // due east
/// ```
#[must_use]
pub fn bearing_deg(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    let phi1 = lat1.to_radians();
    let phi2 = lat2.to_radians();
    let d_lambda = (lon2 - lon1).to_radians();

    let y = d_lambda.sin() * phi2.cos();
    let x = (phi1.sin() * phi2.cos()).mul_add(-d_lambda.cos(), phi1.cos() * phi2.sin());
    let theta = y.atan2(x).to_degrees();
    (theta + 360.0) % 360.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distance_between_identical_points_is_zero() {
        assert_eq!(distance_m(51.5, -0.1, 51.5, -0.1), 0.0);
    }

    #[test]
    fn distance_matches_known_reference_at_equator() {
        // 1 degree of longitude at the equator is ~111.19 km.
        let d = distance_m(0.0, 0.0, 0.0, 1.0);
        assert!((110_000.0..112_500.0).contains(&d), "d={d}");
    }

    #[test]
    fn distance_is_symmetric() {
        let a = distance_m(10.0, 20.0, 30.0, 40.0);
        let b = distance_m(30.0, 40.0, 10.0, 20.0);
        assert!((a - b).abs() < 1e-6);
    }

    #[test]
    fn bearing_due_north() {
        let b = bearing_deg(0.0, 0.0, 1.0, 0.0);
        assert!(b.abs() < 1e-6, "b={b}");
    }

    #[test]
    fn bearing_due_east() {
        let b = bearing_deg(0.0, 0.0, 0.0, 1.0);
        assert!((b - 90.0).abs() < 1e-6, "b={b}");
    }

    #[test]
    fn bearing_due_south() {
        let b = bearing_deg(0.0, 0.0, -1.0, 0.0);
        assert!((b - 180.0).abs() < 1e-6, "b={b}");
    }

    #[test]
    fn bearing_due_west() {
        let b = bearing_deg(0.0, 0.0, 0.0, -1.0);
        assert!((b - 270.0).abs() < 1e-6, "b={b}");
    }

    #[test]
    fn bearing_is_always_in_range() {
        let b = bearing_deg(45.0, 45.0, -45.0, -45.0);
        assert!((0.0..360.0).contains(&b));
    }
}
