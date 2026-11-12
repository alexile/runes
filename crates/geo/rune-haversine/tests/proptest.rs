//! Known great-circle distances and bearings, plus metric properties:
//! symmetry, non-negativity, the half-circumference bound, the triangle
//! inequality and invariance under longitude shifts.

use std::f64::consts::PI;

use proptest::prelude::*;
use rune_haversine::{bearing_deg, distance_m};

/// Mean Earth radius the crate uses, in meters.
const R: f64 = 6_371_000.0;

fn close(actual: f64, expected: f64, tolerance: f64) -> bool {
    (actual - expected).abs() <= tolerance
}

fn dms(deg: f64, min: f64, sec: f64) -> f64 {
    deg + min / 60.0 + sec / 3600.0
}

#[test]
fn known_geometric_distances() {
    let half = PI * R;
    // Quarter of a great circle: equator to pole, and 90 degrees along the equator.
    assert!(close(distance_m(0.0, 0.0, 90.0, 0.0), half / 2.0, 1e-6));
    assert!(close(distance_m(0.0, 0.0, 0.0, 90.0), half / 2.0, 1e-6));
    // Antipodes and pole to pole are half a great circle.
    assert!(close(distance_m(0.0, 0.0, 0.0, 180.0), half, 1e-6));
    assert!(close(distance_m(90.0, 0.0, -90.0, 0.0), half, 1e-6));
    // One degree of arc.
    assert!(close(distance_m(0.0, 0.0, 0.0, 1.0), half / 180.0, 1e-6));
    assert!(close(
        distance_m(10.0, 33.0, 11.0, 33.0),
        half / 180.0,
        1e-6
    ));
    // Every meridian meets at the pole.
    assert!(close(distance_m(90.0, 0.0, 90.0, 123.0), 0.0, 1e-6));
}

#[test]
fn known_city_pairs() {
    // Rosetta Code "Haversine formula": Nashville BNA to Los Angeles LAX is
    // 2887.26 km with R = 6372.8 km, i.e. 2886.44 km with R = 6371 km.
    let bna_lax = distance_m(36.12, -86.67, 33.94, -118.40);
    assert!(close(bna_lax, 2_886_444.44, 0.01), "{bna_lax}");
    assert!(close(bna_lax * 6372.8 / 6371.0, 2_887_259.95, 0.01));

    // movable-type.co.uk worked example: Land's End to John o' Groats,
    // 968.9 km at an initial bearing of 009°07′11″.
    let (lat1, lon1) = (dms(50.0, 3.0, 59.0), -dms(5.0, 42.0, 53.0));
    let (lat2, lon2) = (dms(58.0, 38.0, 38.0), -dms(3.0, 4.0, 12.0));
    let d = distance_m(lat1, lon1, lat2, lon2);
    assert!(close(d, 968_900.0, 50.0), "{d}");
    let b = bearing_deg(lat1, lon1, lat2, lon2);
    assert!(close(b, dms(9.0, 7.0, 11.0), 1.0 / 3600.0), "{b}");
}

#[test]
fn known_bearings() {
    assert!(close(bearing_deg(0.0, 0.0, 1.0, 1.0), 44.995_636, 1e-5));
    assert!(close(
        bearing_deg(36.12, -86.67, 33.94, -118.40),
        274.593_574,
        1e-5
    ));
    // Heading north from anywhere toward the North Pole.
    assert!(close(bearing_deg(-45.0, 100.0, 90.0, 0.0), 0.0, 1e-9));
    // Heading south toward the South Pole.
    assert!(close(bearing_deg(45.0, 100.0, -90.0, 0.0), 180.0, 1e-9));
}

fn lat() -> impl Strategy<Value = f64> {
    -90.0..=90.0f64
}

fn lon() -> impl Strategy<Value = f64> {
    -180.0..=180.0f64
}

proptest! {
    #[test]
    fn distance_is_a_bounded_symmetric_measure(
        lat1 in lat(), lon1 in lon(), lat2 in lat(), lon2 in lon(),
    ) {
        let d = distance_m(lat1, lon1, lat2, lon2);
        prop_assert!(d.is_finite());
        prop_assert!(d >= 0.0);
        prop_assert!(d <= PI.mul_add(R, 1e-6));
        prop_assert!(close(d, distance_m(lat2, lon2, lat1, lon1), 1e-6));
        prop_assert!(distance_m(lat1, lon1, lat1, lon1).abs() < f64::EPSILON);
    }

    #[test]
    fn antipodes_are_half_a_great_circle(lat1 in lat(), lon1 in lon()) {
        // `asin` is ill-conditioned next to 1, so the haversine form loses
        // a few decimetres at the antipode (about 1e-8 relative).
        let d = distance_m(lat1, lon1, -lat1, lon1 + 180.0);
        prop_assert!(close(d, PI * R, 0.5), "{}", d);
    }

    #[test]
    fn triangle_inequality(
        a in (lat(), lon()), b in (lat(), lon()), c in (lat(), lon()),
    ) {
        let ab = distance_m(a.0, a.1, b.0, b.1);
        let bc = distance_m(b.0, b.1, c.0, c.1);
        let ac = distance_m(a.0, a.1, c.0, c.1);
        // Allow for the haversine form's sub-metre error near antipodes.
        prop_assert!(ac <= ab + bc + 1.0, "{} > {} + {}", ac, ab, bc);
    }

    #[test]
    fn invariant_under_longitude_shift(
        lat1 in lat(), lon1 in lon(), lat2 in lat(), lon2 in lon(), shift in -360.0..=360.0f64,
    ) {
        let d = distance_m(lat1, lon1, lat2, lon2);
        prop_assert!(close(distance_m(lat1, lon1 + shift, lat2, lon2 + shift), d, 1e-3));
        // A full turn of longitude is the same point.
        prop_assert!(close(distance_m(lat1, lon1 + 360.0, lat2, lon2), d, 1e-3));
    }

    #[test]
    fn meridian_and_equator_arcs_are_exact(
        lat1 in lat(), lat2 in lat(), lon1 in lon(), dlon in -180.0..=180.0f64,
    ) {
        // Along a meridian the distance is R times the latitude difference.
        let meridian = distance_m(lat1, lon1, lat2, lon1);
        prop_assert!(close(meridian, R * (lat2 - lat1).abs().to_radians(), 1e-3));
        // Along the equator it is R times the longitude difference.
        let equator = distance_m(0.0, lon1, 0.0, lon1 + dlon);
        prop_assert!(close(equator, R * dlon.abs().to_radians(), 1e-3));
    }

    #[test]
    fn bearing_is_in_range(lat1 in lat(), lon1 in lon(), lat2 in lat(), lon2 in lon()) {
        let b = bearing_deg(lat1, lon1, lat2, lon2);
        prop_assert!((0.0..360.0).contains(&b), "{}", b);
    }

    #[test]
    fn meridian_bearings_point_north_or_south(
        lat1 in -89.0..=89.0f64, lat2 in -89.0..=89.0f64, lon1 in lon(),
    ) {
        prop_assume!((lat1 - lat2).abs() > 1e-6);
        let b = bearing_deg(lat1, lon1, lat2, lon1);
        let expected = if lat2 > lat1 { 0.0 } else { 180.0 };
        prop_assert!(close(b, expected, 1e-6) || close(b, 360.0, 1e-6), "{}", b);
    }

    #[test]
    fn equator_bearings_point_east_or_west(lon1 in lon(), dlon in 1e-3..179.0f64, east in any::<bool>()) {
        let lon2 = if east { lon1 + dlon } else { lon1 - dlon };
        let b = bearing_deg(0.0, lon1, 0.0, lon2);
        prop_assert!(close(b, if east { 90.0 } else { 270.0 }, 1e-6), "{}", b);
    }
}
