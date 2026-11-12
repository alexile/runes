//! Offline, dependency-free timezone-from-coordinates estimation.
//!
//! Real timezone boundaries follow political borders, not meridians — two
//! points a few kilometers apart can be an hour or more apart in wall-clock
//! time (western China, for instance, is all one zone despite spanning a
//! longitude range that would naively suggest several). Modeling that
//! correctly means shipping a full IANA tzdata polygon set, which is out of
//! scope for a small, self-contained crate with no data-file dependency.
//!
//! Instead, this crate implements the classic **equal-width longitude
//! model**: the globe is divided into 24 nominal zones of 15° each (`360° /
//! 24h`), and a coordinate's offset is estimated as its longitude divided by
//! 15, rounded to the nearest hour. This is exactly the "nautical time"
//! model used at sea, and it is a reasonable approximation for anywhere
//! whose local time roughly tracks solar time. It diverges from real
//! timezones wherever a country chose political convenience over solar
//! alignment — China (one zone, UTC+8, despite spanning roughly five
//! nominal zones), and everywhere that observes a half-hour or 45-minute
//! offset (India, Newfoundland, Nepal, parts of Australia). A handful of
//! those are modeled as explicit bounding-box exceptions so the common cases
//! aren't silently wrong; anything outside those boxes falls back to the
//! pure longitude model.
//!
//! **This is an approximation, not a replacement for a real tzdb.** Do not
//! use it where legal or scheduling correctness depends on the exact
//! observed offset (DST transitions are not modeled at all).
//!
//! # Features
//!
//! - [`estimate_utc_offset_hours`] — longitude-based UTC offset estimate, in
//!   hours, with a small set of named half/quarter-hour exceptions.
//! - Zero dependencies, zero data files — the whole model fits in one
//!   source file.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_tz_lookup::estimate_utc_offset_hours;
//!
//! // Roughly the Greenwich meridian.
//! let offset = estimate_utc_offset_hours(51.5, 0.0);
//! assert!((offset - 0.0).abs() < 1e-9);
//!
//! // Roughly 15 degrees east.
//! let offset = estimate_utc_offset_hours(52.5, 15.0);
//! assert!((offset - 1.0).abs() < 1e-9);
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-tz-lookup 60.1699 24.9384
//! ```

const NAMED_ZONES: &[(f64, f64, f64, f64, f64)] = &[
    (26.0, 30.5, 80.0, 88.5, 5.75),
    (6.0, 37.0, 68.0, 97.5, 5.5),
    (46.0, 61.0, -59.5, -52.0, -3.5),
    (-39.0, -10.0, 129.0, 141.0, 9.5),
];

/// Estimates the UTC offset, in hours, for a `(lat, lon)` coordinate.
///
/// Longitude is divided by 15 and rounded to the nearest hour (the equal-width
/// "nautical time" model), except within a small set of named bounding boxes
/// that model real half-hour and 45-minute-offset regions (India, Nepal,
/// Newfoundland, and central Australia) where the pure longitude model would
/// otherwise be off by up to half an hour.
///
/// This is a documented approximation of real timezone boundaries, not a
/// replacement for a full IANA tzdb lookup — see the module documentation
/// for where and why it diverges. `lon` is clamped to `[-180, 180]` before
/// the calculation; out-of-range input degrades gracefully rather than
/// producing a nonsensical offset.
///
/// # Example
///
/// ```rust
/// use rune_tz_lookup::estimate_utc_offset_hours;
///
/// // Roughly 75 degrees west (US Eastern longitude band).
/// let offset = estimate_utc_offset_hours(40.7, -75.0);
/// assert!((offset - (-5.0)).abs() < 1e-9);
///
/// // Mumbai, India — a documented half-hour-offset exception.
/// let offset = estimate_utc_offset_hours(19.07, 72.87);
/// assert!((offset - 5.5).abs() < 1e-9);
/// ```
#[must_use]
pub fn estimate_utc_offset_hours(lat: f64, lon: f64) -> f64 {
    if let Some(offset) = named_zone_offset(lat, lon) {
        return offset;
    }
    longitude_offset(lon)
}

fn longitude_offset(lon: f64) -> f64 {
    let clamped = lon.clamp(-180.0, 180.0);
    (clamped / 15.0).round()
}

fn named_zone_offset(lat: f64, lon: f64) -> Option<f64> {
    for &(min_lat, max_lat, min_lon, max_lon, offset) in NAMED_ZONES {
        if lat >= min_lat && lat <= max_lat && lon >= min_lon && lon <= max_lon {
            return Some(offset);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prime_meridian_is_roughly_utc_zero() {
        let offset = estimate_utc_offset_hours(51.5, 0.0);
        assert!((offset - 0.0).abs() < 1e-9);
    }

    #[test]
    fn fifteen_east_is_roughly_utc_plus_one() {
        let offset = estimate_utc_offset_hours(52.0, 15.0);
        assert!((offset - 1.0).abs() < 1e-9);
    }

    #[test]
    fn seventy_five_west_is_roughly_utc_minus_five() {
        let offset = estimate_utc_offset_hours(40.7, -75.0);
        assert!((offset - (-5.0)).abs() < 1e-9);
    }

    #[test]
    fn helsinki_longitude_rounds_to_utc_plus_two() {
        let offset = estimate_utc_offset_hours(60.1699, 24.9384);
        assert!((offset - 2.0).abs() < 1e-9);
    }

    #[test]
    fn date_line_edges_are_extreme_offsets() {
        assert!((estimate_utc_offset_hours(0.0, 180.0) - 12.0).abs() < 1e-9);
        assert!((estimate_utc_offset_hours(0.0, -180.0) - (-12.0)).abs() < 1e-9);
    }

    #[test]
    fn out_of_range_longitude_is_clamped() {
        let over = estimate_utc_offset_hours(0.0, 200.0);
        let clamped_edge = estimate_utc_offset_hours(0.0, 180.0);
        assert_eq!(over, clamped_edge);

        let under = estimate_utc_offset_hours(0.0, -200.0);
        let clamped_edge_neg = estimate_utc_offset_hours(0.0, -180.0);
        assert_eq!(under, clamped_edge_neg);
    }

    #[test]
    fn india_named_zone_overrides_longitude_model() {
        // Mumbai: pure longitude model would suggest round(72.87/15)=5, not 5.5.
        let offset = estimate_utc_offset_hours(19.07, 72.87);
        assert!((offset - 5.5).abs() < 1e-9);
    }

    #[test]
    fn nepal_named_zone_takes_priority_over_india_box() {
        // Kathmandu falls inside both the India and Nepal bounding boxes;
        // the more specific Nepal zone must win.
        let offset = estimate_utc_offset_hours(27.7, 85.3);
        assert!((offset - 5.75).abs() < 1e-9);
    }

    #[test]
    fn newfoundland_named_zone_is_negative_half_hour() {
        // St. John's, Newfoundland.
        let offset = estimate_utc_offset_hours(47.56, -52.71);
        assert!((offset - (-3.5)).abs() < 1e-9);
    }

    #[test]
    fn central_australia_named_zone_is_plus_nine_thirty() {
        // Adelaide.
        let offset = estimate_utc_offset_hours(-34.93, 138.6);
        assert!((offset - 9.5).abs() < 1e-9);
    }

    #[test]
    fn points_outside_named_zones_use_pure_longitude_model() {
        // Tokyo: outside every named box, should fall back to round(lon/15).
        let offset = estimate_utc_offset_hours(35.68, 139.77);
        assert!((offset - 9.0).abs() < 1e-9);
    }
}
