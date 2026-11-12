//! Distance- and speed-profile-based arrival time estimator.
//!
//! Estimates travel time from either a single distance/speed pair or a multi-leg
//! [`SpeedProfile`] (e.g. a route broken into segments with different expected
//! speeds — city streets, then highway, then a final approach), optionally adding
//! fixed dwell time for intermediate stops.
//!
//! # Features
//!
//! - [`eta_constant_speed`] — a single distance at a single speed.
//! - [`eta_profile`] — a multi-leg [`SpeedProfile`], summed.
//! - [`eta_with_stops`] — a profile plus fixed per-stop dwell time.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_eta::eta_constant_speed;
//!
//! let seconds = eta_constant_speed(100.0, 10.0).unwrap();
//! assert_eq!(seconds, 10.0);
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-eta 100.0 10.0
//! ```

/// Estimated seconds to travel `distance_m` at a constant `speed_mps`.
///
/// Returns `None` if `speed_mps` is not positive.
///
/// # Example
///
/// ```rust
/// use rune_eta::eta_constant_speed;
///
/// assert_eq!(eta_constant_speed(100.0, 10.0), Some(10.0));
/// assert_eq!(eta_constant_speed(100.0, 0.0), None);
/// ```
#[must_use]
pub fn eta_constant_speed(distance_m: f64, speed_mps: f64) -> Option<f64> {
    if speed_mps <= 0.0 {
        return None;
    }
    Some(distance_m / speed_mps)
}

/// A route broken into legs, each a `(distance_m, speed_mps)` pair.
#[derive(Debug, Clone, Default)]
pub struct SpeedProfile {
    /// Route legs as `(distance_m, speed_mps)` pairs.
    pub segments: Vec<(f64, f64)>,
}

/// Total estimated seconds across every leg of `profile`.
///
/// Returns `None` if any leg has a non-positive speed. An empty profile returns
/// `Some(0.0)`.
///
/// # Example
///
/// ```rust
/// use rune_eta::{SpeedProfile, eta_profile};
///
/// let profile = SpeedProfile { segments: vec![(100.0, 10.0), (50.0, 5.0)] };
/// assert_eq!(eta_profile(&profile), Some(20.0));
/// ```
#[must_use]
pub fn eta_profile(profile: &SpeedProfile) -> Option<f64> {
    let mut total = 0.0;
    for &(distance_m, speed_mps) in &profile.segments {
        total += eta_constant_speed(distance_m, speed_mps)?;
    }
    Some(total)
}

/// [`eta_profile`] plus `stop_duration_s * num_stops` of fixed dwell time.
///
/// # Example
///
/// ```rust
/// use rune_eta::{SpeedProfile, eta_with_stops};
///
/// let profile = SpeedProfile { segments: vec![(100.0, 10.0)] };
/// assert_eq!(eta_with_stops(&profile, 30.0, 2), Some(70.0));
/// ```
#[allow(
    clippy::cast_precision_loss,
    reason = "counts and indices stay far below 2^52, so the f64 conversion is exact"
)]
#[must_use]
pub fn eta_with_stops(
    profile: &SpeedProfile,
    stop_duration_s: f64,
    num_stops: usize,
) -> Option<f64> {
    let base = eta_profile(profile)?;
    Some(stop_duration_s.mul_add(num_stops as f64, base))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_speed_matches_hand_computation() {
        assert_eq!(eta_constant_speed(100.0, 10.0), Some(10.0));
    }

    #[test]
    fn zero_speed_returns_none() {
        assert_eq!(eta_constant_speed(100.0, 0.0), None);
    }

    #[test]
    fn negative_speed_returns_none() {
        assert_eq!(eta_constant_speed(100.0, -5.0), None);
    }

    #[test]
    fn profile_sums_legs_correctly() {
        let profile = SpeedProfile {
            segments: vec![(100.0, 10.0), (200.0, 20.0), (30.0, 3.0)],
        };
        // 10s + 10s + 10s
        assert_eq!(eta_profile(&profile), Some(30.0));
    }

    #[test]
    fn profile_with_bad_leg_returns_none() {
        let profile = SpeedProfile {
            segments: vec![(100.0, 10.0), (50.0, 0.0)],
        };
        assert_eq!(eta_profile(&profile), None);
    }

    #[test]
    fn empty_profile_is_zero() {
        let profile = SpeedProfile::default();
        assert_eq!(eta_profile(&profile), Some(0.0));
    }

    #[test]
    fn stops_add_fixed_dwell_time() {
        let profile = SpeedProfile {
            segments: vec![(100.0, 10.0)],
        };
        assert_eq!(eta_with_stops(&profile, 15.0, 3), Some(10.0 + 45.0));
    }

    #[test]
    fn zero_stops_matches_base_profile() {
        let profile = SpeedProfile {
            segments: vec![(100.0, 10.0)],
        };
        assert_eq!(eta_with_stops(&profile, 15.0, 0), eta_profile(&profile));
    }
}
