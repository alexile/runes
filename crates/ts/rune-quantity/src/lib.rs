//! A typed physical-quantity/unit system with compile-time-checked conversions.
//!
//! Each unit is its own newtype (`Meters`, `Kilometers`, `MetersPerSecond`, ...)
//! rather than a single struct carrying a runtime unit tag. That means mixing
//! units is a compile error, not a runtime bug: `Meters(1.0) + Kilometers(1.0)`
//! simply does not compile, because `Add` is only implemented between identical
//! unit types. Converting between units is explicit, via `From`/`.into()`.
//!
//! Three quantity families are provided: distance, speed, and energy. Each family
//! has one canonical SI unit that every other unit in the family converts through,
//! so adding a new unit only costs two `From` impls instead of one per existing
//! unit.
//!
//! # Features
//!
//! - Distance: [`Meters`] (canonical), [`Kilometers`], [`Miles`], [`Feet`]
//! - Speed: [`MetersPerSecond`] (canonical), [`KilometersPerHour`], [`MilesPerHour`]
//! - Energy: [`Joules`] (canonical), [`KilowattHours`]
//! - [`speed_mps`] — derive a speed from a distance and a duration
//!
//! # Quick Start
//!
//! ```rust
//! use rune_quantity::{Meters, Kilometers};
//!
//! let a = Meters(500.0);
//! let b: Meters = Kilometers(1.5).into();
//! let total = a + b; // same-unit addition compiles directly
//! assert!((total.0 - 2000.0).abs() < 1e-9);
//!
//! // Meters(1.0) + Kilometers(1.0) does not compile: mixing units requires
//! // an explicit .into() first.
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-quantity km-to-m 5
//! rune-quantity mps-to-kmh 10
//! ```

#![cfg_attr(not(any(feature = "std", test)), no_std)]

use core::ops::{Add, Sub};

macro_rules! unit {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
        pub struct $name(pub f64);

        impl Add for $name {
            type Output = $name;
            fn add(self, rhs: $name) -> $name {
                $name(self.0 + rhs.0)
            }
        }

        impl Sub for $name {
            type Output = $name;
            fn sub(self, rhs: $name) -> $name {
                $name(self.0 - rhs.0)
            }
        }
    };
}

// --- Distance, canonical unit: Meters ---

unit!(
    /// A length in meters.
    Meters
);
unit!(
    /// A length in kilometers.
    Kilometers
);
unit!(
    /// A length in international miles.
    Miles
);
unit!(
    /// A length in international feet.
    Feet
);

const METERS_PER_KM: f64 = 1000.0;
const METERS_PER_MILE: f64 = 1609.344;
const METERS_PER_FOOT: f64 = 0.3048;

impl From<Kilometers> for Meters {
    fn from(k: Kilometers) -> Self {
        Self(k.0 * METERS_PER_KM)
    }
}
impl From<Meters> for Kilometers {
    fn from(m: Meters) -> Self {
        Self(m.0 / METERS_PER_KM)
    }
}

impl From<Miles> for Meters {
    fn from(mi: Miles) -> Self {
        Self(mi.0 * METERS_PER_MILE)
    }
}
impl From<Meters> for Miles {
    fn from(m: Meters) -> Self {
        Self(m.0 / METERS_PER_MILE)
    }
}

impl From<Feet> for Meters {
    fn from(ft: Feet) -> Self {
        Self(ft.0 * METERS_PER_FOOT)
    }
}
impl From<Meters> for Feet {
    fn from(m: Meters) -> Self {
        Self(m.0 / METERS_PER_FOOT)
    }
}

// --- Speed, canonical unit: MetersPerSecond ---

unit!(
    /// A speed in meters per second.
    MetersPerSecond
);
unit!(
    /// A speed in kilometers per hour.
    KilometersPerHour
);
unit!(
    /// A speed in miles per hour.
    MilesPerHour
);

const MPS_PER_KMH: f64 = 1.0 / 3.6;
const MPS_PER_MPH: f64 = 0.44704;

impl From<KilometersPerHour> for MetersPerSecond {
    fn from(kmh: KilometersPerHour) -> Self {
        Self(kmh.0 * MPS_PER_KMH)
    }
}
impl From<MetersPerSecond> for KilometersPerHour {
    fn from(mps: MetersPerSecond) -> Self {
        Self(mps.0 / MPS_PER_KMH)
    }
}

impl From<MilesPerHour> for MetersPerSecond {
    fn from(mph: MilesPerHour) -> Self {
        Self(mph.0 * MPS_PER_MPH)
    }
}
impl From<MetersPerSecond> for MilesPerHour {
    fn from(mps: MetersPerSecond) -> Self {
        Self(mps.0 / MPS_PER_MPH)
    }
}

/// Derives a speed from a distance travelled over a duration in seconds.
///
/// # Example
///
/// ```rust
/// use rune_quantity::{Meters, speed_mps};
///
/// let speed = speed_mps(Meters(100.0), 10.0);
/// assert!((speed.0 - 10.0).abs() < 1e-9);
/// ```
#[must_use]
pub fn speed_mps(distance: Meters, duration_secs: f64) -> MetersPerSecond {
    MetersPerSecond(distance.0 / duration_secs)
}

// --- Energy, canonical unit: Joules ---

unit!(
    /// An energy in joules.
    Joules
);
unit!(
    /// An energy in kilowatt-hours.
    KilowattHours
);

const JOULES_PER_KWH: f64 = 3_600_000.0;

impl From<KilowattHours> for Joules {
    fn from(kwh: KilowattHours) -> Self {
        Self(kwh.0 * JOULES_PER_KWH)
    }
}
impl From<Joules> for KilowattHours {
    fn from(j: Joules) -> Self {
        Self(j.0 / JOULES_PER_KWH)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn km_to_m_matches_known_constant() {
        let m: Meters = Kilometers(1.0).into();
        assert!((m.0 - 1000.0).abs() < 1e-9);
    }

    #[test]
    fn mile_to_m_matches_known_constant() {
        let m: Meters = Miles(1.0).into();
        assert!((m.0 - 1609.344).abs() < 1e-9);
    }

    #[test]
    fn foot_to_m_matches_known_constant() {
        let m: Meters = Feet(1.0).into();
        assert!((m.0 - 0.3048).abs() < 1e-9);
    }

    #[test]
    fn mps_to_kmh_matches_standard_factor() {
        let kmh: KilometersPerHour = MetersPerSecond(1.0).into();
        assert!((kmh.0 - 3.6).abs() < 1e-9);
    }

    #[test]
    fn kwh_to_joules_matches_known_constant() {
        let j: Joules = KilowattHours(1.0).into();
        assert!((j.0 - 3_600_000.0).abs() < 1e-9);
    }

    #[test]
    fn same_unit_addition_compiles_and_is_correct() {
        let total = Meters(500.0) + Meters(1500.0);
        assert!((total.0 - 2000.0).abs() < 1e-9);
    }

    #[test]
    fn round_trip_m_km_m_recovers_original() {
        let original = Meters(12345.678);
        let km: Kilometers = original.into();
        let back: Meters = km.into();
        assert!((original.0 - back.0).abs() < 1e-6);
    }

    #[test]
    fn round_trip_mph_mps_mph_recovers_original() {
        let original = MilesPerHour(65.0);
        let mps: MetersPerSecond = original.into();
        let back: MilesPerHour = mps.into();
        assert!((original.0 - back.0).abs() < 1e-6);
    }

    #[test]
    fn speed_mps_derives_correctly() {
        let speed = speed_mps(Meters(100.0), 10.0);
        assert!((speed.0 - 10.0).abs() < 1e-9);
    }

    #[test]
    fn subtraction_between_same_units() {
        let diff = Meters(10.0) - Meters(4.0);
        assert!((diff.0 - 6.0).abs() < 1e-9);
    }
}
