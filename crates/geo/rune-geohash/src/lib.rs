//! Geohash encoding and decoding — the standard base32 interleaved-bit
//! representation of a latitude/longitude coordinate.
//!
//! A geohash string represents a rectangular cell on Earth's surface: encoding
//! recursively bisects latitude and longitude ranges, appending a `0`/`1` bit for
//! each bisection depending on which half the target point falls into, then packs
//! every 5 bits into one base32 character. Longer hashes describe smaller,
//! more precise cells.
//!
//! # Features
//!
//! - [`encode`] — coordinate + desired character precision to geohash string.
//! - [`decode`] — geohash string to the center point of its cell.
//! - [`decode_bounds`] — geohash string to its full `(min_lat, min_lon, max_lat, max_lon)` cell.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_geohash::{encode, decode};
//!
//! let hash = encode(57.64911, 10.40744, 6);
//! let (lat, lon) = decode(&hash).unwrap();
//! assert!((lat - 57.64911).abs() < 0.01);
//! assert!((lon - 10.40744).abs() < 0.01);
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-geohash encode 57.64911 10.40744 6
//! rune-geohash decode u4pruydqqvj
//! ```

#![cfg_attr(not(any(feature = "std", test)), no_std)]

extern crate alloc;

use alloc::string::String;

const BASE32: &[u8] = b"0123456789bcdefghjkmnpqrstuvwxyz";

/// Error returned when decoding a string that is not a valid geohash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeohashError {
    /// The character is not in the geohash base32 alphabet.
    InvalidChar(char),
}

impl core::fmt::Display for GeohashError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidChar(c) => write!(f, "invalid geohash character {c:?}"),
        }
    }
}

impl core::error::Error for GeohashError {}

/// Encodes a coordinate as a geohash string with `precision` characters.
///
/// # Example
///
/// ```rust
/// use rune_geohash::encode;
///
/// let hash = encode(42.6, -5.6, 5);
/// assert_eq!(hash.len(), 5);
/// ```
#[must_use]
pub fn encode(lat: f64, lon: f64, precision: usize) -> String {
    let mut lat_range = (-90.0f64, 90.0f64);
    let mut lon_range = (-180.0f64, 180.0f64);
    let mut even = true;
    let mut bit = 0u8;
    let mut ch = 0u8;
    let mut out = String::with_capacity(precision);

    while out.len() < precision {
        if even {
            let mid = f64::midpoint(lon_range.0, lon_range.1);
            if lon >= mid {
                ch |= 1 << (4 - bit);
                lon_range.0 = mid;
            } else {
                lon_range.1 = mid;
            }
        } else {
            let mid = f64::midpoint(lat_range.0, lat_range.1);
            if lat >= mid {
                ch |= 1 << (4 - bit);
                lat_range.0 = mid;
            } else {
                lat_range.1 = mid;
            }
        }
        even = !even;

        if bit < 4 {
            bit += 1;
        } else {
            out.push(BASE32[ch as usize] as char);
            bit = 0;
            ch = 0;
        }
    }

    out
}

/// Decodes a geohash string to the center point of its cell.
///
/// # Errors
///
/// Returns [`GeohashError::InvalidChar`] if `hash` contains a character outside
/// the geohash alphabet.
///
/// # Example
///
/// ```rust
/// use rune_geohash::decode;
///
/// let (lat, lon) = decode("s").unwrap();
/// assert!(lat > 0.0 && lon > 0.0);
/// ```
pub fn decode(hash: &str) -> Result<(f64, f64), GeohashError> {
    let (min_lat, min_lon, max_lat, max_lon) = decode_bounds(hash)?;
    Ok((
        f64::midpoint(min_lat, max_lat),
        f64::midpoint(min_lon, max_lon),
    ))
}

/// Decodes a geohash string to the full bounds of its cell:
/// `(min_lat, min_lon, max_lat, max_lon)`.
///
/// # Errors
///
/// Returns [`GeohashError::InvalidChar`] if `hash` contains a character outside
/// the geohash alphabet.
///
/// # Example
///
/// ```rust
/// use rune_geohash::decode_bounds;
///
/// let (min_lat, min_lon, max_lat, max_lon) = decode_bounds("s").unwrap();
/// assert!(min_lat < max_lat);
/// assert!(min_lon < max_lon);
/// ```
pub fn decode_bounds(hash: &str) -> Result<(f64, f64, f64, f64), GeohashError> {
    let mut lat_range = (-90.0f64, 90.0f64);
    let mut lon_range = (-180.0f64, 180.0f64);
    let mut even = true;

    for c in hash.chars() {
        let index = BASE32
            .iter()
            .position(|&b| char::from(b) == c)
            .ok_or(GeohashError::InvalidChar(c))?;

        for i in (0..5).rev() {
            let bit_val = 1 << i;
            if even {
                let mid = f64::midpoint(lon_range.0, lon_range.1);
                if index & bit_val != 0 {
                    lon_range.0 = mid;
                } else {
                    lon_range.1 = mid;
                }
            } else {
                let mid = f64::midpoint(lat_range.0, lat_range.1);
                if index & bit_val != 0 {
                    lat_range.0 = mid;
                } else {
                    lat_range.1 = mid;
                }
            }
            even = !even;
        }
    }

    Ok((lat_range.0, lon_range.0, lat_range.1, lon_range.1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_produces_requested_length() {
        for precision in [1, 5, 9, 12] {
            assert_eq!(encode(10.0, 20.0, precision).len(), precision);
        }
    }

    #[test]
    fn round_trip_within_cell_at_various_precisions() {
        let lat = 57.64911;
        let lon = 10.40744;
        for precision in [3, 6, 9, 11] {
            let hash = encode(lat, lon, precision);
            let (min_lat, min_lon, max_lat, max_lon) = decode_bounds(&hash).unwrap();
            assert!(
                (min_lat..=max_lat).contains(&lat),
                "precision={precision} lat out of bounds"
            );
            assert!(
                (min_lon..=max_lon).contains(&lon),
                "precision={precision} lon out of bounds"
            );
        }
    }

    #[test]
    fn decode_center_is_close_to_original_at_high_precision() {
        let lat = 42.6;
        let lon = -5.6;
        let hash = encode(lat, lon, 10);
        let (d_lat, d_lon) = decode(&hash).unwrap();
        assert!((d_lat - lat).abs() < 0.0001);
        assert!((d_lon - lon).abs() < 0.0001);
    }

    #[test]
    fn longer_hash_bounds_nest_within_shorter_prefix_bounds() {
        let hash = encode(57.64911, 10.40744, 8);
        let short = &hash[..5];
        let long = &hash[..8];

        let (s_min_lat, s_min_lon, s_max_lat, s_max_lon) = decode_bounds(short).unwrap();
        let (l_min_lat, l_min_lon, l_max_lat, l_max_lon) = decode_bounds(long).unwrap();

        assert!(l_min_lat >= s_min_lat);
        assert!(l_max_lat <= s_max_lat);
        assert!(l_min_lon >= s_min_lon);
        assert!(l_max_lon <= s_max_lon);
    }

    #[test]
    fn known_reference_value_ezs42() {
        // Widely cited geohash.org example: "ezs42" ~ (42.6, -5.6).
        let (lat, lon) = decode("ezs42").unwrap();
        assert!((lat - 42.6).abs() < 0.1, "lat={lat}");
        assert!((lon - (-5.6)).abs() < 0.1, "lon={lon}");
    }

    #[test]
    fn bounds_are_ordered() {
        let (min_lat, min_lon, max_lat, max_lon) = decode_bounds("u4pruydqqvj").unwrap();
        assert!(min_lat < max_lat);
        assert!(min_lon < max_lon);
    }
}
