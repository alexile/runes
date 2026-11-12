//! Google Encoded Polyline Algorithm Format — encode and decode.
//!
//! The polyline algorithm compresses a series of coordinates into a compact
//! ASCII string by delta-encoding successive points (scaled to 5 decimal places),
//! zigzag-encoding the sign, and packing each value into 5-bit chunks mapped onto
//! printable ASCII. It's the format used by Google Maps' static/directions APIs
//! and widely supported elsewhere.
//!
//! # Features
//!
//! - [`encode`] — a slice of `(lat, lon)` points to an encoded polyline string.
//! - [`decode`] — an encoded polyline string back to `(lat, lon)` points,
//!   stopping at the first malformed value.
//! - [`try_decode`] — the strict decoder: malformed input is a [`PolylineError`].
//!
//! # Quick Start
//!
//! ```rust
//! use rune_polyline::{decode, encode};
//!
//! let points = vec![(38.5, -120.2), (40.7, -120.95), (43.252, -126.453)];
//! let encoded = encode(&points);
//! assert_eq!(encoded, "_p~iF~ps|U_ulLnnqC_mqNvxq`@");
//!
//! let decoded = decode(&encoded);
//! assert!((decoded[0].0 - 38.5).abs() < 1e-5);
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-polyline encode 38.5,-120.2 40.7,-120.95
//! rune-polyline decode '_p~iF~ps|U_ulLnnqC_mqNvxq`@'
//! ```

const PRECISION: f64 = 1e5;

/// A malformed encoded polyline, reported by [`try_decode`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PolylineError {
    /// A byte outside the polyline alphabet (`?` to `~`, 0x3F to 0x7E).
    #[error("invalid polyline byte 0x{byte:02x} at position {pos}")]
    InvalidByte {
        /// Byte offset in the input.
        pos: usize,
        /// The offending byte.
        byte: u8,
    },
    /// The input ends inside a value, or after a latitude with no longitude.
    #[error("polyline is truncated at position {pos}")]
    Truncated {
        /// Byte offset where more input was expected.
        pos: usize,
    },
    /// A value runs past 64 bits (more than 13 five-bit chunks).
    #[error("polyline value at position {pos} does not fit in 64 bits")]
    Overlong {
        /// Byte offset of the chunk that overflowed.
        pos: usize,
    },
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "values are masked or range-limited first; truncation is the intended encoding"
)]
fn encode_value(mut value: i64) -> String {
    value <<= 1;
    if value < 0 {
        value = !value;
    }
    let mut out = String::new();
    while value >= 0x20 {
        let chunk = ((value & 0x1f) | 0x20) as u8;
        out.push((chunk + 63) as char);
        value >>= 5;
    }
    out.push((value as u8 + 63) as char);
    out
}

/// Encodes a series of `(lat, lon)` points into a Google-encoded polyline string.
///
/// Coordinates are rounded to five decimal places. Any finite coordinate
/// with a magnitude below about 2.3e13 round-trips through [`decode`]; real
/// latitudes and longitudes are far inside that. NaN encodes as `0.0`, and
/// larger values saturate, so encoding never panics.
///
/// # Example
///
/// ```rust
/// use rune_polyline::encode;
///
/// assert_eq!(encode(&[]), "");
/// assert_eq!(encode(&[(38.5, -120.2)]), "_p~iF~ps|U");
/// ```
#[allow(
    clippy::cast_possible_truncation,
    reason = "float to int `as` saturates (and maps NaN to 0), which is the intended clamp"
)]
#[must_use]
pub fn encode(points: &[(f64, f64)]) -> String {
    let mut out = String::new();
    let mut prev_lat = 0i64;
    let mut prev_lon = 0i64;

    for &(lat, lon) in points {
        let lat_e5 = (lat * PRECISION).round() as i64;
        let lon_e5 = (lon * PRECISION).round() as i64;
        // Wrapping keeps saturated extremes from overflowing; the decoder
        // accumulates with the same wrapping arithmetic.
        out.push_str(&encode_value(lat_e5.wrapping_sub(prev_lat)));
        out.push_str(&encode_value(lon_e5.wrapping_sub(prev_lon)));
        prev_lat = lat_e5;
        prev_lon = lon_e5;
    }

    out
}

/// Decodes a Google-encoded polyline string back into `(lat, lon)` points.
///
/// This is the lenient decoder: it returns the points decoded before the
/// first malformed or truncated value and ignores the rest. Use
/// [`try_decode`] to reject malformed input instead.
///
/// # Example
///
/// ```rust
/// use rune_polyline::decode;
///
/// let points = decode("_p~iF~ps|U");
/// assert_eq!(points.len(), 1);
/// assert!((points[0].0 - 38.5).abs() < 1e-5);
/// assert!((points[0].1 - (-120.2)).abs() < 1e-5);
///
/// // A truncated second point is dropped.
/// assert_eq!(decode("_p~iF~ps|U_ulL").len(), 1);
/// ```
#[must_use]
pub fn decode(encoded: &str) -> Vec<(f64, f64)> {
    decode_points(encoded).0
}

/// Decodes a Google-encoded polyline string, rejecting malformed input.
///
/// # Errors
///
/// Returns a [`PolylineError`] for a byte outside the polyline alphabet, a
/// truncated value or point, or a value longer than 64 bits.
///
/// # Example
///
/// ```rust
/// use rune_polyline::{PolylineError, try_decode};
///
/// assert_eq!(try_decode("_p~iF~ps|U").unwrap().len(), 1);
/// assert_eq!(try_decode("_p~iF"), Err(PolylineError::Truncated { pos: 5 }));
/// ```
pub fn try_decode(encoded: &str) -> Result<Vec<(f64, f64)>, PolylineError> {
    match decode_points(encoded) {
        (points, None) => Ok(points),
        (_, Some(err)) => Err(err),
    }
}

/// Decodes as many whole points as possible, plus the error that stopped
/// decoding, if any.
#[allow(
    clippy::cast_precision_loss,
    reason = "coordinates are scaled integers; f64 holds every real coordinate exactly enough"
)]
fn decode_points(encoded: &str) -> (Vec<(f64, f64)>, Option<PolylineError>) {
    let bytes = encoded.as_bytes();
    let mut index = 0usize;
    let mut lat = 0i64;
    let mut lon = 0i64;
    let mut points = Vec::new();

    while index < bytes.len() {
        let delta = decode_value(bytes, &mut index)
            .and_then(|dlat| decode_value(bytes, &mut index).map(|dlon| (dlat, dlon)));
        match delta {
            Ok((dlat, dlon)) => {
                lat = lat.wrapping_add(dlat);
                lon = lon.wrapping_add(dlon);
                points.push((lat as f64 / PRECISION, lon as f64 / PRECISION));
            }
            Err(err) => return (points, Some(err)),
        }
    }

    (points, None)
}

/// Decodes one zigzag value starting at `*index` and advances past it.
fn decode_value(bytes: &[u8], index: &mut usize) -> Result<i64, PolylineError> {
    let mut shift = 0u32;
    let mut result: i64 = 0;
    loop {
        let pos = *index;
        let &byte = bytes.get(pos).ok_or(PolylineError::Truncated { pos })?;
        if !(63..=126).contains(&byte) {
            return Err(PolylineError::InvalidByte { pos, byte });
        }
        // 13 chunks of 5 bits cover 64 bits; a 14th cannot be meaningful.
        if shift > 60 {
            return Err(PolylineError::Overlong { pos });
        }
        let chunk = i64::from(byte - 63);
        *index += 1;
        result |= (chunk & 0x1f) << shift;
        shift += 5;
        if chunk < 0x20 {
            break;
        }
    }
    Ok(if result & 1 != 0 {
        !(result >> 1)
    } else {
        result >> 1
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_known_reference_example() {
        let points = vec![(38.5, -120.2), (40.7, -120.95), (43.252, -126.453)];
        assert_eq!(encode(&points), "_p~iF~ps|U_ulLnnqC_mqNvxq`@");
    }

    #[test]
    fn decodes_known_reference_example() {
        let decoded = decode("_p~iF~ps|U_ulLnnqC_mqNvxq`@");
        let expected = [(38.5, -120.2), (40.7, -120.95), (43.252, -126.453)];
        assert_eq!(decoded.len(), expected.len());
        for ((lat, lon), (elat, elon)) in decoded.iter().zip(expected.iter()) {
            assert!((lat - elat).abs() < 1e-5);
            assert!((lon - elon).abs() < 1e-5);
        }
    }

    #[test]
    fn round_trips_arbitrary_points() {
        let points = vec![(60.17, 24.94), (60.18, 24.95), (59.99, 24.80), (61.0, 25.5)];
        let encoded = encode(&points);
        let decoded = decode(&encoded);
        assert_eq!(decoded.len(), points.len());
        for ((lat, lon), (elat, elon)) in decoded.iter().zip(points.iter()) {
            assert!((lat - elat).abs() < 1e-5);
            assert!((lon - elon).abs() < 1e-5);
        }
    }

    #[test]
    fn empty_input_encodes_to_empty_string() {
        assert_eq!(encode(&[]), "");
    }

    #[test]
    fn empty_string_decodes_to_empty_vec() {
        assert_eq!(decode(""), vec![]);
    }

    #[test]
    fn handles_negative_deltas() {
        let points = vec![(1.0, 1.0), (0.5, 0.5), (0.0, 0.0)];
        let encoded = encode(&points);
        let decoded = decode(&encoded);
        for ((lat, lon), (elat, elon)) in decoded.iter().zip(points.iter()) {
            assert!((lat - elat).abs() < 1e-5);
            assert!((lon - elon).abs() < 1e-5);
        }
    }

    // Regressions: truncated input indexed past the
    // end of the string, and long chunk runs overflowed the shift.
    #[test]
    fn malformed_input_is_an_error_not_a_panic() {
        assert_eq!(decode("_"), vec![]);
        assert_eq!(try_decode("_"), Err(PolylineError::Truncated { pos: 1 }));
        assert_eq!(try_decode("??"), Ok(vec![(0.0, 0.0)]));
        assert_eq!(try_decode("?"), Err(PolylineError::Truncated { pos: 1 }));
        assert_eq!(
            try_decode(&"_".repeat(20)),
            Err(PolylineError::Overlong { pos: 13 })
        );
        assert_eq!(
            try_decode("? "),
            Err(PolylineError::InvalidByte { pos: 1, byte: b' ' })
        );
        assert_eq!(
            try_decode("?é"),
            Err(PolylineError::InvalidByte { pos: 1, byte: 0xc3 })
        );
    }

    // Regression: the delta between saturated extremes overflowed.
    #[test]
    fn extreme_coordinates_do_not_panic() {
        let encoded = encode(&[(f64::MAX, f64::MIN), (f64::MIN, f64::NAN), (0.0, 0.0)]);
        assert_eq!(try_decode(&encoded).map(|p| p.len()), Ok(3));
        assert_eq!(decode(&encoded)[2], (0.0, 0.0));
    }
}
