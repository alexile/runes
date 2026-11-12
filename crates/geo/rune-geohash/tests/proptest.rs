//! Round-trip and robustness property tests.

use proptest::prelude::*;
use rune_geohash::{decode, decode_bounds, encode};

proptest! {
    /// The cell a point encodes to contains the point.
    #[test]
    fn cell_contains_point(lat in -90.0..=90.0f64, lon in -180.0..=180.0f64, precision in 1usize..=12) {
        let hash = encode(lat, lon, precision);
        prop_assert_eq!(hash.len(), precision);
        let (min_lat, min_lon, max_lat, max_lon) = decode_bounds(&hash).unwrap();
        prop_assert!((min_lat..=max_lat).contains(&lat), "{} not in {}..{}", lat, min_lat, max_lat);
        prop_assert!((min_lon..=max_lon).contains(&lon), "{} not in {}..{}", lon, min_lon, max_lon);
    }

    /// Every valid hash decodes to a centre that encodes back to the hash.
    #[test]
    fn hash_round_trips(hash in "[0-9b-hjkmnp-z]{1,12}") {
        let (lat, lon) = decode(&hash).unwrap();
        prop_assert_eq!(encode(lat, lon, hash.len()), hash);
    }

    #[test]
    fn decode_never_panics(chars in prop::collection::vec(any::<char>(), 0..24)) {
        let _ = decode(&String::from_iter(chars));
    }
}

// ---- Known values and further properties ----
//
// Cell edges are dyadic fractions of the 180 x 360 degree globe, so the
// bounds are exact and compared with `==` on purpose.

/// Lowercase geohash alphabet: digits and letters except `a`, `i`, `l`, `o`.
const ALPHABET: &str = "0123456789bcdefghjkmnpqrstuvwxyz";

#[test]
fn wikipedia_known_values() {
    // Wikipedia "Geohash": 57.64911, 10.40744 is u4pruydqqvj.
    assert_eq!(encode(57.64911, 10.40744, 11), "u4pruydqqvj");
    // Wikipedia: ezs42 is the cell 42.583..42.627 N, 5.625..5.581 W.
    assert_eq!(encode(42.6, -5.6, 5), "ezs42");
    let (min_lat, min_lon, max_lat, max_lon) = decode_bounds("ezs42").unwrap();
    assert_eq!(
        (min_lat, min_lon, max_lat, max_lon),
        (42.583_007_812_5, -5.625, 42.626_953_125, -5.581_054_687_5)
    );
    let (lat, lon) = decode("ezs42").unwrap();
    assert!((lat - 42.605).abs() < 1e-3 && (lon - (-5.603)).abs() < 1e-3);
}

#[test]
fn corner_and_origin_cells() {
    assert_eq!(encode(0.0, 0.0, 6), "s00000");
    assert_eq!(encode(-90.0, -180.0, 4), "0000");
    assert_eq!(encode(90.0, 180.0, 4), "zzzz");
    assert_eq!(encode(-0.000_001, -0.000_001, 1), "7");
    assert_eq!(encode(0.0, 0.0, 0), "");
    assert_eq!(decode_bounds("").unwrap(), (-90.0, -180.0, 90.0, 180.0));
    assert_eq!(decode("").unwrap(), (0.0, 0.0));
}

#[test]
fn first_character_tiles_the_globe() {
    // The 32 one-character cells are 45 x 45 degree tiles laid out in
    // Z-order: longitude bits first, so "0" is the south-west corner and
    // "z" the north-east corner.
    let mut area = 0.0;
    for c in ALPHABET.chars() {
        let (min_lat, min_lon, max_lat, max_lon) = decode_bounds(&c.to_string()).unwrap();
        assert_eq!(max_lat - min_lat, 45.0);
        assert_eq!(max_lon - min_lon, 45.0);
        area = (max_lat - min_lat).mul_add(max_lon - min_lon, area);
    }
    assert_eq!(area, 180.0 * 360.0);
    assert_eq!(decode_bounds("0").unwrap(), (-90.0, -180.0, -45.0, -135.0));
    assert_eq!(decode_bounds("z").unwrap(), (45.0, 135.0, 90.0, 180.0));
}

#[test]
fn rejects_characters_outside_the_alphabet() {
    use rune_geohash::GeohashError;
    for bad in ['a', 'i', 'l', 'o', 'A', 'Z', ' ', '-', 'é'] {
        assert_eq!(
            decode(&format!("u4p{bad}")),
            Err(GeohashError::InvalidChar(bad)),
            "{bad:?}"
        );
    }
}

proptest! {
    /// A hash of `p` characters has `5p` bits: `ceil(5p/2)` halve the
    /// longitude range and `floor(5p/2)` halve the latitude range.
    #[test]
    fn cell_size_matches_bit_count(hash in "[0-9b-hjkmnp-z]{1,12}") {
        let bits = 5 * i32::try_from(hash.len()).unwrap();
        let (min_lat, min_lon, max_lat, max_lon) = decode_bounds(&hash).unwrap();
        let (lat_span, lon_span) = (180.0 * 2f64.powi(-(bits / 2)), 360.0 * 2f64.powi(-((bits + 1) / 2)));
        prop_assert_eq!((max_lat - min_lat).to_bits(), lat_span.to_bits());
        prop_assert_eq!((max_lon - min_lon).to_bits(), lon_span.to_bits());
    }

    /// Truncating a hash gives the hash of the same point at lower precision,
    /// and its cell encloses the longer hash's cell.
    #[test]
    fn prefixes_nest(lat in -90.0..=90.0f64, lon in -180.0..=180.0f64, long in 2usize..=12, short in 1usize..12) {
        prop_assume!(short < long);
        let hash = encode(lat, lon, long);
        prop_assert_eq!(&hash[..short], encode(lat, lon, short));
        let outer = decode_bounds(&hash[..short]).unwrap();
        let inner = decode_bounds(&hash).unwrap();
        prop_assert!(outer.0 <= inner.0 && outer.1 <= inner.1);
        prop_assert!(outer.2 >= inner.2 && outer.3 >= inner.3);
    }

    /// The decoded centre is within half a cell of the original point.
    #[test]
    fn centre_error_is_half_a_cell(lat in -90.0..=90.0f64, lon in -180.0..=180.0f64, precision in 1usize..=12) {
        let hash = encode(lat, lon, precision);
        let (min_lat, min_lon, max_lat, max_lon) = decode_bounds(&hash).unwrap();
        let (c_lat, c_lon) = decode(&hash).unwrap();
        prop_assert!((c_lat - lat).abs() <= (max_lat - min_lat) / 2.0);
        prop_assert!((c_lon - lon).abs() <= (max_lon - min_lon) / 2.0);
    }

    /// Encoding only emits alphabet characters, even for out-of-range or
    /// non-finite input.
    #[test]
    fn encode_never_panics(lat in any::<f64>(), lon in any::<f64>(), precision in 0usize..=16) {
        let hash = encode(lat, lon, precision);
        prop_assert_eq!(hash.len(), precision);
        prop_assert!(hash.chars().all(|c| ALPHABET.contains(c)));
    }
}
