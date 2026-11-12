//! Round-trip and robustness property tests.

use proptest::prelude::*;
use rune_polyline::{decode, encode, try_decode};

fn points() -> impl Strategy<Value = Vec<(f64, f64)>> {
    prop::collection::vec((-90.0..=90.0f64, -180.0..=180.0f64), 0..32)
}

proptest! {
    /// Decoding recovers every point to the format's 1e-5 precision, and the
    /// decoded points re-encode to the same string.
    #[test]
    fn round_trips(points in points()) {
        let encoded = encode(&points);
        let decoded = try_decode(&encoded).unwrap();
        prop_assert_eq!(decoded.len(), points.len());
        for (&(lat, lon), &(dlat, dlon)) in points.iter().zip(&decoded) {
            prop_assert!((lat - dlat).abs() <= 0.5e-5 + 1e-9, "{} vs {}", lat, dlat);
            prop_assert!((lon - dlon).abs() <= 0.5e-5 + 1e-9, "{} vs {}", lon, dlon);
        }
        prop_assert_eq!(encode(&decoded), encoded);
        prop_assert_eq!(decode(&encode(&points)), decoded);
    }

    /// The lenient decoder returns a prefix of what the strict one would.
    #[test]
    fn decoders_never_panic(text in prop_oneof![
        prop::collection::vec(any::<char>(), 0..48).prop_map(String::from_iter),
        "[?-~]{0,48}",
    ]) {
        let lenient = decode(&text);
        if let Ok(strict) = try_decode(&text) {
            prop_assert_eq!(strict, lenient);
        }
    }
}

// ---- Known values and further properties ----

#[test]
fn google_known_values() {
    // Google "Encoded Polyline Algorithm Format": the worked example encodes
    // the single value -179.9832104 as "`~oia@"; here it is the latitude,
    // and a zero longitude encodes as "?".
    assert_eq!(encode(&[(-179.983_210_4, 0.0)]), "`~oia@?");
    // The documented three-point path.
    assert_eq!(
        encode(&[(38.5, -120.2), (40.7, -120.95), (43.252, -126.453)]),
        "_p~iF~ps|U_ulLnnqC_mqNvxq`@"
    );
    assert_eq!(encode(&[(0.0, 0.0)]), "??");
    // Small deltas fit in a single chunk: +1e-5 is "A", -1e-5 is "@".
    assert_eq!(encode(&[(0.000_01, -0.000_01)]), "A@");
    // A repeated point encodes as a zero delta.
    assert_eq!(encode(&[(1.0, 2.0), (1.0, 2.0)]), "_ibE_seK??");
}

#[test]
fn decodes_google_example_exactly() {
    let points = try_decode("_p~iF~ps|U_ulLnnqC_mqNvxq`@").unwrap();
    assert_eq!(
        points,
        vec![(38.5, -120.2), (40.7, -120.95), (43.252, -126.453)]
    );
}

proptest! {
    /// Encoders emit only the polyline alphabet `?`..=`~`.
    #[test]
    fn output_alphabet(points in points()) {
        prop_assert!(encode(&points).bytes().all(|b| (b'?'..=b'~').contains(&b)));
    }

    /// Encoding a prefix of a path yields a prefix of the encoding.
    #[test]
    fn prefix_encodes_to_prefix(points in points(), cut in 0usize..32) {
        let cut = cut.min(points.len());
        let full = encode(&points);
        prop_assert!(full.starts_with(&encode(&points[..cut])));
    }

    /// The lenient decoder returns every whole point before a truncation.
    #[test]
    fn truncated_input_decodes_a_prefix(points in points(), cut in any::<prop::sample::Index>()) {
        let encoded = encode(&points);
        let at = cut.index(encoded.len() + 1);
        let partial = decode(&encoded[..at]);
        let all = decode(&encoded);
        prop_assert!(partial.len() <= all.len());
        prop_assert_eq!(&all[..partial.len()], &partial[..]);
    }

    /// Values on the 1e-5 grid round-trip exactly.
    #[test]
    fn grid_points_round_trip_exactly(
        grid in prop::collection::vec((-9_000_000i64..=9_000_000, -18_000_000i64..=18_000_000), 0..16),
    ) {
        #[allow(clippy::cast_precision_loss, reason = "grid values are far below 2^52")]
        let points: Vec<(f64, f64)> = grid
            .iter()
            .map(|&(lat, lon)| (lat as f64 / 1e5, lon as f64 / 1e5))
            .collect();
        prop_assert_eq!(try_decode(&encode(&points)).unwrap(), points);
    }
}
