//! Round-trip and robustness property tests.

use proptest::prelude::*;
use rune_base64::{decode, encode, encode_no_pad, encode_url, encode_url_no_pad};

proptest! {
    #[test]
    fn every_encoder_round_trips(data in prop::collection::vec(any::<u8>(), 0..256)) {
        for encoded in [
            encode(&data),
            encode_url(&data),
            encode_no_pad(&data),
            encode_url_no_pad(&data),
        ] {
            prop_assert_eq!(decode(&encoded), Ok(data.clone()), "{}", encoded);
        }
    }

    #[test]
    fn padded_output_is_whole_quanta(data in prop::collection::vec(any::<u8>(), 0..64)) {
        let padded = encode(&data);
        prop_assert_eq!(padded.len() % 4, 0);
        prop_assert_eq!(padded.trim_end_matches('='), encode_no_pad(&data));
    }

    #[test]
    fn decode_never_panics(text in prop_oneof![
        prop::collection::vec(any::<char>(), 0..48).prop_map(String::from_iter),
        "[A-Za-z0-9+/_=-]{0,48}",
    ]) {
        let _ = decode(&text);
    }
}
