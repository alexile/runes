//! Round-trip and robustness property tests.

use proptest::prelude::*;
use rune_url_encode::{decode, decode_bytes, decode_lossy, encode, encode_bytes};

fn text() -> impl Strategy<Value = String> {
    prop_oneof![
        prop::collection::vec(any::<char>(), 0..48).prop_map(String::from_iter),
        "[a-zA-Z0-9 %+._~-]{0,48}",
    ]
}

proptest! {
    #[test]
    fn round_trips(input in text()) {
        let encoded = encode(&input);
        prop_assert!(encoded.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.~%".contains(&b)));
        prop_assert_eq!(decode(&encoded).ok(), Some(input));
    }

    #[test]
    fn bytes_round_trip_when_utf8(data in prop::collection::vec(any::<u8>(), 0..64)) {
        let decoded = decode(&encode_bytes(&data));
        prop_assert_eq!(decoded.ok(), String::from_utf8(data).ok());
    }

    #[test]
    fn raw_bytes_round_trip(data in prop::collection::vec(any::<u8>(), 0..64)) {
        prop_assert_eq!(decode_bytes(encode_bytes(&data).as_bytes()).ok(), Some(data));
    }

    #[test]
    fn decoders_never_panic(input in text()) {
        let _ = decode_bytes(input.as_bytes());
        let _ = decode(&input);
        let _ = decode_lossy(&input);
    }
}
