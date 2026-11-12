//! Round-trip and robustness property tests.

use proptest::prelude::*;
use rune_binary::{BinaryError, decode, encode, encode_compact};

proptest! {
    #[test]
    fn round_trips(data in prop::collection::vec(any::<u8>(), 0..256)) {
        prop_assert_eq!(decode(&encode(&data)), Ok(data.clone()));
        prop_assert_eq!(decode(&encode_compact(&data)), Ok(data));
    }

    /// Each byte is eight bits; the spaced form adds one separator per gap.
    #[test]
    fn encoded_lengths(data in prop::collection::vec(any::<u8>(), 0..64)) {
        prop_assert_eq!(encode_compact(&data).len(), data.len() * 8);
        prop_assert_eq!(encode(&data).len(), (data.len() * 9).saturating_sub(1));
    }

    /// Valid bit strings, spaced anywhere, re-encode to their compact form.
    #[test]
    fn valid_text_is_canonical(
        bits in "([01]{8}){0,16}",
        spaces in prop::collection::vec(0usize..128, 0..8),
    ) {
        let mut spaced = bits.clone();
        for at in spaces {
            spaced.insert(at.min(spaced.len()), ' ');
        }
        let bytes = decode(&spaced).unwrap();
        prop_assert_eq!(encode_compact(&bytes), bits);
    }

    /// Bit counts that are not a multiple of eight are rejected.
    #[test]
    fn unaligned_is_rejected(bits in "[01]{0,64}") {
        prop_assume!(bits.len() % 8 != 0);
        prop_assert_eq!(decode(&bits), Err(BinaryError::NotByteAligned));
    }

    #[test]
    fn decode_never_panics(text in prop_oneof![
        prop::collection::vec(any::<char>(), 0..48).prop_map(String::from_iter),
        "[01 2x]{0,48}",
    ]) {
        let _ = decode(&text);
    }
}
