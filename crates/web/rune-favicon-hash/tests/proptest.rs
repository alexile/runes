//! Property tests: the hashed text round-trips through base64, wrapping is
//! canonical, and hashing from base64 agrees with hashing raw bytes.

use proptest::prelude::*;
use rune_favicon_hash::{LINE_LEN, favicon_hash, favicon_hash_base64, mime_base64};

proptest! {
    #[test]
    fn mime_base64_round_trips(icon in prop::collection::vec(any::<u8>(), 0..600)) {
        let text = mime_base64(&icon);
        let compact: String = text.chars().filter(|c| *c != '\n').collect();
        prop_assert_eq!(&rune_base64::decode(&compact).unwrap(), &icon);
        prop_assert_eq!(text.is_empty(), icon.is_empty());
        if !icon.is_empty() {
            prop_assert!(text.ends_with('\n'));
            let lines: Vec<_> = text.lines().collect();
            let (last, full) = lines.split_last().unwrap();
            prop_assert!(full.iter().all(|line| line.len() == LINE_LEN));
            prop_assert!(!last.is_empty() && last.len() <= LINE_LEN);
        }
    }

    #[test]
    fn base64_entry_point_agrees(icon in prop::collection::vec(any::<u8>(), 0..600)) {
        let hash = favicon_hash(&icon);
        prop_assert_eq!(favicon_hash_base64(&mime_base64(&icon)), Ok(hash));
        prop_assert_eq!(favicon_hash_base64(&rune_base64::encode(&icon)), Ok(hash));
    }

    #[test]
    fn base64_entry_point_never_panics(s in any::<String>()) {
        let _ = favicon_hash_base64(&s);
    }
}
