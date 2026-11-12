//! Robustness properties for `identify`.

use proptest::prelude::*;
use rune_byte_magic::{FileType, SAMPLE_LEN, identify};

proptest! {
    #[test]
    fn never_panics_and_only_reads_the_sample(
        bytes in prop::collection::vec(any::<u8>(), 0..1200),
    ) {
        let file_type = identify(&bytes);
        prop_assert!(!file_type.name().is_empty());
        prop_assert_eq!(file_type, identify(&bytes[..bytes.len().min(SAMPLE_LEN)]));
    }

    #[test]
    fn printable_ascii_without_magic_is_text(text in "[a-z0-9 ,.\n]{1,600}") {
        prop_assert_eq!(identify(text.as_bytes()), FileType::Text);
    }

    #[test]
    fn utf8_text_is_text(text in "\\PC{1,200}") {
        // Printable Unicode (no control characters).
        let file_type = identify(text.as_bytes());
        // A printable string can still start with a magic such as "BM" or "%PDF-".
        prop_assert!(file_type != FileType::Unknown, "{:?}", text);
    }
}
