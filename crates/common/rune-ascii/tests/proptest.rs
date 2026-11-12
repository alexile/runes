//! Round-trip and robustness property tests.
//!
//! `rune-ascii` has no byte codec; its "encodings" are the hex, octal,
//! binary, decimal and character forms of each code point, which
//! [`parse_input`] reads back.

use proptest::prelude::*;
use rune_ascii::{from_char, lookup, parse_input, table};

proptest! {
    /// Every rendered form of a code point parses back to the same entry.
    #[test]
    fn every_form_round_trips(code in 0u8..=127) {
        let entry = lookup(code).unwrap();
        prop_assert_eq!(parse_input(&entry.hex), Some(entry.clone()));
        prop_assert_eq!(parse_input(&entry.octal), Some(entry.clone()));
        prop_assert_eq!(parse_input(&format!("0b{}", entry.binary)), Some(entry.clone()));
        prop_assert_eq!(parse_input(&entry.hex.to_uppercase().replacen("0X", "0x", 1)), Some(entry.clone()));
        // A single digit is read as a character, so decimals need two digits.
        if code >= 10 {
            prop_assert_eq!(parse_input(&code.to_string()), Some(entry.clone()));
        }
        if entry.character != '?' {
            prop_assert_eq!(from_char(entry.character), Some(entry.clone()));
            prop_assert_eq!(parse_input(&entry.character.to_string()), Some(entry));
        }
    }

    /// The rendered forms agree with Rust's own formatting.
    #[test]
    fn forms_match_std(code in 0u8..=127) {
        let entry = &table()[usize::from(code)];
        prop_assert_eq!(entry.code, code);
        prop_assert_eq!(u8::from_str_radix(&entry.hex[2..], 16), Ok(code));
        prop_assert_eq!(u8::from_str_radix(&entry.octal[2..], 8), Ok(code));
        prop_assert_eq!(u8::from_str_radix(&entry.binary, 2), Ok(code));
        prop_assert_eq!(entry.binary.len(), 8);
    }

    #[test]
    fn non_ascii_is_rejected(code in 128u8..=255, ch in any::<char>()) {
        prop_assert!(lookup(code).is_none());
        prop_assert!(parse_input(&code.to_string()).is_none());
        if !(' '..='~').contains(&ch) {
            prop_assert!(from_char(ch).is_none());
        }
    }

    /// Parsing never panics, and anything it accepts is a valid table entry.
    #[test]
    fn parse_never_panics(text in prop_oneof![
        prop::collection::vec(any::<char>(), 0..16).prop_map(String::from_iter),
        "\\s?(0[xXoObB])?[+-]?[0-9a-fA-F]{0,4}\\s?",
    ]) {
        if let Some(entry) = parse_input(&text) {
            prop_assert_eq!(lookup(entry.code), Some(entry));
        }
    }
}
