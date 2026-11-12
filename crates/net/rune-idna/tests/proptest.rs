//! Property tests: Punycode round-trips and agrees with the `idna` crate's
//! implementation, UTS #46 processing is stable, and no input makes any
//! function panic.

use proptest::prelude::*;
use rune_idna::{
    DomainReport, LookalikeIndex, Options, RestrictionLevel, SpoofPolicy, is_confusable_with,
    punycode, restriction_level, skeleton, to_ascii, to_unicode,
};

/// Short strings drawn from a mix of scripts, digits, hyphens and dots,
/// so that a useful share of them are valid domain names.
fn domainish() -> impl Strategy<Value = String> {
    let pieces = prop_oneof![
        "[a-z0-9]{1,6}",
        "[A-Z]{1,3}",
        Just("-".to_owned()),
        Just(".".to_owned()),
        Just("。".to_owned()),
        "[а-я]{1,4}",
        "[α-ω]{1,4}",
        "[ぁ-ゖ]{1,3}",
        "[一-龥]{1,3}",
        "[à-ÿ]{1,3}",
        Just("xn--".to_owned()),
        Just("\u{200d}".to_owned()),
        Just("\u{0301}".to_owned()),
        "[\u{0590}-\u{06ff}]{1,3}",
    ];
    proptest::collection::vec(pieces, 0..8).prop_map(|v| v.concat())
}

proptest! {
    #[test]
    fn punycode_round_trip(s in any::<String>()) {
        let encoded = punycode::encode(&s).unwrap();
        prop_assert!(encoded.is_ascii());
        prop_assert_eq!(punycode::decode(&encoded).unwrap(), s);
    }

    #[test]
    fn punycode_matches_idna_crate(s in "\\PC{0,40}") {
        prop_assert_eq!(punycode::encode(&s).ok(), idna::punycode::encode_str(&s));
    }

    #[test]
    fn punycode_decode_matches_idna_crate(s in "[a-z0-9-]{0,24}") {
        prop_assert_eq!(punycode::decode(&s).ok(), idna::punycode::decode_to_string(&s));
    }

    #[test]
    fn punycode_decode_never_panics(s in any::<String>()) {
        if let Ok(decoded) = punycode::decode(&s) {
            // What decodes re-encodes, and decodes back to the same text.
            let again = punycode::encode(&decoded).unwrap();
            prop_assert_eq!(punycode::decode(&again).unwrap(), decoded);
        }
    }

    #[test]
    fn to_ascii_is_stable(s in domainish()) {
        let options = Options::default().with_verify_dns_length(false);
        if let Ok(ascii) = to_ascii(&s, &options) {
            prop_assert!(ascii.is_ascii());
            prop_assert_eq!(&to_ascii(&ascii, &options).unwrap(), &ascii);
            let unicode = to_unicode(&s, &options).unwrap();
            prop_assert_eq!(&to_unicode(&ascii, &options).unwrap(), &unicode);
            prop_assert_eq!(to_ascii(&unicode, &options).unwrap(), ascii);
        }
    }

    #[test]
    fn processing_never_panics(s in any::<String>()) {
        for options in [Options::lookup(), Options::registration()] {
            let _ = to_ascii(&s, &options);
            let _ = to_unicode(&s, &options);
            if let Ok(report) = DomainReport::analyze(&s, &options) {
                let display = report.display(&SpoofPolicy::default());
                prop_assert_eq!(to_ascii(&display, &options).unwrap(), report.ascii);
            }
        }
    }

    #[test]
    fn analysis_of_domainish_input(s in domainish()) {
        let options = Options::default();
        if let Ok(report) = DomainReport::analyze(&s, &options) {
            let display = report.display(&SpoofPolicy::default());
            prop_assert_eq!(&to_ascii(&display, &options).unwrap(), &report.ascii);
            let mut index = LookalikeIndex::new(options.clone());
            index.insert(&s).unwrap();
            prop_assert!(index.find(&s).unwrap().is_empty());
        }
    }

    #[test]
    fn skeleton_properties(s in any::<String>(), t in domainish()) {
        prop_assert!(is_confusable_with(&s, &s));
        let k = skeleton(&t);
        prop_assert_eq!(skeleton(&k), k);
        prop_assert_eq!(
            restriction_level(&s) == RestrictionLevel::AsciiOnly,
            s.is_ascii()
        );
    }
}
