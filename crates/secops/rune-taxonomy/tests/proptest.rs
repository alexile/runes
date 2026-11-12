//! Property tests for id parsing: canonical text round-trips, and parsing
//! never panics on arbitrary input.

use proptest::prelude::*;
use rune_finding::{Taxonomy, TaxonomyRef};
use rune_taxonomy::{AsvsId, AttackId, CapecId, CweId, OwaspId, OwaspList, resolve, resolve_id};

fn round_trips<T>(id: T)
where
    T: std::fmt::Display
        + std::str::FromStr<Err = rune_taxonomy::Error>
        + PartialEq
        + std::fmt::Debug,
{
    let text = id.to_string();
    assert_eq!(text.parse::<T>(), Ok(id), "{text}");
}

proptest! {
    #[test]
    fn cwe_and_capec_round_trip(number in 1u32..) {
        round_trips(CweId::new(number));
        round_trips(CapecId::new(number));
    }

    #[test]
    fn attack_round_trips(technique in 1u16..=9999, sub in 0u16..=999) {
        let id = if sub == 0 { AttackId::technique(technique) } else { AttackId::subtechnique(technique, sub) };
        round_trips(id);
    }

    #[test]
    fn owasp_round_trips(list in prop::sample::select(OwaspList::ALL.to_vec()), rank in 1u8..=10) {
        round_trips(OwaspId::new(list, rank).unwrap());
    }

    #[test]
    fn asvs_round_trips(chapter in 1u8.., section in 0u8.., requirement in 0u8..) {
        let id = match (section, requirement) {
            (0, _) => AsvsId::chapter(chapter),
            (s, 0) => AsvsId::section(chapter, s),
            (s, r) => AsvsId::requirement(chapter, s, r),
        };
        round_trips(id);
    }

    /// Whatever parses is canonical: it prints back to the same text.
    #[test]
    fn parsing_is_canonical_and_total(text in any::<String>()) {
        if let Ok(id) = text.parse::<CweId>() { prop_assert_eq!(id.to_string(), text.clone()); }
        if let Ok(id) = text.parse::<CapecId>() { prop_assert_eq!(id.to_string(), text.clone()); }
        if let Ok(id) = text.parse::<AttackId>() { prop_assert_eq!(id.to_string(), text.clone()); }
        if let Ok(id) = text.parse::<OwaspId>() { prop_assert_eq!(id.to_string(), text.clone()); }
        if let Ok(id) = text.parse::<AsvsId>() { prop_assert_eq!(id.to_string(), text.clone()); }
        for taxonomy in Taxonomy::KNOWN {
            let _ = resolve_id(&taxonomy, &text);
        }
        let _ = resolve(&TaxonomyRef::owasp(text));
    }

    /// Id-shaped text near the notation: still canonical when accepted.
    #[test]
    fn near_misses_are_canonical(text in "(CWE-|CAPEC-|T|A|API|V| |cwe-)[0-9.: ]{0,8}") {
        for taxonomy in Taxonomy::KNOWN {
            if let Ok(entry) = resolve_id(&taxonomy, &text) {
                prop_assert_eq!(entry.id(), text.clone());
            }
        }
    }

    /// Whitespace around a valid id is always rejected.
    #[test]
    fn padding_is_rejected(number in 1u32..2000, pad in prop::sample::select(vec![" ", "\t", "\n", "\u{a0}"])) {
        let trailing = format!("CWE-{number}{pad}");
        let leading = format!("{pad}CWE-{number}");
        prop_assert!(trailing.parse::<CweId>().is_err());
        prop_assert!(leading.parse::<CweId>().is_err());
    }
}
