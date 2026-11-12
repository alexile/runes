//! Property tests: every notation round-trips, prefixes round-trip, and no
//! parser panics on arbitrary text.

use proptest::prelude::*;
use rune_macaddr::{
    Case, Eui64, MacAddr, Notation, OuiDb, OuiPrefix, OuiRecord, RegistryFormat, parse_registry,
};

const NOTATIONS: [Notation; 4] = [
    Notation::Colon,
    Notation::Hyphen,
    Notation::Dot,
    Notation::Bare,
];

proptest! {
    #[test]
    fn mac_round_trips(octets in any::<[u8; 6]>(), upper in any::<bool>()) {
        let mac = MacAddr(octets);
        let case = if upper { Case::Upper } else { Case::Lower };
        for n in NOTATIONS {
            prop_assert_eq!(mac.format(n, case).parse::<MacAddr>(), Ok(mac));
        }
        prop_assert_eq!(mac.to_string().parse::<MacAddr>(), Ok(mac));
        prop_assert_eq!(MacAddr::from_u64(mac.to_u64()), Some(mac));
        prop_assert_eq!(mac.to_eui64().to_mac(), Some(mac));
        prop_assert_eq!(MacAddr::from_ipv6_interface_id(mac.to_ipv6_link_local()), Some(mac));
    }

    #[test]
    fn eui64_round_trips(octets in any::<[u8; 8]>(), upper in any::<bool>()) {
        let eui = Eui64(octets);
        let case = if upper { Case::Upper } else { Case::Lower };
        for n in NOTATIONS {
            prop_assert_eq!(eui.format(n, case).parse::<Eui64>(), Ok(eui));
        }
        prop_assert_eq!(eui.toggle_modified().toggle_modified(), eui);
    }

    #[test]
    fn prefix_round_trips(value in 0u64..(1 << 48), len in 1u8..=48) {
        let p = OuiPrefix::from_u64(value, len).unwrap();
        prop_assert_eq!(p.to_string().parse::<OuiPrefix>(), Ok(p));
        prop_assert!(p.contains(&p.network()));
        let db: OuiDb = std::iter::once(OuiRecord::new(p, "x")).collect();
        prop_assert!(db.lookup(&p.network()).is_some());
    }

    #[test]
    fn parsers_never_panic(s in "\\PC*") {
        let _ = s.parse::<MacAddr>();
        let _ = s.parse::<Eui64>();
        let _ = s.parse::<OuiPrefix>();
        for f in [RegistryFormat::IeeeCsv, RegistryFormat::IeeeTxt, RegistryFormat::Manuf] {
            for _ in parse_registry(&s, f) {}
        }
    }

    #[test]
    fn registry_like_text_never_panics(
        lines in proptest::collection::vec("[0-9A-Fa-f:/ ,\"\t#()-]{0,40}|.{0,20}\\(hex\\).{0,10}|[0-9A-F-]{6,13} +\\(base 16\\)\t.{0,10}", 0..12)
    ) {
        let text = lines.join("\n");
        let mut db = OuiDb::new();
        let _ = db.load(&text);
        for record in db.iter() {
            prop_assert!((1..=48).contains(&record.prefix.bits()));
        }
    }
}
