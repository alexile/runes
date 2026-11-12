//! Property tests: CPE names round-trip through their formatted string,
//! version comparison is a total preorder, and no parser panics.

use core::cmp::Ordering;

use proptest::prelude::*;
use rune_cve::{Cpe, CveId, NvdFeed, compare_versions};

fn component() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("*".to_owned()),
        Just("-".to_owned()),
        Just(r"\-".to_owned()),
        "[a-z0-9_.]{1,8}",
        r"\*?[a-z0-9]{1,4}(\\[:+!*?~])?[a-z0-9.]{0,4}\??",
        "[a-z0-9]{1,4}\\*",
    ]
}

fn cpe_string() -> impl Strategy<Value = String> {
    (
        prop_oneof![Just("a"), Just("o"), Just("h"), Just("*")],
        proptest::collection::vec(component(), 10),
    )
        .prop_map(|(part, rest)| format!("cpe:2.3:{part}:{}", rest.join(":")))
}

fn version() -> impl Strategy<Value = String> {
    "v?[0-9]{1,3}([._-]([0-9]{1,3}|rc|beta|alpha|dev|p|a|k|post)){0,5}"
}

proptest! {
    #[test]
    fn cpe_round_trips(s in cpe_string()) {
        let cpe: Cpe = s.parse().unwrap();
        let text = cpe.to_string();
        prop_assert_eq!(&text.parse::<Cpe>().unwrap(), &cpe);
        // Canonical text is a fixed point.
        prop_assert_eq!(text.parse::<Cpe>().unwrap().to_string(), text);
        // Every name matches itself.
        prop_assert!(cpe.matches(&cpe));
    }

    #[test]
    fn version_order_is_a_total_preorder(a in version(), b in version(), c in version()) {
        prop_assert_eq!(compare_versions(&a, &a), Ordering::Equal);
        prop_assert_eq!(compare_versions(&a, &b), compare_versions(&b, &a).reverse());
        let ab = compare_versions(&a, &b);
        let bc = compare_versions(&b, &c);
        if ab != Ordering::Greater && bc != Ordering::Greater {
            prop_assert_ne!(compare_versions(&a, &c), Ordering::Greater, "{} {} {}", a, b, c);
        }
        if ab == Ordering::Equal && bc == Ordering::Equal {
            prop_assert_eq!(compare_versions(&a, &c), Ordering::Equal);
        }
    }

    #[test]
    fn parsers_never_panic(s in "\\PC{0,64}") {
        let _ = s.parse::<Cpe>();
        let _ = format!("cpe:2.3:{s}").parse::<Cpe>();
        let _ = format!("cpe:/{s}").parse::<Cpe>();
        let _ = s.parse::<CveId>();
        let _ = compare_versions(&s, "1.0");
        let _ = NvdFeed::from_json(s.as_bytes());
    }

    #[test]
    fn cve_ids_round_trip(year in 1999u16..=2099, seq in 1u64..100_000_000) {
        let id = CveId::new(year, seq).unwrap();
        prop_assert_eq!(id.to_string().parse::<CveId>().unwrap(), id);
    }
}
