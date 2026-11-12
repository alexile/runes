//! Properties of fingerprint matching.

use std::net::{IpAddr, Ipv4Addr};

use proptest::prelude::*;
use rune_wildcard_dns::{Fingerprint, Match};

fn addrs() -> impl Strategy<Value = Vec<IpAddr>> {
    prop::collection::vec(
        any::<u8>().prop_map(|b| IpAddr::V4(Ipv4Addr::new(10, 0, 0, b))),
        1..12,
    )
}

proptest! {
    #[test]
    fn any_subset_of_the_wildcard_is_covered(pool in addrs(), picks in prop::collection::vec(any::<prop::sample::Index>(), 1..6)) {
        let wildcard = Fingerprint::from_parts(pool.clone(), []);
        let subset: Vec<IpAddr> = picks.iter().map(|i| *i.get(&pool)).collect();
        prop_assert_eq!(wildcard.compare(&Fingerprint::from_parts(subset, [])), Match::Covered);
    }

    #[test]
    fn match_follows_set_relations(pool in addrs(), candidate in addrs()) {
        let wildcard = Fingerprint::from_parts(pool.clone(), []);
        let got = wildcard.compare(&Fingerprint::from_parts(candidate.clone(), []));
        let inside = candidate.iter().filter(|a| pool.contains(a)).count();
        let expected = if inside == candidate.len() {
            Match::Covered
        } else if inside > 0 {
            Match::Partial
        } else {
            Match::Disjoint
        };
        prop_assert_eq!(got, expected);
    }

    #[test]
    fn merging_makes_the_other_covered(a in addrs(), b in addrs()) {
        let mut wildcard = Fingerprint::from_parts(a, []);
        let other = Fingerprint::from_parts(b, []);
        wildcard.merge(&other);
        prop_assert_eq!(wildcard.compare(&other), Match::Covered);
        prop_assert!(!wildcard.merge(&other));
    }
}
