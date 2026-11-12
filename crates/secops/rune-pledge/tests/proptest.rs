//! Property tests: promise and permission strings round-trip, parsing never
//! panics, and granting more never filters less.

#![allow(clippy::unwrap_used, reason = "test assertions")]

use proptest::prelude::*;
use rune_pledge::{Permissions, Profile, Promise, PromiseSet};

fn promise_set() -> impl Strategy<Value = PromiseSet> {
    proptest::sample::subsequence(Promise::ALL.to_vec(), 0..=Promise::ALL.len())
        .prop_map(|promises| promises.into_iter().collect())
}

fn permissions() -> impl Strategy<Value = Permissions> {
    proptest::sample::subsequence(vec!['r', 'w', 'x', 'c'], 0..=4)
        .prop_map(|letters| letters.into_iter().collect::<String>().parse().unwrap())
}

proptest! {
    #[test]
    fn promise_sets_round_trip(set in promise_set()) {
        prop_assert_eq!(set.to_string().parse::<PromiseSet>().unwrap(), set);
    }

    #[test]
    fn permissions_round_trip(permissions in permissions()) {
        prop_assert_eq!(permissions.to_string().parse::<Permissions>().unwrap(), permissions);
    }

    #[test]
    fn parsing_never_panics(text in "\\PC*") {
        let _ = text.parse::<PromiseSet>();
        let _ = text.parse::<Permissions>();
        let _ = Profile::pledge(&text);
    }

    #[test]
    fn more_promises_allow_more_syscalls(a in promise_set(), b in promise_set()) {
        let small = Profile::new(a).syscalls();
        let large = Profile::new(a.union(b)).syscalls();
        prop_assert!(large.is_superset(&small));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn more_promises_grant_more_rights(
        a in promise_set(),
        b in promise_set(),
        permissions in permissions(),
    ) {
        let rights = |promises| {
            Profile::new(promises)
                .with_path("/srv", permissions)
                .landlock_options()
                .rules
                .first()
                .map_or(rune_landlock::RightSet::EMPTY, |rule| rule.rights)
        };
        let small = rights(a);
        let large = rights(a.union(b));
        prop_assert_eq!(small.intersection(large), small);
    }
}
