//! Property tests: structured policies round-trip in both syntaxes, the
//! canonical form is a fixed point, and nothing panics on arbitrary input.

use proptest::prelude::*;
use rune_permissions_policy::{
    Allowlist, Directive, Member, Options, PermissionsPolicy, Syntax, run, run_fields,
};

fn member() -> impl Strategy<Value = Member> {
    prop_oneof![
        Just(Member::All),
        Just(Member::SelfOrigin),
        Just(Member::Src),
        "(https|http)://(\\*\\.)?[a-z0-9-]{1,8}(\\.[a-z]{2,4})?(:[0-9]{1,4})?"
            .prop_map(Member::Origin),
    ]
}

fn policy(syntax: Syntax) -> impl Strategy<Value = PermissionsPolicy> {
    prop::collection::vec(
        (
            "[a-z][a-z0-9_.-]{0,12}",
            prop::collection::vec(member(), 0..4),
            prop::option::of("[a-z][a-z0-9-]{0,6}|[ -~]{0,8}"),
        ),
        0..5,
    )
    .prop_map(move |ds| {
        let mut p = PermissionsPolicy::new(syntax);
        for (name, members, report_to) in ds {
            let mut d = Directive::new(name, Allowlist::new(members));
            // Feature-Policy has no report-to.
            if let (Some(r), Syntax::PermissionsPolicy) = (report_to, syntax) {
                d = d.with_report_to(r);
            }
            p = p.with_directive(d);
        }
        p
    })
}

proptest! {
    #[test]
    fn permissions_policy_round_trips(p in policy(Syntax::PermissionsPolicy)) {
        prop_assert_eq!(PermissionsPolicy::parse(&p.to_string()), Ok(p));
    }

    #[test]
    fn feature_policy_round_trips(p in policy(Syntax::FeaturePolicy)) {
        prop_assert_eq!(PermissionsPolicy::parse_feature_policy(&p.to_string()), Ok(p.clone()));
        let migrated = p.to_permissions_policy();
        prop_assert_eq!(PermissionsPolicy::parse(&migrated.to_string()), Ok(migrated));
    }

    #[test]
    fn canonical_is_a_fixed_point(s in "[a-z*=(),;\" .:/?0-9'-]{0,60}") {
        if let Ok(p) = PermissionsPolicy::parse(&s) {
            let once = p.to_string();
            let again = PermissionsPolicy::parse(&once);
            prop_assert_eq!(again.as_ref().map(ToString::to_string), Ok(once));
            prop_assert_eq!(again, Ok(p));
        }
        if let Ok(p) = PermissionsPolicy::parse_feature_policy(&s) {
            prop_assert_eq!(PermissionsPolicy::parse_feature_policy(&p.to_string()), Ok(p));
        }
    }

    #[test]
    fn arbitrary_text_never_panics(s in any::<String>()) {
        let r = run(&s, &Options::default());
        prop_assert_eq!(r.policy.is_some(), r.error.is_none());
        prop_assert!(r.weaknesses.windows(2).all(|w| w[0].severity >= w[1].severity));
        let _ = run_fields([s.as_str()], [s.as_str()], &Options::default());
        let _ = run_fields([], [s.as_str()], &Options::default());
    }
}
