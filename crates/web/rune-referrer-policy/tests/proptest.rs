//! Property tests: keywords round-trip, the effective policy is the last
//! recognised token, and nothing panics on arbitrary input.

use proptest::prelude::*;
use rune_referrer_policy::{
    Header, Options, ReferrerPolicy, parse_meta, run, run_fields, run_meta,
};

fn policy() -> impl Strategy<Value = ReferrerPolicy> {
    prop::sample::select(ReferrerPolicy::ALL.to_vec())
}

proptest! {
    #[test]
    fn keyword_round_trips(p in policy()) {
        prop_assert_eq!(p.to_string().parse::<ReferrerPolicy>(), Ok(p));
        prop_assert_eq!(Header::parse(p.as_str()).policy(), Some(p));
        prop_assert_eq!(parse_meta(p.as_str()).map(|m| m.policy), Ok(p));
    }

    #[test]
    fn last_recognised_token_wins(
        ps in prop::collection::vec(prop::option::of(policy()), 0..6),
    ) {
        let text: Vec<String> = ps
            .iter()
            .map(|p| p.map_or_else(|| "x-unknown".to_owned(), |p| p.as_str().to_owned()))
            .collect();
        let expected = ps.iter().rev().find_map(|p| *p);
        prop_assert_eq!(Header::parse(&text.join(" , ")).policy(), expected);
        let r = run(&text.join(","), &Options::default());
        prop_assert_eq!(r.policy, expected);
    }

    #[test]
    fn arbitrary_text_never_panics(s in any::<String>()) {
        let r = run_fields([s.as_str(), s.as_str()], &Options::default().with_cross_origin(false));
        prop_assert!(r.weaknesses.windows(2).all(|w| w[0].severity >= w[1].severity));
        let _ = run_meta(&s, &Options::default());
        let _ = s.parse::<ReferrerPolicy>();
    }
}
