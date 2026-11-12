//! Property tests for the text forms and the limit invariants.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers: a failed parse fails the property"
)]

use std::fmt::Write as _;

use proptest::prelude::*;
use rune_rlimits::{LimitSet, Resource, Rlimit, Value, parse_proc_limits};

fn value() -> impl Strategy<Value = Value> {
    prop_oneof![
        any::<u64>().prop_map(Value::Limited),
        Just(Value::Unlimited)
    ]
}

fn resource() -> impl Strategy<Value = Resource> {
    prop::sample::select(Resource::ALL)
}

proptest! {
    #[test]
    fn value_display_round_trips(v in value()) {
        prop_assert_eq!(v.to_string().parse::<Value>().unwrap(), v);
    }

    #[test]
    fn rlimit_display_round_trips(a in value(), b in value()) {
        let limit = Rlimit::new(a.min(b), a.max(b)).unwrap();
        prop_assert_eq!(limit.to_string().parse::<Rlimit>().unwrap(), limit);
    }

    #[test]
    fn new_enforces_soft_at_most_hard(a in value(), b in value()) {
        prop_assert_eq!(Rlimit::new(a, b).is_ok(), a <= b);
    }

    #[test]
    fn clamping_never_exceeds_the_ceiling(a in value(), b in value(), c in value()) {
        let clamped = Rlimit::new(a.min(b), a.max(b)).unwrap().clamped_to(c);
        prop_assert!(clamped.soft() <= clamped.hard());
        prop_assert!(clamped.hard() <= c);
    }

    #[test]
    fn resource_names_round_trip(r in resource()) {
        prop_assert_eq!(r.name().parse::<Resource>().unwrap(), r);
        prop_assert_eq!(r.short_name().parse::<Resource>().unwrap(), r);
    }

    #[test]
    fn a_set_holds_each_resource_once(pairs in prop::collection::vec((resource(), value()), 0..40)) {
        let set: LimitSet = pairs.iter().map(|(r, v)| (*r, Rlimit::fixed(*v))).collect();
        let mut seen: Vec<Resource> = set.iter().map(|(r, _)| r).collect();
        let len = seen.len();
        seen.sort_unstable();
        seen.dedup();
        prop_assert_eq!(seen.len(), len);
        for (r, _) in &pairs {
            let last = pairs.iter().rev().find(|(r2, _)| r2 == r).map(|(_, v)| *v);
            prop_assert_eq!(set.get(*r).map(Rlimit::soft), last);
        }
    }

    #[test]
    fn proc_table_round_trips(pairs in prop::collection::vec((resource(), value(), value()), 0..20)) {
        let mut text = String::from("Limit                     Soft Limit           Hard Limit           Units     \n");
        let mut expected = Vec::new();
        for (r, a, b) in pairs {
            let limit = Rlimit::new(a.min(b), a.max(b)).unwrap();
            writeln!(text, "{:<26}{:<21}{:<21}{:<10}", r.proc_label(), limit.soft(), limit.hard(), "").unwrap();
            expected.push((r, limit));
        }
        prop_assert_eq!(parse_proc_limits(&text).unwrap(), expected);
    }

    #[test]
    fn proc_parser_never_panics(text in "\\PC*") {
        let _ = parse_proc_limits(&text);
        let _ = text.parse::<Resource>();
        let _ = text.parse::<Rlimit>();
    }
}
