//! Property tests: the text parsers never panic, and counting agrees with
//! line-by-line parsing.

#![allow(clippy::unwrap_used, reason = "a failed parse fails the property")]

use std::fmt::Write as _;

use proptest::prelude::*;
use rune_strace::{Profile, SyscallId, call_name, count_calls, first_quoted_string, parse_line};

fn name() -> impl Strategy<Value = String> {
    "[a-z_][a-z0-9_]{0,15}"
}

proptest! {
    #[test]
    fn parsers_never_panic(text in "\\PC*") {
        let _ = parse_line(&text);
        let _ = call_name(&text);
        let _ = first_quoted_string(&text);
        let _ = count_calls(&text);
    }

    #[test]
    fn complete_lines_round_trip(
        pid in proptest::option::of(1u32..4_000_000),
        name in name(),
        args in "[a-zA-Z0-9_, ]{0,20}",
        result in "-?[0-9]{1,6}",
    ) {
        let prefix = pid.map(|p| format!("{p} ")).unwrap_or_default();
        let line = format!("{prefix}{name}({args}) = {result}");
        let call = parse_line(&line).unwrap();
        prop_assert_eq!(call.pid, pid.map(|p| p.to_string()));
        prop_assert_eq!(&call.name, &name);
        prop_assert_eq!(call.args, args);
        prop_assert_eq!(call.result, result);
        prop_assert_eq!(call_name(&line), Some(name.as_str()));
    }

    #[test]
    fn split_calls_count_once(names in prop::collection::vec(name(), 0..20)) {
        let mut log = String::new();
        for (i, name) in names.iter().enumerate() {
            writeln!(log, "{i} {name}(1, <unfinished ...>").unwrap();
            writeln!(log, "{i} <... {name} resumed>2) = 0").unwrap();
        }
        let counts = count_calls(&log);
        prop_assert_eq!(counts.values().sum::<u64>(), names.len() as u64);
    }

    #[test]
    fn profile_counts_sum_to_total(ids in prop::collection::vec((0u32..3, 0u64..50), 0..100)) {
        let profile: Profile = ids.iter().map(|(a, n)| SyscallId::new(*a, *n)).collect();
        prop_assert_eq!(profile.total(), ids.len() as u64);
        prop_assert_eq!(profile.iter().map(|(_, n)| n).sum::<u64>(), ids.len() as u64);
        for arch in profile.arches() {
            let numbers = profile.numbers_for(arch);
            prop_assert!(numbers.windows(2).all(|w| w[0] < w[1]));
        }
    }
}
