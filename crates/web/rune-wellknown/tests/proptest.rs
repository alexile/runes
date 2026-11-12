//! Property tests: MTA-STS policies round-trip through their canonical
//! form, and no parser panics on arbitrary input.

use proptest::prelude::*;
use rune_wellknown::{MtaStsPolicy, Response, WellKnown, parse, parse_body};

proptest! {
    #[test]
    fn mta_sts_round_trips(
        mode in prop::sample::select(vec!["enforce", "testing", "none"]),
        mx in prop::collection::vec("(\\*\\.)?[a-z0-9]{1,10}(\\.[a-z0-9]{1,10}){0,3}", 1..4),
        max_age in 0u64..=31_557_600,
    ) {
        let mut text = format!("version: STSv1\nmode: {mode}\nmax_age: {max_age}\n");
        for m in &mx {
            text.push_str("mx: ");
            text.push_str(m);
            text.push('\n');
        }
        let policy = MtaStsPolicy::parse(&text).unwrap();
        prop_assert_eq!(&policy.mx, &mx);
        prop_assert_eq!(MtaStsPolicy::parse(&policy.to_string()), Ok(policy));
    }

    #[test]
    fn arbitrary_input_never_panics(s in any::<String>(), status in any::<u16>(), path in "[ -~]{0,40}") {
        for kind in WellKnown::ALL {
            let _ = parse_body(kind, &s);
            let _ = parse(&kind.path(), &Response::new(status, s.as_bytes()).with_header("Location", s.clone()));
        }
        let _ = parse(&path, &Response::new(status, s.as_bytes()));
    }
}
