//! Property tests: canonical form is a fixed point, structured policies
//! round-trip, and parsing never panics.

use proptest::prelude::*;
use rune_csp::{Directive, Options, Policy, parse_header, run, serialize_header};

const DIRECTIVES: &[&str] = &[
    "default-src",
    "script-src",
    "style-src",
    "img-src",
    "object-src",
    "base-uri",
    "frame-ancestors",
    "sandbox",
    "report-to",
    "upgrade-insecure-requests",
    "x-custom",
];

fn source() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("'self'".to_owned()),
        Just("'none'".to_owned()),
        Just("'unsafe-inline'".to_owned()),
        Just("'strict-dynamic'".to_owned()),
        Just("*".to_owned()),
        Just("data:".to_owned()),
        "[a-z0-9+/_-]{1,30}={0,2}".prop_map(|v| format!("'nonce-{v}'")),
        "[A-Za-z0-9+/]{1,64}={0,2}".prop_map(|v| format!("'sha384-{v}'")),
        (
            prop::option::of("(https|wss|http)"),
            "(\\*\\.)?[a-z0-9-]{1,10}(\\.[a-z0-9-]{1,10}){0,2}",
            prop::option::of(prop_oneof![
                Just("*".to_owned()),
                (0u16..).prop_map(|p| p.to_string())
            ]),
            prop::option::of("/[A-Za-z0-9/._-]{0,10}"),
        )
            .prop_map(|(scheme, host, port, path)| {
                let mut s = scheme.map(|s| format!("{s}://")).unwrap_or_default();
                s.push_str(&host);
                if let Some(p) = port {
                    s.push(':');
                    s.push_str(&p);
                }
                s.push_str(&path.unwrap_or_default());
                s
            }),
    ]
}

fn policy() -> impl Strategy<Value = Policy> {
    prop::collection::vec(
        (
            prop::sample::select(DIRECTIVES),
            prop::collection::vec(source(), 0..5),
        ),
        1..8,
    )
    .prop_map(|ds| {
        let mut p = Policy::new();
        for (name, tokens) in ds {
            p.insert(Directive::new(name, tokens));
        }
        p
    })
}

proptest! {
    #[test]
    fn structured_policies_round_trip(p in policy()) {
        let text = p.to_string();
        prop_assert_eq!(&Policy::parse(&text), &p);
        prop_assert_eq!(text.parse::<Policy>(), Ok(p));
    }

    #[test]
    fn canonical_is_a_fixed_point(s in "\\PC{0,200}") {
        let once = serialize_header(&parse_header(&s));
        let twice = serialize_header(&parse_header(&once));
        prop_assert_eq!(&once, &twice);
        let p = Policy::parse(&s);
        prop_assert_eq!(Policy::parse(&p.to_string()).to_string(), p.to_string());
    }

    #[test]
    fn csp_like_text_never_panics(s in "([a-zA-Z-]{1,12}( ('[a-z0-9=+/-]{0,12}'|[a-z*.:/0-9-]{0,16})){0,4}[;,] ?){0,6}") {
        let report = run(&s, &Options::default());
        prop_assert!(report.weaknesses.iter().all(|w| w.policy < report.policies.len().max(1)));
        let _ = s.parse::<Policy>();
    }

    #[test]
    fn arbitrary_text_never_panics(s in any::<String>()) {
        let _ = run(&s, &Options::default().with_report_only(true));
        let _ = s.parse::<Policy>();
    }
}
