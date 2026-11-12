//! Property tests: origins round-trip, analysis never panics, and the
//! report agrees with the Fetch CORS check.

use proptest::prelude::*;
use rune_cors::{
    AllowOrigin, CorsHeaders, Exchange, Exposure, Options, Origin, classify, cors_check, probes,
    run,
};

fn origin() -> impl Strategy<Value = String> {
    (
        prop_oneof![Just("https"), Just("http"), Just("wss"), Just("HTTPS")],
        "[a-zA-Z0-9-]{1,10}(\\.[a-zA-Z0-9-]{1,10}){0,3}",
        prop::option::of(any::<u16>()),
    )
        .prop_map(|(s, h, p)| p.map_or_else(|| format!("{s}://{h}"), |p| format!("{s}://{h}:{p}")))
}

fn header_value() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("*".to_owned()),
        Just("null".to_owned()),
        Just("true".to_owned()),
        origin(),
        "[ -~]{0,40}",
    ]
}

fn headers() -> impl Strategy<Value = Vec<(String, String)>> {
    prop::collection::vec(
        (
            prop_oneof![
                Just("Access-Control-Allow-Origin".to_owned()),
                Just("access-control-allow-credentials".to_owned()),
                Just("Access-Control-Allow-Headers".to_owned()),
                Just("Access-Control-Allow-Private-Network".to_owned()),
                Just("Vary".to_owned()),
                "[A-Za-z-]{1,20}",
            ],
            header_value(),
        ),
        0..6,
    )
}

proptest! {
    #[test]
    fn origin_serialization_is_a_fixed_point(s in origin()) {
        if let Ok(o) = Origin::parse(&s) {
            let text = o.to_string();
            prop_assert_eq!(Origin::parse(&text), Ok(o));
            prop_assert_eq!(AllowOrigin::parse(&text).granted(), Some(text));
        }
    }

    #[test]
    fn origin_parse_never_panics(s in "\\PC{0,60}") {
        let _ = Origin::parse(&s);
        let _ = AllowOrigin::parse(&s);
        let _ = CorsHeaders::parse_block(&s);
    }

    #[test]
    fn run_agrees_with_cors_check(
        req in prop::option::of(prop_oneof![origin(), Just("null".to_owned())]),
        pairs in headers(),
        target in origin(),
    ) {
        let h = CorsHeaders::from_pairs(pairs);
        let options = Origin::parse(&target).map(Options::for_target).unwrap_or_default();
        let report = run(&[Exchange::new(req.as_deref(), h.clone())], &options);
        let row = &report.rows[0];
        if let Some(o) = &req {
            prop_assert_eq!(row.exposure, cors_check(o, &h));
            prop_assert_eq!(row.class, Some(classify(o, &options)));
        }
        if row.exposure == Exposure::Credentialed {
            prop_assert!(h.allows_credentials());
        }
        prop_assert_eq!(row.severity, report.max_severity());
        prop_assert!(report.weaknesses.windows(2).all(|w| w[0].severity >= w[1].severity));
    }

    #[test]
    fn probes_classify_as_labelled(target in origin()) {
        if let Ok(t) = Origin::parse(&target) {
            let options = Options::for_target(t.clone());
            for p in probes(&t) {
                prop_assert_eq!(classify(&p.origin, &options), p.class, "{}", p.origin);
            }
        }
    }
}
