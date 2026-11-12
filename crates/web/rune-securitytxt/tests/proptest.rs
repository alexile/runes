//! Property tests: the canonical form is a fixed point, structured
//! documents round-trip, and nothing panics on arbitrary input.

use proptest::prelude::*;
use rune_securitytxt::{Options, SecurityTxt, Timestamp, run};

fn document() -> impl Strategy<Value = SecurityTxt> {
    prop::collection::vec(
        (
            prop_oneof![
                Just("Contact".to_owned()),
                Just("Expires".to_owned()),
                Just("Canonical".to_owned()),
                Just("Preferred-Languages".to_owned()),
                "[A-Za-z][A-Za-z0-9_-]{0,12}",
            ],
            "[!-~\u{a0}-\u{10ff}]([ -~\u{a0}-\u{10ff}]{0,30}[!-~])?",
        ),
        0..8,
    )
    .prop_map(|fields| {
        fields
            .into_iter()
            .fold(SecurityTxt::new(), |d, (n, v)| d.with_field(n, v))
    })
}

proptest! {
    #[test]
    fn structured_documents_round_trip(doc in document()) {
        let parsed = SecurityTxt::parse(&doc.to_string()).unwrap();
        prop_assert!(parsed.malformed.is_empty());
        let a: Vec<_> = doc.fields.iter().map(|f| (f.kind, f.value.clone())).collect();
        let b: Vec<_> = parsed.fields.iter().map(|f| (f.kind, f.value.clone())).collect();
        prop_assert_eq!(a, b);
    }

    #[test]
    fn canonical_is_a_fixed_point(s in "([A-Za-z#-]{0,10}(: ?)?[ -~]{0,20}\r?\n){0,8}") {
        if let Ok(doc) = SecurityTxt::parse(&s) {
            let once = doc.to_string();
            let again = SecurityTxt::parse(&once).unwrap();
            prop_assert_eq!(again.to_string(), once);
        }
    }

    #[test]
    fn timestamps_round_trip(secs in -62_167_219_200i64..253_402_300_800) {
        let t = Timestamp::from_unix_seconds(secs);
        prop_assert_eq!(Timestamp::parse(&t.to_string()), Ok(t));
    }

    #[test]
    fn arbitrary_text_never_panics(s in any::<String>(), t in any::<String>()) {
        let options = Options::default()
            .with_now(Timestamp::from_unix_seconds(0))
            .with_retrieved_from(t.clone());
        let r = run(&s, &options);
        prop_assert_eq!(r.security_txt.is_some(), r.error.is_none());
        prop_assert!(r.weaknesses.windows(2).all(|w| w[0].severity >= w[1].severity));
        let _ = Timestamp::parse(&t);
        let signed = format!("-----BEGIN PGP SIGNED MESSAGE-----\n{s}\n-----BEGIN PGP SIGNATURE-----\n{t}");
        let _ = run(&signed, &options);
    }
}
