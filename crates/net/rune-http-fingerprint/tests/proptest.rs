//! Property tests: analysis never panics and the fingerprint ignores
//! header values.

use proptest::prelude::*;
use rune_http_fingerprint::{
    Database, Observations, ProbeKind, analyze, analyze_raw_head, fingerprint,
};
use rune_http_model::HttpResponse;
use std::sync::OnceLock;

fn database() -> &'static Database {
    static DB: OnceLock<Database> = OnceLock::new();
    DB.get_or_init(Database::builtin)
}

fn names() -> impl Strategy<Value = Vec<String>> {
    prop::collection::vec("[A-Za-z][A-Za-z0-9-]{0,15}", 0..12)
}

proptest! {
    #[test]
    fn raw_head_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        let _ = analyze_raw_head(&bytes);
        let mut prefixed = b"HTTP/1.1 ".to_vec();
        prefixed.extend_from_slice(&bytes);
        let head = analyze_raw_head(&prefixed);
        prop_assert!(head.is_some());
    }

    #[test]
    fn analyze_never_panics(
        status in any::<u16>(),
        reason in proptest::option::of(".{0,20}"),
        names in names(),
        raw in proptest::option::of(prop::collection::vec(any::<u8>(), 0..256)),
        body in ".{0,64}",
    ) {
        let mut response = HttpResponse::new(status)
            .with_headers(names.iter().map(|name| (name.as_str(), "v")))
            .with_body(body);
        response.reason = reason;
        if let Some(raw) = raw {
            response = response.with_raw(raw);
        }
        let observations = Observations::new()
            .with_response(ProbeKind::Baseline, response.clone())
            .with_response(ProbeKind::NotFound, response);
        let report = analyze(&observations, database());
        prop_assert_eq!(report.fingerprint.hash.split('_').count(), 3);
        prop_assert!(report.candidates.iter().all(|c| c.confidence <= 100));
    }

    #[test]
    fn values_do_not_change_the_fingerprint(names in names(), a in "[ -~]{0,20}", b in "[ -~]{0,20}") {
        let with = |value: &str| {
            Observations::new().with_response(
                ProbeKind::Baseline,
                HttpResponse::new(200).with_headers(names.iter().map(|name| (name.as_str(), value))),
            )
        };
        prop_assert_eq!(fingerprint(&with(&a)), fingerprint(&with(&b)));
    }
}
