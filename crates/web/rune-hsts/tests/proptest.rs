//! Property tests: canonical form is a fixed point, structured policies
//! round-trip, and nothing panics on arbitrary input.

use proptest::prelude::*;
use rune_hsts::{Extension, Hsts, Options, PreloadList, Site, check_preload, run, run_fields};

fn hsts() -> impl Strategy<Value = Hsts> {
    (
        any::<u64>(),
        any::<bool>(),
        any::<bool>(),
        prop::collection::vec(
            (
                "[a-z][a-z0-9!#$%&'*+.^_`|~-]{0,10}",
                prop::option::of("[ -~\\t\u{a0}-\u{10ff}]{0,12}"),
            ),
            0..4,
        ),
    )
        .prop_map(|(max_age, sub, preload, exts)| {
            let mut h = Hsts::new(max_age)
                .with_include_subdomains(sub)
                .with_preload(preload);
            for (name, value) in exts {
                // Names the parser interprets itself are not extensions.
                if matches!(name.as_str(), "max-age" | "includesubdomains" | "preload") {
                    continue;
                }
                h = h.with_extension(Extension::new(&name, value));
            }
            h
        })
}

proptest! {
    #[test]
    fn structured_policies_round_trip(h in hsts()) {
        let text = h.to_string();
        prop_assert_eq!(Hsts::parse(&text), Ok(h));
    }

    #[test]
    fn canonical_is_a_fixed_point(s in "[a-zA-Z0-9=;\" \\t\\\\,._-]{0,60}") {
        if let Ok(h) = Hsts::parse(&s) {
            let once = h.to_string();
            let again = Hsts::parse(&once);
            prop_assert_eq!(again.as_ref().map(ToString::to_string), Ok(once));
            prop_assert_eq!(again, Ok(h));
        }
    }

    #[test]
    fn hsts_like_text_never_panics(
        s in "((max-age|includeSubDomains|preload|[a-z_-]{1,8})(=(\"[^\"]{0,6}\"?|[0-9a-z]{0,25}))? ?;? ?){0,6}"
    ) {
        let r = run(&s, &Options::default());
        prop_assert_eq!(r.hsts.is_some(), r.error.is_none());
        prop_assert!(r.weaknesses.windows(2).all(|w| w[0].severity >= w[1].severity));
    }

    #[test]
    fn arbitrary_text_never_panics(s in any::<String>(), d in any::<String>()) {
        let _ = run_fields([s.as_str(), s.as_str()], &Options::default().with_insecure_transport(true));
        let _ = check_preload(&Site::new(d.clone()).with_https_header(s.clone()).with_http_redirect(s.clone()));
        let _ = PreloadList::parse(&s);
        if let Ok(list) = PreloadList::parse(&d) {
            let _ = list.lookup(&s);
        }
    }
}
