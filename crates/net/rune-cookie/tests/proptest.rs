//! Property tests: round trips and no panics on arbitrary input.

#![allow(clippy::unwrap_used, reason = "test helpers")]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use proptest::prelude::*;
use rune_cookie::{
    CookieJar, CookiePair, JarOptions, RequestContext, SameSite, SetCookie, SiteContext,
    domain_match, format_cookie_date, parse_cookie_date, parse_cookie_header, path_match,
    serialize_cookie_header,
};
use url::Url;

/// 1601-01-01T00:00:00Z and 9999-12-31T23:59:59Z.
const MIN_DATE: i64 = -11_644_473_600;
const MAX_DATE: i64 = 253_402_300_799;

fn time(secs: i64) -> SystemTime {
    if secs >= 0 {
        UNIX_EPOCH + Duration::from_secs(secs.unsigned_abs())
    } else {
        UNIX_EPOCH - Duration::from_secs(secs.unsigned_abs())
    }
}

fn name() -> impl Strategy<Value = String> {
    "[A-Za-z0-9!#$%&'*+.^_`|~-]{1,12}"
}

fn value() -> impl Strategy<Value = String> {
    prop_oneof![
        "[A-Za-z0-9!#$%&'()*+./:<=>?@^_`{|}~-]{0,16}",
        "\"[A-Za-z0-9/:=-]{0,8}\"",
    ]
}

fn same_site() -> impl Strategy<Value = SameSite> {
    prop_oneof![
        Just(SameSite::Strict),
        Just(SameSite::Lax),
        Just(SameSite::None)
    ]
}

prop_compose! {
    fn set_cookie()(
        name in name(),
        value in value(),
        expires in proptest::option::of(MIN_DATE..=MAX_DATE),
        max_age in proptest::option::of(any::<i64>().prop_filter("saturated", |v| *v != i64::MIN)),
        domain in proptest::option::of("[a-z0-9-]{1,8}(\\.[a-z0-9-]{1,8}){0,2}"),
        path in proptest::option::of("/[A-Za-z0-9/._~-]{0,12}"),
        flags in any::<(bool, bool, bool)>(),
        same_site in proptest::option::of(same_site()),
    ) -> SetCookie {
        let mut cookie = SetCookie::new(name, value)
            .with_secure(flags.0)
            .with_http_only(flags.1)
            .with_partitioned(flags.2);
        if let Some(secs) = expires { cookie = cookie.with_expires(time(secs)); }
        if let Some(age) = max_age { cookie = cookie.with_max_age(age); }
        if let Some(domain) = domain { cookie = cookie.with_domain(domain); }
        if let Some(path) = path { cookie = cookie.with_path(path); }
        if let Some(same_site) = same_site { cookie = cookie.with_same_site(same_site); }
        cookie
    }
}

proptest! {
    #[test]
    fn set_cookie_round_trip(cookie in set_cookie()) {
        let mut parsed = SetCookie::parse(&cookie.to_string()).unwrap();
        parsed.attributes.clear();
        prop_assert_eq!(parsed, cookie);
    }

    #[test]
    fn set_cookie_never_panics(header in "\\PC{0,64}") {
        let _ = SetCookie::parse(&header);
    }

    /// Parsing what we serialized from any parsed cookie gives the same
    /// interpretation.
    #[test]
    fn reparse_is_stable(header in "[ -~\\t]{0,64}") {
        if let Ok(first) = SetCookie::parse(&header) {
            let mut second = SetCookie::parse(&first.to_string()).unwrap();
            let mut first = first;
            first.attributes.clear();
            second.attributes.clear();
            prop_assert_eq!(second, first);
        }
    }

    #[test]
    fn date_round_trip(secs in MIN_DATE..=MAX_DATE) {
        let text = format_cookie_date(time(secs));
        prop_assert_eq!(parse_cookie_date(&text), Some(time(secs)));
    }

    #[test]
    fn date_never_panics(input in "\\PC{0,40}") {
        if let Some(date) = parse_cookie_date(&input) {
            prop_assert!(date >= time(MIN_DATE) && date <= time(MAX_DATE));
        }
    }

    #[test]
    fn cookie_header_round_trip(pairs in proptest::collection::vec((name(), value()), 0..6)) {
        let pairs: Vec<CookiePair> = pairs.into_iter().map(|(n, v)| CookiePair::new(n, v)).collect();
        prop_assert_eq!(parse_cookie_header(&serialize_cookie_header(&pairs)), pairs);
    }

    #[test]
    fn cookie_header_never_panics(header in "\\PC{0,64}") {
        let _ = parse_cookie_header(&header);
    }

    /// Whatever is stored, a lookup only returns cookies whose domain and
    /// path match the URL, and secure cookies only over https.
    #[test]
    fn jar_lookup_respects_scope(
        sets in proptest::collection::vec(
            (0..4_usize, "[ -~]{0,48}", any::<bool>()), 0..12),
        target in 0..4_usize,
        target_path in "/[a-c/]{0,6}",
        rfc6265 in any::<bool>(),
    ) {
        let hosts = ["example.com", "www.example.com", "a.b.example.com", "example.org"];
        let options = if rfc6265 { JarOptions::rfc6265() } else { JarOptions::default() };
        let mut jar = CookieJar::with_options(options);
        let now = time(1_700_000_000);
        for (host, header, https) in &sets {
            let scheme = if *https { "https" } else { "http" };
            let url = Url::parse(&format!("{scheme}://{}/a/b", hosts[*host])).unwrap();
            let ctx = RequestContext::http().with_site(SiteContext::SameSite);
            let _ = jar.store(&url, header, &ctx, now);
        }
        let url = Url::parse(&format!("http://{}{target_path}", hosts[target])).unwrap();
        let path = url.path().to_owned();
        for cookie in jar.cookies_for(&url, &RequestContext::http(), now).unwrap() {
            prop_assert!(!cookie.secure);
            prop_assert!(path_match(&path, &cookie.path));
            if cookie.host_only {
                prop_assert_eq!(&cookie.domain, hosts[target]);
            } else {
                prop_assert!(domain_match(hosts[target], &cookie.domain));
            }
        }
    }
}
