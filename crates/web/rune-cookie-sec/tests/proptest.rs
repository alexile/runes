//! Properties: the analyzer never panics, and every finding is well formed.

use proptest::prelude::*;
use rune_cookie_sec::{Options, run, run_fields};
use rune_finding::Location;

fn attribute() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("Secure".to_owned()),
        Just("HttpOnly".to_owned()),
        Just("Partitioned".to_owned()),
        "(Strict|Lax|None|lax|x)".prop_map(|v| format!("SameSite={v}")),
        "(/|/a|a|)".prop_map(|v| format!("Path={v}")),
        "(\\.?example\\.com|com|co\\.uk|)".prop_map(|v| format!("Domain={v}")),
        "-?[0-9]{0,12}".prop_map(|v| format!("Max-Age={v}")),
        Just("Expires=Wed, 21 Oct 2099 07:28:00 GMT".to_owned()),
        "[ -~]{0,12}",
    ]
}

proptest! {
    #[test]
    fn arbitrary_text_never_panics(header in "\\PC{0,200}") {
        let report = run(&header, &Options::default());
        prop_assert_eq!(report.cookies.len(), 1);
        let _ = report.to_findings::<()>(&Location::url("https://example.com/"));
    }

    #[test]
    fn structured_cookies(
        name in "(__Host-|__Secure-|)(sid|theme|a b|XSRF-TOKEN)",
        value in "[ -~]{0,16}",
        attrs in prop::collection::vec(attribute(), 0..8),
        https in any::<bool>(),
        url in prop::option::of("https?://(app\\.)?example\\.com/(x/)?"),
    ) {
        let header = format!("{name}={value}; {}", attrs.join("; "));
        let mut options = Options::default().with_https(https);
        if let Some(url) = url {
            options = options.with_request_url(url.parse().unwrap());
        }
        let report = run_fields([header.as_str(), header.as_str()], &options);
        let findings = report.to_findings::<()>(&Location::url("https://example.com/"));
        prop_assert_eq!(findings.len(), report.weaknesses.len());
        for pair in report.weaknesses.windows(2) {
            prop_assert!(pair[0].severity >= pair[1].severity);
        }
        for f in &findings {
            prop_assert!(f.check_id.starts_with("cookie."));
        }
    }
}
