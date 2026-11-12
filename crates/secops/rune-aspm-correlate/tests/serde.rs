//! JSON round trips of the public types.

use rune_aspm_correlate::{Batch, Corroboration, Kind, Options, Report, Route};
use rune_finding::{Confidence, Finding, Location, Severity, TaxonomyRef};

#[test]
fn route_json_shape() {
    let route = Route::new("/users/{id}", "src/users.py")
        .unwrap()
        .with_name("users")
        .with_host("a.test")
        .with_lines(3, 9);
    let json = serde_json::to_string(&route).unwrap();
    assert_eq!(
        json,
        r#"{"name":"users","pattern":"/users/{id}","host":"a.test","file":"src/users.py","lines":[3,9]}"#
    );
    assert_eq!(serde_json::from_str::<Route>(&json).unwrap(), route);
    let plain = Route::new("/x", "x.py").unwrap();
    assert_eq!(
        serde_json::to_string(&plain).unwrap(),
        r#"{"pattern":"/x","file":"x.py"}"#
    );
    assert!(serde_json::from_str::<Route>(r#"{"pattern":"x","file":"x.py"}"#).is_err());
    assert!(serde_json::from_str::<Route>(r#"{"pattern":"/x","file":"x.py","y":1}"#).is_err());
}

#[test]
fn enums_are_snake_case() {
    assert_eq!(serde_json::to_string(&Kind::Sast).unwrap(), r#""sast""#);
    assert_eq!(
        serde_json::to_string(&Corroboration::MultiTool).unwrap(),
        r#""multi_tool""#
    );
}

#[test]
fn options_and_report_round_trip() {
    let options = Options::default().with_route(Route::new("/s", "s.py").unwrap());
    let json = serde_json::to_string(&options).unwrap();
    assert_eq!(serde_json::from_str::<Options>(&json).unwrap(), options);
    assert_eq!(
        serde_json::from_str::<Options>("{}").unwrap(),
        Options::default()
    );

    let mut batch = Batch::new();
    batch.add_findings(
        "dast-scanner",
        [Finding::<()>::new(
            "xss",
            "XSS",
            Severity::High,
            Confidence::Firm,
            Location::url("https://a.test/s"),
        )
        .push_taxonomy(TaxonomyRef::cwe(79))],
    );
    batch.add_findings(
        "semgrep",
        [Finding::<()>::new(
            "xss",
            "XSS",
            Severity::Medium,
            Confidence::Firm,
            Location::file("s.py"),
        )
        .push_taxonomy(TaxonomyRef::cwe(79))],
    );
    let report = batch.correlate(&options);
    assert_eq!(report.confirmed().count(), 1);
    let json = serde_json::to_string(&report).unwrap();
    assert!(json.contains(r#""sources":["#));
    assert!(json.contains(r#""corroboration":"confirmed""#));
    assert_eq!(serde_json::from_str::<Report>(&json).unwrap(), report);
}
