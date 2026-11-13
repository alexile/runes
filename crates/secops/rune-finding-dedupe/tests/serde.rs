//! The tracker's state survives a JSON round trip, and corrupt state is
//! rejected.

use rune_finding::{Confidence, Finding, Location, Severity, TaxonomyRef};
use rune_finding_dedupe::{Scan, Strategy, Tracker};

fn sqli(rule: &str, line: u32) -> Finding {
    Finding::<()>::new(
        rule,
        "SQL injection",
        Severity::High,
        Confidence::Firm,
        Location::file("app.py").with_lines(line, line),
    )
    .push_taxonomy(TaxonomyRef::cwe(89))
}

#[test]
fn identity_persists_across_restarts() -> Result<(), serde_json::Error> {
    let strategy = Strategy::FingerprintOrCwe;
    let mut tracker = Tracker::default();
    let first = tracker.observe(&Scan::new("codeql", 1), [sqli("a", 1)], &strategy);

    let json = serde_json::to_string(&tracker)?;
    let mut restored: Tracker = serde_json::from_str(&json)?;
    assert_eq!(restored, tracker);

    let second = restored.observe(&Scan::new("semgrep", 2), [sqli("b", 1)], &strategy);
    assert_eq!(second.recurring, first.new);
    assert_eq!(second.scan, 2);
    Ok(())
}

#[test]
fn reports_serialize() -> Result<(), serde_json::Error> {
    let mut tracker = Tracker::default();
    let report = tracker.observe(&Scan::new("t", 1), [sqli("a", 1)], &Strategy::Fingerprint);
    let value = serde_json::to_value(&report)?;
    assert_eq!(value["scan"], 1);
    assert_eq!(value["new"][0], sqli("a", 1).fingerprint());
    Ok(())
}

#[test]
fn rejects_shared_keys() -> Result<(), serde_json::Error> {
    let mut tracker = Tracker::default();
    tracker.observe(
        &Scan::new("t", 1),
        [sqli("a", 1), sqli("a", 2)],
        &Strategy::Fingerprint,
    );
    let mut json = serde_json::to_value(&tracker)?;
    let fp = sqli("a", 2).fingerprint();
    let first = sqli("a", 1).fingerprint();
    if let Some(keys) = json["issues"][&first]["keys"].as_array_mut() {
        keys.push(serde_json::Value::String(format!("fp:{fp}")));
    }
    let err = serde_json::from_value::<Tracker>(json).map(|_| ());
    assert!(err.is_err_and(|e| e.to_string().contains("belongs to two issues")));
    Ok(())
}

#[test]
fn options_saved_before_the_list_bounds_still_load() -> Result<(), serde_json::Error> {
    let options: rune_finding_dedupe::Options = serde_json::from_str(r#"{"max_evidence":8}"#)?;
    assert_eq!(
        options,
        rune_finding_dedupe::Options::default().with_max_evidence(8)
    );
    Ok(())
}
