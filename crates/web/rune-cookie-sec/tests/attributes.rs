//! Attribute-weakness table: each header and the check ids it must (and
//! must not) produce.

use std::time::{Duration, SystemTime};

use rune_cookie_sec::{Options, WeaknessKind, run, run_fields, run_response};
use rune_finding::{Location, Severity, Taxonomy};
use rune_http_model::HttpResponse;

fn ids(header: &str, options: &Options) -> Vec<String> {
    run(header, options)
        .weaknesses
        .iter()
        .map(|w| w.kind.check_id())
        .collect()
}

fn has(header: &str, options: &Options, id: &str) -> bool {
    ids(header, options).iter().any(|i| i == id)
}

const GOOD: &str = "; Path=/; Secure; HttpOnly; SameSite=Lax";

#[test]
fn table() {
    let o = Options::default();
    let cases: &[(&str, &str)] = &[
        (
            "sid=1; Path=/; HttpOnly; SameSite=Lax",
            "cookie.missing_secure",
        ),
        (
            "sid=1; Path=/; Secure; SameSite=Lax",
            "cookie.missing_http_only",
        ),
        (
            "sid=1; Path=/; Secure; HttpOnly",
            "cookie.missing_same_site",
        ),
        (
            "sid=1; Path=/; Secure; HttpOnly; SameSite=None",
            "cookie.same_site_none",
        ),
        (
            "sid=1; Path=/; HttpOnly; SameSite=None",
            "cookie.same_site_none_without_secure",
        ),
        (
            "sid=1; Path=/; Secure; HttpOnly; SameSite=Lenient",
            "cookie.invalid_same_site",
        ),
        (
            "sid=1; Path=/; Secure; HttpOnly; SameSite=Lax; Domain=example.com",
            "cookie.broad_domain",
        ),
        (
            "sid=1; Secure; HttpOnly; SameSite=Lax",
            "cookie.missing_path",
        ),
        (
            "sid=1; Path=account; Secure; HttpOnly; SameSite=Lax",
            "cookie.invalid_attribute",
        ),
        (
            "sid=1; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=1d",
            "cookie.invalid_attribute",
        ),
        (
            "sid=1; Path=/; Secure; HttpOnly; SameSite=Lax; Expires=tomorrow",
            "cookie.invalid_attribute",
        ),
        (
            "sid=1; Path=/; Secure=yes; HttpOnly; SameSite=Lax",
            "cookie.invalid_attribute",
        ),
        (
            "sid=1; Path=/; Secure; Http-Only; SameSite=Lax",
            "cookie.misspelled_attribute",
        ),
        (
            "sid=1; Path=/; Secure; HttpOnly; SameSite=Lax; Flavour=mint",
            "cookie.unknown_attribute",
        ),
        (
            "sid=1; Path=/; Secure; HttpOnly; SameSite=Lax; Path=/a",
            "cookie.duplicate_attribute",
        ),
        (
            "sid=1; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=31536000",
            "cookie.long_lifetime",
        ),
        (
            "theme=1; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=63072000",
            "cookie.long_lifetime",
        ),
        (
            "sid=1; Path=/; HttpOnly; SameSite=Lax; Partitioned",
            "cookie.partitioned_without_secure",
        ),
        (
            "__Secure-id=1; Path=/; HttpOnly; SameSite=Lax",
            "cookie.secure_prefix",
        ),
        (
            "__Host-id=1; Path=/app; Secure; HttpOnly; SameSite=Lax",
            "cookie.host_prefix",
        ),
        (
            "__host-id=1; Path=/; Secure; HttpOnly; SameSite=Lax; Domain=example.com",
            "cookie.host_prefix",
        ),
        (
            "sid=1; Path=/; Secure; HttpOnly; SameSite=Lax",
            "cookie.missing_host_prefix",
        ),
        (
            "bad name=1; Path=/; Secure; HttpOnly; SameSite=Lax",
            "cookie.invalid_name",
        ),
        (
            "v=a,b; Path=/; Secure; HttpOnly; SameSite=Lax",
            "cookie.invalid_value",
        ),
        ("no-equals-sign", "cookie.invalid_header"),
        ("=value", "cookie.invalid_header"),
    ];
    for (header, id) in cases {
        assert!(
            has(header, &o, id),
            "{header:?} should report {id}, got {:?}",
            ids(header, &o)
        );
    }
}

#[test]
fn hardened_cookies_are_clean() {
    let o = Options::default();
    for header in [
        "__Host-sid=abc; Path=/; Secure; HttpOnly; SameSite=Strict",
        "__Secure-pref=1; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=86400",
        "theme=dark; Path=/; Secure; HttpOnly; SameSite=Lax; Priority=High",
    ] {
        assert_eq!(ids(header, &o), Vec::<String>::new(), "{header}");
    }
}

#[test]
fn plain_http_transport() {
    let o = Options::default().with_https(false);
    assert!(has(
        "sid=1; Path=/; HttpOnly; SameSite=Lax",
        &o,
        "cookie.insecure_transport"
    ));
    assert!(!has(
        "sid=1; Path=/; HttpOnly; SameSite=Lax",
        &o,
        "cookie.missing_secure"
    ));
    assert!(has(
        &format!("sid=1{GOOD}"),
        &o,
        "cookie.secure_from_insecure_origin"
    ));
    assert!(has(
        &format!("__Secure-a=1{GOOD}"),
        &o,
        "cookie.secure_prefix"
    ));
    assert!(has(&format!("__Host-a=1{GOOD}"), &o, "cookie.host_prefix"));

    let o = Options::default().with_request_url("http://example.com/".parse().unwrap());
    assert!(!o.https);
    assert!(has(
        "sid=1; Path=/; HttpOnly; SameSite=Lax",
        &o,
        "cookie.insecure_transport"
    ));
}

#[test]
fn domain_rejections_with_request_url() {
    let o = Options::default().with_request_url("https://app.example.com/login".parse().unwrap());
    let h = |domain: &str| format!("pref=1{GOOD}; Domain={domain}");
    assert!(has(&h("com"), &o, "cookie.public_suffix_domain"));
    assert!(has(&h("other.org"), &o, "cookie.domain_mismatch"));
    let ok = ids(&h("example.com"), &o);
    assert_eq!(ok, ["cookie.broad_domain"]);
    // Host-only cookies pass the jar's rules.
    assert!(run(&format!("__Host-sid=1{GOOD}"), &o).is_clean());
}

#[test]
fn expires_needs_now() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let header = format!("sid=1{GOOD}; Expires=Fri, 01 Jan 2100 00:00:00 GMT");
    assert!(!has(&header, &Options::default(), "cookie.long_lifetime"));
    let o = Options::default().with_now(now);
    assert!(has(&header, &o, "cookie.long_lifetime"));
    let short = Options::default()
        .with_now(now)
        .with_max_sensitive_lifetime(Duration::from_secs(u64::MAX / 4));
    assert!(!has(&header, &short, "cookie.long_lifetime"));
}

#[test]
fn response_level() {
    let response = HttpResponse::new(200)
        .with_header(
            "Set-Cookie",
            "sid=1; Path=/; Secure; HttpOnly; SameSite=Lax",
        )
        .with_header("Content-Type", "text/html")
        .with_header(
            "set-cookie",
            "sid=2; Path=/; Secure; HttpOnly; SameSite=Lax",
        )
        .with_header("Set-Cookie", "broken");
    let report = run_response(&response, &Options::default());
    assert_eq!(report.cookies.len(), 3);
    assert!(report.cookies[2].is_err());
    let kinds: Vec<_> = report.weaknesses.iter().map(|w| w.kind).collect();
    assert!(kinds.contains(&WeaknessKind::DuplicateCookie));
    assert!(kinds.contains(&WeaknessKind::InvalidHeader));
    assert_eq!(report.weaknesses_of("sid").count(), 3); // 2 x missing_host_prefix + duplicate

    let empty = run_fields([], &Options::default());
    assert!(empty.is_clean() && empty.cookies.is_empty());
}

#[test]
fn ordering_and_findings() {
    let report = run("sessionid=1; Domain=example.com", &Options::default());
    let severities: Vec<_> = report.weaknesses.iter().map(|w| w.severity).collect();
    let mut sorted = severities.clone();
    sorted.sort_by(|a, b| b.cmp(a));
    assert_eq!(severities, sorted);
    assert_eq!(report.max_severity(), Some(Severity::Medium));

    let location = Location::url("https://example.com/");
    let findings = report.to_findings::<()>(&location);
    assert_eq!(findings.len(), report.weaknesses.len());
    for f in &findings {
        assert!(f.check_id.starts_with("cookie."), "{}", f.check_id);
        assert!(f.remediation.is_some());
        assert!(f.taxonomy.iter().any(|t| t.framework == Taxonomy::Cwe));
    }
    let secure = findings
        .iter()
        .find(|f| f.check_id == "cookie.missing_secure")
        .unwrap();
    assert!(
        secure
            .taxonomy
            .iter()
            .any(|t| t.framework == Taxonomy::Cwe && t.cwe_number() == Some(614))
    );
    assert!(secure.evidence.iter().any(|e| e.snippet == "sessionid"));
    let domain = findings
        .iter()
        .find(|f| f.check_id == "cookie.broad_domain")
        .unwrap();
    assert!(domain.evidence.iter().any(|e| e.snippet == "Domain"));
}
