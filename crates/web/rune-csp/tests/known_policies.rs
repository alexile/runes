//! Known real-world-style policies and the weaknesses they must produce.

use rune_csp::{Options, Policy, WeaknessKind as K, run};
use rune_finding::{Location, Severity as S};

fn weaknesses(header: &str) -> Vec<(K, S, Option<String>)> {
    run(header, &Options::default())
        .weaknesses
        .into_iter()
        .map(|w| (w.kind, w.severity, w.directive))
        .collect()
}

fn kinds(header: &str) -> Vec<K> {
    let mut k: Vec<K> = weaknesses(header).into_iter().map(|w| w.0).collect();
    k.sort();
    k.dedup();
    k
}

#[test]
fn google_style_strict_policy_is_clean() {
    let header = "object-src 'none'; script-src 'nonce-9cRzT3x1b2Q5fKpL7mNw0A==' 'unsafe-inline' \
                  'unsafe-eval' 'strict-dynamic' https: http:; base-uri 'self'; \
                  report-uri https://csp.example.com/report";
    let w = weaknesses(header);
    // 'unsafe-inline' is neutralized by the nonce; https:/http: by 'strict-dynamic'.
    assert!(w.contains(&(K::UnsafeInline, S::Informational, Some("script-src".into()))));
    assert!(w.contains(&(K::UnsafeEval, S::Medium, Some("script-src".into()))));
    assert!(!w.iter().any(|x| x.0 == K::WildcardSource));
    assert!(w.iter().all(|x| x.1 <= S::Medium));
}

#[test]
fn legacy_allowlist_policy() {
    let header = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' \
                  *.googleapis.com data: http://cdn.example.com; img-src * data:; \
                  style-src 'self' 'unsafe-inline'";
    let w = weaknesses(header);
    let script = Some("script-src".to_owned());
    assert!(w.contains(&(K::UnsafeInline, S::High, script.clone())));
    assert!(w.contains(&(K::UnsafeEval, S::Medium, script.clone())));
    assert!(w.contains(&(K::UnsafeScheme, S::High, script.clone())));
    assert!(w.contains(&(K::InsecureScheme, S::Medium, script)));
    assert!(w.contains(&(K::UnsafeInline, S::Low, Some("style-src".into()))));
    assert!(w.contains(&(K::MissingObjectSrc, S::Low, Some("default-src".into()))));
    assert!(w.contains(&(K::MissingBaseUri, S::Low, None)));
    // img-src * is common and not reported.
    assert!(!w.iter().any(|x| x.0 == K::WildcardSource));
    assert_eq!(w[0].1, S::High, "sorted most severe first");
}

#[test]
fn wildcards_in_script_and_object() {
    let w = weaknesses("script-src *; object-src https:; base-uri *.com");
    assert!(w.contains(&(K::WildcardSource, S::High, Some("script-src".into()))));
    assert!(w.contains(&(K::WildcardSource, S::Medium, Some("object-src".into()))));
    assert!(w.contains(&(K::WildcardSource, S::Medium, Some("base-uri".into()))));
}

#[test]
fn missing_everything() {
    assert_eq!(
        kinds("upgrade-insecure-requests"),
        [
            K::MissingScriptSrc,
            K::MissingObjectSrc,
            K::MissingBaseUri,
            K::MissingFrameAncestors,
            K::MissingReporting,
        ]
    );
    assert_eq!(kinds(""), [K::EmptyPolicy]);
    assert_eq!(kinds(" ; , ;"), [K::EmptyPolicy]);
}

#[test]
fn nonce_and_hash_misuse() {
    let header = "script-src 'nonce-abc123' 'sha256-tooShort=' 'sha512-AAAA' 'strict-dynamic'; \
                  img-src 'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='; \
                  object-src 'none'";
    let w = weaknesses(header);
    assert!(w.contains(&(K::WeakNonce, S::Medium, Some("script-src".into()))));
    assert_eq!(w.iter().filter(|x| x.0 == K::MalformedHash).count(), 2);
    assert!(w.contains(&(
        K::MisplacedNonceOrHash,
        S::Informational,
        Some("img-src".into())
    )));
    // Nonce-based policy without base-uri: Medium.
    assert!(w.contains(&(K::MissingBaseUri, S::Medium, None)));
}

#[test]
fn strict_dynamic_without_nonce() {
    assert!(
        kinds("script-src 'strict-dynamic' https://cdn.example; object-src 'none'")
            .contains(&K::StrictDynamicWithoutNonce)
    );
}

#[test]
fn syntax_mistakes() {
    let header = "default-src self 'none' 'bogus'; script-src 'self'; SCRIPT-SRC *; \
                  img_src *; plugin-types application/pdf; foo-src 'self'";
    let k = kinds(header);
    for expected in [
        K::UnquotedKeyword,
        K::NoneWithOtherSources,
        K::InvalidSource,
        K::DuplicateDirective,
        K::InvalidDirectiveName,
        K::DeprecatedDirective,
        K::UnknownDirective,
    ] {
        assert!(k.contains(&expected), "{expected:?} missing from {k:?}");
    }
    // The ignored duplicate `SCRIPT-SRC *` is not analyzed as a wildcard.
    assert!(!k.contains(&K::WildcardSource));
}

#[test]
fn multiple_policies_are_indexed() {
    let report = run("default-src 'none', script-src *", &Options::default());
    assert_eq!(report.policies.len(), 2);
    let wildcard = report
        .weaknesses
        .iter()
        .find(|w| w.kind == K::WildcardSource)
        .map(|w| w.policy);
    assert_eq!(wildcard, Some(1));
}

#[test]
fn findings_mapping() {
    let report = run(
        "script-src 'unsafe-inline'; object-src 'none'; base-uri 'none'",
        &Options::default(),
    );
    let findings = report.to_findings::<()>(&Location::url("https://example.com/"));
    assert_eq!(findings.len(), report.weaknesses.len());
    let f = findings
        .iter()
        .find(|f| f.check_id == "csp.unsafe_inline")
        .expect("unsafe-inline finding");
    assert_eq!(f.severity, S::High);
    assert_eq!(
        f.location,
        Location::url("https://example.com/").with_parameter("script-src")
    );
    let cwes: Vec<_> = f
        .taxonomy
        .iter()
        .filter_map(rune_finding::TaxonomyRef::cwe_number)
        .collect();
    assert_eq!(cwes, [693, 79]);
    assert!(f.remediation.is_some());
    assert!(f.evidence.iter().any(|e| e.snippet == "'unsafe-inline'"));
    // Different directives fingerprint differently.
    let fps: std::collections::HashSet<_> = findings
        .iter()
        .map(rune_finding::Finding::fingerprint)
        .collect();
    assert_eq!(fps.len(), findings.len());
}

#[test]
fn canonical_form_of_known_policies() {
    let cases = [
        (
            "Default-Src 'SELF'  HTTPS://CDN.Example.COM:443/Path ;  Upgrade-Insecure-Requests",
            "default-src 'self' https://cdn.example.com:443/Path; upgrade-insecure-requests",
        ),
        (
            "script-src 'NONCE-AbC' 'SHA256-XyZ=' 'Strict-Dynamic'; ",
            "script-src 'nonce-AbC' 'sha256-XyZ=' 'strict-dynamic'",
        ),
        ("img-src *:* data: BLOB:", "img-src *:* data: blob:"),
    ];
    for (input, canonical) in cases {
        let policy = Policy::parse(input);
        assert_eq!(policy.to_string(), canonical);
        assert_eq!(Policy::parse(canonical).to_string(), canonical);
        assert_eq!(canonical.parse::<Policy>(), Ok(Policy::parse(canonical)));
    }
}
