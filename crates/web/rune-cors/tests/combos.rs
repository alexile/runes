//! The verdict table: (request origin, response headers) -> exposure and
//! weaknesses, for a site at `https://example.com`.

use rune_cors::{CorsHeaders, Exchange, Exposure, Options, Origin, WeaknessKind, probes, run};
use rune_finding::{Location, Severity};

const ACAO: &str = "Access-Control-Allow-Origin";
const ACAC: &str = "Access-Control-Allow-Credentials";

fn origin(s: &str) -> Origin {
    match Origin::parse(s) {
        Ok(o) => o,
        Err(e) => unreachable!("{e}"),
    }
}

fn options() -> Options {
    Options::for_target(origin("https://example.com"))
        .with_trusted(origin("https://partner.example"))
}

struct Case {
    origin: Option<&'static str>,
    headers: &'static [(&'static str, &'static str)],
    exposure: Exposure,
    severity: Option<Severity>,
    kinds: &'static [WeaknessKind],
}

#[allow(clippy::too_many_lines)]
fn table() -> Vec<Case> {
    use Exposure::{Anonymous, Credentialed, None as NoAccess};
    use WeaknessKind as K;
    vec![
        // No CORS headers at all.
        Case {
            origin: Some("https://evil.net"),
            headers: &[],
            exposure: NoAccess,
            severity: None,
            kinds: &[],
        },
        // Reflected arbitrary origin with credentials.
        Case {
            origin: Some("https://evil.net"),
            headers: &[
                (ACAO, "https://evil.net"),
                (ACAC, "true"),
                ("Vary", "Origin"),
            ],
            exposure: Credentialed,
            severity: Some(Severity::Critical),
            kinds: &[K::OriginReflection],
        },
        // ... without Vary as well.
        Case {
            origin: Some("https://evil.net"),
            headers: &[(ACAO, "https://evil.net"), (ACAC, "true")],
            exposure: Credentialed,
            severity: Some(Severity::Critical),
            kinds: &[K::OriginReflection, K::MissingVaryOrigin],
        },
        // Reflected arbitrary origin, anonymous only.
        Case {
            origin: Some("https://evil.net"),
            headers: &[(ACAO, "https://evil.net"), ("Vary", "origin")],
            exposure: Anonymous,
            severity: Some(Severity::Low),
            kinds: &[K::OriginReflection],
        },
        // `*` with credentials: the browser refuses the credentialed read.
        Case {
            origin: Some("https://evil.net"),
            headers: &[(ACAO, "*"), (ACAC, "true")],
            exposure: Anonymous,
            severity: Some(Severity::Low),
            kinds: &[K::WildcardWithCredentials],
        },
        // Plain `*`.
        Case {
            origin: Some("https://evil.net"),
            headers: &[(ACAO, "*")],
            exposure: Anonymous,
            severity: Some(Severity::Informational),
            kinds: &[K::WildcardOrigin],
        },
        // `null` with credentials.
        Case {
            origin: Some("null"),
            headers: &[(ACAO, "null"), (ACAC, "true"), ("Vary", "Origin")],
            exposure: Credentialed,
            severity: Some(Severity::High),
            kinds: &[K::NullOrigin],
        },
        // A static `null` grant is flagged even for another request origin.
        Case {
            origin: Some("https://example.com"),
            headers: &[(ACAO, "null")],
            exposure: NoAccess,
            severity: Some(Severity::Low),
            kinds: &[K::NullOrigin],
        },
        // Unanchored suffix match ("ends with example.com").
        Case {
            origin: Some("https://evilexample.com"),
            headers: &[
                (ACAO, "https://evilexample.com"),
                (ACAC, "true"),
                ("Vary", "Origin"),
            ],
            exposure: Credentialed,
            severity: Some(Severity::High),
            kinds: &[K::UnanchoredAllowlist],
        },
        // Unanchored prefix match ("starts with example.com").
        Case {
            origin: Some("https://example.com.evil.net"),
            headers: &[
                (ACAO, "https://example.com.evil.net"),
                (ACAC, "true"),
                ("Vary", "Origin"),
            ],
            exposure: Credentialed,
            severity: Some(Severity::High),
            kinds: &[K::UnanchoredAllowlist],
        },
        // Plain-http variant of the target.
        Case {
            origin: Some("http://example.com"),
            headers: &[
                (ACAO, "http://example.com"),
                (ACAC, "true"),
                ("Vary", "Origin"),
            ],
            exposure: Credentialed,
            severity: Some(Severity::Medium),
            kinds: &[K::InsecureOrigin],
        },
        // Any subdomain is echoed.
        Case {
            origin: Some("https://x.example.com"),
            headers: &[
                (ACAO, "https://x.example.com"),
                (ACAC, "true"),
                ("Vary", "Origin"),
            ],
            exposure: Credentialed,
            severity: Some(Severity::Low),
            kinds: &[K::SubdomainOrigin],
        },
        // Same origin and trusted partner: fine.
        Case {
            origin: Some("https://example.com"),
            headers: &[(ACAO, "https://example.com"), (ACAC, "true")],
            exposure: Credentialed,
            severity: None,
            kinds: &[],
        },
        Case {
            origin: Some("https://partner.example"),
            headers: &[
                (ACAO, "https://partner.example"),
                (ACAC, "true"),
                ("Vary", "Origin"),
            ],
            exposure: Credentialed,
            severity: None,
            kinds: &[],
        },
        // A static grant to the trusted partner, probed from elsewhere.
        Case {
            origin: Some("https://evil.net"),
            headers: &[(ACAO, "https://partner.example"), (ACAC, "true")],
            exposure: NoAccess,
            severity: None,
            kinds: &[],
        },
        // Two Access-Control-Allow-Origin headers never match.
        Case {
            origin: Some("https://example.com"),
            headers: &[(ACAO, "https://example.com"), (ACAO, "https://example.com")],
            exposure: NoAccess,
            severity: Some(Severity::Informational),
            kinds: &[K::InvalidAllowOrigin],
        },
        // A space-separated allowlist pasted into the header.
        Case {
            origin: Some("https://example.com"),
            headers: &[(ACAO, "https://example.com https://partner.example")],
            exposure: NoAccess,
            severity: Some(Severity::Informational),
            kinds: &[K::InvalidAllowOrigin],
        },
        // `True` is not `true`.
        Case {
            origin: Some("https://example.com"),
            headers: &[(ACAO, "https://example.com"), (ACAC, "True")],
            exposure: Anonymous,
            severity: Some(Severity::Informational),
            kinds: &[K::InvalidAllowCredentials],
        },
        // `*` is literal in lists of credentialed responses.
        Case {
            origin: Some("https://example.com"),
            headers: &[
                (ACAO, "https://example.com"),
                (ACAC, "true"),
                ("Access-Control-Allow-Headers", "*"),
            ],
            exposure: Credentialed,
            severity: Some(Severity::Informational),
            kinds: &[K::WildcardListWithCredentials],
        },
        // Private network access to a reflected origin.
        Case {
            origin: Some("https://evil.net"),
            headers: &[
                (ACAO, "https://evil.net"),
                ("Access-Control-Allow-Private-Network", "true"),
                ("Vary", "Origin"),
            ],
            exposure: Anonymous,
            severity: Some(Severity::Medium),
            kinds: &[K::PrivateNetworkAccess, K::OriginReflection],
        },
        // Response headers alone: a static insecure grant.
        Case {
            origin: None,
            headers: &[(ACAO, "http://example.com"), (ACAC, "true")],
            exposure: Credentialed,
            severity: Some(Severity::Medium),
            kinds: &[K::InsecureOrigin],
        },
        // Response headers alone: `*`.
        Case {
            origin: None,
            headers: &[(ACAO, "*")],
            exposure: Anonymous,
            severity: Some(Severity::Informational),
            kinds: &[K::WildcardOrigin],
        },
    ]
}

#[test]
fn verdict_table() {
    let options = options();
    for (i, case) in table().iter().enumerate() {
        let ex = Exchange::new(
            case.origin,
            CorsHeaders::from_pairs(case.headers.iter().copied()),
        );
        let report = run(std::slice::from_ref(&ex), &options);
        let row = &report.rows[0];
        let kinds: Vec<_> = report.weaknesses.iter().map(|w| w.kind).collect();
        assert_eq!(row.exposure, case.exposure, "case {i}: exposure");
        assert_eq!(row.severity, case.severity, "case {i}: severity");
        assert_eq!(report.max_severity(), case.severity, "case {i}");
        assert_eq!(kinds, case.kinds, "case {i}: {:?}", report.weaknesses);
        for f in report.to_findings::<()>(&Location::url("https://example.com/api")) {
            assert!(f.check_id.starts_with("cors."));
            assert!(f.remediation.is_some());
            assert_ne!(f.taxonomy, []);
        }
    }
}

/// A server that echoes every origin with credentials, probed with the
/// standard probe set: every attacker-controlled probe is flagged.
#[test]
fn reflecting_server_fails_every_probe() {
    let target: Origin = "https://example.com".parse().unwrap();
    let exchanges: Vec<Exchange> = probes(&target)
        .iter()
        .map(|p| {
            Exchange::new(
                Some(&p.origin),
                CorsHeaders::from_pairs([(ACAO, p.origin.as_str()), (ACAC, "true")]),
            )
        })
        .collect();
    let report = run(&exchanges, &Options::for_target(target));
    let kinds: Vec<_> = report.weaknesses.iter().map(|w| w.kind).collect();
    for k in [
        WeaknessKind::OriginReflection,
        WeaknessKind::NullOrigin,
        WeaknessKind::SubdomainOrigin,
        WeaknessKind::InsecureOrigin,
        WeaknessKind::UnanchoredAllowlist,
        WeaknessKind::MissingVaryOrigin,
    ] {
        assert!(kinds.contains(&k), "{k:?} missing from {kinds:?}");
    }
    assert_eq!(report.max_severity(), Some(Severity::Critical));
    // Weaknesses are sorted most severe first.
    assert!(
        report
            .weaknesses
            .windows(2)
            .all(|w| w[0].severity >= w[1].severity)
    );
    // Only the same-origin probe is clean.
    assert_eq!(report.rows[0].severity, Some(Severity::Low));
    assert!(
        report
            .rows
            .iter()
            .all(|r| r.exposure == Exposure::Credentialed)
    );
}

/// A strict allowlist server: grants only its own origin, with Vary.
#[test]
fn strict_server_passes_every_probe() {
    let target: Origin = "https://example.com".parse().unwrap();
    let exchanges: Vec<Exchange> = probes(&target)
        .iter()
        .map(|p| {
            let mut h = CorsHeaders::from_pairs([("Vary", "Origin")]);
            if p.origin == "https://example.com" {
                h.push(ACAO, &p.origin);
                h.push(ACAC, "true");
            }
            Exchange::new(Some(&p.origin), h)
        })
        .collect();
    let report = run(&exchanges, &Options::for_target(target));
    assert!(report.weaknesses.is_empty(), "{:?}", report.weaknesses);
    assert_eq!(report.rows[0].exposure, Exposure::Credentialed);
    assert!(
        report.rows[1..]
            .iter()
            .all(|r| r.exposure == Exposure::None)
    );
}
