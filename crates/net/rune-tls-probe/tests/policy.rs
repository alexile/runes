//! The policy grader over whole scans of scripted servers.

#![allow(clippy::unwrap_used, reason = "test code")]

mod support;

use rune_finding::Severity;
use rune_service_probe::Target;
use rune_tls_hello::{ClientHello, NamedGroup, ProtocolVersion};
use rune_tls_probe::policy::{Category, Grade, Level, Policy, Report};
use rune_tls_probe::{ResponseReader, ScanOptions, Scanner};
use support::MockServer;

const SSL3: ProtocolVersion = ProtocolVersion::SSL_3_0;
const TLS10: ProtocolVersion = ProtocolVersion::TLS_1_0;
const TLS11: ProtocolVersion = ProtocolVersion::TLS_1_1;
const TLS12: ProtocolVersion = ProtocolVersion::TLS_1_2;
const TLS13: ProtocolVersion = ProtocolVersion::TLS_1_3;

fn scan(server: &MockServer) -> rune_tls_probe::Report {
    let mut scanner = Scanner::new(ScanOptions::default());
    while let Some(offer) = scanner.next_offer() {
        let wire = offer.to_records([9; 32]).unwrap();
        ClientHello::parse_records(&wire).unwrap();
        let mut reader = ResponseReader::for_offer(&offer);
        let outcome = reader
            .feed(&server.respond(&wire))
            .unwrap_or_else(|| reader.finish());
        scanner.record(&outcome);
    }
    scanner.finish()
}

fn items(report: &Report, level: Level) -> Vec<&str> {
    report
        .assessments
        .iter()
        .filter(|a| a.level == level)
        .map(|a| a.item.as_str())
        .collect()
}

fn check_ids(report: &Report) -> Vec<String> {
    report
        .findings(&Target::new("server.test", 443))
        .into_iter()
        .map(|f| f.check_id)
        .collect()
}

/// Mozilla's intermediate configuration: TLS 1.2 and 1.3, forward-secret
/// AEAD suites only.
fn intermediate_server() -> MockServer {
    MockServer::new(
        &[TLS12, TLS13],
        &[
            0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0x009e, 0x009f,
            0xccaa,
        ],
    )
}

#[test]
fn mozilla_intermediate_config_gets_an_a() {
    let scan = scan(&intermediate_server());
    let report = Policy::intermediate().grade(&scan);
    assert_eq!(report.grade, Grade::A, "{:?}", report.reasons);
    assert_eq!(report.grade_reason, "nothing the policy objects to");
    assert_eq!(report.reasons, [] as [String; 0]);
    assert!(report.complete);
    assert_eq!(check_ids(&report), [] as [String; 0]);
    assert_eq!(items(&report, Level::Fail), [] as [&str; 0]);
    let kx: Vec<&str> = report
        .assessments
        .iter()
        .filter(|a| a.category == Category::KeyExchange)
        .map(|a| a.item.as_str())
        .collect();
    assert_eq!(
        kx,
        [
            "DHE 2048-bit",
            "ECDHE x25519",
            "TLS 1.3 key share x25519",
            "forward secrecy"
        ]
    );

    // Modern wants TLS 1.3 only.
    let modern = Policy::modern().grade(&scan);
    assert_eq!(modern.grade, Grade::B);
    assert_eq!(items(&modern, Level::Warn), ["TLSv1.2"]);
    assert_eq!(check_ids(&modern), ["tls.discouraged_protocol"]);
}

#[test]
fn tls13_only_server_is_an_a_everywhere() {
    let server = MockServer::new(&[TLS13], &[0x1302, 0x1301, 0x1303]);
    let scan = scan(&server);
    for policy in [Policy::modern(), Policy::intermediate(), Policy::old()] {
        let report = policy.grade(&scan);
        assert_eq!(
            report.grade,
            Grade::A,
            "{}: {:?}",
            policy.profile(),
            report.reasons
        );
    }
}

#[test]
fn old_style_server() {
    // Mozilla's "old" list: TLS 1.0-1.3, CBC, static RSA and 3DES at the end.
    let mut server = MockServer::new(
        &[TLS10, TLS11, TLS12, TLS13],
        &[
            0x1301, 0xc02f, 0xc030, 0xc027, 0xc013, 0xc014, 0x009c, 0x002f, 0x0035, 0x000a,
        ],
    );
    server.dh_prime_bits = 1024;
    let scan = scan(&server);

    let old = Policy::old().grade(&scan);
    assert_eq!(old.grade, Grade::B, "{:?}", old.reasons);
    assert!(old.failures().next().is_none());
    assert_eq!(
        items(&old, Level::Warn),
        [
            "TLSv1.1",
            "TLSv1.0",
            "TLS_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_RSA_WITH_AES_128_CBC_SHA",
            "TLS_RSA_WITH_AES_256_CBC_SHA",
            "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        ]
    );
    let fs = old
        .assessments
        .iter()
        .find(|a| a.item == "forward secrecy")
        .unwrap();
    assert_eq!(fs.level, Level::Ok);

    let intermediate = Policy::intermediate().grade(&scan);
    assert_eq!(intermediate.grade, Grade::C);
    assert_eq!(
        intermediate.grade_reason,
        "items the policy rejects: TLSv1.1, TLSv1.0, TLS_RSA_WITH_AES_128_GCM_SHA256, \
         TLS_RSA_WITH_AES_128_CBC_SHA, TLS_RSA_WITH_AES_256_CBC_SHA, \
         TLS_RSA_WITH_3DES_EDE_CBC_SHA"
    );
    assert_eq!(intermediate.reasons.len(), 2);
    assert_eq!(
        check_ids(&intermediate),
        [
            "tls.weak_protocol",
            "tls.weak_cipher",
            "tls.discouraged_cipher",
        ]
    );
    let findings = intermediate.findings(&Target::new("server.test", 443));
    assert_eq!(findings[1].severity, Severity::Medium); // 3DES
    let evidence: Vec<&str> = findings[0]
        .evidence
        .iter()
        .map(|e| e.label.as_str())
        .collect();
    assert_eq!(evidence, ["TLSv1.1", "TLSv1.0"]);
    assert_eq!(
        findings[0].evidence[0].snippet,
        "deprecated; only the old profile still allows it (RFC 8996)"
    );
}

#[test]
fn small_dh_and_curves() {
    let mut server = MockServer::new(&[TLS12], &[0x009e, 0xc02f]);
    server.dh_prime_bits = 1024;
    server.ecdhe_group = NamedGroup(0x0015); // secp224r1
    let scan = scan(&server);
    let report = Policy::intermediate().grade(&scan);
    assert_eq!(report.grade, Grade::C);
    assert_eq!(items(&report, Level::Fail), ["DHE 1024-bit"]);
    assert!(items(&report, Level::Warn).contains(&"ECDHE 0x0015"));
    assert_eq!(Policy::old().grade(&scan).grade, Grade::B);

    server.dh_prime_bits = 768;
    let report = Policy::old().grade(&self::scan(&server));
    assert_eq!(report.grade, Grade::D);
    assert_eq!(report.grade_reason, "badly broken items: DHE 768-bit");
}

#[test]
fn broken_servers() {
    // NULL and export suites: F under every profile.
    let server = MockServer::new(&[TLS10], &[0x0002, 0x0003, 0x002f]);
    let scan_f = scan(&server);
    for policy in [Policy::modern(), Policy::intermediate(), Policy::old()] {
        let report = policy.grade(&scan_f);
        assert_eq!(report.grade, Grade::F);
        assert!(report.grade_reason.starts_with("critical failures: "));
    }

    // SSL 3.0: D.
    let server = MockServer::new(&[SSL3, TLS12], &[0xc02f]);
    let report = Policy::old().grade(&scan(&server));
    assert_eq!(report.grade, Grade::D);
    assert_eq!(report.grade_reason, "badly broken items: SSLv3");

    // Compression and no secure renegotiation: C, even under old.
    let mut server = MockServer::new(&[TLS12, TLS13], &[0x1301, 0xc02f]);
    server.compression = true;
    server.secure_renegotiation = false;
    let report = Policy::old().grade(&scan(&server));
    assert_eq!(report.grade, Grade::C);
    assert_eq!(
        items(&report, Level::Fail),
        ["compression", "secure_renegotiation"]
    );
    assert_eq!(check_ids(&report), ["tls.weak_configuration"]);
}

#[test]
fn forward_secrecy() {
    // Static RSA only.
    let server = MockServer::new(&[TLS12], &[0x009c, 0x002f]);
    let report = Policy::intermediate().grade(&scan(&server));
    let fs = report
        .assessments
        .iter()
        .find(|a| a.item == "forward secrecy")
        .unwrap();
    assert_eq!((fs.level, fs.severity), (Level::Fail, Severity::Medium));
    assert_eq!(fs.reason, "no accepted suite gives forward secrecy");

    // TLS 1.3 alone gives forward secrecy.
    let server = MockServer::new(&[TLS13], &[0x1301]);
    let report = Policy::modern().grade(&scan(&server));
    let fs = report
        .assessments
        .iter()
        .find(|a| a.item == "forward secrecy")
        .unwrap();
    assert_eq!(fs.level, Level::Good);
}

#[test]
fn fallback_scsv_is_a_warning() {
    let mut server = MockServer::new(&[TLS12, TLS13], &[0x1301, 0xc02f]);
    server.honor_fallback = false;
    let report = Policy::intermediate().grade(&scan(&server));
    assert_eq!(report.grade, Grade::B);
    assert_eq!(items(&report, Level::Warn), ["fallback_scsv"]);
    assert_eq!(check_ids(&report), ["tls.discouraged_configuration"]);
}

#[test]
fn custom_rules() {
    let scan = scan(&intermediate_server());
    // No DHE at all, and nothing but TLS 1.3 and ECDHE suites.
    let policy = Policy::intermediate()
        .deny(Category::KeyExchange, "DHE *")
        .allow_only(
            Category::Cipher,
            ["TLS_AES_*", "TLS_CHACHA20_*", "TLS_ECDHE_*"],
        );
    let report = policy.grade(&scan);
    assert!(report.customised);
    assert_eq!(report.grade, Grade::C);
    assert_eq!(
        items(&report, Level::Fail),
        [
            "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            "DHE 2048-bit",
        ]
    );
    let dhe = report
        .assessments
        .iter()
        .find(|a| a.item == "DHE 2048-bit")
        .unwrap();
    assert_eq!(
        (dhe.reason, dhe.source),
        ("denied by the policy", Some("policy"))
    );
    assert_eq!(dhe.severity, Severity::Low);
}

#[test]
fn not_probed_is_not_judged() {
    // Versions-only scans have no suites to judge, and no TLS 1.3 verdict
    // when TLS 1.3 was not probed.
    let server = MockServer::new(&[TLS12], &[0xc02f]);
    let mut scanner = Scanner::new(
        ScanOptions::default()
            .with_versions([TLS12])
            .with_enumerate_ciphers(false)
            .with_extra_checks(false),
    );
    while let Some(offer) = scanner.next_offer() {
        let wire = offer.to_records([9; 32]).unwrap();
        let outcome = ResponseReader::new().feed(&server.respond(&wire)).unwrap();
        scanner.record(&outcome);
    }
    let report = Policy::intermediate().grade(&scanner.finish());
    let judged: Vec<&str> = report.assessments.iter().map(|a| a.item.as_str()).collect();
    assert_eq!(
        judged,
        [
            "TLSv1.2",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "forward secrecy"
        ]
    );
    assert_eq!(report.grade, Grade::A);

    // A truncated scan says so.
    let mut scanner = Scanner::new(ScanOptions::default().with_max_attempts(2));
    while let Some(offer) = scanner.next_offer() {
        let wire = offer.to_records([9; 32]).unwrap();
        let outcome = ResponseReader::new().feed(&server.respond(&wire)).unwrap();
        scanner.record(&outcome);
    }
    assert!(!Policy::intermediate().grade(&scanner.finish()).complete);
}
