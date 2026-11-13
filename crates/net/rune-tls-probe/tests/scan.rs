//! Full scans against scripted servers, in memory.

#![allow(clippy::unwrap_used, reason = "test helpers")]

mod support;

use rune_service_probe::Target;
use rune_tls_hello::{CipherSuite, ClientHello, DowngradeSentinel, ProtocolVersion};
use rune_tls_probe::{Observed, Offer, Report, ResponseReader, ScanOptions, Scanner};
use support::MockServer;

const SSL3: ProtocolVersion = ProtocolVersion::SSL_3_0;
const TLS10: ProtocolVersion = ProtocolVersion::TLS_1_0;
const TLS11: ProtocolVersion = ProtocolVersion::TLS_1_1;
const TLS12: ProtocolVersion = ProtocolVersion::TLS_1_2;
const TLS13: ProtocolVersion = ProtocolVersion::TLS_1_3;

/// Weak suites an old OpenSSL with `ALL:eNULL` would accept, in server order.
const LEGACY_SUITES: &[u16] = &[
    0x0035, // RSA_WITH_AES_256_CBC_SHA
    0x000a, // RSA_WITH_3DES_EDE_CBC_SHA
    0x0005, // RSA_WITH_RC4_128_SHA
    0x0004, // RSA_WITH_RC4_128_MD5
    0x0009, // RSA_WITH_DES_CBC_SHA
    0x0003, // RSA_EXPORT_WITH_RC4_40_MD5
    0x0008, // RSA_EXPORT_WITH_DES40_CBC_SHA
    0x0018, // DH_anon_WITH_RC4_128_MD5
    0x0002, // RSA_WITH_NULL_SHA
];

const MODERN_SUITES: &[u16] = &[0x1302, 0x1301, 0x1303, 0xc030, 0xc02f, 0xcca8];

fn run(server: &MockServer, options: ScanOptions) -> (Report, Vec<Offer>) {
    let mut scanner = Scanner::new(options);
    let mut offers = Vec::new();
    while let Some(offer) = scanner.next_offer() {
        // The hello must be valid TLS for every offer.
        let wire = offer.to_records([9; 32]).unwrap();
        ClientHello::parse_records(&wire).unwrap();
        let mut reader = ResponseReader::for_offer(&offer);
        let outcome = reader
            .feed(&server.respond(&wire))
            .unwrap_or_else(|| reader.finish());
        scanner.record(&outcome);
        offers.push(offer);
    }
    (scanner.finish(), offers)
}

fn suites(codes: &[u16]) -> Vec<CipherSuite> {
    codes.iter().map(|&c| CipherSuite(c)).collect()
}

fn check_ids(report: &Report) -> Vec<String> {
    report
        .findings(&Target::new("server.test", 443))
        .into_iter()
        .map(|f| f.check_id)
        .collect()
}

#[test]
fn tls10_only_server_rustls_cannot_probe() {
    let mut server = MockServer::new(&[TLS10], LEGACY_SUITES);
    server.secure_renegotiation = false;
    let (report, _) = run(&server, ScanOptions::default());

    assert_eq!(report.supported_versions(), [TLS10]);
    let tls10 = report.version(TLS10).unwrap();
    assert_eq!(tls10.cipher_suites, suites(LEGACY_SUITES));
    assert!(tls10.complete);
    // TLS 1.1/1.2 hellos were answered with TLS 1.0: not support.
    assert!(!report.version(TLS11).unwrap().supported);
    assert!(!report.version(TLS12).unwrap().supported);
    assert_eq!(report.fallback_scsv, Observed::NotApplicable);
    assert_eq!(report.compression, Observed::No);
    assert_eq!(report.secure_renegotiation, Observed::No);
    assert!(!report.truncated);
    assert_eq!(report.anomalies, [] as [String; 0]);

    assert_eq!(
        check_ids(&report),
        [
            "tls.tls1_0",
            "tls.no_modern_version",
            "tls.cipher.null",
            "tls.cipher.anon",
            "tls.cipher.export",
            "tls.cipher.des",
            "tls.cipher.rc4",
            "tls.cipher.sweet32",
            "tls.cipher.no_forward_secrecy",
            "tls.insecure_renegotiation",
        ]
    );
    let findings = report.findings(&Target::new("server.test", 443));
    let export = findings
        .iter()
        .find(|f| f.check_id == "tls.cipher.export")
        .unwrap();
    assert_eq!(export.evidence[0].label, "TLSv1.0");
    assert_eq!(
        export.evidence[0].snippet,
        "TLS_RSA_EXPORT_WITH_RC4_40_MD5, TLS_RSA_EXPORT_WITH_DES40_CBC_SHA"
    );
}

#[test]
fn modern_server_has_no_findings() {
    let server = MockServer::new(&[TLS12, TLS13], MODERN_SUITES);
    let (report, _) = run(&server, ScanOptions::default());
    assert_eq!(report.supported_versions(), [TLS13, TLS12]);
    assert_eq!(
        report.version(TLS13).unwrap().cipher_suites,
        suites(&[0x1302, 0x1301, 0x1303])
    );
    let tls12 = report.version(TLS12).unwrap();
    assert_eq!(tls12.cipher_suites, suites(&[0xc030, 0xc02f, 0xcca8]));
    assert_eq!(tls12.downgrade_sentinel, Some(DowngradeSentinel::Tls12));
    assert_eq!(report.fallback_scsv, Observed::Yes);
    assert_eq!(report.compression, Observed::No);
    assert_eq!(report.secure_renegotiation, Observed::Yes);
    assert_eq!(
        check_ids(&report),
        [] as [String; 0],
        "{:?}",
        check_ids(&report)
    );

    let info = report.service_info(&Target::new("server.test", 443));
    assert_eq!(info.capabilities, ["TLSv1.3", "TLSv1.2"]);
    assert_eq!(info.details["tls.fallback_scsv"], "yes");
    assert_eq!(
        info.details["tls.TLSv1.3.cipher_suites"],
        "TLS_AES_256_GCM_SHA384, TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256"
    );
    assert_eq!(info.findings.len(), 0);
}

#[test]
fn missing_fallback_scsv_and_compression() {
    let mut server = MockServer::new(&[TLS10, TLS11, TLS12], &[0xc02f, 0x002f]);
    server.honor_fallback = false;
    server.compression = true;
    let (report, offers) = run(&server, ScanOptions::default());
    assert_eq!(report.supported_versions(), [TLS12, TLS11, TLS10]);
    assert_eq!(report.fallback_scsv, Observed::No);
    assert_eq!(report.compression, Observed::Yes);
    // The fallback hello is the second-newest version with the signal.
    let fallback = offers.iter().find(|o| o.fallback_scsv).unwrap();
    assert_eq!(fallback.version, TLS11);
    let ids = check_ids(&report);
    assert!(ids.contains(&"tls.no_fallback_scsv".to_owned()));
    assert!(ids.contains(&"tls.compression".to_owned()));
    assert!(ids.contains(&"tls.tls1_1".to_owned()));
}

#[test]
fn sslv3_server() {
    let server = MockServer::new(&[SSL3], &[0x0005, 0x000a]);
    let (report, offers) = run(&server, ScanOptions::default());
    assert_eq!(report.supported_versions(), [SSL3]);
    assert_eq!(
        report.version(SSL3).unwrap().cipher_suites,
        suites(&[0x0005, 0x000a])
    );
    // SSL 3.0 hellos carry no extension block.
    assert!(
        offers
            .iter()
            .filter(|o| o.version == SSL3)
            .all(|o| { o.client_hello([0; 32]).unwrap().extensions.is_none() })
    );
    assert_eq!(report.secure_renegotiation, Observed::Yes); // via the SCSV
    assert_eq!(check_ids(&report)[0], "tls.sslv3");
}

#[test]
fn chunked_enumeration_finds_suites_in_every_chunk() {
    // One suite near the start, one in the middle, one at the end of the registry.
    let server = MockServer::new(&[TLS12], &[0xccaa, 0x0033, 0xc09e]);
    let options = ScanOptions::default()
        .with_versions([TLS12])
        .with_max_suites_per_hello(16)
        .with_extra_checks(false);
    let (report, offers) = run(&server, options);
    let tls12 = report.version(TLS12).unwrap();
    let mut found = tls12.cipher_suites.clone();
    found.sort_unstable();
    assert_eq!(found, suites(&[0x0033, 0xc09e, 0xccaa]));
    assert!(offers.iter().all(|o| o.cipher_suites.len() <= 16));
    // Every chunk is refused once, and each accepted suite costs one more hello.
    let chunks = 334_usize.div_ceil(16);
    assert_eq!(report.attempts, chunks + 3);
}

#[test]
fn versions_only_scan_is_short() {
    let server = MockServer::new(&[TLS10, TLS12], LEGACY_SUITES);
    let options = ScanOptions::default()
        .with_enumerate_ciphers(false)
        .with_extra_checks(false);
    let (report, _) = run(&server, options);
    assert_eq!(report.supported_versions(), [TLS12, TLS10]);
    assert_eq!(report.version(TLS12).unwrap().cipher_suites.len(), 1);
    assert!(report.attempts <= 12, "{}", report.attempts);
}

#[test]
fn attempt_budget_truncates() {
    let server = MockServer::new(&[TLS10], LEGACY_SUITES);
    let (report, offers) = run(&server, ScanOptions::default().with_max_attempts(3));
    assert_eq!(offers.len(), 3);
    assert_eq!(report.attempts, 3);
    assert!(report.truncated);
}

#[test]
fn unoffered_suite_is_an_anomaly_not_a_loop() {
    let mut server = MockServer::new(&[TLS12], &[0xc02f]);
    server.force_suite = Some(CipherSuite(0xfefe));
    let (report, offers) = run(&server, ScanOptions::default().with_versions([TLS12]));
    assert!(offers.len() < 10);
    assert!(report.version(TLS12).unwrap().supported);
    assert!(
        report.anomalies.iter().any(|a| a.contains("not offered")),
        "{:?}",
        report.anomalies
    );
}

#[test]
fn non_tls_service() {
    let mut scanner = Scanner::new(ScanOptions::default());
    while let Some(_offer) = scanner.next_offer() {
        let mut reader = ResponseReader::new();
        let outcome = reader.feed(b"HTTP/1.1 400 Bad Request\r\n\r\n").unwrap();
        scanner.record(&outcome);
    }
    let report = scanner.finish();
    assert!(!report.speaks_tls());
    assert_eq!(check_ids(&report), [] as [String; 0]);
    assert_eq!(report.compression, Observed::NotApplicable);
}

#[test]
fn sni_is_sent() {
    let server = MockServer::new(&[TLS12], &[0xc02f]);
    let (_, offers) = run(
        &server,
        ScanOptions::default().with_server_name("www.example.com"),
    );
    let hello = offers[0].client_hello([0; 32]).unwrap();
    assert_eq!(hello.server_name(), Some("www.example.com"));
}
