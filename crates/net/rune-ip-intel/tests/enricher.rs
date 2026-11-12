//! The enricher's cache, pacing, back-off and address policy, against a
//! counting fake transport.

#![cfg(all(
    feature = "abuseipdb",
    feature = "greynoise",
    feature = "shodan",
    feature = "censys"
))]
#![allow(clippy::unwrap_used, reason = "test helpers")]

use std::cell::{Cell, RefCell};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use rune_ip_intel::{
    AbuseIpDb, Classification, Enricher, Error, GreyNoise, HttpRequest, HttpResponse, Options,
    ShodanInternetDb, TransportError,
};
use rune_secret_ref::SecretValue;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// Answers per provider host; counts requests.
struct Fake {
    calls: Cell<usize>,
    urls: RefCell<Vec<String>>,
    greynoise_status: Cell<u16>,
}

impl Fake {
    const fn new() -> Self {
        Self {
            calls: Cell::new(0),
            urls: RefCell::new(Vec::new()),
            greynoise_status: Cell::new(200),
        }
    }

    fn send(&self, request: &HttpRequest) -> Result<HttpResponse, TransportError> {
        self.calls.set(self.calls.get() + 1);
        self.urls.borrow_mut().push(request.url.clone());
        if request.url.contains("abuseipdb") {
            return Ok(HttpResponse::new(200).with_body(
                r#"{"data":{"abuseConfidenceScore":30,"totalReports":3,"lastReportedAt":"2024-01-01T00:00:00+00:00"}}"#,
            ));
        }
        if request.url.contains("greynoise") {
            let status = self.greynoise_status.get();
            return Ok(match status {
                200 => HttpResponse::new(200).with_body(
                    r#"{"noise":true,"riot":false,"classification":"malicious","last_seen":"2024-02-01"}"#,
                ),
                429 => HttpResponse::new(429).with_header("Retry-After", "120"),
                other => HttpResponse::new(other),
            });
        }
        Err(TransportError::permanent("unexpected host"))
    }
}

fn enricher(options: Options) -> Enricher {
    Enricher::new(options)
        .with_provider(
            AbuseIpDb::new(SecretValue::new("k")),
            Duration::from_secs(1),
        )
        .with_provider(GreyNoise::new(), Duration::from_secs(10))
}

#[test]
fn merges_providers() {
    let fake = Fake::new();
    let transport = |r: &HttpRequest| fake.send(r);
    let mut e = enricher(Options::default());
    assert_eq!(e.providers(), ["abuseipdb", "greynoise"]);
    let summary = e.enrich(ip("8.8.4.4"), &transport, Instant::now()).unwrap();
    assert_eq!(summary.classification, Classification::Malicious);
    assert_eq!(summary.score, Some(30));
    assert_eq!(summary.tags, ["scanner"]);
    assert_eq!(summary.last_seen, Some(1_706_745_600));
    assert_eq!(summary.verdicts.len(), 2);
    assert_eq!(summary.errors, [] as [(&str, rune_ip_intel::Error); 0]);
    assert_eq!(fake.calls.get(), 2);
}

#[test]
fn caches_until_the_ttl() {
    let fake = Fake::new();
    let transport = |r: &HttpRequest| fake.send(r);
    let mut e = enricher(Options::default().with_cache_ttl(Duration::from_secs(60)));
    let t0 = Instant::now();
    e.enrich(ip("8.8.4.4"), &transport, t0).unwrap();
    let again = e
        .enrich(ip("8.8.4.4"), &transport, t0 + Duration::from_secs(30))
        .unwrap();
    assert_eq!(fake.calls.get(), 2);
    assert_eq!(again.verdicts.len(), 2);
    assert_eq!(e.cached(), 2);
    // Expired: asked again.
    e.enrich(ip("8.8.4.4"), &transport, t0 + Duration::from_secs(61))
        .unwrap();
    assert_eq!(fake.calls.get(), 4);
    e.clear_cache();
    assert_eq!(e.cached(), 0);
}

#[test]
fn paces_each_provider() {
    let fake = Fake::new();
    let transport = |r: &HttpRequest| fake.send(r);
    let mut e = enricher(Options::default());
    let t0 = Instant::now();
    e.enrich(ip("8.8.4.4"), &transport, t0).unwrap();
    // A different address 2 s later: AbuseIPDB (1 s) may go, GreyNoise
    // (10 s) is held back without a request.
    let s = e
        .enrich(ip("1.0.0.1"), &transport, t0 + Duration::from_secs(2))
        .unwrap();
    assert_eq!(fake.calls.get(), 3);
    assert_eq!(s.verdicts.len(), 1);
    assert_eq!(
        s.errors,
        [(
            "greynoise",
            Error::RateLimited {
                provider: "greynoise",
                retry_after: Some(Duration::from_secs(8))
            }
        )]
    );
    let s = e
        .enrich(ip("1.0.0.1"), &transport, t0 + Duration::from_secs(10))
        .unwrap();
    assert_eq!(s.errors, [] as [(&str, rune_ip_intel::Error); 0]);
    assert_eq!(fake.calls.get(), 4); // AbuseIPDB answer was cached
}

#[test]
fn backs_off_after_429() {
    let fake = Fake::new();
    fake.greynoise_status.set(429);
    let transport = |r: &HttpRequest| fake.send(r);
    let mut e = enricher(Options::default().with_cache_ttl(Duration::ZERO));
    let t0 = Instant::now();
    let s = e.enrich(ip("8.8.4.4"), &transport, t0).unwrap();
    assert!(matches!(
        s.errors[0],
        ("greynoise", Error::RateLimited { retry_after: Some(d), .. }) if d == Duration::from_secs(120)
    ));
    fake.greynoise_status.set(200);
    // Within the Retry-After window: no request to GreyNoise.
    let s = e
        .enrich(ip("8.8.4.4"), &transport, t0 + Duration::from_secs(60))
        .unwrap();
    assert_eq!(s.errors.len(), 1);
    assert_eq!(fake.calls.get(), 3);
    let s = e
        .enrich(ip("8.8.4.4"), &transport, t0 + Duration::from_secs(120))
        .unwrap();
    assert_eq!(s.errors, [] as [(&str, rune_ip_intel::Error); 0]);
    assert_eq!(fake.calls.get(), 5);
}

#[test]
fn errors_are_not_cached() {
    let fake = Fake::new();
    fake.greynoise_status.set(500);
    let transport = |r: &HttpRequest| fake.send(r);
    let mut e = Enricher::default().with_provider(GreyNoise::new(), Duration::ZERO);
    let t0 = Instant::now();
    let s = e.enrich(ip("8.8.4.4"), &transport, t0).unwrap();
    assert!(matches!(s.errors[0].1, Error::Status { status: 500, .. }));
    assert_eq!(s.classification, Classification::Unknown);
    fake.greynoise_status.set(200);
    let s = e.enrich(ip("8.8.4.4"), &transport, t0).unwrap();
    assert_eq!(s.classification, Classification::Malicious);
}

#[test]
fn refuses_non_global_and_unwraps_mapped() {
    let fake = Fake::new();
    let transport = |r: &HttpRequest| fake.send(r);
    let mut e = enricher(Options::default());
    for addr in [
        "10.1.2.3",
        "127.0.0.1",
        "::1",
        "fe80::1",
        "192.0.2.1",
        "::ffff:192.168.1.1",
    ] {
        assert!(matches!(
            e.enrich(ip(addr), &transport, Instant::now()),
            Err(Error::NonGlobalAddress(_))
        ));
    }
    assert_eq!(fake.calls.get(), 0);

    let s = e
        .enrich(ip("::ffff:8.8.4.4"), &transport, Instant::now())
        .unwrap();
    assert_eq!(s.ip, ip("8.8.4.4"));
    assert!(fake.urls.borrow()[0].contains("ipAddress=8.8.4.4&"));

    let mut open = enricher(Options::default().with_allow_non_global(true));
    assert!(
        open.enrich(ip("10.1.2.3"), &transport, Instant::now())
            .is_ok()
    );
}

#[test]
fn bounds_the_cache() {
    let fake = Fake::new();
    let transport = |r: &HttpRequest| fake.send(r);
    let mut e = Enricher::new(Options::default().with_max_cache_entries(3))
        .with_provider(AbuseIpDb::new(SecretValue::new("k")), Duration::ZERO);
    let t0 = Instant::now();
    for i in 1..=10u8 {
        let addr = IpAddr::from([9, 9, 9, i]);
        e.enrich(addr, &transport, t0 + Duration::from_secs(i.into()))
            .unwrap();
        assert!(e.cached() <= 3);
    }
    // The most recent entries survive.
    let before = fake.calls.get();
    e.enrich(
        IpAddr::from([9, 9, 9, 10]),
        &transport,
        t0 + Duration::from_secs(11),
    )
    .unwrap();
    assert_eq!(fake.calls.get(), before);
}

#[test]
fn shodan_only_needs_no_key() {
    let mut e = Enricher::default().with_provider(ShodanInternetDb::new(), Duration::ZERO);
    let transport = |r: &HttpRequest| {
        assert!(r.headers.iter().all(|(_, v)| !v.is_secret()));
        Ok(HttpResponse::new(404).with_body(r#"{"detail":"No information available"}"#))
    };
    let s = e.enrich(ip("9.9.9.9"), &transport, Instant::now()).unwrap();
    assert_eq!(s.classification, Classification::Unknown);
}
