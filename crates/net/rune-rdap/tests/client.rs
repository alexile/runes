//! `Client` over an in-memory `Fetcher` that replays captured responses,
//! on Tokio's paused clock (no network, no real waiting).
#![cfg(feature = "client")]
#![allow(
    clippy::unwrap_used,
    reason = "test helpers outside #[test] fns: any failure fails the test"
)]

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::Duration;

use rune_rdap::bootstrap::{Bootstrap, Registry, RegistryKind};
use rune_rdap::client::{Client, Fetcher, Options};
use rune_rdap::response::Response;
use rune_rdap::{Error, Query};
use tokio::time::Instant;

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

#[derive(Debug, thiserror::Error)]
#[error("connection refused")]
struct Refused;

/// Replays queued responses per URL and records each request with the
/// (paused) time it was made. A URL with nothing queued is refused.
#[derive(Default)]
struct Mock {
    routes: Mutex<HashMap<String, VecDeque<Response>>>,
    log: Mutex<Vec<(String, Instant)>>,
}

impl Mock {
    fn on(self, url: &str, response: Response) -> Self {
        self.routes
            .lock()
            .unwrap()
            .entry(url.to_owned())
            .or_default()
            .push_back(response);
        self
    }

    fn requests(&self) -> Vec<String> {
        self.log
            .lock()
            .unwrap()
            .iter()
            .map(|(u, _)| u.clone())
            .collect()
    }

    fn times(&self) -> Vec<Instant> {
        self.log.lock().unwrap().iter().map(|(_, t)| *t).collect()
    }
}

impl Fetcher for &Mock {
    type Error = Refused;

    fn get(
        &self,
        url: &str,
    ) -> impl std::future::Future<Output = Result<Response, Refused>> + Send {
        self.log
            .lock()
            .unwrap()
            .push((url.to_owned(), Instant::now()));
        let next = self
            .routes
            .lock()
            .unwrap()
            .get_mut(url)
            .and_then(VecDeque::pop_front);
        async move { next.ok_or(Refused) }
    }
}

const BOOT: &str = "http://boot.test/";

fn options() -> Options {
    Options::default().with_bootstrap_base(BOOT)
}

fn ok(body: Vec<u8>) -> Response {
    Response::new(200, body).with_header("Content-Type", "application/rdap+json")
}

#[tokio::test(start_paused = true)]
async fn bootstraps_then_looks_up_and_caches() {
    let mock = Mock::default()
        .on(
            "http://boot.test/dns.json",
            ok(fixture("bootstrap-dns.json")),
        )
        .on(
            "https://rdap.verisign.com/com/v1/domain/example.com",
            ok(fixture("domain-example.com.json")),
        );
    let client = Client::new(&mock, options());

    let found = client.lookup_str("Example.COM").await.unwrap();
    assert!(!found.cached);
    assert_eq!(
        found.object.as_domain().unwrap().registrar_iana_id(),
        Some("376")
    );
    let again = client.lookup_str("example.com").await.unwrap();
    assert!(again.cached);
    assert_eq!(again.object, found.object);
    assert_eq!(
        mock.requests(),
        [
            "http://boot.test/dns.json",
            "https://rdap.verisign.com/com/v1/domain/example.com"
        ]
    );
    assert!(client.bootstrap().get(RegistryKind::Dns).is_some());

    // After clearing, the object is fetched again but the registry is not.
    client.clear_cache();
    assert!(matches!(
        client.lookup_str("example.com").await,
        Err(Error::Transport(_))
    ));
    assert_eq!(mock.requests().len(), 3);
}

#[tokio::test(start_paused = true)]
async fn follows_redirects_like_arin_to_ripe() {
    let mock = Mock::default()
        .on(
            "http://boot.test/ipv4.json",
            ok(br#"{"version":"1.0","services":[[["193.0.0.0/8"],["https://rdap.arin.net/registry/"]]]}"#.to_vec()),
        )
        .on(
            "https://rdap.arin.net/registry/ip/193.0.6.139",
            Response::new(303, "").with_header("Location", "https://rdap.db.ripe.net/ip/193.0.6.139"),
        )
        .on(
            "https://rdap.db.ripe.net/ip/193.0.6.139",
            ok(fixture("ip-ripe-193.0.6.139.json")),
        );
    let client = Client::new(&mock, options());
    let found = client.lookup_str("193.0.6.139").await.unwrap();
    assert_eq!(found.url, "https://rdap.arin.net/registry/ip/193.0.6.139");
    assert_eq!(found.final_url, "https://rdap.db.ripe.net/ip/193.0.6.139");
    assert_eq!(
        found.object.as_ip_network().unwrap().country.as_deref(),
        Some("NL")
    );
}

#[tokio::test(start_paused = true)]
async fn redirect_limits_and_schemes() {
    let base = "https://loop.test/";
    let boot = Bootstrap::new().with(
        Registry::parse(
            RegistryKind::Asn,
            br#"{"version":"1.0","services":[[["1-100"],["https://loop.test/"]]]}"#,
        )
        .unwrap(),
    );
    // A relative redirect loop.
    let mut mock = Mock::default();
    for _ in 0..10 {
        mock = mock.on(
            &format!("{base}autnum/1"),
            Response::new(302, "").with_header("Location", "/autnum/1"),
        );
    }
    let client = Client::new(&mock, options().with_max_redirects(3)).with_bootstrap(boot.clone());
    assert!(matches!(
        client.lookup(&Query::Autnum(1)).await,
        Err(Error::Redirect(_))
    ));
    assert_eq!(mock.requests().len(), 4);

    let mock = Mock::default().on(
        &format!("{base}autnum/2"),
        Response::new(301, "").with_header("Location", "file:///etc/passwd"),
    );
    let client = Client::new(&mock, options()).with_bootstrap(boot);
    assert!(matches!(
        client.lookup(&Query::Autnum(2)).await,
        Err(Error::Redirect(_))
    ));
    assert_eq!(mock.requests().len(), 1);
}

#[tokio::test(start_paused = true)]
async fn spaces_requests_per_host() {
    let boot = Bootstrap::new()
        .with(Registry::parse(RegistryKind::Asn, &fixture("bootstrap-asn.json")).unwrap());
    let mut mock = Mock::default();
    for asn in [15_169, 15_170, 15_171] {
        mock = mock.on(
            &format!("https://rdap.arin.net/registry/autnum/{asn}"),
            ok(fixture("autnum-arin-15169.json")),
        );
    }
    let client = Client::new(&mock, options().with_min_interval(Duration::from_secs(2)))
        .with_bootstrap(boot);
    let start = Instant::now();
    for asn in [15_169, 15_170, 15_171] {
        client.lookup(&Query::Autnum(asn)).await.unwrap();
    }
    let offsets: Vec<u64> = mock
        .times()
        .iter()
        .map(|t| t.duration_since(start).as_secs())
        .collect();
    assert_eq!(offsets, [0, 2, 4]);
}

#[tokio::test(start_paused = true)]
async fn retries_after_429() {
    let boot = Bootstrap::new()
        .with(Registry::parse(RegistryKind::Asn, &fixture("bootstrap-asn.json")).unwrap());
    let url = "https://rdap.arin.net/registry/autnum/15169";
    let mock = Mock::default()
        .on(url, Response::new(429, "").with_header("Retry-After", "10"))
        .on(url, ok(fixture("autnum-arin-15169.json")));
    let client = Client::new(&mock, options().with_min_interval(Duration::ZERO))
        .with_bootstrap(boot.clone());
    let start = Instant::now();
    client.lookup(&Query::Autnum(15_169)).await.unwrap();
    let times = mock.times();
    assert_eq!(times[1].duration_since(start), Duration::from_secs(10));

    // Too long a wait, or no retries left, fails at once.
    let mock = Mock::default().on(
        url,
        Response::new(429, "").with_header("Retry-After", "3600"),
    );
    let client = Client::new(&mock, options()).with_bootstrap(boot.clone());
    assert!(matches!(
        client.lookup(&Query::Autnum(15_169)).await,
        Err(Error::RateLimited { retry_after: Some(d) }) if d == Duration::from_secs(3600)
    ));
    let mock = Mock::default()
        .on(url, Response::new(429, ""))
        .on(url, Response::new(429, ""));
    let client = Client::new(&mock, options()).with_bootstrap(boot);
    assert!(matches!(
        client.lookup(&Query::Autnum(15_169)).await,
        Err(Error::RateLimited { retry_after: None })
    ));
    assert_eq!(mock.requests().len(), 2);
}

#[tokio::test(start_paused = true)]
async fn falls_back_to_http_mirror_on_transport_error() {
    let boot = Bootstrap::new()
        .with(Registry::parse(RegistryKind::Ipv4, &fixture("bootstrap-ipv4.json")).unwrap());
    // AFRINIC lists an https and an http base URL; only the second answers.
    let mock = Mock::default().on(
        "http://rdap.afrinic.net/rdap/ip/41.0.0.1",
        ok(
            br#"{"objectClassName":"ip network","handle":"AFRINIC-41","startAddress":"41.0.0.0"}"#
                .to_vec(),
        ),
    );
    let client = Client::new(&mock, options()).with_bootstrap(boot);
    let found = client.lookup_str("41.0.0.1").await.unwrap();
    assert_eq!(found.object.handle(), Some("AFRINIC-41"));
    assert_eq!(
        mock.requests(),
        [
            "https://rdap.afrinic.net/rdap/ip/41.0.0.1",
            "http://rdap.afrinic.net/rdap/ip/41.0.0.1"
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn honours_cache_control_and_expiry() {
    let url = "https://rdap.verisign.com/com/v1/domain/example.com";
    let mock = Mock::default()
        .on(
            "http://boot.test/dns.json",
            ok(fixture("bootstrap-dns.json")).with_header("Cache-Control", "max-age=60"),
        )
        .on(
            url,
            ok(fixture("domain-example.com.json")).with_header("Cache-Control", "max-age=30"),
        )
        .on(
            url,
            ok(fixture("domain-example.com.json")).with_header("Cache-Control", "no-store"),
        )
        .on(url, ok(fixture("domain-example.com.json")))
        .on("http://boot.test/dns.json", Response::new(503, ""));
    let client = Client::new(&mock, options().with_min_interval(Duration::ZERO));
    assert!(!client.lookup_str("example.com").await.unwrap().cached);
    tokio::time::advance(Duration::from_secs(29)).await;
    assert!(client.lookup_str("example.com").await.unwrap().cached);
    tokio::time::advance(Duration::from_secs(2)).await;
    // Expired: fetched again, this time with no-store.
    assert!(!client.lookup_str("example.com").await.unwrap().cached);
    assert!(!client.lookup_str("example.com").await.unwrap().cached);
    // The bootstrap file has expired too; its refresh fails, so the stale
    // copy keeps serving (and the object is still cached for an hour).
    tokio::time::advance(Duration::from_secs(60)).await;
    let before = mock.requests().len();
    assert!(client.lookup_str("example.com").await.unwrap().cached);
    let requests = mock.requests();
    assert_eq!(requests.len(), before + 1);
    assert_eq!(requests[before], "http://boot.test/dns.json");
}

#[tokio::test(start_paused = true)]
async fn surfaces_errors() {
    let mock = Mock::default().on("http://boot.test/ipv4.json", Response::new(500, "nope"));
    let client = Client::new(&mock, options());
    assert!(matches!(
        client.lookup_str("8.8.8.8").await,
        Err(Error::Server { status: 500, .. })
    ));

    let boot = Bootstrap::new()
        .with(Registry::parse(RegistryKind::Ipv4, &fixture("bootstrap-ipv4.json")).unwrap());
    let mock = Mock::default()
        .on(
            "https://rdap.arin.net/registry/ip/8.8.8.8",
            Response::new(404, ""),
        )
        .on(
            "https://rdap.arin.net/registry/ip/8.8.4.4",
            Response::new(400, fixture("error-arin-400.json")),
        );
    let client = Client::new(&mock, options()).with_bootstrap(boot);
    assert!(matches!(
        client.lookup_str("8.8.8.8").await,
        Err(Error::NotFound)
    ));
    assert!(matches!(
        client.lookup_str("8.8.4.4").await,
        Err(Error::Server {
            error_code: Some(400),
            ..
        })
    ));
    assert!(matches!(
        client.lookup_str("example.com").await,
        Err(Error::MissingRegistry("dns"))
    ));
    assert!(matches!(
        client.lookup_str("").await,
        Err(Error::InvalidQuery { .. })
    ));
}
