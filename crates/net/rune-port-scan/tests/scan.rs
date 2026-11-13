//! The tokio scanner against listeners on loopback only.

#![allow(clippy::unwrap_used, reason = "test code")]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use rune_port_scan::{Error, HintSource, Options, PortSet, PortState, Scanner};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// A loopback listener that writes `banner` to every connection and then
/// keeps it open for a while.
async fn listener(banner: &'static [u8]) -> u16 {
    let listener = TcpListener::bind((LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let _ = stream.write_all(banner).await;
                tokio::time::sleep(Duration::from_secs(5)).await;
            });
        }
    });
    port
}

/// A loopback port with nothing listening (bound, then released).
async fn closed_port() -> u16 {
    let listener = TcpListener::bind((LOCALHOST, 0)).await.unwrap();
    listener.local_addr().unwrap().port()
}

fn options() -> Options {
    Options::default()
        .with_rate(None)
        .with_connect_timeout(Duration::from_secs(2))
        .with_banner_timeout(Duration::from_millis(300))
}

#[tokio::test]
async fn open_closed_banner_and_hints() {
    let ssh = listener(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n").await;
    let silent = listener(b"").await;
    let closed = closed_port().await;
    let ports: PortSet = [ssh, silent, closed].into_iter().collect();

    let scanner = Scanner::new(options().with_banners(true));
    let report = scanner.scan(&[LOCALHOST], &ports).await.unwrap();
    assert_eq!(report.stats.attempted, 3);
    assert_eq!((report.stats.open, report.stats.closed), (2, 1));

    let by_port = |port| {
        report
            .results
            .iter()
            .find(|r| r.addr.port() == port)
            .unwrap()
    };
    let ssh = by_port(ssh);
    assert_eq!(ssh.state, PortState::Open);
    let hint = ssh.service.as_ref().unwrap();
    assert_eq!(
        (hint.service.as_str(), hint.source),
        ("ssh", HintSource::Banner)
    );
    assert_eq!(hint.version.as_deref(), Some("9.6p1"));
    assert_eq!(
        report.os_hint(LOCALHOST),
        Some(rune_port_scan::OsHint::Linux)
    );

    let silent = by_port(silent);
    assert_eq!(silent.state, PortState::Open);
    assert_eq!(silent.banner.as_deref(), Some(&b""[..]));

    let closed = by_port(closed);
    assert_eq!(closed.state, PortState::Closed);
    assert!(closed.banner.is_none() && closed.service.is_none());
}

#[tokio::test]
async fn banners_off_reads_nothing_and_banner_is_bounded() {
    let port = listener(b"0123456789abcdef").await;
    let addr = SocketAddr::new(LOCALHOST, port);
    let off = Scanner::new(options()).scan_addr(addr).await;
    assert_eq!((off.state, off.banner.as_ref()), (PortState::Open, None));

    let on = Scanner::new(options().with_banners(true).with_max_banner(4))
        .scan_addr(addr)
        .await;
    assert_eq!(on.banner.as_deref(), Some(&b"0123"[..]));
}

#[tokio::test]
async fn rate_limit_spaces_attempts() {
    let closed = closed_port().await;
    let ports = PortSet::from_iter([closed]);
    // Five attempts at 20/s: the last starts at least 200 ms after the first.
    let scanner = Scanner::new(options().with_rate(Some(20)));
    let hosts = [LOCALHOST; 5];
    let started = Instant::now();
    let report = scanner.scan(&hosts, &ports).await.unwrap();
    assert!(started.elapsed() >= Duration::from_millis(190));
    assert_eq!(report.stats.closed, 5);
}

#[tokio::test]
async fn concurrency_one_still_completes() {
    let open = listener(b"").await;
    let closed = closed_port().await;
    let ports = PortSet::from_iter([open, closed]);
    let scanner = Scanner::new(options().with_concurrency(0));
    let report = scanner.scan(&[LOCALHOST], &ports).await.unwrap();
    assert_eq!((report.stats.open, report.stats.closed), (1, 1));
}

#[tokio::test]
async fn too_many_targets_is_refused_before_connecting() {
    let scanner = Scanner::new(options().with_max_targets(10));
    let err = scanner
        .scan(&[LOCALHOST; 2], &PortSet::top(10).unwrap())
        .await
        .unwrap_err();
    assert_eq!(err, Error::TooManyTargets { count: 20, max: 10 });
}

#[tokio::test]
async fn an_unbounded_banner_timeout_still_reports_the_port() {
    let ftp = listener(b"220 ready\r\n").await;
    let mut ports = PortSet::new();
    ports.insert(ftp);
    let scanner = Scanner::new(
        options()
            .with_banners(true)
            .with_banner_timeout(Duration::MAX),
    );
    let report = scanner.scan(&[LOCALHOST], &ports).await.unwrap();
    assert_eq!(report.results.len(), 1, "the port's result went missing");
    assert_eq!(
        report.results[0].banner.as_deref(),
        Some(&b"220 ready\r\n"[..])
    );
}
