//! `scan` through rune-service-probe's tokio runner against scripted TLS
//! servers on loopback. No traffic leaves the host.

#![allow(clippy::unwrap_used, reason = "test helpers")]

mod support;

use std::net::SocketAddr;
use std::time::Duration;

use rune_service_probe::{Options, Runner, ServiceProbe, Target};
use rune_tls_hello::{CipherSuite, ClientHello, ProtocolVersion};
use rune_tls_probe::{Observed, Offer, ScanOptions, TlsHelloProbe, jarm, scan};
use support::MockServer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn runner() -> Runner {
    Runner::new(
        Options::default()
            .with_connect_timeout(Duration::from_secs(2))
            .with_io_timeout(Duration::from_secs(2))
            .with_total_timeout(Duration::from_secs(5)),
    )
}

/// Serves `server` on 127.0.0.1: one hello per connection, then close.
async fn spawn(server: MockServer) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let server = server.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    let Ok(n) = stream.read(&mut chunk).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    match ClientHello::parse_records(&buf) {
                        Err(e) if e.is_incomplete() => {}
                        _ => break,
                    }
                }
                let _ = stream.write_all(&server.respond(&buf)).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    addr
}

#[tokio::test]
async fn reports_a_tls10_only_server() {
    let server = MockServer::new(&[ProtocolVersion::TLS_1_0], &[0x0005, 0x000a, 0x0003]);
    let addr = spawn(server).await;
    let target = Target::from_addr(addr);
    let report = scan(&runner(), &target, &ScanOptions::default())
        .await
        .unwrap();
    assert_eq!(report.supported_versions(), [ProtocolVersion::TLS_1_0]);
    assert_eq!(
        report
            .version(ProtocolVersion::TLS_1_0)
            .unwrap()
            .cipher_suites,
        [
            CipherSuite(0x0005),
            CipherSuite(0x000a),
            CipherSuite(0x0003)
        ]
    );
    assert_eq!(
        report.anomalies,
        [] as [String; 0],
        "{:?}",
        report.anomalies
    );
    let ids: Vec<String> = report
        .findings(&target)
        .into_iter()
        .map(|f| f.check_id)
        .collect();
    assert!(ids.contains(&"tls.tls1_0".to_owned()));
    assert!(ids.contains(&"tls.cipher.export".to_owned()));
    assert!(ids.contains(&"tls.cipher.rc4".to_owned()));
    let info = report.service_info(&target);
    assert_eq!(info.capabilities, ["TLSv1.0"]);
}

#[tokio::test]
async fn reports_a_modern_server() {
    let server = MockServer::new(
        &[ProtocolVersion::TLS_1_2, ProtocolVersion::TLS_1_3],
        &[0x1301, 0xc02f],
    );
    let addr = spawn(server).await;
    let report = scan(&runner(), &Target::from_addr(addr), &ScanOptions::default())
        .await
        .unwrap();
    assert_eq!(
        report.supported_versions(),
        [ProtocolVersion::TLS_1_3, ProtocolVersion::TLS_1_2]
    );
    assert_eq!(report.fallback_scsv, Observed::Yes);
    assert_eq!(report.findings(&Target::from_addr(addr)).len(), 0);
}

#[tokio::test]
async fn single_hello_probe_over_the_runner() {
    let addr = spawn(MockServer::new(&[ProtocolVersion::TLS_1_1], &[0x002f])).await;
    let probe = TlsHelloProbe::new(Offer::new(ProtocolVersion::TLS_1_1, [CipherSuite(0x002f)]));
    assert!(probe.default_ports().contains(&443));
    let info = runner()
        .probe(&probe, &Target::from_addr(addr))
        .await
        .unwrap();
    assert_eq!(info.version.as_deref(), Some("TLSv1.1"));
    assert_eq!(
        info.details["tls.cipher_suite"],
        "TLS_RSA_WITH_AES_128_CBC_SHA"
    );
}

#[tokio::test]
async fn unreachable_target_is_an_error() {
    // Bind then drop, so the port is closed.
    let addr = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap();
    let error = scan(&runner(), &Target::from_addr(addr), &ScanOptions::default())
        .await
        .unwrap_err();
    assert!(matches!(error, rune_tls_probe::Error::Probe(e) if e.is_unreachable()));
}

#[tokio::test]
async fn scan_reads_the_server_key_exchange() {
    let mut server = MockServer::new(&[ProtocolVersion::TLS_1_2], &[0xc02f, 0x009e]);
    server.dh_prime_bits = 1024;
    server.ecdhe_group = rune_tls_hello::NamedGroup::SECP384R1;
    let addr = spawn(server).await;
    let target = Target::from_addr(addr);
    let report = scan(&runner(), &target, &ScanOptions::default())
        .await
        .unwrap();
    let seen: Vec<String> = report
        .key_exchanges
        .iter()
        .map(|k| k.key_exchange.to_string())
        .collect();
    assert_eq!(seen, ["DHE 1024-bit", "ECDHE secp384r1"]);
    let info = report.service_info(&target);
    assert_eq!(info.details["tls.dhe"], "DHE 1024-bit");
    assert_eq!(info.details["tls.grade"], "C");
    assert_eq!(info.details["tls.policy"], "intermediate");
}

#[tokio::test]
async fn jarm_over_the_runner_matches_the_sans_io_result() {
    let server = MockServer::new(
        &[
            ProtocolVersion::TLS_1_1,
            ProtocolVersion::TLS_1_2,
            ProtocolVersion::TLS_1_3,
        ],
        &[0x1302, 0x1301, 0xc030, 0xc013],
    );
    let addr = spawn(server.clone()).await;
    let fp = jarm::fingerprint(&runner(), &Target::from_addr(addr))
        .await
        .unwrap();
    let expected: Vec<String> = jarm::PROBES
        .iter()
        .map(|p| {
            let hello = p.client_hello(&addr.ip().to_string(), &[0; 32]).unwrap();
            jarm::Entry::parse(&server.respond(&hello)).to_string()
        })
        .collect();
    assert_eq!(fp.raw(), expected.join(","));
    assert!(!fp.is_empty());
    assert_eq!(fp.hash().len(), 62);
}

/// A server that reads the hello and then sends nothing.
async fn spawn_silent() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut chunk = [0u8; 4096];
                while matches!(stream.read(&mut chunk).await, Ok(n) if n > 0) {}
            });
        }
    });
    addr
}

/// A server that answers with an endless stream of handshake bytes.
async fn spawn_flood() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut chunk = [0u8; 4096];
                let _ = stream.read(&mut chunk).await;
                // A record header promising a full record, then filler, forever.
                let mut block = vec![22, 3, 3, 0x40, 0x00, 2, 0x00, 0x3f, 0xfb];
                block.resize(64 * 1024, 0x41);
                for _ in 0..64 {
                    if stream.write_all(&block).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    addr
}

#[tokio::test]
async fn jarm_gives_up_on_silent_servers_within_the_timeouts() {
    let addr = spawn_silent().await;
    let runner = Runner::new(
        Options::default()
            .with_io_timeout(Duration::from_millis(100))
            .with_total_timeout(Duration::from_millis(300)),
    );
    let started = std::time::Instant::now();
    let fp = jarm::fingerprint(&runner, &Target::from_addr(addr))
        .await
        .unwrap();
    assert!(fp.is_empty());
    assert_eq!(fp.hash(), "0".repeat(62));
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn jarm_and_scan_cap_flooding_servers() {
    let addr = spawn_flood().await;
    let fp = jarm::fingerprint(&runner(), &Target::from_addr(addr))
        .await
        .unwrap();
    assert!(fp.is_empty());
    let report = scan(
        &runner(),
        &Target::from_addr(addr),
        &ScanOptions::default().with_versions([ProtocolVersion::TLS_1_2]),
    )
    .await
    .unwrap();
    assert!(!report.speaks_tls());
}

#[tokio::test]
async fn jarm_unreachable_target_is_an_error() {
    let addr = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap();
    let error = jarm::fingerprint(&runner(), &Target::from_addr(addr))
        .await
        .unwrap_err();
    assert!(matches!(error, rune_tls_probe::Error::Probe(e) if e.is_unreachable()));
}
