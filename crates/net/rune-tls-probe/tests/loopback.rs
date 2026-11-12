//! `scan` through rune-service-probe's tokio runner against scripted TLS
//! servers on loopback. No traffic leaves the host.

#![allow(clippy::unwrap_used, reason = "test helpers")]

mod support;

use std::net::SocketAddr;
use std::time::Duration;

use rune_service_probe::{Options, Runner, ServiceProbe, Target};
use rune_tls_hello::{CipherSuite, ClientHello, ProtocolVersion};
use rune_tls_probe::{Observed, Offer, ScanOptions, TlsHelloProbe, scan};
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
