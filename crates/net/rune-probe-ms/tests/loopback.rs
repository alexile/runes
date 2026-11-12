//! The probes over real sockets, against mock servers on loopback that
//! replay captured handshakes.

#![allow(clippy::unwrap_used, reason = "test code")]

mod common;

use std::time::Duration;

use rune_probe_ms::rdp::{self, Protocols};
use rune_probe_ms::{RdpProbe, Smb1Probe, SmbProbe, smb};
use rune_service_probe::{AuthRequirement, Error, Options, Runner, Target};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn runner() -> Runner {
    Runner::new(
        Options::default()
            .with_io_timeout(Duration::from_millis(500))
            .with_total_timeout(Duration::from_secs(3)),
    )
}

/// Serve one connection: read one request of `request_len` bytes, check
/// it, write `reply` (or close when empty).
async fn serve(expected: Vec<u8>, reply: Vec<u8>) -> Target {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut s, _): (TcpStream, _) = listener.accept().await.unwrap();
        let mut buf = vec![0; expected.len()];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, expected);
        if !reply.is_empty() {
            let (a, b) = reply.split_at(reply.len() / 2);
            s.write_all(a).await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
            s.write_all(b).await.unwrap();
            // Stay open: the probe must stop on its own.
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });
    Target::from_addr(addr)
}

#[tokio::test]
async fn smb2_negotiate() {
    let target = serve(smb::negotiate_request(), common::windows_2022(3)).await;
    let info = runner().probe(&SmbProbe::new(), &target).await.unwrap();
    assert_eq!(info.details["smb.dialect"], "3.1.1");
    assert_eq!(info.details["smb.signing"], "required");
}

#[tokio::test]
async fn smb1_enabled() {
    let target = serve(
        smb::smb1_negotiate_request(),
        common::smb1_response(0x03, false),
    )
    .await;
    let info = runner().probe(&Smb1Probe::new(), &target).await.unwrap();
    assert!(
        info.findings
            .iter()
            .any(|f| f.check_id == "smb.smb1_enabled")
    );
}

#[tokio::test]
async fn smb1_reset_is_no_response() {
    let target = serve(smb::smb1_negotiate_request(), Vec::new()).await;
    let err = runner()
        .probe(&Smb1Probe::new(), &target)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::NoResponse { .. }));
}

#[tokio::test]
async fn rdp_nla_required() {
    let target = serve(
        rdp::connection_request(Protocols::RDP),
        common::rdp_confirm(3, 0, 5),
    )
    .await;
    let info = runner().probe(&RdpProbe::new(), &target).await.unwrap();
    assert_eq!(info.auth, AuthRequirement::Required);
    assert_eq!(info.findings.len(), 0);
}

#[tokio::test]
async fn rdp_prefers_hybrid_ex() {
    let all = Protocols::SSL
        .union(Protocols::HYBRID)
        .union(Protocols::HYBRID_EX);
    let target = serve(
        rdp::connection_request(all),
        common::rdp_confirm(2, 0x1f, 8),
    )
    .await;
    let info = runner()
        .probe(&RdpProbe::requesting(all), &target)
        .await
        .unwrap();
    assert_eq!(info.details["rdp.selected_protocol"], "hybrid_ex");
    assert!(info.capabilities.iter().any(|c| c == "restricted_admin"));
}
