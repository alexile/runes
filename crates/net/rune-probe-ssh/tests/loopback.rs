//! The probe through the tokio runner against a mock SSH server on
//! loopback. No traffic leaves the host.

#![allow(
    clippy::field_reassign_with_default,
    reason = "KexInit is non_exhaustive: other crates build it from Default"
)]
// Test helpers outside `#[test]` functions may unwrap too.
#![allow(clippy::unwrap_used, reason = "test code")]

use std::time::Duration;

use rune_probe_ssh::{KexInit, SshProbe, encode_packet, parse_packet};
use rune_service_probe::{Error, Options, Runner, Target};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

const ED25519: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIOJv+0BnO5Sq9IS18Q8eLfxJL3GuLtonL4clXHHkg4EX";

fn runner() -> Runner {
    Runner::new(
        Options::default()
            .with_connect_timeout(Duration::from_secs(2))
            .with_io_timeout(Duration::from_millis(500))
            .with_total_timeout(Duration::from_secs(5)),
    )
}

fn offer() -> KexInit {
    let mut k = KexInit::default();
    k.kex_algorithms = vec![
        "curve25519-sha256".into(),
        "kex-strict-s-v00@openssh.com".into(),
    ];
    k.server_host_key_algorithms = vec!["ssh-ed25519".into()];
    k.encryption_client_to_server = vec!["aes256-ctr".into(), "aes128-cbc".into()];
    k.encryption_server_to_client
        .clone_from(&k.encryption_client_to_server);
    k.mac_client_to_server = vec!["hmac-sha2-256".into()];
    k.mac_server_to_client.clone_from(&k.mac_client_to_server);
    k.compression_client_to_server = vec!["none".into()];
    k.compression_server_to_client = vec!["none".into()];
    k
}

/// Read until `buf` holds a full line.
async fn read_line(stream: &mut TcpStream, buf: &mut Vec<u8>) -> Vec<u8> {
    loop {
        if let Some(end) = buf.iter().position(|&b| b == b'\n') {
            return buf.drain(..=end).collect();
        }
        let mut chunk = [0u8; 512];
        let n = stream.read(&mut chunk).await.unwrap();
        assert!(n > 0, "client closed before sending a line");
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Read one binary packet payload.
async fn read_packet(stream: &mut TcpStream, buf: &mut Vec<u8>) -> Vec<u8> {
    loop {
        if let Some((payload, used)) = parse_packet(buf).unwrap() {
            let payload = payload.to_vec();
            buf.drain(..used);
            return payload;
        }
        let mut chunk = [0u8; 512];
        let n = stream.read(&mut chunk).await.unwrap();
        assert!(n > 0, "client closed before sending a packet");
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// What the mock server saw from the client.
#[derive(Debug)]
struct Seen {
    ident: Vec<u8>,
    kexinit: KexInit,
    init: Vec<u8>,
    trailing: Vec<u8>,
}

/// An OpenSSH-like server: identification first, KEXINIT after the
/// client's identification, the ECDH reply after the client's init.
async fn mock_server() -> (Target, oneshot::Receiver<Seen>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        stream
            .write_all(b"SSH-2.0-OpenSSH_9.9 mock\r\n")
            .await
            .unwrap();
        let mut buf = Vec::new();
        let ident = read_line(&mut stream, &mut buf).await;
        stream
            .write_all(&encode_packet(&offer().encode()))
            .await
            .unwrap();
        let kexinit = KexInit::parse(&read_packet(&mut stream, &mut buf).await).unwrap();
        let init = read_packet(&mut stream, &mut buf).await;

        let key = rune_base64::decode(ED25519).unwrap();
        let mut reply = vec![31];
        reply.extend_from_slice(&u32::try_from(key.len()).unwrap().to_be_bytes());
        reply.extend_from_slice(&key);
        reply.extend_from_slice(&[0, 0, 0, 32]);
        reply.extend_from_slice(&[1; 32]);
        reply.extend_from_slice(&[0, 0, 0, 0]);
        stream.write_all(&encode_packet(&reply)).await.unwrap();

        // The client must hang up now: no NEWKEYS, no authentication.
        let mut trailing = buf;
        let mut chunk = [0u8; 512];
        loop {
            match tokio::time::timeout(Duration::from_secs(2), stream.read(&mut chunk)).await {
                Ok(Ok(0) | Err(_)) | Err(_) => break,
                Ok(Ok(n)) => trailing.extend_from_slice(&chunk[..n]),
            }
        }
        let _ = tx.send(Seen {
            ident,
            kexinit,
            init,
            trailing,
        });
    });
    (Target::new("localhost", addr.port()).with_addr(addr), rx)
}

#[tokio::test]
async fn fetches_host_key_and_hangs_up() {
    let (target, seen) = mock_server().await;
    let info = runner().probe(&SshProbe::new(), &target).await.unwrap();
    assert_eq!(info.product.as_deref(), Some("OpenSSH"));
    assert_eq!(info.version.as_deref(), Some("9.9"));
    assert_eq!(
        info.details["ssh.host_key_fingerprint"],
        "SHA256:sy6hgZYNW2YfQFZt6xYCu+D96SlMGrevKRhp8XYPN74"
    );
    let checks: Vec<&str> = info.findings.iter().map(|f| f.check_id.as_str()).collect();
    // OpenSSH_9.9 is before 9.9p2, so the banner heuristic flags it too.
    assert_eq!(
        checks,
        [
            "ssh.weak_cipher",
            "ssh.discouraged_mac",
            "ssh.cve-2025-26466"
        ]
    );
    assert_eq!(info.details["ssh.grade"], "C");

    let seen = seen.await.unwrap();
    assert_eq!(seen.ident, b"SSH-2.0-rune_probe_ssh\r\n");
    assert_eq!(seen.kexinit.kex_algorithms, ["curve25519-sha256"]);
    assert_eq!(seen.init[0], 30);
    assert!(seen.trailing.is_empty(), "client sent {:?}", seen.trailing);
}

#[tokio::test]
async fn closed_port_is_unreachable() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let err = runner()
        .probe(&SshProbe::new(), &Target::from_addr(addr))
        .await
        .unwrap_err();
    assert!(err.is_unreachable(), "{err}");
}

#[tokio::test]
async fn silent_server_is_no_response() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(3)).await;
        drop(stream);
    });
    let err = runner()
        .probe(&SshProbe::new(), &Target::from_addr(addr))
        .await
        .unwrap_err();
    assert!(matches!(err, Error::NoResponse { .. }), "{err}");
}
