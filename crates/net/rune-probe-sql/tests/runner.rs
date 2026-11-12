//! The probes over real sockets, against mock servers on loopback that
//! replay captured handshakes.

#![allow(clippy::unwrap_used, reason = "test code")]

use std::time::Duration;

use rune_probe_sql::{MssqlProbe, MysqlProbe, PostgresAuthProbe, PostgresProbe, postgres};
use rune_service_probe::{AuthRequirement, Error, Options, Runner, Target, TlsSupport};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn runner() -> Runner {
    Runner::new(
        Options::default()
            .with_io_timeout(Duration::from_millis(500))
            .with_total_timeout(Duration::from_secs(3))
            .with_allow_intrusive(true),
    )
}

/// Serve one connection with `handler` and return the target.
async fn serve<F, Fut>(handler: F) -> Target
where
    F: FnOnce(TcpStream) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            handler(stream).await;
        }
    });
    Target::from_addr(addr)
}

async fn read_exact(stream: &mut TcpStream, n: usize) -> Vec<u8> {
    let mut buf = vec![0; n];
    stream.read_exact(&mut buf).await.unwrap();
    buf
}

fn mysql_greeting() -> Vec<u8> {
    let mut p = vec![10];
    p.extend_from_slice(b"8.4.3\0");
    p.extend_from_slice(&[9, 0, 0, 0]);
    p.extend_from_slice(b"abcdefgh\0");
    p.extend_from_slice(&[0xff, 0xff, 0xff, 2, 0, 0xff, 0xdf, 21]);
    p.extend_from_slice(&[0; 10]);
    p.extend_from_slice(b"ijklmnopqrst\0caching_sha2_password\0");
    let mut packet = vec![u8::try_from(p.len()).unwrap(), 0, 0, 0];
    packet.extend_from_slice(&p);
    packet
}

fn pg_message(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&u32::try_from(body.len() + 4).unwrap().to_be_bytes());
    out.extend_from_slice(body);
    out
}

#[tokio::test]
async fn mysql_greeting_in_two_writes() {
    let target = serve(|mut s| async move {
        let g = mysql_greeting();
        s.write_all(&g[..10]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        s.write_all(&g[10..]).await.unwrap();
        // Keep the connection open: the probe must stop on its own.
        tokio::time::sleep(Duration::from_secs(2)).await;
    })
    .await;
    let info = runner().probe(&MysqlProbe::new(), &target).await.unwrap();
    assert_eq!(info.version.as_deref(), Some("8.4.3"));
    assert_eq!(info.tls, TlsSupport::Optional);
}

#[tokio::test]
async fn postgres_without_tls() {
    let target = serve(|mut s| async move {
        assert_eq!(read_exact(&mut s, 8).await, postgres::ssl_request());
        s.write_all(b"N").await.unwrap();
        assert_eq!(read_exact(&mut s, 8).await, postgres::version_probe());
        let mut body = Vec::new();
        for (code, value) in [
            (b'S', "FATAL"),
            (b'V', "FATAL"),
            (b'C', "0A000"),
            (
                b'M',
                "unsupported frontend protocol 9.0: server supports 3.0 to 3.2",
            ),
            (b'F', "backend_startup.c"),
            (b'L', "773"),
            (b'R', "ProcessStartupPacket"),
        ] {
            body.push(code);
            body.extend_from_slice(value.as_bytes());
            body.push(0);
        }
        body.push(0);
        s.write_all(&pg_message(b'E', &body)).await.unwrap();
    })
    .await;
    let info = runner()
        .probe(&PostgresProbe::new(), &target)
        .await
        .unwrap();
    assert_eq!(info.tls, TlsSupport::NotOffered);
    assert_eq!(info.details["postgresql.version_hint"], ">=18");
    assert_eq!(info.findings[0].check_id, "postgresql.tls_not_offered");
}

#[tokio::test]
async fn postgres_auth_probe_trust() {
    let target = serve(|mut s| async move {
        let mut len = [0; 4];
        s.read_exact(&mut len).await.unwrap();
        let rest = read_exact(&mut s, u32::from_be_bytes(len) as usize - 4).await;
        assert!(rest.ends_with(b"user\0postgres\0\0"));
        let mut reply = pg_message(b'R', &0u32.to_be_bytes());
        reply.extend(pg_message(b'S', b"server_version\x0017.2\0"));
        reply.extend(pg_message(b'Z', b"I"));
        s.write_all(&reply).await.unwrap();
        assert_eq!(read_exact(&mut s, 5).await, postgres::TERMINATE);
    })
    .await;
    let info = runner()
        .probe(&PostgresAuthProbe::new(), &target)
        .await
        .unwrap();
    assert_eq!(info.auth, AuthRequirement::NotRequired);
    assert_eq!(info.version.as_deref(), Some("17.2"));
    assert_eq!(info.findings[0].check_id, "postgresql.unauthenticated");
}

#[tokio::test]
async fn auth_probe_refused_by_default() {
    let target = Target::new("127.0.0.1", 9);
    let err = Runner::new(Options::default())
        .probe(&PostgresAuthProbe::new(), &target)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::IntrusiveNotAllowed { .. }));
}

#[tokio::test]
async fn mssql_prelogin() {
    let target = serve(|mut s| async move {
        let header = read_exact(&mut s, 8).await;
        assert_eq!(header[0], 0x12);
        let len = usize::from(u16::from_be_bytes([header[2], header[3]]));
        read_exact(&mut s, len - 8).await;
        let payload = [
            0x00, 0x00, 0x15, 0x00, 0x06, 0x01, 0x00, 0x1b, 0x00, 0x01, 0x02, 0x00, 0x1c, 0x00,
            0x01, 0x03, 0x00, 0x1d, 0x00, 0x00, 0xff, 0x0f, 0x00, 0x11, 0x94, 0x00, 0x00, 0x00,
            0x00,
        ];
        let mut reply = vec![
            0x04,
            0x01,
            0x00,
            u8::try_from(payload.len() + 8).unwrap(),
            0,
            0,
            1,
            0,
        ];
        reply.extend_from_slice(&payload);
        s.write_all(&reply).await.unwrap();
    })
    .await;
    let info = runner().probe(&MssqlProbe::new(), &target).await.unwrap();
    assert_eq!(info.version.as_deref(), Some("15.0.4500"));
    assert_eq!(info.details["mssql.release"], "2019");
    assert_eq!(info.tls, TlsSupport::Optional);
}

#[tokio::test]
async fn silent_server_is_no_response() {
    let target = serve(|s| async move {
        tokio::time::sleep(Duration::from_secs(2)).await;
        drop(s);
    })
    .await;
    let err = runner()
        .probe(&MysqlProbe::new(), &target)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::NoResponse { .. }));
}
