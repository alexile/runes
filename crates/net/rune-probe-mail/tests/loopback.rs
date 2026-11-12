//! The probes through the tokio runner against mock servers on loopback
//! and over an in-memory stream. No traffic leaves the host.

// Test helpers outside `#[test]` functions may unwrap too.
#![allow(clippy::unwrap_used, reason = "test code")]

use std::time::Duration;

use rune_probe_mail::{FtpProbe, SmtpProbe};
use rune_service_probe::{Options, Runner, Target, TlsSupport};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

fn runner() -> Runner {
    Runner::new(
        Options::default()
            .with_connect_timeout(Duration::from_secs(2))
            .with_io_timeout(Duration::from_millis(500))
            .with_total_timeout(Duration::from_secs(5)),
    )
}

/// A line-based server: writes `greeting`, then answers each command line
/// with the reply `script` gives it, and reports every command it got
/// once the client hangs up.
async fn converse<S>(
    stream: S,
    greeting: &'static [u8],
    script: fn(&str) -> &'static [u8],
) -> Vec<String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut stream = BufReader::new(stream);
    stream.write_all(greeting).await.unwrap();
    let mut commands = Vec::new();
    loop {
        let mut line = String::new();
        let read = tokio::time::timeout(Duration::from_secs(2), stream.read_line(&mut line)).await;
        match read {
            Ok(Ok(n)) if n > 0 => {
                stream.write_all(script(line.trim_end())).await.unwrap();
                commands.push(line);
            }
            _ => return commands,
        }
    }
}

async fn serve(
    greeting: &'static [u8],
    script: fn(&str) -> &'static [u8],
) -> (Target, oneshot::Receiver<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let _ = tx.send(converse(stream, greeting, script).await);
    });
    (Target::new("localhost", addr.port()).with_addr(addr), rx)
}

fn smtp_script(command: &str) -> &'static [u8] {
    match command.split(' ').next().unwrap_or_default() {
        "EHLO" => b"250-mock.test\r\n250-STARTTLS\r\n250 AUTH PLAIN\r\n",
        "QUIT" => b"221 bye\r\n",
        _ => b"500 unexpected\r\n",
    }
}

fn ftp_script(command: &str) -> &'static [u8] {
    match command {
        "FEAT" => b"211-Features:\r\n MDTM\r\n211 End\r\n",
        "SYST" => b"215 UNIX Type: L8\r\n",
        "QUIT" => b"221 bye\r\n",
        _ => b"500 unexpected\r\n",
    }
}

#[tokio::test]
async fn smtp_over_tcp() {
    let (target, commands) =
        serve(b"220 mock.test ESMTP Haraka 3.0.3 ready\r\n", smtp_script).await;
    let info = runner().probe(&SmtpProbe::new(), &target).await.unwrap();
    assert_eq!(info.product.as_deref(), Some("Haraka"));
    assert_eq!(info.version.as_deref(), Some("3.0.3"));
    assert_eq!(info.tls, TlsSupport::Optional);
    let checks: Vec<&str> = info.findings.iter().map(|f| f.check_id.as_str()).collect();
    assert_eq!(checks, ["smtp.auth_before_tls"]);
    assert_eq!(
        commands.await.unwrap(),
        ["EHLO probe.invalid\r\n", "QUIT\r\n"]
    );
}

#[tokio::test]
async fn ftp_over_tcp() {
    let (target, commands) = serve(b"220 ProFTPD 1.3.8 Server ready.\r\n", ftp_script).await;
    let info = runner().probe(&FtpProbe::new(), &target).await.unwrap();
    assert_eq!(info.product.as_deref(), Some("ProFTPD"));
    assert_eq!(info.tls, TlsSupport::NotOffered);
    assert_eq!(info.details["ftp.system"], "UNIX Type: L8");
    assert_eq!(
        commands.await.unwrap(),
        ["FEAT\r\n", "SYST\r\n", "QUIT\r\n"]
    );
}

#[tokio::test]
async fn smtps_over_caller_stream() {
    // Stands in for the TLS stream a caller opens for port 465.
    let (mut client, server) = tokio::io::duplex(4096);
    let server = tokio::spawn(converse(server, b"220 mock.test ESMTP\r\n", smtp_script));
    let info = runner()
        .probe_stream(
            &SmtpProbe::smtps(),
            &Target::new("mock.test", 465),
            &mut client,
        )
        .await
        .unwrap();
    assert_eq!(info.service, "smtps");
    assert_eq!(info.tls, TlsSupport::Implicit);
    drop(client);
    assert_eq!(server.await.unwrap().len(), 2);
}
