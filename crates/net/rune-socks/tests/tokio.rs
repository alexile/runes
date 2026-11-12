//! Client and server over loopback sockets only: test connectors map host
//! names to local listeners, so nothing touches DNS or the network.

#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use rune_socks::tokio::{Client, Connector, Server, TcpConnector};
use rune_socks::v4::Socks4Status;
use rune_socks::v5::{Credentials, ReplyCode, UdpHeader};
use rune_socks::{Error, TargetAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// Resolves `echo.test` to the echo server and refuses `denied.test`.
#[derive(Clone)]
struct TestConnector {
    echo: SocketAddr,
}

impl TestConnector {
    fn map(&self, target: &TargetAddr) -> io::Result<SocketAddr> {
        match target {
            TargetAddr::Ip(addr) => Ok(*addr),
            TargetAddr::Domain(host, _) if host == "echo.test" => Ok(self.echo),
            TargetAddr::Domain(host, _) if host == "denied.test" => {
                Err(io::Error::from(io::ErrorKind::PermissionDenied))
            }
            _ => Err(io::Error::from(io::ErrorKind::NotFound)),
        }
    }
}

impl Connector for TestConnector {
    type Stream = TcpStream;

    async fn connect(&self, target: &TargetAddr) -> io::Result<(TcpStream, SocketAddr)> {
        let stream = TcpStream::connect(self.map(target)?).await?;
        let local = stream.local_addr()?;
        Ok((stream, local))
    }

    fn resolve_udp(
        &self,
        target: &TargetAddr,
    ) -> impl Future<Output = io::Result<SocketAddr>> + Send {
        std::future::ready(self.map(target))
    }
}

async fn echo_server() -> SocketAddr {
    let listener = TcpListener::bind((LOOPBACK, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = stream.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    addr
}

async fn proxy<C: Connector + 'static>(server: Server<C>) -> SocketAddr {
    let listener = TcpListener::bind((LOOPBACK, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = Arc::new(server);
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let server = Arc::clone(&server);
            tokio::spawn(async move {
                let _ = server.serve_tcp(stream).await;
            });
        }
    });
    addr
}

async fn round_trip(stream: &mut TcpStream) {
    stream.write_all(b"ping").await.unwrap();
    let mut buf = [0; 4];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");
}

#[tokio::test]
async fn v5_connect_by_ip_through_tcp_connector() {
    let echo = echo_server().await;
    let proxy = proxy(Server::new(TcpConnector)).await;
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    let bound = Client::v5()
        .connect(&mut stream, &echo.into())
        .await
        .unwrap();
    assert_eq!(bound.ip().map(|a| a.ip()), Some(LOOPBACK));
    round_trip(&mut stream).await;
}

#[tokio::test]
async fn v5_connect_by_name_with_credentials() {
    let echo = echo_server().await;
    let server = Server::new(TestConnector { echo })
        .with_authenticator(|c: &Credentials| c.username == b"alice" && c.password == b"pw");
    let proxy = proxy(server).await;

    let client = Client::v5().with_credentials(Credentials::new("alice", "pw"));
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    client
        .connect(&mut stream, &TargetAddr::domain("echo.test", 7))
        .await
        .unwrap();
    round_trip(&mut stream).await;

    let wrong = Client::v5().with_credentials(Credentials::new("alice", "nope"));
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    let err = wrong
        .connect(&mut stream, &TargetAddr::domain("echo.test", 7))
        .await
        .unwrap_err();
    assert!(matches!(err, Error::AuthFailed), "{err:?}");

    let anonymous = Client::v5();
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    let err = anonymous
        .connect(&mut stream, &echo.into())
        .await
        .unwrap_err();
    assert!(matches!(err, Error::NoAcceptableMethod), "{err:?}");

    // SOCKS4 has no passwords, so an authenticating server refuses it.
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    let err = Client::v4()
        .connect(&mut stream, &echo.into())
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::Socks4Rejected(Socks4Status::Rejected)),
        "{err:?}"
    );
}

#[tokio::test]
async fn v5_refusals_carry_reply_codes() {
    let echo = echo_server().await;
    let proxy = proxy(Server::new(TestConnector { echo })).await;
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    let err = Client::v5()
        .connect(&mut stream, &TargetAddr::domain("denied.test", 1))
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::Rejected(ReplyCode::NotAllowed)),
        "{err:?}"
    );

    // UDP ASSOCIATE is off by default.
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    let err = Client::v5()
        .udp_associate(&mut stream, &TargetAddr::unspecified())
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::Rejected(ReplyCode::CommandNotSupported)),
        "{err:?}"
    );

    // A closed loopback port is refused.
    let closed = TcpListener::bind((LOOPBACK, 0))
        .await
        .unwrap()
        .local_addr()
        .unwrap();
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    let err = Client::v5()
        .connect(&mut stream, &closed.into())
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::Rejected(ReplyCode::ConnectionRefused)),
        "{err:?}"
    );
}

#[tokio::test]
async fn v4_and_v4a_connect() {
    let echo = echo_server().await;
    let proxy = proxy(Server::new(TestConnector { echo })).await;

    let mut stream = TcpStream::connect(proxy).await.unwrap();
    let bound = Client::v4()
        .with_user_id("fred")
        .connect(&mut stream, &echo.into())
        .await
        .unwrap();
    assert!(bound.ip().is_some());
    round_trip(&mut stream).await;

    let mut stream = TcpStream::connect(proxy).await.unwrap();
    Client::v4()
        .connect(&mut stream, &TargetAddr::domain("echo.test", 7))
        .await
        .unwrap();
    round_trip(&mut stream).await;

    let disabled = self::proxy(Server::new(TestConnector { echo }).with_socks4(false)).await;
    let mut stream = TcpStream::connect(disabled).await.unwrap();
    let err = Client::v4()
        .connect(&mut stream, &echo.into())
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Socks4Rejected(_)), "{err:?}");
}

#[tokio::test]
async fn v5_udp_associate_relays_datagrams() {
    let udp_echo = UdpSocket::bind((LOOPBACK, 0)).await.unwrap();
    let echo_addr = udp_echo.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0; 1500];
        loop {
            let (n, from) = udp_echo.recv_from(&mut buf).await.unwrap();
            udp_echo.send_to(&buf[..n], from).await.unwrap();
        }
    });
    let server = Server::new(TestConnector { echo: echo_addr }).with_udp_relay(LOOPBACK);
    let proxy = proxy(server).await;

    let mut control = TcpStream::connect(proxy).await.unwrap();
    let local = UdpSocket::bind((LOOPBACK, 0)).await.unwrap();
    let relay = Client::v5()
        .udp_associate(&mut control, &local.local_addr().unwrap().into())
        .await
        .unwrap();
    let relay = relay.ip().unwrap();

    for target in [
        TargetAddr::Ip(echo_addr),
        TargetAddr::domain("echo.test", 9),
    ] {
        let datagram = UdpHeader::new(target)
            .encode_datagram(b"hello udp")
            .unwrap();
        local.send_to(&datagram, relay).await.unwrap();
        let mut buf = [0; 1500];
        let (n, from) = local.recv_from(&mut buf).await.unwrap();
        assert_eq!(from, relay);
        let (header, payload) = UdpHeader::decode_datagram(&buf[..n]).unwrap();
        assert_eq!(header.target, TargetAddr::Ip(echo_addr));
        assert_eq!(payload, b"hello udp");
    }
}

#[tokio::test]
async fn client_reports_gssapi_selection_as_unsupported() {
    let (mut client_side, mut server_side) = tokio::io::duplex(64);
    let fake = tokio::spawn(async move {
        let mut greeting = [0; 3];
        server_side.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 1, 0]);
        server_side.write_all(&[5, 1]).await.unwrap();
    });
    let err = Client::v5()
        .connect(&mut client_side, &TargetAddr::domain("x", 1))
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        Error::UnsupportedMethod(rune_socks::v5::AuthMethod::Gssapi)
    ));
    fake.await.unwrap();
}

#[tokio::test]
async fn server_rejects_unknown_versions_and_commands() {
    let server = Server::new(TcpConnector);
    let (mut a, b) = tokio::io::duplex(64);
    a.write_all(&[0x47]).await.unwrap();
    assert!(matches!(server.serve(b).await, Err(Error::Version(0x47))));

    let (mut a, b) = tokio::io::duplex(64);
    a.write_all(&[5, 1, 0, 5, 9, 0]).await.unwrap();
    let result = server.serve(b).await;
    assert!(matches!(result, Err(Error::Command(9))));
    let mut reply = [0; 12];
    a.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply[..4], [5, 0, 5, 7]);
}
