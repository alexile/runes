//! The SOCKS server: accept a handshake and forward through a pluggable
//! connector.

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use ::tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use ::tokio::net::{TcpStream, UdpSocket};

use super::read_message;
use crate::v4::{Socks4Command, Socks4Reply, Socks4Request, Socks4Status};
use crate::v5::{
    AuthMethod, AuthReply, Command, Credentials, Greeting, MethodSelection, Reply, ReplyCode,
    Request, UdpHeader,
};
use crate::{Error, TargetAddr};

/// Opens outbound connections for the server.
///
/// Implement it to add allowlists, DNS pinning, chaining or test doubles;
/// return an error of
/// kind [`io::ErrorKind::PermissionDenied`] to refuse a target with "not
/// allowed by ruleset".
pub trait Connector: Send + Sync {
    /// The outbound stream type.
    type Stream: AsyncRead + AsyncWrite + Unpin + Send;

    /// Connects to `target`, returning the stream and its local address
    /// (reported to the client as the bound address).
    fn connect(
        &self,
        target: &TargetAddr,
    ) -> impl Future<Output = io::Result<(Self::Stream, SocketAddr)>> + Send;

    /// Resolves the destination of a relayed UDP datagram. The default
    /// passes IP addresses through and resolves host names with the system
    /// resolver. Return an error to drop the datagram.
    fn resolve_udp(
        &self,
        target: &TargetAddr,
    ) -> impl Future<Output = io::Result<SocketAddr>> + Send {
        let target = target.clone();
        async move { resolve(&target).await }
    }
}

async fn resolve(target: &TargetAddr) -> io::Result<SocketAddr> {
    match target {
        TargetAddr::Ip(addr) => Ok(*addr),
        TargetAddr::Domain(host, port) => ::tokio::net::lookup_host((host.as_str(), *port))
            .await?
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "host name has no address")),
    }
}

/// A [`Connector`] that opens plain TCP connections, resolving host names
/// with the system resolver. It applies no policy: put it behind an
/// allowlisting connector before exposing a server beyond loopback.
#[derive(Debug, Clone, Copy, Default)]
pub struct TcpConnector;

impl Connector for TcpConnector {
    type Stream = TcpStream;

    async fn connect(&self, target: &TargetAddr) -> io::Result<(TcpStream, SocketAddr)> {
        let stream = match target {
            TargetAddr::Ip(addr) => TcpStream::connect(addr).await?,
            TargetAddr::Domain(host, port) => TcpStream::connect((host.as_str(), *port)).await?,
        };
        let local = stream.local_addr()?;
        Ok((stream, local))
    }
}

/// Checks SOCKS5 username/password credentials.
pub trait Authenticator: Send + Sync {
    /// Whether `credentials` are valid.
    fn authenticate(&self, credentials: &Credentials) -> bool;
}

impl<F> Authenticator for F
where
    F: Fn(&Credentials) -> bool + Send + Sync,
{
    fn authenticate(&self, credentials: &Credentials) -> bool {
        self(credentials)
    }
}

/// A SOCKS4/4a/5 server.
///
/// It handles `CONNECT` (SOCKS4 and 5) and `UDP ASSOCIATE` (SOCKS5, when a
/// relay address is configured), and refuses `BIND`. With an
/// [`Authenticator`], SOCKS5 clients must authenticate with
/// username/password and SOCKS4 (which has no passwords) is refused.
#[non_exhaustive]
pub struct Server<C> {
    connector: C,
    authenticator: Option<Arc<dyn Authenticator>>,
    allow_socks4: bool,
    udp_relay_ip: Option<IpAddr>,
}

impl<C: Connector> Server<C> {
    /// A server that accepts SOCKS4 and SOCKS5 without authentication and
    /// has UDP relaying disabled.
    #[must_use]
    pub const fn new(connector: C) -> Self {
        Self {
            connector,
            authenticator: None,
            allow_socks4: true,
            udp_relay_ip: None,
        }
    }

    /// Requires SOCKS5 username/password authentication.
    #[must_use]
    pub fn with_authenticator(mut self, authenticator: impl Authenticator + 'static) -> Self {
        self.authenticator = Some(Arc::new(authenticator));
        self
    }

    /// Accepts (`true`, the default) or refuses SOCKS4/4a clients.
    #[must_use]
    pub const fn with_socks4(mut self, allow: bool) -> Self {
        self.allow_socks4 = allow;
        self
    }

    /// Enables `UDP ASSOCIATE`, binding relay sockets on `ip`.
    #[must_use]
    pub const fn with_udp_relay(mut self, ip: IpAddr) -> Self {
        self.udp_relay_ip = Some(ip);
        self
    }

    /// Serves one TCP client. UDP associations only accept datagrams from
    /// the client's IP address.
    ///
    /// # Errors
    ///
    /// As [`Server::serve`].
    pub async fn serve_tcp(&self, client: TcpStream) -> Result<(), Error> {
        let peer = client.peer_addr()?.ip();
        self.serve_inner(client, Some(peer)).await
    }

    /// Serves one client over any stream: runs the handshake, connects
    /// through the [`Connector`] and relays until either side closes.
    ///
    /// Refusals the client is told about (bad credentials, a refused
    /// target, an unsupported command) return `Ok(())`.
    ///
    /// # Errors
    ///
    /// Malformed client messages and [`Error::Io`].
    pub async fn serve<S>(&self, client: S) -> Result<(), Error>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        self.serve_inner(client, None).await
    }

    async fn serve_inner<S>(&self, mut client: S, peer: Option<IpAddr>) -> Result<(), Error>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let version = client.read_u8().await?;
        match version {
            crate::v4::VERSION => self.serve_v4(client).await,
            crate::v5::VERSION => self.serve_v5(client, peer).await,
            other => Err(Error::Version(other)),
        }
    }

    async fn serve_v4<S>(&self, mut client: S) -> Result<(), Error>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let request =
            read_message(&mut client, vec![crate::v4::VERSION], Socks4Request::decode).await?;
        let refuse = Socks4Reply::new(
            Socks4Status::Rejected,
            std::net::SocketAddrV4::new(0.into(), 0),
        );
        if !self.allow_socks4
            || self.authenticator.is_some()
            || request.command != Socks4Command::Connect
        {
            client.write_all(&refuse.encode()).await?;
            return Ok(());
        }
        let Ok((mut upstream, bound)) = self.connector.connect(&request.target).await else {
            client.write_all(&refuse.encode()).await?;
            return Ok(());
        };
        let bound = match bound {
            SocketAddr::V4(addr) => addr,
            SocketAddr::V6(_) => std::net::SocketAddrV4::new(0.into(), 0),
        };
        client
            .write_all(&Socks4Reply::new(Socks4Status::Granted, bound).encode())
            .await?;
        ::tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
        Ok(())
    }

    async fn serve_v5<S>(&self, mut client: S, peer: Option<IpAddr>) -> Result<(), Error>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let greeting =
            read_message(&mut client, vec![crate::v5::VERSION], Greeting::decode).await?;
        let supported = if self.authenticator.is_some() {
            [AuthMethod::UsernamePassword]
        } else {
            [AuthMethod::NoAuth]
        };
        let method = greeting.select(&supported);
        client
            .write_all(&MethodSelection::new(method).encode())
            .await?;
        match (method, &self.authenticator) {
            (AuthMethod::UsernamePassword, Some(authenticator)) => {
                let credentials =
                    read_message(&mut client, Vec::new(), Credentials::decode).await?;
                let ok = authenticator.authenticate(&credentials);
                client.write_all(&AuthReply::new(ok).encode()).await?;
                if !ok {
                    return Ok(());
                }
            }
            (AuthMethod::NoAuth, _) => {}
            _ => return Ok(()),
        }

        let request = match read_message(&mut client, Vec::new(), Request::decode).await {
            Ok(request) => request,
            Err(err @ (Error::Command(_) | Error::AddressType(_))) => {
                let code = if matches!(err, Error::Command(_)) {
                    ReplyCode::CommandNotSupported
                } else {
                    ReplyCode::AddressTypeNotSupported
                };
                client.write_all(&Reply::failure(code).encode()?).await?;
                return Err(err);
            }
            Err(err) => return Err(err),
        };
        match (request.command, self.udp_relay_ip) {
            (Command::Connect, _) => self.connect_v5(client, &request.target).await,
            (Command::UdpAssociate, Some(ip)) => {
                self.udp_relay(client, ip, peer, &request.target).await
            }
            _ => {
                let reply = Reply::failure(ReplyCode::CommandNotSupported);
                client.write_all(&reply.encode()?).await?;
                Ok(())
            }
        }
    }

    async fn connect_v5<S>(&self, mut client: S, target: &TargetAddr) -> Result<(), Error>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        match self.connector.connect(target).await {
            Ok((mut upstream, bound)) => {
                let reply = Reply::new(ReplyCode::Succeeded, bound.into());
                client.write_all(&reply.encode()?).await?;
                ::tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
            }
            Err(err) => {
                let reply = Reply::failure(ReplyCode::from_io_error(&err));
                client.write_all(&reply.encode()?).await?;
            }
        }
        Ok(())
    }

    async fn udp_relay<S>(
        &self,
        mut client: S,
        ip: IpAddr,
        peer: Option<IpAddr>,
        declared: &TargetAddr,
    ) -> Result<(), Error>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let socket = UdpSocket::bind(SocketAddr::new(ip, 0)).await?;
        let reply = Reply::new(ReplyCode::Succeeded, socket.local_addr()?.into());
        client.write_all(&reply.encode()?).await?;
        let mut association = Association {
            peer,
            declared,
            client: None,
        };
        let mut buf = vec![0; 65_535];
        let mut control = [0; 64];
        loop {
            ::tokio::select! {
                read = client.read(&mut control) => {
                    // The association ends with the control connection.
                    if matches!(read, Ok(0) | Err(_)) {
                        return Ok(());
                    }
                }
                received = socket.recv_from(&mut buf) => {
                    let (n, from) = received?;
                    self.relay_datagram(&socket, &buf[..n], from, &mut association).await;
                }
            }
        }
    }

    async fn relay_datagram(
        &self,
        socket: &UdpSocket,
        data: &[u8],
        from: SocketAddr,
        association: &mut Association<'_>,
    ) {
        if association.is_client(from) {
            let Ok((header, payload)) = UdpHeader::decode_datagram(data) else {
                return;
            };
            // Fragment reassembly is optional (RFC 1928 §7); drop fragments.
            if header.frag != 0 {
                return;
            }
            let Ok(destination) = self.connector.resolve_udp(&header.target).await else {
                return;
            };
            association.client = Some(from);
            let _ = socket.send_to(payload, destination).await;
        } else if let Some(client) = association.client {
            let Ok(datagram) = UdpHeader::new(from.into()).encode_datagram(data) else {
                return;
            };
            let _ = socket.send_to(&datagram, client).await;
        }
    }
}

/// State of one UDP association.
struct Association<'a> {
    /// IP of the control connection's client, when known.
    peer: Option<IpAddr>,
    /// The address the client said it would send from.
    declared: &'a TargetAddr,
    /// The client's UDP address, once it has sent a datagram.
    client: Option<SocketAddr>,
}

impl Association<'_> {
    fn is_client(&self, from: SocketAddr) -> bool {
        if let Some(client) = self.client {
            return from == client;
        }
        if self.peer.is_some_and(|peer| peer != from.ip()) {
            return false;
        }
        match self.declared {
            TargetAddr::Ip(addr) => {
                (addr.ip().is_unspecified() || addr.ip() == from.ip())
                    && (addr.port() == 0 || addr.port() == from.port())
            }
            TargetAddr::Domain(..) => true,
        }
    }
}
