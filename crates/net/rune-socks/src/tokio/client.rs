//! The SOCKS client: dial through a proxy.

use std::net::SocketAddr;

use ::tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use super::read_message;
use crate::v4::{Socks4Reply, Socks4Request, Socks4Status};
use crate::v5::{
    AuthMethod, AuthReply, Command, Credentials, Greeting, MethodSelection, Reply, ReplyCode,
    Request,
};
use crate::{Error, TargetAddr};

/// The protocol a [`Client`] speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ClientVersion {
    /// SOCKS4, or SOCKS 4a for host name targets.
    V4,
    /// SOCKS5.
    V5,
}

/// A SOCKS client handshake configuration.
///
/// The client runs the handshake over a stream the caller has already
/// connected to the proxy, so it works over any transport (TCP, TLS, a
/// chained proxy).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Client {
    /// The protocol version.
    pub version: ClientVersion,
    /// SOCKS5 username/password, offered alongside "no authentication".
    pub credentials: Option<Credentials>,
    /// SOCKS4 user id.
    pub user_id: Vec<u8>,
}

impl Default for Client {
    fn default() -> Self {
        Self::v5()
    }
}

impl Client {
    /// A SOCKS5 client without credentials.
    #[must_use]
    pub const fn v5() -> Self {
        Self {
            version: ClientVersion::V5,
            credentials: None,
            user_id: Vec::new(),
        }
    }

    /// A SOCKS4/4a client with an empty user id.
    #[must_use]
    pub const fn v4() -> Self {
        Self {
            version: ClientVersion::V4,
            credentials: None,
            user_id: Vec::new(),
        }
    }

    /// Sets SOCKS5 username/password credentials.
    #[must_use]
    pub fn with_credentials(mut self, credentials: Credentials) -> Self {
        self.credentials = Some(credentials);
        self
    }

    /// Sets the SOCKS4 user id.
    #[must_use]
    pub fn with_user_id(mut self, user_id: impl Into<Vec<u8>>) -> Self {
        self.user_id = user_id.into();
        self
    }

    /// Asks the proxy to connect to `target`. On success the stream is the
    /// tunnel, and the proxy's bound address is returned.
    ///
    /// # Errors
    ///
    /// [`Error::Rejected`] / [`Error::Socks4Rejected`] when the proxy refuses,
    /// the authentication errors, codec errors and [`Error::Io`].
    pub async fn connect<S>(&self, stream: &mut S, target: &TargetAddr) -> Result<TargetAddr, Error>
    where
        S: AsyncRead + AsyncWrite + Unpin + ?Sized,
    {
        match self.version {
            ClientVersion::V4 => {
                let request =
                    Socks4Request::connect(target.clone()).with_user_id(self.user_id.clone());
                stream.write_all(&request.encode()?).await?;
                let reply = read_message(stream, Vec::new(), Socks4Reply::decode).await?;
                if reply.status != Socks4Status::Granted {
                    return Err(Error::Socks4Rejected(reply.status));
                }
                Ok(TargetAddr::Ip(SocketAddr::V4(reply.address)))
            }
            ClientVersion::V5 => {
                self.request_v5(stream, Request::new(Command::Connect, target.clone()))
                    .await
            }
        }
    }

    /// Sets up a SOCKS5 UDP association and returns the relay address to
    /// send [`UdpHeader`](crate::v5::UdpHeader)-framed datagrams to. `from`
    /// is the address the client will send from, or
    /// [`TargetAddr::unspecified`]. The association lasts as long as
    /// `stream` stays open.
    ///
    /// # Errors
    ///
    /// [`Error::NotRepresentable`] for a SOCKS4 client, otherwise as
    /// [`Client::connect`].
    pub async fn udp_associate<S>(
        &self,
        stream: &mut S,
        from: &TargetAddr,
    ) -> Result<TargetAddr, Error>
    where
        S: AsyncRead + AsyncWrite + Unpin + ?Sized,
    {
        if self.version != ClientVersion::V5 {
            return Err(Error::NotRepresentable("UDP ASSOCIATE needs SOCKS5"));
        }
        self.request_v5(stream, Request::new(Command::UdpAssociate, from.clone()))
            .await
    }

    async fn request_v5<S>(&self, stream: &mut S, request: Request) -> Result<TargetAddr, Error>
    where
        S: AsyncRead + AsyncWrite + Unpin + ?Sized,
    {
        let methods: &[AuthMethod] = if self.credentials.is_some() {
            &[AuthMethod::UsernamePassword, AuthMethod::NoAuth]
        } else {
            &[AuthMethod::NoAuth]
        };
        stream.write_all(&Greeting::new(methods).encode()?).await?;
        let selection = read_message(stream, Vec::new(), MethodSelection::decode).await?;
        match (selection.method, &self.credentials) {
            (AuthMethod::NoAuth, _) => {}
            (AuthMethod::UsernamePassword, Some(credentials)) => {
                stream.write_all(&credentials.encode()?).await?;
                let reply = read_message(stream, Vec::new(), AuthReply::decode).await?;
                if !reply.is_success() {
                    return Err(Error::AuthFailed);
                }
            }
            (AuthMethod::NoAcceptable, _) => return Err(Error::NoAcceptableMethod),
            (other, _) => return Err(Error::UnsupportedMethod(other)),
        }
        stream.write_all(&request.encode()?).await?;
        let reply = read_message(stream, Vec::new(), Reply::decode).await?;
        if reply.code != ReplyCode::Succeeded {
            return Err(Error::Rejected(reply.code));
        }
        Ok(reply.bound)
    }
}
