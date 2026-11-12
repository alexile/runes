//! One query/response exchange per transport.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use rune_dns_wire::{MAX_MESSAGE_LEN, Message};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::{Error, check_response};

/// Sends `query` over UDP and waits for the matching answer. Datagrams that
/// do not decode or do not match the query (wrong id or question, as a
/// spoofer would send) are ignored. A truncated answer is retried over TCP.
pub async fn udp(addr: SocketAddr, query: &Message) -> Result<Message, Error> {
    let local: SocketAddr = if addr.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let socket = UdpSocket::bind(local).await?;
    // Connected: the kernel drops datagrams from other addresses.
    socket.connect(addr).await?;
    socket.send(&query.encode()?).await?;
    let mut buffer = vec![0; MAX_MESSAGE_LEN];
    loop {
        let len = socket.recv(&mut buffer).await?;
        let Some(response) = buffer
            .get(..len)
            .and_then(|bytes| Message::decode(bytes).ok())
        else {
            continue;
        };
        if check_response(query, &response).is_err() {
            continue;
        }
        if response.header.truncated {
            return tcp(addr, query).await;
        }
        return Ok(response);
    }
}

/// Sends `query` over a new TCP connection.
pub async fn tcp(addr: SocketAddr, query: &Message) -> Result<Message, Error> {
    let mut stream = TcpStream::connect(addr).await?;
    stream.set_nodelay(true)?;
    stream_exchange(&mut stream, query).await
}

/// Writes `query` with its two-octet length (RFC 1035 §4.2.2, RFC 7766)
/// and reads one answer.
pub async fn stream_exchange<S>(stream: &mut S, query: &Message) -> Result<Message, Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let bytes = query.encode()?;
    let len = u16::try_from(bytes.len()).map_err(|_| rune_dns_wire::Error::MessageTooLong {
        len: bytes.len(),
        max: MAX_MESSAGE_LEN,
    })?;
    let mut frame = Vec::with_capacity(bytes.len() + 2);
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&bytes);
    stream.write_all(&frame).await?;
    stream.flush().await?;

    let mut prefix = [0; 2];
    stream.read_exact(&mut prefix).await?;
    let mut body = vec![0; usize::from(u16::from_be_bytes(prefix))];
    stream.read_exact(&mut body).await?;
    let response = Message::decode(&body)?;
    check_response(query, &response)?;
    if response.header.truncated {
        return Err(Error::Truncated);
    }
    Ok(response)
}

#[cfg(feature = "tls")]
pub mod tls {
    //! DNS over TLS (RFC 7858).

    use std::net::SocketAddr;
    use std::sync::Arc;

    use rune_dns_wire::Message;
    use tokio::net::TcpStream;
    use tokio_rustls::TlsConnector;
    use tokio_rustls::rustls::ClientConfig;
    use tokio_rustls::rustls::pki_types::ServerName;

    use super::stream_exchange;
    use crate::Error;

    /// The validated name a certificate must match.
    pub fn server_name(name: &str) -> Result<ServerName<'static>, Error> {
        ServerName::try_from(name.to_owned()).map_err(|_| Error::InvalidUpstream {
            reason: "invalid TLS server name",
        })
    }

    /// The default client configuration: webpki roots and the ring
    /// provider, chosen explicitly so that another rustls provider elsewhere
    /// in the build cannot make the choice ambiguous.
    pub fn default_config() -> Result<ClientConfig, Error> {
        let roots = tokio_rustls::rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        Ok(ClientConfig::builder_with_provider(Arc::new(
            tokio_rustls::rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|error| Error::Tls(error.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth())
    }

    /// `config` with ALPN set to `protocols`.
    pub fn with_alpn(config: &ClientConfig, protocols: &[&[u8]]) -> Arc<ClientConfig> {
        let mut config = config.clone();
        config.alpn_protocols = protocols.iter().map(|p| p.to_vec()).collect();
        Arc::new(config)
    }

    /// Sends `query` over a new TLS connection to `addr`.
    pub async fn exchange(
        config: Arc<ClientConfig>,
        addr: SocketAddr,
        name: &str,
        query: &Message,
    ) -> Result<Message, Error> {
        let name = server_name(name)?;
        let tcp = TcpStream::connect(addr).await?;
        tcp.set_nodelay(true)?;
        let mut stream = TlsConnector::from(config)
            .connect(name, tcp)
            .await
            .map_err(|error| Error::Tls(error.to_string()))?;
        stream_exchange(&mut stream, query).await
    }
}

#[cfg(feature = "doh")]
pub mod doh {
    //! DNS over HTTPS (RFC 8484), `POST` with `application/dns-message`.

    use std::net::SocketAddr;
    use std::sync::Arc;

    use bytes::Bytes;
    use http::header::{ACCEPT, CONTENT_TYPE, HOST};
    use http::{Method, Request, StatusCode};
    use http_body_util::{BodyExt, Full, Limited};
    use hyper::rt::{Read, Write};
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use rune_dns_wire::{MAX_MESSAGE_LEN, Message};
    use tokio::net::TcpStream;
    use tokio_rustls::TlsConnector;
    use tokio_rustls::rustls::ClientConfig;

    use super::tls::server_name;
    use crate::{DohEndpoint, Error, check_response};

    const DNS_MESSAGE: &str = "application/dns-message";

    fn http_error(error: impl core::fmt::Display) -> Error {
        Error::Http(error.to_string())
    }

    /// Sends `query` to `endpoint`, over HTTP/2 when the server offers it
    /// in ALPN and HTTP/1.1 otherwise.
    pub async fn exchange(
        config: Arc<ClientConfig>,
        endpoint: &DohEndpoint,
        query: &Message,
    ) -> Result<Message, Error> {
        let addr = match endpoint.addr() {
            Some(addr) => addr,
            None => resolve(endpoint).await?,
        };
        let tcp = TcpStream::connect(addr).await?;
        tcp.set_nodelay(true)?;
        let body = Bytes::from(query.encode()?);
        let response = if endpoint.is_tls() {
            let name = server_name(endpoint.host())?;
            let stream = TlsConnector::from(config)
                .connect(name, tcp)
                .await
                .map_err(|error| Error::Tls(error.to_string()))?;
            let h2 = stream.get_ref().1.alpn_protocol() == Some(b"h2");
            send(TokioIo::new(stream), h2, endpoint, body).await?
        } else {
            send(TokioIo::new(tcp), false, endpoint, body).await?
        };
        let response = Message::decode(&response)?;
        check_response(query, &response)?;
        if response.header.truncated {
            return Err(Error::Truncated);
        }
        Ok(response)
    }

    /// Looks the endpoint's host up with the system resolver (the
    /// bootstrap problem: set [`DohEndpoint::with_addr`] to avoid it).
    async fn resolve(endpoint: &DohEndpoint) -> Result<SocketAddr, Error> {
        tokio::net::lookup_host((endpoint.host(), endpoint.port()))
            .await?
            .next()
            .ok_or(Error::InvalidUpstream {
                reason: "DoH host did not resolve",
            })
    }

    async fn send<IO>(io: IO, h2: bool, endpoint: &DohEndpoint, body: Bytes) -> Result<Bytes, Error>
    where
        IO: Read + Write + Unpin + Send + 'static,
    {
        let request = Request::builder()
            .method(Method::POST)
            .header(CONTENT_TYPE, DNS_MESSAGE)
            .header(ACCEPT, DNS_MESSAGE);
        let response = if h2 {
            let request = request
                .uri(endpoint.url())
                .body(Full::new(body))
                .map_err(http_error)?;
            let (mut sender, connection) =
                hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
                    .await
                    .map_err(http_error)?;
            tokio::spawn(connection);
            sender.send_request(request).await.map_err(http_error)?
        } else {
            let request = request
                .uri(endpoint.path())
                .header(HOST, endpoint.authority())
                .body(Full::new(body))
                .map_err(http_error)?;
            let (mut sender, connection) = hyper::client::conn::http1::handshake(io)
                .await
                .map_err(http_error)?;
            tokio::spawn(connection);
            sender.send_request(request).await.map_err(http_error)?
        };
        if response.status() != StatusCode::OK {
            return Err(Error::HttpStatus(response.status().as_u16()));
        }
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        let essence = content_type.split(';').next().unwrap_or_default().trim();
        if !essence.eq_ignore_ascii_case(DNS_MESSAGE) {
            return Err(Error::Http(format!(
                "unexpected content type {content_type:?}"
            )));
        }
        Limited::new(response.into_body(), MAX_MESSAGE_LEN)
            .collect()
            .await
            .map(http_body_util::Collected::to_bytes)
            .map_err(|error| Error::Http(error.to_string()))
    }
}
