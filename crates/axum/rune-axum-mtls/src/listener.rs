//! [`MtlsListener`]: an `axum::serve` listener terminating TLS with
//! tokio-rustls.

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use axum::{
    extract::connect_info::Connected,
    serve::{IncomingStream, Listener},
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Semaphore, mpsc},
    task::JoinHandle,
};
use tokio_rustls::{TlsAcceptor, rustls::ServerConfig, server::TlsStream};

use crate::{Error, MtlsConnectInfo, PeerCertificates};

/// Tuning for [`MtlsListener`].
///
/// ```
/// use std::time::Duration;
/// use rune_axum_mtls::ListenerOptions;
///
/// let options = ListenerOptions::default()
///     .handshake_timeout(Duration::from_secs(5))
///     .max_handshakes(256);
/// assert_eq!(options.handshake_timeout, Duration::from_secs(5));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ListenerOptions {
    /// Longest a TLS handshake may take before the connection is dropped.
    /// Default 10 s.
    pub handshake_timeout: Duration,
    /// Most handshakes in progress at once; further TCP connections wait
    /// to start theirs. Default 1024.
    pub max_handshakes: usize,
    /// Completed connections queued for `axum::serve`. Default 64.
    pub backlog: usize,
}

impl Default for ListenerOptions {
    fn default() -> Self {
        Self {
            handshake_timeout: Duration::from_secs(10),
            max_handshakes: 1024,
            backlog: 64,
        }
    }
}

impl ListenerOptions {
    /// Sets [`ListenerOptions::handshake_timeout`].
    #[must_use]
    pub const fn handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    /// Sets [`ListenerOptions::max_handshakes`] (at least 1).
    #[must_use]
    pub const fn max_handshakes(mut self, max: usize) -> Self {
        self.max_handshakes = max;
        self
    }

    /// Sets [`ListenerOptions::backlog`] (at least 1).
    #[must_use]
    pub const fn backlog(mut self, backlog: usize) -> Self {
        self.backlog = backlog;
        self
    }
}

type Accepted = (TlsStream<TcpStream>, SocketAddr);

/// An [`axum::serve()`] [`Listener`] that accepts TCP connections and
/// completes the TLS handshake with a rustls [`ServerConfig`].
///
/// Client authentication is whatever the config's client-certificate
/// verifier says: build it with
/// [`WebPkiClientVerifier`](tokio_rustls::rustls::server::WebPkiClientVerifier)
/// (adding `allow_unauthenticated()` for optional certificates). Serve with
/// [`MtlsConnectInfo`] connect info so [`ClientCertLayer`](crate::ClientCertLayer)
/// can see the peer chain:
///
/// ```no_run
/// use std::sync::Arc;
/// use axum::{Router, routing::get};
/// use rune_axum_mtls::{ClientCert, ClientCertLayer, MtlsConfig, MtlsConnectInfo, MtlsListener};
///
/// # async fn run(tls: Arc<rune_axum_mtls::rustls::ServerConfig>, ca_pem: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
/// let app = Router::new()
///     .route("/me", get(|cert: ClientCert| async move { cert.subject().to_owned() }))
///     .layer(ClientCertLayer::new(MtlsConfig::from_pem(ca_pem)?));
///
/// let tcp = tokio::net::TcpListener::bind("0.0.0.0:8443").await?;
/// let listener = MtlsListener::new(tcp, tls)?;
/// axum::serve(listener, app.into_make_service_with_connect_info::<MtlsConnectInfo>()).await?;
/// # Ok(()) }
/// ```
///
/// Handshakes run in background tasks, concurrently and under
/// [`ListenerOptions::handshake_timeout`], so a slow or silent client
/// cannot stall the accept loop. Failed handshakes are dropped. The tasks
/// stop when the listener is dropped.
#[derive(Debug)]
pub struct MtlsListener {
    local_addr: SocketAddr,
    incoming: mpsc::Receiver<Accepted>,
    acceptor: JoinHandle<()>,
}

impl MtlsListener {
    /// Wraps `tcp` with [`ListenerOptions::default`].
    ///
    /// Must be called inside a Tokio runtime.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] when the local address of `tcp` cannot be read.
    pub fn new(tcp: TcpListener, config: Arc<ServerConfig>) -> Result<Self, Error> {
        Self::with_options(tcp, config, ListenerOptions::default())
    }

    /// Wraps `tcp` with explicit options.
    ///
    /// Must be called inside a Tokio runtime.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] when the local address of `tcp` cannot be read.
    pub fn with_options(
        tcp: TcpListener,
        config: Arc<ServerConfig>,
        options: ListenerOptions,
    ) -> Result<Self, Error> {
        let local_addr = tcp.local_addr()?;
        let (tx, incoming) = mpsc::channel(options.backlog.max(1));
        let acceptor = tokio::spawn(accept_loop(tcp, TlsAcceptor::from(config), tx, options));
        Ok(Self {
            local_addr,
            incoming,
            acceptor,
        })
    }
}

impl Drop for MtlsListener {
    fn drop(&mut self) {
        self.acceptor.abort();
    }
}

async fn accept_loop(
    tcp: TcpListener,
    tls: TlsAcceptor,
    tx: mpsc::Sender<Accepted>,
    options: ListenerOptions,
) {
    let permits = Arc::new(Semaphore::new(options.max_handshakes.max(1)));
    loop {
        let Ok(permit) = Arc::clone(&permits).acquire_owned().await else {
            return;
        };
        let (stream, addr) = match tcp.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                if is_connection_error(&error) {
                    continue;
                }
                // Out of file descriptors and the like: back off, as
                // `axum::serve` does for a plain `TcpListener`.
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        if tx.is_closed() {
            return;
        }
        let tls = tls.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            let handshake = tokio::time::timeout(options.handshake_timeout, tls.accept(stream));
            if let Ok(Ok(stream)) = handshake.await {
                drop(permit);
                // The receiver is gone when the listener was dropped.
                let _ = tx.send((stream, addr)).await;
            }
        });
    }
}

fn is_connection_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
    )
}

impl Listener for MtlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.incoming.recv().await {
            Some(accepted) => accepted,
            // The accept task only ends when the listener is dropped, so
            // this is unreachable; never hand out a connection.
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        Ok(self.local_addr)
    }
}

impl Connected<IncomingStream<'_, MtlsListener>> for MtlsConnectInfo {
    fn connect_info(stream: IncomingStream<'_, MtlsListener>) -> Self {
        Self::new(*stream.remote_addr(), PeerCertificates::from(stream.io()))
    }
}

/// The chain the client presented during the handshake (empty when it sent
/// none).
impl From<&TlsStream<TcpStream>> for PeerCertificates {
    fn from(stream: &TlsStream<TcpStream>) -> Self {
        stream
            .get_ref()
            .1
            .peer_certificates()
            .map(|chain| chain.iter().map(|cert| cert.as_ref().to_vec()).collect())
            .unwrap_or_default()
    }
}
