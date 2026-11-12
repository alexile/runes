//! Mutual-TLS client-certificate extraction for Axum.
//!
//! A TLS server that asks for client certificates hands the peer chain to
//! the application; this crate turns it into a typed, verified identity:
//!
//! - [`ClientCertLayer`] finds the peer chain of each request (a
//!   [`PeerCertificates`] extension, or [`MtlsConnectInfo`] connect info),
//!   validates it with [`rune_x509::verify_chain`] for
//!   [`Purpose::ClientAuth`](rune_x509::Purpose::ClientAuth) against an
//!   [`MtlsConfig`] trust store, and rejects the request (`401` without a
//!   certificate, `403` with a bad one) or stores a [`ClientCert`].
//! - [`ClientCert`] is the extractor: subject, common name, SANs,
//!   fingerprint and the validated chain, from rune-x509's
//!   [`CertSummary`](rune_x509::CertSummary). `Option<ClientCert>` works
//!   on routes where the certificate is optional.
//! - With the `tokio` feature, [`MtlsListener`] is an `axum::serve`
//!   listener that terminates TLS with tokio-rustls (handshakes in the
//!   background, with a timeout) and provides [`MtlsConnectInfo`].
//!
//! The certificate logic is sans-I/O ([`MtlsConfig::verify`]), so any TLS
//! terminator works: insert [`PeerCertificates`] into the request.
//!
//! # Example
//!
//! ```
//! use axum::{Router, body::Body, routing::get};
//! use http::{Request, StatusCode};
//! use rune_axum_mtls::{ClientCert, ClientCertLayer, MtlsConfig, PeerCertificates};
//! use tower::ServiceExt;
//!
//! # let ca_pem = include_bytes!("../tests/fixtures/ca.pem");
//! # let client_pem = include_bytes!("../tests/fixtures/client.pem");
//! async fn whoami(cert: ClientCert) -> String {
//!     cert.common_name().unwrap_or_default().to_owned()
//! }
//!
//! let app = Router::new()
//!     .route("/whoami", get(whoami))
//!     .layer(ClientCertLayer::new(MtlsConfig::from_pem(ca_pem)?));
//!
//! // What the TLS server saw (here: a PEM fixture).
//! let chain = rune_x509::parse_pem(client_pem)?;
//! let peer: PeerCertificates = chain.iter().map(|c| c.der().to_vec()).collect();
//!
//! # tokio::runtime::Builder::new_current_thread().build()?.block_on(async {
//! let mut request = Request::get("/whoami").body(Body::empty())?;
//! request.extensions_mut().insert(peer);
//! let response = app.clone().oneshot(request).await?;
//! assert_eq!(response.status(), StatusCode::OK);
//!
//! // No certificate: 401.
//! let response = app.oneshot(Request::get("/whoami").body(Body::empty())?).await?;
//! assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! # })?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod cert;
mod error;
mod layer;
#[cfg(feature = "tokio")]
mod listener;

use std::net::SocketAddr;

pub use cert::{ClientCert, ClientCertRejection, PeerCertificates};
pub use error::Error;
pub use layer::{ClientCertFuture, ClientCertLayer, ClientCertService, MtlsConfig};
#[cfg(feature = "tokio")]
pub use listener::{ListenerOptions, MtlsListener};
pub use rune_x509;
/// The rustls version [`MtlsListener`] is built on, for building its
/// `ServerConfig`.
#[cfg(feature = "tokio")]
pub use tokio_rustls::rustls;

/// Per-connection information for
/// `Router::into_make_service_with_connect_info::<MtlsConnectInfo>()`:
/// the client's address and the certificate chain it presented.
///
/// [`MtlsListener`] provides it with the `tokio` feature;
/// [`ClientCertLayer`] reads the chain from
/// `ConnectInfo<MtlsConnectInfo>`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MtlsConnectInfo {
    /// The client's socket address.
    pub remote_addr: SocketAddr,
    /// The chain the client presented, leaf first.
    pub peer_certificates: PeerCertificates,
}

impl MtlsConnectInfo {
    /// Builds the connect info.
    #[must_use]
    pub const fn new(remote_addr: SocketAddr, peer_certificates: PeerCertificates) -> Self {
        Self {
            remote_addr,
            peer_certificates,
        }
    }
}
