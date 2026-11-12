# rune-axum-mtls

> Mutual-TLS client-certificate extraction for Axum: rustls listener, rune-x509 clientAuth verification, typed extractor.

[![crates.io](https://img.shields.io/crates/v/rune-axum-mtls)](https://crates.io/crates/rune-axum-mtls)
[![docs.rs](https://img.shields.io/docsrs/rune-axum-mtls)](https://docs.rs/rune-axum-mtls)
[![license](https://img.shields.io/crates/l/rune-axum-mtls)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

Turns the certificate a TLS client presented into a typed, verified
identity for Axum handlers.

- **`ClientCertLayer`** finds the peer chain of each request, validates it
  with [`rune-x509`](../../net/rune-x509) (`verify_chain`, always for
  `Purpose::ClientAuth`, with its weak-crypto policy) against your CA
  bundle, and answers `401` without a certificate or `403` with an
  untrusted, expired, wrong-purpose or malformed one. The rejection reason
  is stored in the response extensions for logging, never sent.
- **`ClientCert`** is the extractor: subject, common name, DNS / e-mail /
  URI SANs, SHA-256 fingerprint, the validated chain and the full
  `ChainReport`. Use `Option<ClientCert>` where the certificate is optional
  (`MtlsConfig::optional()`).
- **`MtlsListener`** (feature `tokio`) is an `axum::serve` listener that
  terminates TLS with tokio-rustls. Handshakes run in background tasks
  with a timeout and a concurrency cap, so a silent client cannot stall
  the accept loop. It provides `MtlsConnectInfo` (remote address + peer
  chain) as connect info.

Behind another TLS terminator, insert `PeerCertificates` (DER, leaf first)
into the request yourself; `MtlsConfig::verify` is the same decision
without tower.

## Installation

```toml
[dependencies]
rune-axum-mtls = { version = "0.1", features = ["tokio"] }
```

or `cargo add rune-axum-mtls --features tokio`. Without `tokio` you get
the layer and extractor only.

No rustls crypto provider is enabled by this crate: enable `ring` or
`aws-lc-rs` on `tokio-rustls`/`rustls` in your application and build the
`ServerConfig` with it.

## Usage

```rust,no_run
use std::sync::Arc;

use axum::{Router, routing::get};
use rune_axum_mtls::{
    ClientCert, ClientCertLayer, MtlsConfig, MtlsConnectInfo, MtlsListener,
    rustls::{
        RootCertStore, ServerConfig,
        pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
        server::WebPkiClientVerifier,
    },
};

async fn whoami(cert: ClientCert) -> String {
    format!(
        "{} [{}]",
        cert.common_name().unwrap_or("?"),
        cert.dns_names().collect::<Vec<_>>().join(", ")
    )
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ca_pem = std::fs::read("ca.pem")?;

    // TLS: require a client certificate issued by the CA.
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(&ca_pem) {
        roots.add(cert?)?;
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots)).build()?;
    let tls = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            CertificateDer::pem_file_iter("server.pem")?.collect::<Result<_, _>>()?,
            PrivateKeyDer::from_pem_file("server.key")?,
        )?;

    // HTTP: verify again with rune-x509 and expose the identity.
    let app = Router::new()
        .route("/whoami", get(whoami))
        .layer(ClientCertLayer::new(MtlsConfig::from_pem(&ca_pem)?));

    let tcp = tokio::net::TcpListener::bind("0.0.0.0:8443").await?;
    let listener = MtlsListener::new(tcp, Arc::new(tls))?;
    axum::serve(listener, app.into_make_service_with_connect_info::<MtlsConnectInfo>()).await?;
    Ok(())
}
```

`ServerConfig::builder()` uses rustls' process-default crypto provider;
use `builder_with_provider` to pass one explicitly.

### Optional client certificates

Build the verifier with `.allow_unauthenticated()`, configure
`MtlsConfig::from_pem(..)?.optional()`, and take `Option<ClientCert>`:
anonymous clients get `None`, clients with a valid certificate get
`Some`, and clients with an invalid one are still refused with `403`.

## Scope

Revocation (CRL / OCSP), name constraints and certificate policies are not
checked (see `rune-x509`). The layer re-validates on every request; the
work is a few signature checks over a short chain.
