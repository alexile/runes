//! End to end over loopback TLS: `MtlsListener` + `ClientCertLayer` +
//! the `ClientCert` extractor, with a tokio-rustls client.
#![cfg(feature = "tokio")]
#![allow(clippy::unwrap_used, reason = "test helpers: a failure fails the test")]

use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum::{Router, extract::ConnectInfo, routing::get};
use rune_axum_mtls::{
    ClientCert, ClientCertLayer, ListenerOptions, MtlsConfig, MtlsConnectInfo, MtlsListener,
    rustls::{
        ClientConfig, RootCertStore, ServerConfig,
        crypto::ring::default_provider,
        pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject},
        server::WebPkiClientVerifier,
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::TlsConnector;

const CA: &[u8] = include_bytes!("fixtures/ca.pem");
const SERVER: &[u8] = include_bytes!("fixtures/server.pem");
const SERVER_KEY: &[u8] = include_bytes!("fixtures/server.key");
const CLIENT: &[u8] = include_bytes!("fixtures/client.pem");
const CLIENT_KEY: &[u8] = include_bytes!("fixtures/client.key");
const ROGUE_CLIENT: &[u8] = include_bytes!("fixtures/rogue-client.pem");
const ROGUE_CLIENT_KEY: &[u8] = include_bytes!("fixtures/rogue-client.key");

fn certs(pem: &[u8]) -> Vec<CertificateDer<'static>> {
    CertificateDer::pem_slice_iter(pem)
        .collect::<Result<_, _>>()
        .unwrap()
}

fn roots() -> Arc<RootCertStore> {
    let mut roots = RootCertStore::empty();
    for cert in certs(CA) {
        roots.add(cert).unwrap();
    }
    Arc::new(roots)
}

fn server_config(optional: bool) -> Arc<ServerConfig> {
    let provider = Arc::new(default_provider());
    let verifier = WebPkiClientVerifier::builder_with_provider(roots(), Arc::clone(&provider));
    let verifier = if optional {
        verifier.allow_unauthenticated()
    } else {
        verifier
    };
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(verifier.build().unwrap())
        .with_single_cert(
            certs(SERVER),
            PrivateKeyDer::from_pem_slice(SERVER_KEY).unwrap(),
        )
        .unwrap();
    Arc::new(config)
}

fn client_config(identity: Option<(&[u8], &[u8])>) -> Arc<ClientConfig> {
    let builder = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots());
    let config = match identity {
        Some((cert, key)) => builder
            .with_client_auth_cert(certs(cert), PrivateKeyDer::from_pem_slice(key).unwrap())
            .unwrap(),
        None => builder.with_no_client_auth(),
    };
    Arc::new(config)
}

async fn whoami(cert: ClientCert, ConnectInfo(info): ConnectInfo<MtlsConnectInfo>) -> String {
    format!(
        "cn={} subject={} san={} email={} chain={} loopback={}",
        cert.common_name().unwrap_or("-"),
        cert.subject(),
        cert.dns_names().collect::<Vec<_>>().join(","),
        cert.emails().collect::<Vec<_>>().join(","),
        cert.chain().len(),
        info.remote_addr.ip().is_loopback(),
    )
}

async fn hello(cert: Option<ClientCert>) -> String {
    cert.map_or_else(
        || "anonymous".to_owned(),
        |c| c.common_name().unwrap_or("-").to_owned(),
    )
}

async fn serve(optional: bool) -> SocketAddr {
    let config = MtlsConfig::from_pem(CA).unwrap();
    let config = if optional { config.optional() } else { config };
    let app = Router::new()
        .route("/whoami", get(whoami))
        .route("/hello", get(hello))
        .layer(ClientCertLayer::new(config));
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let options = ListenerOptions::default().handshake_timeout(Duration::from_secs(2));
    let listener = MtlsListener::with_options(tcp, server_config(optional), options).unwrap();
    let addr = axum::serve::Listener::local_addr(&listener).unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<MtlsConnectInfo>(),
        )
        .await
        .unwrap();
    });
    addr
}

/// One HTTP/1.1 GET over TLS; `Err` when the handshake or I/O fails.
async fn get_over_tls(
    addr: SocketAddr,
    path: &str,
    identity: Option<(&[u8], &[u8])>,
) -> std::io::Result<String> {
    let tcp = TcpStream::connect(addr).await?;
    let connector = TlsConnector::from(client_config(identity));
    let mut tls = connector
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await?;
    let request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    tls.write_all(request.as_bytes()).await?;
    let mut response = String::new();
    tls.read_to_string(&mut response).await?;
    Ok(response)
}

fn status_and_body(response: &str) -> (&str, &str) {
    let status = response.split(' ').nth(1).unwrap();
    let body = response.split_once("\r\n\r\n").unwrap().1;
    (status, body)
}

#[tokio::test]
async fn handler_reads_client_cert_subject_and_san() {
    let addr = serve(false).await;
    let response = get_over_tls(addr, "/whoami", Some((CLIENT, CLIENT_KEY)))
        .await
        .unwrap();
    let (status, body) = status_and_body(&response);
    assert_eq!(status, "200");
    assert_eq!(
        body,
        "cn=alice subject=O=Rune mTLS Test, CN=alice san=alice.example.com \
         email=alice@example.com chain=2 loopback=true"
    );
}

#[tokio::test]
async fn required_mode_refuses_clients_without_a_trusted_cert() {
    let addr = serve(false).await;
    // rustls refuses the handshake; the listener drops the connection.
    assert!(get_over_tls(addr, "/hello", None).await.is_err());
    assert!(
        get_over_tls(addr, "/hello", Some((ROGUE_CLIENT, ROGUE_CLIENT_KEY)))
            .await
            .is_err()
    );
    // The listener keeps serving after failed handshakes.
    let response = get_over_tls(addr, "/hello", Some((CLIENT, CLIENT_KEY)))
        .await
        .unwrap();
    assert_eq!(status_and_body(&response), ("200", "alice"));
}

#[tokio::test]
async fn optional_mode_serves_anonymous_and_authenticated_clients() {
    let addr = serve(true).await;
    let response = get_over_tls(addr, "/hello", None).await.unwrap();
    assert_eq!(status_and_body(&response), ("200", "anonymous"));
    let response = get_over_tls(addr, "/whoami", None).await.unwrap();
    assert_eq!(status_and_body(&response).0, "401");
    let response = get_over_tls(addr, "/hello", Some((CLIENT, CLIENT_KEY)))
        .await
        .unwrap();
    assert_eq!(status_and_body(&response), ("200", "alice"));
}

#[tokio::test]
async fn silent_client_does_not_block_others() {
    let addr = serve(false).await;
    // A TCP client that never starts the handshake.
    let _silent = TcpStream::connect(addr).await.unwrap();
    let response = tokio::time::timeout(
        Duration::from_secs(5),
        get_over_tls(addr, "/hello", Some((CLIENT, CLIENT_KEY))),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(status_and_body(&response), ("200", "alice"));
}
