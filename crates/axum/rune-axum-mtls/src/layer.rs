//! [`ClientCertLayer`]: verifies the peer chain with rune-x509.

use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{self, Poll},
};

use axum::response::{IntoResponse, Response};
use pin_project_lite::pin_project;
use rune_x509::{Certificate, Purpose, TrustStore, VerifyOptions, verify_chain};
use tower_layer::Layer;
use tower_service::Service;

use crate::{ClientCert, ClientCertRejection, Error, PeerCertificates};

/// What [`ClientCertLayer`] trusts and requires.
///
/// Chains are validated with [`rune_x509::verify_chain`] against
/// [`MtlsConfig::trust_store`], always for
/// [`Purpose::ClientAuth`]: a leaf whose `extendedKeyUsage` does not allow
/// TLS client authentication is rejected, whatever the
/// [`VerifyOptions`] say.
///
/// ```
/// use rune_axum_mtls::MtlsConfig;
///
/// # let ca_pem = include_bytes!("../tests/fixtures/ca.pem");
/// let config = MtlsConfig::from_pem(ca_pem)?.optional();
/// assert!(!config.is_required());
/// # Ok::<(), rune_axum_mtls::Error>(())
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct MtlsConfig {
    store: TrustStore,
    options: VerifyOptions,
    required: bool,
}

impl MtlsConfig {
    /// Trusts the anchors of `store`, requires a certificate, and checks
    /// with the default [`VerifyOptions`] (system clock, default
    /// [`Policy`](rune_x509::Policy)) for [`Purpose::ClientAuth`].
    #[must_use]
    pub fn new(store: TrustStore) -> Self {
        Self {
            store,
            options: client_auth(VerifyOptions::default()),
            required: true,
        }
    }

    /// [`MtlsConfig::new`] with the CA certificates of a PEM bundle.
    ///
    /// # Errors
    ///
    /// [`Error::TrustStore`] when the PEM holds no certificate or a
    /// malformed one.
    pub fn from_pem(pem: &[u8]) -> Result<Self, Error> {
        let store = TrustStore::from_pem(pem)?;
        if store.iter().next().is_none() {
            // An empty store would reject every client: a configuration error.
            return Err(Error::TrustStore(rune_x509::Error::NoCertificate));
        }
        Ok(Self::new(store))
    }

    /// Sets the validation options (time, weak-crypto policy, depth). The
    /// purpose is forced to [`Purpose::ClientAuth`], and a host name, if
    /// set, is checked against the client certificate's SANs.
    #[must_use]
    pub fn verify_options(mut self, options: VerifyOptions) -> Self {
        self.options = client_auth(options);
        self
    }

    /// Lets requests without a client certificate through, without a
    /// [`ClientCert`] extension. A certificate that is sent but does not
    /// validate is still rejected. Pair it with a TLS server that allows
    /// unauthenticated clients, and with `Option<ClientCert>` in handlers.
    #[must_use]
    pub const fn optional(mut self) -> Self {
        self.required = false;
        self
    }

    /// Whether a request without a client certificate is rejected.
    #[must_use]
    pub const fn is_required(&self) -> bool {
        self.required
    }

    /// The trust anchors.
    #[must_use]
    pub const fn trust_store(&self) -> &TrustStore {
        &self.store
    }

    /// The validation options in use; their purpose is always
    /// [`Purpose::ClientAuth`].
    #[must_use]
    pub const fn options(&self) -> &VerifyOptions {
        &self.options
    }

    /// Verifies a peer chain: `Ok(None)` when it is empty and the
    /// certificate is optional, `Ok(Some(_))` when it validates.
    ///
    /// This is the layer's decision, usable outside a tower stack (a
    /// WebSocket upgrade, a custom accept loop).
    ///
    /// # Errors
    ///
    /// The [`ClientCertRejection`] the layer would respond with.
    pub fn verify(
        &self,
        peer: &PeerCertificates,
    ) -> Result<Option<ClientCert>, ClientCertRejection> {
        let mut certs = peer.iter().map(Certificate::from_der);
        let Some(leaf) = certs.next() else {
            return if self.required {
                Err(ClientCertRejection::Missing)
            } else {
                Ok(None)
            };
        };
        let leaf = leaf.map_err(ClientCertRejection::Malformed)?;
        let intermediates = certs
            .collect::<Result<Vec<_>, _>>()
            .map_err(ClientCertRejection::Malformed)?;
        let report = verify_chain(&leaf, &intermediates, &self.store, &self.options);
        if report.is_trusted() {
            ClientCert::from_report(report)
                .map(Some)
                .ok_or(ClientCertRejection::Missing)
        } else {
            Err(ClientCertRejection::Untrusted(
                report.errors().cloned().collect(),
            ))
        }
    }
}

const fn client_auth(options: VerifyOptions) -> VerifyOptions {
    options.with_purpose(Purpose::ClientAuth)
}

/// Finds the peer chain in a request: a [`PeerCertificates`] extension, or
/// the one in [`MtlsConnectInfo`](crate::MtlsConnectInfo) connect info.
fn peer_certificates<B>(req: &http::Request<B>) -> Option<PeerCertificates> {
    let extensions = req.extensions();
    extensions.get::<PeerCertificates>().cloned().or_else(|| {
        extensions
            .get::<axum::extract::ConnectInfo<crate::MtlsConnectInfo>>()
            .map(|info| info.0.peer_certificates.clone())
    })
}

/// Tower [`Layer`] that verifies the client certificate of every request
/// and stores it for the [`ClientCert`] extractor.
///
/// The peer chain comes from the TLS connection: a [`PeerCertificates`]
/// request extension, or [`MtlsConnectInfo`](crate::MtlsConnectInfo)
/// connect info (what [`MtlsListener`](crate::MtlsListener) provides). It
/// is validated with [`MtlsConfig::verify`]. A request without a
/// certificate gets `401 Unauthorized` (unless [`MtlsConfig::optional`]);
/// one whose certificate does not validate gets `403 Forbidden`. The
/// rejection is also stored in the response's extensions, for logging.
///
/// Verifying here, on top of the TLS server's own check, gives one
/// rune-x509 view of the certificate (weak-crypto policy, `clientAuth`
/// purpose) whatever terminated TLS.
///
/// ```
/// use axum::{Router, routing::get};
/// use rune_axum_mtls::{ClientCert, ClientCertLayer, MtlsConfig};
///
/// # let ca_pem = include_bytes!("../tests/fixtures/ca.pem");
/// let app: Router = Router::new()
///     .route("/me", get(|cert: ClientCert| async move { cert.subject().to_owned() }))
///     .layer(ClientCertLayer::new(MtlsConfig::from_pem(ca_pem)?));
/// # Ok::<(), rune_axum_mtls::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct ClientCertLayer {
    config: Arc<MtlsConfig>,
}

impl ClientCertLayer {
    /// Creates the layer.
    #[must_use]
    pub fn new(config: MtlsConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }
}

impl<S> Layer<S> for ClientCertLayer {
    type Service = ClientCertService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ClientCertService {
            inner,
            config: Arc::clone(&self.config),
        }
    }
}

/// Tower [`Service`] produced by [`ClientCertLayer`].
#[derive(Debug, Clone)]
pub struct ClientCertService<S> {
    inner: S,
    config: Arc<MtlsConfig>,
}

impl<S, B> Service<http::Request<B>> for ClientCertService<S>
where
    S: Service<http::Request<B>, Response = Response>,
{
    type Response = Response;
    type Error = S::Error;
    type Future = ClientCertFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: http::Request<B>) -> Self::Future {
        let peer = peer_certificates(&req).unwrap_or_default();
        // Never trust a `ClientCert` that something upstream inserted.
        req.extensions_mut().remove::<ClientCert>();
        let kind = match self.config.verify(&peer) {
            Ok(cert) => {
                if let Some(cert) = cert {
                    req.extensions_mut().insert(cert);
                }
                Kind::Allow {
                    future: self.inner.call(req),
                }
            }
            Err(rejection) => {
                let mut response = rejection.clone().into_response();
                response.extensions_mut().insert(rejection);
                Kind::Reject {
                    response: Some(response),
                }
            }
        };
        ClientCertFuture { kind }
    }
}

pin_project! {
    /// Future returned by [`ClientCertService`].
    pub struct ClientCertFuture<F> {
        #[pin]
        kind: Kind<F>,
    }
}

pin_project! {
    #[project = KindProj]
    enum Kind<F> {
        Reject { response: Option<Response> },
        Allow { #[pin] future: F },
    }
}

impl<F, E> Future for ClientCertFuture<F>
where
    F: Future<Output = Result<Response, E>>,
{
    type Output = Result<Response, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        match self.project().kind.project() {
            // Polling again after `Ready` breaks the `Future` contract; stay pending.
            KindProj::Reject { response } => response
                .take()
                .map_or(Poll::Pending, |r| Poll::Ready(Ok(r))),
            KindProj::Allow { future } => future.poll(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, body::Body, routing::get};
    use http::{Request, StatusCode};
    use rune_x509::{ChainIssue, parse_pem};
    use tower::ServiceExt;

    const CA: &[u8] = include_bytes!("../tests/fixtures/ca.pem");
    const CLIENT: &[u8] = include_bytes!("../tests/fixtures/client.pem");
    const SERVER_EKU: &[u8] = include_bytes!("../tests/fixtures/server-eku.pem");
    const ROGUE_CLIENT: &[u8] = include_bytes!("../tests/fixtures/rogue-client.pem");

    fn peer(pem: &[u8]) -> PeerCertificates {
        parse_pem(pem)
            .unwrap()
            .iter()
            .map(|c| c.der().to_vec())
            .collect()
    }

    fn config() -> MtlsConfig {
        MtlsConfig::from_pem(CA).unwrap()
    }

    fn app(config: MtlsConfig) -> Router {
        Router::new()
            .route(
                "/",
                get(|cert: Option<ClientCert>| async move {
                    cert.map_or_else(|| "anonymous".to_owned(), |c| c.subject().to_owned())
                }),
            )
            .route(
                "/strict",
                get(|cert: ClientCert| async move { cert.subject().to_owned() }),
            )
            .layer(ClientCertLayer::new(config))
    }

    async fn send(
        app: Router,
        path: &str,
        peer: Option<PeerCertificates>,
    ) -> (StatusCode, String, Option<ClientCertRejection>) {
        let mut req = Request::get(path).body(Body::empty()).unwrap();
        if let Some(peer) = peer {
            req.extensions_mut().insert(peer);
        }
        let res = app.oneshot(req).await.unwrap();
        let status = res.status();
        let rejection = res.extensions().get::<ClientCertRejection>().cloned();
        let body = axum::body::to_bytes(res.into_body(), 1 << 16)
            .await
            .unwrap();
        (status, String::from_utf8(body.to_vec()).unwrap(), rejection)
    }

    #[test]
    fn verify_accepts_client_cert_and_exposes_identity() {
        let cert = config().verify(&peer(CLIENT)).unwrap().unwrap();
        assert_eq!(cert.subject(), "O=Rune mTLS Test, CN=alice");
        assert_eq!(cert.common_name(), Some("alice"));
        assert_eq!(cert.dns_names().collect::<Vec<_>>(), ["alice.example.com"]);
        assert_eq!(cert.emails().collect::<Vec<_>>(), ["alice@example.com"]);
        assert_eq!(cert.uris().count(), 0);
        assert_eq!(cert.issuer(), "O=Rune mTLS Test, CN=Rune mTLS Test CA");
        assert_eq!(cert.chain().len(), 2);
        assert!(cert.report().is_trusted());
        assert_eq!(cert.fingerprint().len(), 32 * 3 - 1);
        assert_eq!(cert.certificate().der(), peer(CLIENT).leaf().unwrap());
    }

    #[test]
    fn purpose_is_always_client_auth() {
        let config =
            config().verify_options(VerifyOptions::default().with_purpose(Purpose::ServerAuth));
        assert_eq!(config.options().purpose, Purpose::ClientAuth);
        let Err(ClientCertRejection::Untrusted(issues)) = config.verify(&peer(SERVER_EKU)) else {
            panic!("serverAuth-only leaf accepted");
        };
        assert!(issues.contains(&ChainIssue::WrongPurpose {
            purpose: Purpose::ClientAuth
        }));
    }

    #[test]
    fn untrusted_and_malformed_chains_are_rejected() {
        assert!(matches!(
            config().verify(&peer(ROGUE_CLIENT)),
            Err(ClientCertRejection::Untrusted(_))
        ));
        let garbage = PeerCertificates::new(vec![b"not a certificate".to_vec()]);
        let rejection = config().verify(&garbage).unwrap_err();
        assert!(matches!(rejection, ClientCertRejection::Malformed(_)));
        assert_eq!(rejection.status(), StatusCode::FORBIDDEN);
        // A bad intermediate is malformed too, not silently ignored.
        let mut chain: Vec<Vec<u8>> = peer(CLIENT).iter().map(<[u8]>::to_vec).collect();
        chain.push(vec![0x30, 0x00]);
        assert!(matches!(
            config().verify(&PeerCertificates::new(chain)),
            Err(ClientCertRejection::Malformed(_))
        ));
    }

    #[test]
    fn expired_at_verification_time() {
        // 2200-01-01: past the fixtures' notAfter.
        let config = config().verify_options(VerifyOptions::default().with_time(7_258_118_400));
        let Err(ClientCertRejection::Untrusted(issues)) = config.verify(&peer(CLIENT)) else {
            panic!("expired chain accepted");
        };
        assert!(
            issues
                .iter()
                .any(|i| matches!(i, ChainIssue::Expired { .. }))
        );
        assert!(
            ClientCertRejection::Untrusted(issues)
                .to_string()
                .starts_with("untrusted client certificate: ")
        );
    }

    #[test]
    fn missing_certificate_depends_on_required() {
        let empty = PeerCertificates::default();
        assert_eq!(
            config().verify(&empty).unwrap_err(),
            ClientCertRejection::Missing
        );
        assert!(config().optional().verify(&empty).unwrap().is_none());
        assert_eq!(
            ClientCertRejection::Missing.status(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[test]
    fn bad_trust_store_is_an_error() {
        assert!(matches!(
            MtlsConfig::from_pem(b"nope"),
            Err(Error::TrustStore(_))
        ));
    }

    #[tokio::test]
    async fn layer_inserts_verified_cert() {
        let (status, body, _) = send(app(config()), "/strict", Some(peer(CLIENT))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "O=Rune mTLS Test, CN=alice");
    }

    #[tokio::test]
    async fn layer_rejects_missing_and_untrusted() {
        let (status, _, rejection) = send(app(config()), "/", None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(rejection, Some(ClientCertRejection::Missing));

        let (status, _, rejection) = send(app(config()), "/", Some(peer(ROGUE_CLIENT))).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(matches!(rejection, Some(ClientCertRejection::Untrusted(_))));

        let (status, _, _) = send(app(config().optional()), "/", Some(peer(SERVER_EKU))).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn optional_mode_passes_anonymous_requests() {
        let (status, body, _) = send(app(config().optional()), "/", None).await;
        assert_eq!((status, body.as_str()), (StatusCode::OK, "anonymous"));
        // The strict extractor still refuses without a certificate.
        let (status, _, _) = send(app(config().optional()), "/strict", None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, body, _) = send(app(config().optional()), "/", Some(peer(CLIENT))).await;
        assert_eq!(
            (status, body.as_str()),
            (StatusCode::OK, "O=Rune mTLS Test, CN=alice")
        );
    }

    #[tokio::test]
    async fn forged_upstream_extension_is_discarded() {
        let forged = config().verify(&peer(CLIENT)).unwrap().unwrap();
        let mut req = Request::get("/").body(Body::empty()).unwrap();
        req.extensions_mut().insert(forged);
        let res = app(config().optional()).oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(res.into_body(), 1 << 16)
            .await
            .unwrap();
        assert_eq!(&body[..], b"anonymous");
    }

    #[tokio::test]
    async fn extractor_without_layer_is_unauthorized() {
        let app: Router = Router::new().route(
            "/",
            get(|cert: ClientCert| async move { cert.fingerprint() }),
        );
        let res = app
            .oneshot(Request::get("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn reads_chain_from_connect_info() {
        let info = crate::MtlsConnectInfo::new(([127, 0, 0, 1], 9).into(), peer(CLIENT));
        let mut req = Request::get("/strict").body(Body::empty()).unwrap();
        req.extensions_mut()
            .insert(axum::extract::ConnectInfo(info));
        let res = app(config()).oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }
}
