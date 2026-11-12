//! The peer certificate chain and the verified [`ClientCert`] extractor.

use std::sync::Arc;

use axum::{
    extract::{FromRequestParts, OptionalFromRequestParts},
    response::{IntoResponse, Response},
};
use http::{StatusCode, request::Parts};
use rune_x509::{CertSummary, Certificate, ChainIssue, ChainReport, SubjectAltName};

/// The certificate chain a TLS client presented, as DER, leaf first.
///
/// This is raw handshake output: nothing here has been checked by this
/// crate. [`ClientCertLayer`](crate::ClientCertLayer) looks for it in the
/// request (as an extension, or inside
/// [`ConnectInfo<MtlsConnectInfo>`](crate::MtlsConnectInfo)), verifies it
/// and turns it into a [`ClientCert`].
///
/// A server stack other than [`MtlsListener`](crate::MtlsListener) inserts
/// it as a request extension:
///
/// ```
/// use rune_axum_mtls::PeerCertificates;
///
/// let mut request = http::Request::new(());
/// let chain: Vec<Vec<u8>> = Vec::new(); // from the TLS session
/// request.extensions_mut().insert(PeerCertificates::new(chain));
/// assert!(request.extensions().get::<PeerCertificates>().is_some_and(PeerCertificates::is_empty));
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeerCertificates {
    chain: Arc<[Vec<u8>]>,
}

impl PeerCertificates {
    /// Wraps a DER chain, leaf first.
    #[must_use]
    pub fn new(chain: Vec<Vec<u8>>) -> Self {
        Self {
            chain: chain.into(),
        }
    }

    /// Whether the client sent no certificate.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.chain.is_empty()
    }

    /// Number of certificates sent.
    #[must_use]
    pub fn len(&self) -> usize {
        self.chain.len()
    }

    /// The leaf (end-entity) certificate's DER, if any.
    #[must_use]
    pub fn leaf(&self) -> Option<&[u8]> {
        self.chain.first().map(Vec::as_slice)
    }

    /// Every certificate's DER, leaf first.
    pub fn iter(&self) -> impl Iterator<Item = &[u8]> {
        self.chain.iter().map(Vec::as_slice)
    }
}

impl FromIterator<Vec<u8>> for PeerCertificates {
    fn from_iter<I: IntoIterator<Item = Vec<u8>>>(iter: I) -> Self {
        Self {
            chain: iter.into_iter().collect(),
        }
    }
}

/// A client certificate that [`ClientCertLayer`](crate::ClientCertLayer)
/// verified with [`rune_x509::verify_chain`] for
/// [`Purpose::ClientAuth`](rune_x509::Purpose::ClientAuth).
///
/// Use it as an extractor. It is only ever produced by the layer, so a
/// handler that takes `ClientCert` only runs for a trusted client; take
/// `Option<ClientCert>` on routes where the certificate is optional.
/// Without the layer, extraction fails with `401 Unauthorized`.
///
/// Cloning is cheap (the data is shared).
///
/// ```
/// use rune_axum_mtls::ClientCert;
///
/// async fn whoami(cert: ClientCert) -> String {
///     format!("{} ({})", cert.subject(), cert.dns_names().collect::<Vec<_>>().join(", "))
/// }
///
/// let app: axum::Router = axum::Router::new().route("/whoami", axum::routing::get(whoami));
/// ```
#[derive(Debug, Clone)]
pub struct ClientCert {
    inner: Arc<Verified>,
}

#[derive(Debug)]
struct Verified {
    leaf: Certificate,
    report: ChainReport,
}

impl ClientCert {
    /// Wraps a trusted report; `None` when it is not trusted.
    pub(crate) fn from_report(report: ChainReport) -> Option<Self> {
        if !report.is_trusted() {
            return None;
        }
        let leaf = report.path.first()?.clone();
        Some(Self {
            inner: Arc::new(Verified { leaf, report }),
        })
    }

    /// The leaf certificate.
    #[must_use]
    pub fn certificate(&self) -> &Certificate {
        &self.inner.leaf
    }

    /// The leaf's typed summary.
    #[must_use]
    pub fn summary(&self) -> &CertSummary {
        self.certificate().summary()
    }

    /// The leaf's subject distinguished name (RFC 4514 style,
    /// `O=Example,CN=alice`).
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.summary().subject
    }

    /// The leaf's issuer distinguished name.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.summary().issuer
    }

    /// The leaf subject's last common name, the usual identity of a client
    /// certificate.
    #[must_use]
    pub fn common_name(&self) -> Option<&str> {
        self.summary()
            .subject_common_names
            .last()
            .map(String::as_str)
    }

    /// The leaf's `subjectAltName` entries.
    #[must_use]
    pub fn subject_alt_names(&self) -> &[SubjectAltName] {
        &self.summary().subject_alt_names
    }

    /// The leaf's `dNSName` SAN entries.
    pub fn dns_names(&self) -> impl Iterator<Item = &str> {
        self.summary().dns_names()
    }

    /// The leaf's `rfc822Name` (e-mail) SAN entries.
    pub fn emails(&self) -> impl Iterator<Item = &str> {
        self.subject_alt_names().iter().filter_map(|san| match san {
            SubjectAltName::Email(email) => Some(email.as_str()),
            _ => None,
        })
    }

    /// The leaf's `uniformResourceIdentifier` SAN entries (SPIFFE IDs and
    /// the like).
    pub fn uris(&self) -> impl Iterator<Item = &str> {
        self.subject_alt_names().iter().filter_map(|san| match san {
            SubjectAltName::Uri(uri) => Some(uri.as_str()),
            _ => None,
        })
    }

    /// The leaf's SHA-256 fingerprint, uppercase hex with `:` separators;
    /// a stable key for certificate pinning or per-client lookups.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        self.summary().sha256_fingerprint_hex()
    }

    /// The validated path, leaf first, ending at the trust anchor.
    #[must_use]
    pub fn chain(&self) -> &[Certificate] {
        &self.inner.report.path
    }

    /// The full validation report, including warning-level issues such as
    /// weak-but-allowed crypto.
    #[must_use]
    pub fn report(&self) -> &ChainReport {
        &self.inner.report
    }
}

/// Why a request has no usable client certificate.
///
/// [`ClientCertRejection::Missing`] responds `401 Unauthorized`; the others
/// respond `403 Forbidden`. The details are for logging and are never sent
/// to the client.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClientCertRejection {
    /// The client sent no certificate, or no
    /// [`ClientCertLayer`](crate::ClientCertLayer) ran for this route.
    Missing,
    /// A certificate in the chain is not valid DER.
    Malformed(rune_x509::Error),
    /// The chain does not validate for client authentication.
    Untrusted(Vec<ChainIssue>),
}

impl ClientCertRejection {
    /// The response status: 401 for [`ClientCertRejection::Missing`], 403
    /// otherwise.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        match self {
            Self::Missing => StatusCode::UNAUTHORIZED,
            Self::Malformed(_) | Self::Untrusted(_) => StatusCode::FORBIDDEN,
        }
    }
}

impl std::fmt::Display for ClientCertRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => f.write_str("no client certificate"),
            Self::Malformed(error) => write!(f, "malformed client certificate: {error}"),
            Self::Untrusted(issues) => {
                f.write_str("untrusted client certificate")?;
                for (i, issue) in issues.iter().enumerate() {
                    f.write_str(if i == 0 { ": " } else { "; " })?;
                    write!(f, "{issue}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for ClientCertRejection {}

impl IntoResponse for ClientCertRejection {
    fn into_response(self) -> Response {
        self.status().into_response()
    }
}

impl<S: Send + Sync> FromRequestParts<S> for ClientCert {
    type Rejection = ClientCertRejection;

    #[allow(
        clippy::unused_async_trait_impl,
        reason = "the extractor trait is async; this implementation happens not to await"
    )]
    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Self>()
            .cloned()
            .ok_or(ClientCertRejection::Missing)
    }
}

impl<S: Send + Sync> OptionalFromRequestParts<S> for ClientCert {
    type Rejection = std::convert::Infallible;

    #[allow(
        clippy::unused_async_trait_impl,
        reason = "the extractor trait is async; this implementation happens not to await"
    )]
    async fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        Ok(parts.extensions.get::<Self>().cloned())
    }
}
