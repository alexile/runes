//! Parsing a certificate into an owned, typed summary.

use std::fmt;
use std::net::IpAddr;

use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::FromDer;

use crate::Error;
use crate::algorithm::{PublicKeyInfo, SignatureAlgorithm};

/// One `subjectAltName` entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SubjectAltName {
    /// `dNSName`, as encoded (not normalized).
    Dns(String),
    /// `iPAddress`: an IPv4 or IPv6 address.
    Ip(IpAddr),
    /// `rfc822Name` (an e-mail address).
    Email(String),
    /// `uniformResourceIdentifier`.
    Uri(String),
    /// Any other form (`otherName`, `directoryName`, an `iPAddress` that is
    /// not 4 or 16 bytes, a name that is not valid text...), described.
    Other(String),
}

impl SubjectAltName {
    fn from_general_name(name: &GeneralName<'_>) -> Self {
        match name {
            GeneralName::DNSName(dns) => Self::Dns((*dns).to_owned()),
            GeneralName::RFC822Name(email) => Self::Email((*email).to_owned()),
            GeneralName::URI(uri) => Self::Uri((*uri).to_owned()),
            GeneralName::IPAddress(bytes) => ip_from_bytes(bytes).map_or_else(
                || Self::Other(format!("IP address of {} bytes", bytes.len())),
                Self::Ip,
            ),
            GeneralName::DirectoryName(dn) => Self::Other(format!("DirName:{dn}")),
            GeneralName::OtherName(oid, _) => {
                Self::Other(format!("othername:{}", oid.to_id_string()))
            }
            GeneralName::RegisteredID(oid) => Self::Other(format!("RID:{}", oid.to_id_string())),
            GeneralName::X400Address(_) => Self::Other("x400Address".to_owned()),
            GeneralName::EDIPartyName(_) => Self::Other("ediPartyName".to_owned()),
            GeneralName::Invalid(tag, _) => Self::Other(format!("invalid entry (tag {})", tag.0)),
        }
    }
}

impl fmt::Display for SubjectAltName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dns(name) => write!(f, "DNS:{name}"),
            Self::Ip(ip) => write!(f, "IP:{ip}"),
            Self::Email(email) => write!(f, "email:{email}"),
            Self::Uri(uri) => write!(f, "URI:{uri}"),
            Self::Other(other) => f.write_str(other),
        }
    }
}

fn ip_from_bytes(bytes: &[u8]) -> Option<IpAddr> {
    if let Ok(v4) = <[u8; 4]>::try_from(bytes) {
        return Some(IpAddr::from(v4));
    }
    <[u8; 16]>::try_from(bytes).ok().map(IpAddr::from)
}

/// The `basicConstraints` extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct BasicConstraints {
    /// `cA`: the key may sign certificates.
    pub ca: bool,
    /// `pathLenConstraint`: the most non-self-issued intermediates that
    /// may follow this certificate in a path.
    pub path_len: Option<u32>,
    /// Whether the extension is marked critical.
    pub critical: bool,
}

/// The `keyUsage` extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
#[allow(
    clippy::struct_excessive_bools,
    reason = "one flag per KeyUsage bit (RFC 5280 §4.2.1.3)"
)]
pub struct KeyUsage {
    /// `digitalSignature`.
    pub digital_signature: bool,
    /// `nonRepudiation` (`contentCommitment`).
    pub non_repudiation: bool,
    /// `keyEncipherment`.
    pub key_encipherment: bool,
    /// `dataEncipherment`.
    pub data_encipherment: bool,
    /// `keyAgreement`.
    pub key_agreement: bool,
    /// `keyCertSign`: the key may sign certificates.
    pub key_cert_sign: bool,
    /// `cRLSign`.
    pub crl_sign: bool,
    /// `encipherOnly`.
    pub encipher_only: bool,
    /// `decipherOnly`.
    pub decipher_only: bool,
}

/// One `extendedKeyUsage` purpose.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ExtendedKeyUsage {
    /// `anyExtendedKeyUsage`.
    Any,
    /// `id-kp-serverAuth`: TLS server.
    ServerAuth,
    /// `id-kp-clientAuth`: TLS client.
    ClientAuth,
    /// `id-kp-codeSigning`.
    CodeSigning,
    /// `id-kp-emailProtection`.
    EmailProtection,
    /// `id-kp-timeStamping`.
    TimeStamping,
    /// `id-kp-OCSPSigning`.
    OcspSigning,
    /// Another purpose, by dotted OID.
    Other(String),
}

/// A typed, owned summary of one certificate.
///
/// Built by [`Certificate::from_der`]; read it through
/// [`Certificate::summary`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CertSummary {
    /// X.509 version: 1, 2 or 3.
    pub version: u32,
    /// Serial number, lowercase hex with `:` separators, as encoded.
    pub serial: String,
    /// Subject distinguished name (RFC 4514 style, `CN=example.com`).
    pub subject: String,
    /// Issuer distinguished name.
    pub issuer: String,
    /// The subject's common names, in order.
    pub subject_common_names: Vec<String>,
    /// `notBefore`, in seconds since the Unix epoch.
    pub not_before: i64,
    /// `notAfter`, in seconds since the Unix epoch.
    pub not_after: i64,
    /// Public key type and size.
    pub public_key: PublicKeyInfo,
    /// Signature algorithm of the certificate.
    pub signature_algorithm: SignatureAlgorithm,
    /// `subjectAltName` entries (empty when absent).
    pub subject_alt_names: Vec<SubjectAltName>,
    /// `basicConstraints`, when present.
    pub basic_constraints: Option<BasicConstraints>,
    /// `keyUsage`, when present.
    pub key_usage: Option<KeyUsage>,
    /// `extendedKeyUsage`, when present.
    pub extended_key_usage: Option<Vec<ExtendedKeyUsage>>,
    /// `subjectKeyIdentifier`, when present.
    pub subject_key_id: Option<Vec<u8>>,
    /// The `keyIdentifier` of `authorityKeyIdentifier`, when present.
    pub authority_key_id: Option<Vec<u8>>,
    /// Number of embedded Certificate Transparency SCTs (RFC 6962 §3.3).
    pub sct_count: usize,
    /// Dotted OIDs of critical extensions this crate does not understand.
    /// RFC 5280 §4.2 says such a certificate must be rejected.
    pub unhandled_critical_extensions: Vec<String>,
    /// Whether subject and issuer are the same name (byte for byte).
    pub self_issued: bool,
    /// Whether the certificate is self-issued and its signature verifies
    /// with its own key.
    pub self_signed: bool,
    /// SHA-256 over the DER encoding.
    pub sha256_fingerprint: [u8; 32],
}

impl CertSummary {
    /// Whether the certificate may act as a CA: `basicConstraints` with
    /// `cA` set.
    #[must_use]
    pub fn is_ca(&self) -> bool {
        self.basic_constraints.is_some_and(|bc| bc.ca)
    }

    /// The `dNSName` SAN entries.
    pub fn dns_names(&self) -> impl Iterator<Item = &str> {
        self.subject_alt_names.iter().filter_map(|san| match san {
            SubjectAltName::Dns(name) => Some(name.as_str()),
            _ => None,
        })
    }

    /// The `iPAddress` SAN entries.
    pub fn ip_addresses(&self) -> impl Iterator<Item = IpAddr> + '_ {
        self.subject_alt_names.iter().filter_map(|san| match san {
            SubjectAltName::Ip(ip) => Some(*ip),
            _ => None,
        })
    }

    /// Whether `at` (Unix seconds) lies in `[not_before, not_after]`.
    #[must_use]
    pub const fn is_valid_at(&self, at: i64) -> bool {
        self.not_before <= at && at <= self.not_after
    }

    /// Validity period length in whole days.
    #[must_use]
    pub const fn validity_days(&self) -> i64 {
        self.not_after.saturating_sub(self.not_before) / 86_400
    }

    /// The SHA-256 fingerprint as uppercase hex with `:` separators, the
    /// way browsers and `openssl x509 -fingerprint` show it.
    #[must_use]
    pub fn sha256_fingerprint_hex(&self) -> String {
        hex_colon(&self.sha256_fingerprint, true)
    }
}

/// A parsed certificate: its DER encoding and a [`CertSummary`].
///
/// ```
/// use rune_x509::{Certificate, PublicKeyInfo};
///
/// # let pem = include_bytes!("../tests/fixtures/leaf.pem");
/// let cert = Certificate::from_pem(pem)?;
/// let summary = cert.summary();
/// assert_eq!(summary.subject, "CN=example.com");
/// assert!(matches!(summary.public_key, PublicKeyInfo::Ec { bits: 256, .. }));
/// assert!(cert.matches_host("www.example.com"));
/// # Ok::<(), rune_x509::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct Certificate {
    der: Vec<u8>,
    summary: CertSummary,
    subject_raw: Vec<u8>,
    issuer_raw: Vec<u8>,
    spki_raw: Vec<u8>,
}

impl PartialEq for Certificate {
    fn eq(&self, other: &Self) -> bool {
        self.der == other.der
    }
}

impl Eq for Certificate {}

impl Certificate {
    /// Parses one DER-encoded certificate.
    ///
    /// # Errors
    ///
    /// [`Error::Der`] when the bytes are not a certificate and
    /// [`Error::TrailingData`] when bytes follow it.
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let cert = parse(der)?;
        let summary = summarize(&cert, der);
        Ok(Self {
            der: der.to_vec(),
            subject_raw: cert.subject().as_raw().to_vec(),
            issuer_raw: cert.issuer().as_raw().to_vec(),
            spki_raw: cert.public_key().raw.to_vec(),
            summary,
        })
    }

    /// Parses the first `CERTIFICATE` block of PEM text.
    ///
    /// # Errors
    ///
    /// [`Error::NoCertificate`] when there is none, plus those of
    /// [`Certificate::from_der`] and [`parse_pem`].
    pub fn from_pem(pem: &[u8]) -> Result<Self, Error> {
        parse_pem(pem)?
            .into_iter()
            .next()
            .ok_or(Error::NoCertificate)
    }

    /// The DER encoding.
    #[must_use]
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// The typed summary.
    #[must_use]
    pub const fn summary(&self) -> &CertSummary {
        &self.summary
    }

    /// The certificate as a PEM `CERTIFICATE` block.
    #[must_use]
    pub fn to_pem(&self) -> String {
        let b64 = rune_base64::encode(&self.der);
        let mut out = String::with_capacity(b64.len() + b64.len() / 64 + 60);
        out.push_str("-----BEGIN CERTIFICATE-----\n");
        let mut rest = b64.as_str();
        while !rest.is_empty() {
            let (line, tail) = rest.split_at(rest.len().min(64));
            out.push_str(line);
            out.push('\n');
            rest = tail;
        }
        out.push_str("-----END CERTIFICATE-----\n");
        out
    }

    /// The DER encoding of the subject name.
    #[must_use]
    pub fn subject_der(&self) -> &[u8] {
        &self.subject_raw
    }

    /// The DER encoding of the issuer name.
    #[must_use]
    pub fn issuer_der(&self) -> &[u8] {
        &self.issuer_raw
    }

    /// The DER `SubjectPublicKeyInfo`.
    #[must_use]
    pub fn spki_der(&self) -> &[u8] {
        &self.spki_raw
    }

    /// Checks this certificate's signature against `issuer`'s public key.
    ///
    /// ```
    /// use rune_x509::Certificate;
    ///
    /// # let leaf = Certificate::from_pem(include_bytes!("../tests/fixtures/leaf.pem"))?;
    /// # let inter = Certificate::from_pem(include_bytes!("../tests/fixtures/inter.pem"))?;
    /// # let root = Certificate::from_pem(include_bytes!("../tests/fixtures/root.pem"))?;
    /// assert!(leaf.verify_signed_by(&inter).is_ok());
    /// assert!(leaf.verify_signed_by(&root).is_err());
    /// # Ok::<(), rune_x509::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// A [`SignatureError`] when the signature does not verify, or uses an
    /// algorithm the verifier (`ring`) does not support, such as MD5 or
    /// RSA keys under 2048 bits with SHA-2.
    pub fn verify_signed_by(&self, issuer: &Self) -> Result<(), SignatureError> {
        let cert = parse(&self.der).map_err(|_| SignatureError::Invalid)?;
        let signer = parse(&issuer.der).map_err(|_| SignatureError::Invalid)?;
        match verify(&cert, &signer) {
            // A key of the wrong type for the algorithm is a plain
            // mismatch, not a gap in the verifier.
            Err(SignatureError::Unsupported)
                if !key_fits(
                    &self.summary.signature_algorithm,
                    &issuer.summary.public_key,
                ) =>
            {
                Err(SignatureError::Invalid)
            }
            other => other,
        }
    }

    /// Whether the certificate covers `host`: a DNS name (Unicode names
    /// are converted to A-labels) or an IP address literal (`[...]`
    /// brackets allowed). See [`HostOptions`](crate::HostOptions) for the
    /// rules; this uses the defaults.
    #[must_use]
    pub fn matches_host(&self, host: &str) -> bool {
        crate::host::matches(&self.summary, host, crate::HostOptions::default())
    }

    /// [`Certificate::matches_host`] with explicit options.
    #[must_use]
    pub fn matches_host_with(&self, host: &str, options: crate::HostOptions) -> bool {
        crate::host::matches(&self.summary, host, options)
    }

    /// Whether `issuer`'s subject is this certificate's issuer and, when
    /// both key identifiers are present, they agree. This is the cheap
    /// candidate test of path building; it does not check the signature.
    #[must_use]
    pub fn may_be_issued_by(&self, issuer: &Self) -> bool {
        if self.issuer_raw != issuer.subject_raw {
            return false;
        }
        match (
            &self.summary.authority_key_id,
            &issuer.summary.subject_key_id,
        ) {
            (Some(aki), Some(ski)) => aki == ski,
            _ => true,
        }
    }
}

/// Why [`Certificate::verify_signed_by`] failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[non_exhaustive]
pub enum SignatureError {
    /// The signature does not verify with the issuer's key.
    #[error("signature does not verify")]
    Invalid,
    /// The algorithm, or the key for it, is not supported by the verifier.
    #[error("unsupported signature algorithm or key")]
    Unsupported,
}

/// Whether a key of type `key` can produce `signature` at all.
const fn key_fits(signature: &SignatureAlgorithm, key: &PublicKeyInfo) -> bool {
    matches!(
        (signature, key),
        (
            SignatureAlgorithm::RsaPkcs1(_) | SignatureAlgorithm::RsaPss(_),
            PublicKeyInfo::Rsa { .. }
        ) | (SignatureAlgorithm::Ecdsa(_), PublicKeyInfo::Ec { .. })
            | (SignatureAlgorithm::Dsa(_), PublicKeyInfo::Dsa { .. })
            | (SignatureAlgorithm::Ed25519, PublicKeyInfo::Ed25519)
            | (SignatureAlgorithm::Ed448, PublicKeyInfo::Ed448)
            | (SignatureAlgorithm::Other(_), _)
            | (_, PublicKeyInfo::Other(_))
    )
}

fn parse(der: &[u8]) -> Result<X509Certificate<'_>, Error> {
    let (rest, cert) = X509Certificate::from_der(der).map_err(|err| Error::Der {
        reason: err.to_string(),
    })?;
    if !rest.is_empty() {
        return Err(Error::TrailingData { len: rest.len() });
    }
    // RFC 5280 §4.1.1.2: the unsigned outer algorithm must repeat the
    // signed one, or an attacker could relabel the signature.
    if cert.signature_algorithm != cert.tbs_certificate.signature {
        return Err(Error::Der {
            reason: "signatureAlgorithm differs from tbsCertificate.signature".to_owned(),
        });
    }
    Ok(cert)
}

fn verify(cert: &X509Certificate<'_>, signer: &X509Certificate<'_>) -> Result<(), SignatureError> {
    use x509_parser::error::X509Error;
    match cert.verify_signature(Some(signer.public_key())) {
        Ok(()) => Ok(()),
        Err(X509Error::SignatureUnsupportedAlgorithm) => Err(SignatureError::Unsupported),
        Err(_) => Err(SignatureError::Invalid),
    }
}

/// Parses every `CERTIFICATE` block in PEM text, in order. Other blocks
/// (keys, CRLs) and text between blocks are skipped.
///
/// ```
/// # let bundle = [
/// #     &include_bytes!("../tests/fixtures/leaf.pem")[..],
/// #     &include_bytes!("../tests/fixtures/inter.pem")[..],
/// # ].concat();
/// let certs = rune_x509::parse_pem(&bundle)?;
/// assert_eq!(certs.len(), 2);
/// assert_eq!(rune_x509::parse_pem(b"no pem here")?.len(), 0);
/// # Ok::<(), rune_x509::Error>(())
/// ```
///
/// # Errors
///
/// [`Error::Pem`] for a malformed block, and those of
/// [`Certificate::from_der`] for a block that is not a certificate.
pub fn parse_pem(input: &[u8]) -> Result<Vec<Certificate>, Error> {
    let mut certs = Vec::new();
    for block in x509_parser::pem::Pem::iter_from_buffer(input) {
        let block = block.map_err(|err| Error::Pem {
            reason: err.to_string(),
        })?;
        if block.label == "CERTIFICATE"
            || block.label == "X509 CERTIFICATE"
            || block.label == "TRUSTED CERTIFICATE"
        {
            // OpenSSL's TRUSTED CERTIFICATE appends trust settings after
            // the certificate; keep only the certificate itself.
            let der = if block.label == "TRUSTED CERTIFICATE" {
                first_der_element(&block.contents).unwrap_or(&block.contents)
            } else {
                &block.contents
            };
            certs.push(Certificate::from_der(der)?);
        }
    }
    Ok(certs)
}

/// The first DER TLV of `bytes`, by its definite length.
fn first_der_element(bytes: &[u8]) -> Option<&[u8]> {
    let (_tag, rest) = bytes.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, header) = if first < 0x80 {
        (usize::from(first), 2)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 {
            return None;
        }
        let len = rest
            .get(..count)?
            .iter()
            .fold(0usize, |acc, &b| (acc << 8) | usize::from(b));
        (len, 2 + count)
    };
    bytes.get(..header.checked_add(len)?)
}

fn summarize(cert: &X509Certificate<'_>, der: &[u8]) -> CertSummary {
    let sig_oid = cert.signature_algorithm.algorithm.to_id_string();
    let pss_hash = if sig_oid == "1.2.840.113549.1.1.10" {
        cert.signature_algorithm
            .parameters
            .as_ref()
            .and_then(|params| {
                x509_parser::signature_algorithm::RsaSsaPssParams::try_from(params).ok()
            })
            .map(|params| params.hash_algorithm_oid().to_id_string())
    } else {
        None
    };
    let signature_algorithm = SignatureAlgorithm::from_oid(&sig_oid, pss_hash.as_deref());

    let mut summary = CertSummary {
        version: cert.version().0.saturating_add(1),
        serial: hex_colon(cert.raw_serial(), false),
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        subject_common_names: cert
            .subject()
            .iter_common_name()
            .filter_map(|cn| cn.as_str().ok().map(str::to_owned))
            .collect(),
        not_before: cert.validity().not_before.timestamp(),
        not_after: cert.validity().not_after.timestamp(),
        public_key: PublicKeyInfo::from_spki(cert.public_key()),
        signature_algorithm,
        subject_alt_names: Vec::new(),
        basic_constraints: None,
        key_usage: None,
        extended_key_usage: None,
        subject_key_id: None,
        authority_key_id: None,
        sct_count: 0,
        unhandled_critical_extensions: Vec::new(),
        self_issued: cert.subject().as_raw() == cert.issuer().as_raw(),
        self_signed: false,
        sha256_fingerprint: rune_sha256::hash_raw(der),
    };
    for ext in cert.extensions() {
        apply_extension(
            &mut summary,
            ext.critical,
            ext.oid.to_id_string(),
            ext.parsed_extension(),
        );
    }
    summary.self_signed = summary.self_issued && verify(cert, cert).is_ok();
    summary
}

fn apply_extension(
    summary: &mut CertSummary,
    critical: bool,
    oid: String,
    ext: &ParsedExtension<'_>,
) {
    match ext {
        ParsedExtension::SubjectAlternativeName(san) => {
            summary.subject_alt_names = san
                .general_names
                .iter()
                .map(SubjectAltName::from_general_name)
                .collect();
        }
        ParsedExtension::BasicConstraints(bc) => {
            summary.basic_constraints = Some(BasicConstraints {
                ca: bc.ca,
                path_len: bc.path_len_constraint,
                critical,
            });
        }
        ParsedExtension::KeyUsage(ku) => {
            summary.key_usage = Some(KeyUsage {
                digital_signature: ku.digital_signature(),
                non_repudiation: ku.non_repudiation(),
                key_encipherment: ku.key_encipherment(),
                data_encipherment: ku.data_encipherment(),
                key_agreement: ku.key_agreement(),
                key_cert_sign: ku.key_cert_sign(),
                crl_sign: ku.crl_sign(),
                encipher_only: ku.encipher_only(),
                decipher_only: ku.decipher_only(),
            });
        }
        ParsedExtension::ExtendedKeyUsage(eku) => {
            let flags = [
                (eku.any, ExtendedKeyUsage::Any),
                (eku.server_auth, ExtendedKeyUsage::ServerAuth),
                (eku.client_auth, ExtendedKeyUsage::ClientAuth),
                (eku.code_signing, ExtendedKeyUsage::CodeSigning),
                (eku.email_protection, ExtendedKeyUsage::EmailProtection),
                (eku.time_stamping, ExtendedKeyUsage::TimeStamping),
                (eku.ocsp_signing, ExtendedKeyUsage::OcspSigning),
            ];
            let mut usages: Vec<_> = flags
                .into_iter()
                .filter(|(on, _)| *on)
                .map(|(_, usage)| usage)
                .collect();
            usages.extend(
                eku.other
                    .iter()
                    .map(|oid| ExtendedKeyUsage::Other(oid.to_id_string())),
            );
            summary.extended_key_usage = Some(usages);
        }
        ParsedExtension::SubjectKeyIdentifier(ski) => summary.subject_key_id = Some(ski.0.to_vec()),
        ParsedExtension::AuthorityKeyIdentifier(aki) => {
            summary.authority_key_id = aki.key_identifier.as_ref().map(|id| id.0.to_vec());
        }
        ParsedExtension::SCT(scts) => summary.sct_count = scts.len(),
        ParsedExtension::UnsupportedExtension { .. } | ParsedExtension::ParseError { .. }
            if critical =>
        {
            summary.unhandled_critical_extensions.push(oid);
        }
        _ => {}
    }
}

fn hex_colon(bytes: &[u8], upper: bool) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 3);
    for (i, byte) in bytes.iter().enumerate() {
        if i > 0 {
            out.push(':');
        }
        // Writing to a String cannot fail.
        let _ = if upper {
            write!(out, "{byte:02X}")
        } else {
            write!(out, "{byte:02x}")
        };
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_colon_formats() {
        assert_eq!(hex_colon(&[], false), "");
        assert_eq!(hex_colon(&[0x0a, 0xff], false), "0a:ff");
        assert_eq!(hex_colon(&[0x0a, 0xff], true), "0A:FF");
    }

    #[test]
    fn ip_bytes() {
        assert_eq!(
            ip_from_bytes(&[192, 0, 2, 1]),
            Some("192.0.2.1".parse().unwrap())
        );
        assert_eq!(ip_from_bytes(&[0; 16]), Some("::".parse().unwrap()));
        assert_eq!(ip_from_bytes(&[1, 2, 3]), None);
    }

    #[test]
    fn first_der_element_by_length() {
        assert_eq!(
            first_der_element(&[0x30, 0x01, 0xaa, 0xbb]),
            Some(&[0x30, 0x01, 0xaa][..])
        );
        assert_eq!(
            first_der_element(&[0x30, 0x81, 0x01, 0xaa, 0xbb]),
            Some(&[0x30, 0x81, 0x01, 0xaa][..])
        );
        assert_eq!(first_der_element(&[0x30, 0x05, 0xaa]), None);
        assert_eq!(first_der_element(&[0x30]), None);
    }

    #[test]
    fn garbage_is_an_error() {
        assert!(matches!(
            Certificate::from_der(b"nope"),
            Err(Error::Der { .. })
        ));
        assert_eq!(Certificate::from_pem(b"nothing"), Err(Error::NoCertificate));
    }
}
