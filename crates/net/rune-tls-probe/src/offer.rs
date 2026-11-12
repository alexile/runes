//! One handshake attempt: the `ClientHello` sent and how the server answered.

use std::net::IpAddr;

use rune_tls_hello::{
    Alert, AlertDescription, CipherSuite, ClientHello, DowngradeSentinel, Extension,
    HandshakeMessage, Message, MessageReader, NamedGroup, ProtocolVersion, ServerHello,
    SignatureScheme,
};

use crate::Error;

/// Largest record fragment the probe sends.
const FRAGMENT: usize = 16_384;

const GROUPS: &[NamedGroup] = &[
    NamedGroup::X25519,
    NamedGroup::SECP256R1,
    NamedGroup::SECP384R1,
    NamedGroup::SECP521R1,
    NamedGroup::X448,
    NamedGroup::FFDHE2048,
    NamedGroup::FFDHE3072,
    NamedGroup::FFDHE4096,
];

const SIGNATURE_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::ECDSA_SECP256R1_SHA256,
    SignatureScheme::ECDSA_SECP384R1_SHA384,
    SignatureScheme::ECDSA_SECP521R1_SHA512,
    SignatureScheme::ED25519,
    SignatureScheme::ED448,
    SignatureScheme::RSA_PSS_RSAE_SHA256,
    SignatureScheme::RSA_PSS_RSAE_SHA384,
    SignatureScheme::RSA_PSS_RSAE_SHA512,
    SignatureScheme::RSA_PSS_PSS_SHA256,
    SignatureScheme::RSA_PSS_PSS_SHA384,
    SignatureScheme::RSA_PSS_PSS_SHA512,
    SignatureScheme::RSA_PKCS1_SHA256,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::ECDSA_SHA1,
    SignatureScheme::RSA_PKCS1_SHA1,
    // DSA with SHA-256 and SHA-1, for old DSS servers.
    SignatureScheme(0x0402),
    SignatureScheme(0x0202),
];

/// What one `ClientHello` offers.
///
/// The hello is built to get a `ServerHello` out of as many servers as
/// possible, so the answer reflects the server's policy rather than a
/// missing extension:
///
/// - SSL 3.0: no extension block (SSL 3.0 servers may choke on one), with
///   `TLS_EMPTY_RENEGOTIATION_INFO_SCSV` to ask for RFC 5746.
/// - TLS 1.0-1.2: `server_name` (for a host name), `renegotiation_info`,
///   `supported_groups`, `ec_point_formats`, and for TLS 1.2
///   `signature_algorithms`; `legacy_version` is the probed version.
/// - TLS 1.3: `supported_versions` with only TLS 1.3, and an empty
///   `key_share`, so a TLS 1.3 server answers with a `HelloRetryRequest`
///   naming its suite. No key material is ever sent.
///
/// ```
/// use rune_tls_hello::{ClientHello, CipherSuite, ProtocolVersion};
/// use rune_tls_probe::Offer;
///
/// let offer = Offer::new(ProtocolVersion::TLS_1_0, [CipherSuite(0x002f)])
///     .with_server_name("legacy.example");
/// let wire = offer.to_records([7; 32])?;
/// let hello = ClientHello::parse_records(&wire)?;
/// assert_eq!(hello.legacy_version, ProtocolVersion::TLS_1_0);
/// assert_eq!(hello.server_name(), Some("legacy.example"));
/// # Ok::<(), rune_tls_probe::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Offer {
    /// The version probed.
    pub version: ProtocolVersion,
    /// The cipher suites offered, in order.
    pub cipher_suites: Vec<CipherSuite>,
    /// Offer DEFLATE compression before null.
    pub compression: bool,
    /// Append `TLS_FALLBACK_SCSV` ([RFC 7507](https://www.rfc-editor.org/rfc/rfc7507)).
    pub fallback_scsv: bool,
    /// SNI host name; ignored for SSL 3.0 and for IP literals.
    pub server_name: Option<String>,
}

impl Offer {
    /// An offer of `cipher_suites` at `version`.
    pub fn new(
        version: ProtocolVersion,
        cipher_suites: impl IntoIterator<Item = CipherSuite>,
    ) -> Self {
        Self {
            version,
            cipher_suites: cipher_suites.into_iter().collect(),
            compression: false,
            fallback_scsv: false,
            server_name: None,
        }
    }

    /// Sets [`Offer::server_name`].
    #[must_use]
    pub fn with_server_name(mut self, name: impl Into<String>) -> Self {
        self.server_name = Some(name.into());
        self
    }

    /// Sets [`Offer::compression`].
    #[must_use]
    pub const fn with_compression(mut self, compression: bool) -> Self {
        self.compression = compression;
        self
    }

    /// Sets [`Offer::fallback_scsv`].
    #[must_use]
    pub const fn with_fallback_scsv(mut self, fallback_scsv: bool) -> Self {
        self.fallback_scsv = fallback_scsv;
        self
    }

    /// Whether this is a TLS 1.3 offer.
    #[must_use]
    pub fn is_tls13(&self) -> bool {
        self.version >= ProtocolVersion::TLS_1_3
    }

    /// The `ClientHello`, with `random` as the client random.
    ///
    /// # Errors
    ///
    /// [`Error::Hello`] when a field is too long to encode (a server name
    /// over 65535 bytes, say).
    pub fn client_hello(&self, random: [u8; 32]) -> Result<ClientHello, Error> {
        let mut suites = self.cipher_suites.clone();
        if self.version == ProtocolVersion::SSL_3_0 {
            suites.push(CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
        }
        if self.fallback_scsv {
            suites.push(CipherSuite::TLS_FALLBACK_SCSV);
        }
        let compression: Vec<u8> = if self.compression {
            vec![1, 0]
        } else {
            vec![0]
        };
        let hello = ClientHello::new()
            .with_random(random)
            .with_cipher_suites(suites)
            .with_compression_methods(compression);
        if self.version == ProtocolVersion::SSL_3_0 {
            return Ok(hello
                .with_legacy_version(ProtocolVersion::SSL_3_0)
                .without_extensions());
        }

        let mut extensions = Vec::new();
        if let Some(name) = self.sni() {
            extensions.push(Extension::server_name(name)?);
        }
        extensions.push(Extension::supported_groups(GROUPS)?);
        if self.is_tls13() {
            extensions.push(Extension::signature_algorithms(SIGNATURE_SCHEMES)?);
            extensions.push(Extension::supported_versions(&[ProtocolVersion::TLS_1_3])?);
            extensions.push(Extension::key_shares(&[])?);
            return Ok(hello
                .with_legacy_version(ProtocolVersion::TLS_1_2)
                .with_extensions(extensions));
        }
        extensions.push(Extension::ec_point_formats(&[0])?);
        if self.version >= ProtocolVersion::TLS_1_2 {
            extensions.push(Extension::signature_algorithms(SIGNATURE_SCHEMES)?);
        }
        extensions.push(Extension::renegotiation_info(&[])?);
        Ok(hello
            .with_legacy_version(self.version)
            .with_extensions(extensions))
    }

    /// The `ClientHello` as records, ready to write to the socket. The
    /// record layer says SSL 3.0 for an SSL 3.0 offer and TLS 1.0
    /// otherwise, as browsers did.
    ///
    /// # Errors
    ///
    /// As [`Offer::client_hello`].
    pub fn to_records(&self, random: [u8; 32]) -> Result<Vec<u8>, Error> {
        let record_version = self.version.min(ProtocolVersion::TLS_1_0);
        Ok(self
            .client_hello(random)?
            .to_records(record_version, FRAGMENT)?)
    }

    fn sni(&self) -> Option<&str> {
        self.server_name
            .as_deref()
            .map(|name| name.trim_end_matches('.'))
            .filter(|name| !name.is_empty() && name.parse::<IpAddr>().is_err())
    }
}

/// The parts of a `ServerHello` (or `HelloRetryRequest`) the probe keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Accepted {
    /// The negotiated version (`supported_versions` for TLS 1.3).
    pub version: ProtocolVersion,
    /// The cipher suite the server picked.
    pub cipher_suite: CipherSuite,
    /// The compression method the server picked; 1 is DEFLATE.
    pub compression_method: u8,
    /// Whether the server confirmed RFC 5746 secure renegotiation.
    pub secure_renegotiation: bool,
    /// Whether the answer was a TLS 1.3 `HelloRetryRequest`.
    pub hello_retry_request: bool,
    /// The TLS 1.3 downgrade sentinel in the server random, if any.
    pub downgrade_sentinel: Option<DowngradeSentinel>,
}

impl From<&ServerHello> for Accepted {
    fn from(hello: &ServerHello) -> Self {
        Self {
            version: hello.selected_version(),
            cipher_suite: hello.cipher_suite,
            compression_method: hello.compression_method,
            secure_renegotiation: hello.secure_renegotiation(),
            hello_retry_request: hello.is_hello_retry_request(),
            downgrade_sentinel: hello.downgrade_sentinel(),
        }
    }
}

/// How the server answered one [`Offer`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Outcome {
    /// A `ServerHello` or `HelloRetryRequest`.
    Accepted(Accepted),
    /// An alert, usually `handshake_failure` or `protocol_version`.
    Alert(Alert),
    /// The connection closed, or timed out, without an answer.
    NoResponse,
    /// The answer is not a TLS handshake (an HTTP error page, an SSL 2.0
    /// server, garbage).
    NotTls {
        /// What did not parse.
        reason: String,
    },
    /// The attempt could not be made: connecting failed.
    Unreachable {
        /// Why.
        reason: String,
    },
}

impl Outcome {
    /// The `ServerHello` fields, when accepted.
    #[must_use]
    pub const fn accepted(&self) -> Option<&Accepted> {
        match self {
            Self::Accepted(accepted) => Some(accepted),
            _ => None,
        }
    }

    /// Whether the server answered with this alert.
    #[must_use]
    pub fn is_alert(&self, description: AlertDescription) -> bool {
        matches!(self, Self::Alert(alert) if alert.description == description)
    }
}

/// Reads the server's first handshake message or alert, sans-I/O.
///
/// ```
/// use rune_tls_hello::{CipherSuite, ProtocolVersion, ServerHello};
/// use rune_tls_probe::{Outcome, ResponseReader};
///
/// let hello = ServerHello::new()
///     .with_legacy_version(ProtocolVersion::TLS_1_0)
///     .with_cipher_suite(CipherSuite(0x0005));
/// let wire = hello.to_records(ProtocolVersion::TLS_1_0, 16_384)?;
///
/// let mut reader = ResponseReader::new();
/// assert_eq!(reader.feed(&wire[..3]), None); // needs more bytes
/// let outcome = reader.feed(&wire[3..]).unwrap();
/// assert_eq!(outcome.accepted().unwrap().version, ProtocolVersion::TLS_1_0);
/// # Ok::<(), rune_tls_hello::Error>(())
/// ```
#[derive(Debug, Clone, Default)]
pub struct ResponseReader {
    reader: MessageReader,
    seen: bool,
}

impl ResponseReader {
    /// A reader that has seen nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Feeds bytes; returns the outcome once it is known.
    pub fn feed(&mut self, bytes: &[u8]) -> Option<Outcome> {
        if bytes.is_empty() {
            return None;
        }
        self.seen = true;
        self.reader.feed(bytes);
        match self.reader.next_message() {
            Ok(None) => None,
            Ok(Some(Message::Handshake(HandshakeMessage::ServerHello(hello)))) => {
                Some(Outcome::Accepted(Accepted::from(&hello)))
            }
            Ok(Some(Message::Alert(alert))) => Some(Outcome::Alert(alert)),
            Ok(Some(other)) => Some(Outcome::NotTls {
                reason: format!("expected ServerHello or alert, got {}", describe(&other)),
            }),
            Err(error) => Some(Outcome::NotTls {
                reason: error.to_string(),
            }),
        }
    }

    /// The outcome when the connection ended before [`ResponseReader::feed`]
    /// returned one.
    #[must_use]
    pub fn finish(&self) -> Outcome {
        if self.seen {
            Outcome::NotTls {
                reason: "connection ended inside a TLS message".to_owned(),
            }
        } else {
            Outcome::NoResponse
        }
    }
}

fn describe(message: &Message) -> &'static str {
    match message {
        Message::Handshake(handshake) => handshake.msg_type().name().unwrap_or("handshake message"),
        Message::ChangeCipherSpec(_) => "change_cipher_spec",
        Message::ApplicationData(_) => "application_data",
        Message::Heartbeat(_) => "heartbeat",
        _ => "record",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rune_tls_hello::{AlertLevel, ExtensionType};

    #[test]
    fn ssl3_offer_has_no_extensions_and_asks_for_renegotiation_info() {
        let offer = Offer::new(ProtocolVersion::SSL_3_0, [CipherSuite(0x000a)])
            .with_server_name("a.example");
        let wire = offer.to_records([1; 32]).unwrap();
        assert_eq!(&wire[1..3], [3, 0]); // record version SSL 3.0
        let hello = ClientHello::parse_records(&wire).unwrap();
        assert_eq!(hello.legacy_version, ProtocolVersion::SSL_3_0);
        assert!(hello.extensions.is_none());
        assert!(hello.offers_secure_renegotiation());
        assert_eq!(hello.server_name(), None);
    }

    #[test]
    fn legacy_offer_extensions() {
        let offer = Offer::new(ProtocolVersion::TLS_1_1, [CipherSuite(0x002f)])
            .with_server_name("192.0.2.1")
            .with_compression(true)
            .with_fallback_scsv(true);
        let hello = ClientHello::parse_records(&offer.to_records([1; 32]).unwrap()).unwrap();
        assert_eq!(hello.legacy_version, ProtocolVersion::TLS_1_1);
        assert_eq!(hello.compression_methods, [1, 0]);
        assert!(hello.offers_fallback_scsv());
        assert!(hello.offers_secure_renegotiation());
        assert_eq!(hello.server_name(), None); // IP literals get no SNI
        assert!(
            hello
                .extension(ExtensionType::SIGNATURE_ALGORITHMS)
                .is_none()
        );
        assert!(hello.supported_versions().is_none());

        let tls12 = Offer::new(ProtocolVersion::TLS_1_2, [CipherSuite(0xc02f)])
            .with_server_name("host.example.");
        let hello = ClientHello::parse_records(&tls12.to_records([1; 32]).unwrap()).unwrap();
        assert_eq!(hello.server_name(), Some("host.example"));
        assert!(
            hello
                .extension(ExtensionType::SIGNATURE_ALGORITHMS)
                .is_some()
        );
    }

    #[test]
    fn tls13_offer_sends_no_key_material() {
        let offer = Offer::new(
            ProtocolVersion::TLS_1_3,
            [CipherSuite::TLS_AES_128_GCM_SHA256],
        );
        let hello = ClientHello::parse_records(&offer.to_records([1; 32]).unwrap()).unwrap();
        assert_eq!(hello.legacy_version, ProtocolVersion::TLS_1_2);
        assert_eq!(
            hello.supported_versions(),
            Some(vec![ProtocolVersion::TLS_1_3])
        );
        assert_eq!(hello.key_shares(), Some(Vec::new()));
        assert_eq!(hello.max_version(), ProtocolVersion::TLS_1_3);
    }

    #[test]
    fn reader_outcomes() {
        let mut reader = ResponseReader::new();
        assert_eq!(reader.finish(), Outcome::NoResponse);
        let alert = reader.feed(&[21, 3, 1, 0, 2, 2, 70]).unwrap();
        assert!(alert.is_alert(AlertDescription::PROTOCOL_VERSION));
        assert_eq!(
            alert,
            Outcome::Alert(Alert::new(
                AlertLevel::FATAL,
                AlertDescription::PROTOCOL_VERSION
            ))
        );

        let mut reader = ResponseReader::new();
        assert!(matches!(
            reader.feed(b"HTTP/1.1 400 Bad Request\r\n\r\n"),
            Some(Outcome::NotTls { .. })
        ));

        let mut reader = ResponseReader::new();
        assert_eq!(reader.feed(&[22, 3, 1]), None);
        assert!(matches!(reader.finish(), Outcome::NotTls { .. }));
    }
}
