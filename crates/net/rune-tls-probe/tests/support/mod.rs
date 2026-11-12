//! A scripted TLS server for tests: answers a `ClientHello` the way an
//! OpenSSL server with a given configuration would, up to the
//! `ServerHello`. No cryptography, no network.

#![allow(dead_code, reason = "each test binary uses part of the support module")]
#![allow(clippy::unwrap_used, reason = "test helpers")]

use rune_tls_hello::{
    AlertDescription, CipherSuite, ClientHello, Extension, HELLO_RETRY_REQUEST_RANDOM, NamedGroup,
    ProtocolVersion, ServerHello,
};

/// A server configuration.
#[derive(Debug, Clone)]
pub struct MockServer {
    /// Versions accepted.
    pub versions: Vec<ProtocolVersion>,
    /// Suites in server preference order (TLS 1.3 suites included).
    pub suites: Vec<CipherSuite>,
    /// Refuse a downgraded hello carrying `TLS_FALLBACK_SCSV`.
    pub honor_fallback: bool,
    /// Accept DEFLATE.
    pub compression: bool,
    /// Confirm RFC 5746.
    pub secure_renegotiation: bool,
    /// Ignore the client's offer and pick this suite (a broken server).
    pub force_suite: Option<CipherSuite>,
}

impl MockServer {
    pub fn new(versions: &[ProtocolVersion], suites: &[u16]) -> Self {
        Self {
            versions: versions.to_vec(),
            suites: suites.iter().map(|&s| CipherSuite(s)).collect(),
            honor_fallback: true,
            compression: false,
            secure_renegotiation: true,
            force_suite: None,
        }
    }

    fn max_version(&self) -> ProtocolVersion {
        self.versions.iter().copied().max().unwrap()
    }

    fn supports(&self, version: ProtocolVersion) -> bool {
        self.versions.contains(&version)
    }

    /// The server's reply to the bytes of a `ClientHello`.
    pub fn respond(&self, wire: &[u8]) -> Vec<u8> {
        let Ok(hello) = ClientHello::parse_records(wire) else {
            return alert(AlertDescription::DECODE_ERROR);
        };
        let tls13_client = hello
            .supported_versions()
            .is_some_and(|v| v.contains(&ProtocolVersion::TLS_1_3));
        if tls13_client && self.supports(ProtocolVersion::TLS_1_3) {
            let Some(suite) = self.pick(&hello, true) else {
                return alert(AlertDescription::HANDSHAKE_FAILURE);
            };
            return ServerHello::new()
                .with_random(HELLO_RETRY_REQUEST_RANDOM)
                .with_session_id(hello.session_id)
                .with_cipher_suite(suite)
                .with_extension(Extension::selected_version(ProtocolVersion::TLS_1_3))
                .with_extension(Extension::key_share_request(NamedGroup::X25519))
                .to_records(ProtocolVersion::TLS_1_2, 16_384)
                .unwrap();
        }
        let client_max = hello.legacy_version.min(ProtocolVersion::TLS_1_2);
        let Some(version) = self
            .versions
            .iter()
            .copied()
            .filter(|v| *v <= client_max && *v < ProtocolVersion::TLS_1_3)
            .max()
        else {
            return alert(AlertDescription::PROTOCOL_VERSION);
        };
        if self.honor_fallback && hello.offers_fallback_scsv() && version < self.max_version() {
            return alert(AlertDescription::INAPPROPRIATE_FALLBACK);
        }
        let Some(suite) = self.pick(&hello, false) else {
            return alert(AlertDescription::HANDSHAKE_FAILURE);
        };
        let mut random = [0x5a; 32];
        if self.supports(ProtocolVersion::TLS_1_3) {
            random[24..].copy_from_slice(b"DOWNGRD\x01");
        }
        let mut reply = ServerHello::new()
            .with_legacy_version(version)
            .with_random(random)
            .with_cipher_suite(suite)
            .with_compression_method(u8::from(
                self.compression && hello.compression_methods.contains(&1),
            ));
        if self.secure_renegotiation && hello.offers_secure_renegotiation() {
            reply = reply.with_extension(Extension::renegotiation_info(&[]).unwrap());
        }
        if version == ProtocolVersion::SSL_3_0 && reply.extensions().is_empty() {
            reply = reply.without_extensions();
        }
        reply.to_records(version, 16_384).unwrap()
    }

    fn pick(&self, hello: &ClientHello, tls13: bool) -> Option<CipherSuite> {
        if let Some(forced) = self.force_suite {
            return Some(forced);
        }
        self.suites
            .iter()
            .copied()
            .filter(|s| (s.0 >> 8 == 0x13) == tls13)
            .find(|s| hello.offers(*s))
    }
}

/// A fatal alert record.
pub fn alert(description: AlertDescription) -> Vec<u8> {
    vec![21, 3, 1, 0, 2, 2, description.0]
}
