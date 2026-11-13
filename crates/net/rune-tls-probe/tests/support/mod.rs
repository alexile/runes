//! A scripted TLS server for tests: answers a `ClientHello` the way an
//! OpenSSL server with a given configuration would, up to the
//! `ServerHello`. No cryptography, no network.

#![allow(dead_code, reason = "each test binary uses part of the support module")]
#![allow(clippy::unwrap_used, reason = "test helpers")]
#![allow(
    clippy::cast_possible_truncation,
    reason = "lengths of small test messages"
)]

use rune_tls_hello::{
    AlertDescription, CipherSuite, ClientHello, Extension, HELLO_RETRY_REQUEST_RANDOM, NamedGroup,
    ProtocolVersion, ServerHello,
};
use rune_tls_probe::KeyExchangeKind;

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
    /// Size of the DHE prime sent in the `ServerKeyExchange`.
    pub dh_prime_bits: usize,
    /// The ECDHE curve sent in the `ServerKeyExchange`.
    pub ecdhe_group: NamedGroup,
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
            dh_prime_bits: 2048,
            ecdhe_group: NamedGroup::X25519,
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
        let mut out = reply.to_records(version, 16_384).unwrap();
        out.extend(self.key_exchange(version, suite));
        out
    }

    /// Certificate (empty), `ServerKeyExchange` and `ServerHelloDone` for an
    /// ephemeral suite, as one record; nothing otherwise.
    fn key_exchange(&self, version: ProtocolVersion, suite: CipherSuite) -> Vec<u8> {
        let ske = match rune_tls_probe::key_exchange_kind(suite) {
            Some(KeyExchangeKind::Dhe) => {
                let len = self.dh_prime_bits.div_ceil(8);
                let mut body = (len as u16).to_be_bytes().to_vec();
                let top = match self.dh_prime_bits % 8 {
                    0 => 0xff,
                    r => (1u8 << r) - 1,
                };
                body.push(top);
                body.extend(vec![0xa5; len - 1]);
                body.extend([0, 1, 2, 0, 1, 9, 0, 0]); // g, Ys, empty signature
                body
            }
            Some(KeyExchangeKind::Ecdhe) => {
                let mut body = vec![3];
                body.extend(self.ecdhe_group.0.to_be_bytes());
                body.extend([1, 4, 0, 0]);
                body
            }
            _ => return Vec::new(),
        };
        let mut messages = Vec::new();
        for (msg_type, body) in [(11u8, vec![0, 0, 0]), (12, ske), (14, Vec::new())] {
            messages.push(msg_type);
            messages.extend(&(body.len() as u32).to_be_bytes()[1..]);
            messages.extend(body);
        }
        let mut record = vec![22];
        record.extend(version.0.to_be_bytes());
        record.extend((messages.len() as u16).to_be_bytes());
        record.extend(messages);
        record
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
