//! Registered TLS code points as transparent newtypes.
//!
//! Every type wraps the raw wire value, so unknown and
//! [GREASE](https://www.rfc-editor.org/rfc/rfc8701) values survive a parse
//! and re-encode unchanged. Names come from the
//! [IANA TLS parameters registry](https://www.iana.org/assignments/tls-parameters/).

use std::fmt;

/// Whether a 16-bit code point is a GREASE value
/// ([RFC 8701](https://www.rfc-editor.org/rfc/rfc8701)): `0x0a0a`, `0x1a1a`,
/// …, `0xfafa`. Cipher suites, extensions, named groups, signature
/// algorithms and versions all reserve these values.
#[must_use]
pub const fn is_grease(value: u16) -> bool {
    let [hi, lo] = value.to_be_bytes();
    hi == lo && lo & 0x0f == 0x0a
}

macro_rules! code_point {
    (
        $(#[$meta:meta])*
        $name:ident($repr:ty), $fmt:literal;
        $( $(#[$cmeta:meta])* $konst:ident = $value:literal => $label:literal, )*
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub $repr);

        impl $name {
            $(
                $(#[$cmeta])*
                pub const $konst: Self = Self($value);
            )*

            /// The registered name, if this crate knows the value.
            #[must_use]
            pub const fn name(self) -> Option<&'static str> {
                match self.0 {
                    $( $value => Some($label), )*
                    _ => None,
                }
            }
        }

        impl From<$repr> for $name {
            fn from(value: $repr) -> Self {
                Self(value)
            }
        }

        impl From<$name> for $repr {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self.name() {
                    Some(name) => f.write_str(name),
                    None => write!(f, $fmt, self.0),
                }
            }
        }
    };
}

macro_rules! grease {
    ($($name:ident),*) => {$(
        impl $name {
            /// Whether this is a GREASE value ([`is_grease`]).
            #[must_use]
            pub const fn is_grease(self) -> bool {
                is_grease(self.0)
            }
        }
    )*};
}

grease!(
    ProtocolVersion,
    CipherSuite,
    ExtensionType,
    NamedGroup,
    SignatureScheme
);

code_point! {
    /// A protocol version (`ProtocolVersion`, two bytes). Versions order
    /// numerically, so `SSL_3_0 < TLS_1_0 < … < TLS_1_3`.
    ProtocolVersion(u16), "0x{:04x}";
    /// SSL 3.0 ([RFC 6101](https://www.rfc-editor.org/rfc/rfc6101)).
    SSL_3_0 = 0x0300 => "SSLv3",
    /// TLS 1.0 ([RFC 2246](https://www.rfc-editor.org/rfc/rfc2246)).
    TLS_1_0 = 0x0301 => "TLSv1.0",
    /// TLS 1.1 ([RFC 4346](https://www.rfc-editor.org/rfc/rfc4346)).
    TLS_1_1 = 0x0302 => "TLSv1.1",
    /// TLS 1.2 ([RFC 5246](https://www.rfc-editor.org/rfc/rfc5246)).
    TLS_1_2 = 0x0303 => "TLSv1.2",
    /// TLS 1.3 ([RFC 8446](https://www.rfc-editor.org/rfc/rfc8446)).
    TLS_1_3 = 0x0304 => "TLSv1.3",
}

code_point! {
    /// A cipher suite (`CipherSuite`, two bytes). Only the signalling
    /// values and the TLS 1.3 suites have constants here; any value parses.
    CipherSuite(u16), "0x{:04x}";
    /// Secure renegotiation signal ([RFC 5746](https://www.rfc-editor.org/rfc/rfc5746)).
    TLS_EMPTY_RENEGOTIATION_INFO_SCSV = 0x00ff => "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
    /// Downgrade protection signal ([RFC 7507](https://www.rfc-editor.org/rfc/rfc7507)).
    TLS_FALLBACK_SCSV = 0x5600 => "TLS_FALLBACK_SCSV",
    /// TLS 1.3 AES-128-GCM with SHA-256.
    TLS_AES_128_GCM_SHA256 = 0x1301 => "TLS_AES_128_GCM_SHA256",
    /// TLS 1.3 AES-256-GCM with SHA-384.
    TLS_AES_256_GCM_SHA384 = 0x1302 => "TLS_AES_256_GCM_SHA384",
    /// TLS 1.3 ChaCha20-Poly1305 with SHA-256.
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
    /// TLS 1.3 AES-128-CCM with SHA-256.
    TLS_AES_128_CCM_SHA256 = 0x1304 => "TLS_AES_128_CCM_SHA256",
    /// TLS 1.3 AES-128-CCM-8 with SHA-256.
    TLS_AES_128_CCM_8_SHA256 = 0x1305 => "TLS_AES_128_CCM_8_SHA256",
}

code_point! {
    /// An extension type (`ExtensionType`, two bytes).
    ExtensionType(u16), "0x{:04x}";
    /// `server_name` (SNI, [RFC 6066](https://www.rfc-editor.org/rfc/rfc6066#section-3)).
    SERVER_NAME = 0 => "server_name",
    /// `max_fragment_length` ([RFC 6066](https://www.rfc-editor.org/rfc/rfc6066#section-4)).
    MAX_FRAGMENT_LENGTH = 1 => "max_fragment_length",
    /// `status_request` (OCSP stapling, [RFC 6066](https://www.rfc-editor.org/rfc/rfc6066#section-8)).
    STATUS_REQUEST = 5 => "status_request",
    /// `supported_groups` ([RFC 8422](https://www.rfc-editor.org/rfc/rfc8422), [RFC 7919](https://www.rfc-editor.org/rfc/rfc7919)).
    SUPPORTED_GROUPS = 10 => "supported_groups",
    /// `ec_point_formats` ([RFC 8422](https://www.rfc-editor.org/rfc/rfc8422#section-5.1.2)).
    EC_POINT_FORMATS = 11 => "ec_point_formats",
    /// `signature_algorithms` ([RFC 8446](https://www.rfc-editor.org/rfc/rfc8446#section-4.2.3)).
    SIGNATURE_ALGORITHMS = 13 => "signature_algorithms",
    /// `use_srtp` ([RFC 5764](https://www.rfc-editor.org/rfc/rfc5764)).
    USE_SRTP = 14 => "use_srtp",
    /// `heartbeat` ([RFC 6520](https://www.rfc-editor.org/rfc/rfc6520)).
    HEARTBEAT = 15 => "heartbeat",
    /// `application_layer_protocol_negotiation` (ALPN, [RFC 7301](https://www.rfc-editor.org/rfc/rfc7301)).
    ALPN = 16 => "application_layer_protocol_negotiation",
    /// `signed_certificate_timestamp` ([RFC 6962](https://www.rfc-editor.org/rfc/rfc6962)).
    SIGNED_CERTIFICATE_TIMESTAMP = 18 => "signed_certificate_timestamp",
    /// `padding` ([RFC 7685](https://www.rfc-editor.org/rfc/rfc7685)).
    PADDING = 21 => "padding",
    /// `encrypt_then_mac` ([RFC 7366](https://www.rfc-editor.org/rfc/rfc7366)).
    ENCRYPT_THEN_MAC = 22 => "encrypt_then_mac",
    /// `extended_master_secret` ([RFC 7627](https://www.rfc-editor.org/rfc/rfc7627)).
    EXTENDED_MASTER_SECRET = 23 => "extended_master_secret",
    /// `compress_certificate` ([RFC 8879](https://www.rfc-editor.org/rfc/rfc8879)).
    COMPRESS_CERTIFICATE = 27 => "compress_certificate",
    /// `record_size_limit` ([RFC 8449](https://www.rfc-editor.org/rfc/rfc8449)).
    RECORD_SIZE_LIMIT = 28 => "record_size_limit",
    /// `session_ticket` ([RFC 5077](https://www.rfc-editor.org/rfc/rfc5077)).
    SESSION_TICKET = 35 => "session_ticket",
    /// `pre_shared_key` ([RFC 8446](https://www.rfc-editor.org/rfc/rfc8446#section-4.2.11)).
    PRE_SHARED_KEY = 41 => "pre_shared_key",
    /// `early_data` ([RFC 8446](https://www.rfc-editor.org/rfc/rfc8446#section-4.2.10)).
    EARLY_DATA = 42 => "early_data",
    /// `supported_versions` ([RFC 8446](https://www.rfc-editor.org/rfc/rfc8446#section-4.2.1)).
    SUPPORTED_VERSIONS = 43 => "supported_versions",
    /// `cookie` ([RFC 8446](https://www.rfc-editor.org/rfc/rfc8446#section-4.2.2)).
    COOKIE = 44 => "cookie",
    /// `psk_key_exchange_modes` ([RFC 8446](https://www.rfc-editor.org/rfc/rfc8446#section-4.2.9)).
    PSK_KEY_EXCHANGE_MODES = 45 => "psk_key_exchange_modes",
    /// `certificate_authorities` ([RFC 8446](https://www.rfc-editor.org/rfc/rfc8446#section-4.2.4)).
    CERTIFICATE_AUTHORITIES = 47 => "certificate_authorities",
    /// `post_handshake_auth` ([RFC 8446](https://www.rfc-editor.org/rfc/rfc8446#section-4.2.6)).
    POST_HANDSHAKE_AUTH = 49 => "post_handshake_auth",
    /// `signature_algorithms_cert` ([RFC 8446](https://www.rfc-editor.org/rfc/rfc8446#section-4.2.3)).
    SIGNATURE_ALGORITHMS_CERT = 50 => "signature_algorithms_cert",
    /// `key_share` ([RFC 8446](https://www.rfc-editor.org/rfc/rfc8446#section-4.2.8)).
    KEY_SHARE = 51 => "key_share",
    /// `encrypted_client_hello` (ECH, draft-ietf-tls-esni).
    ENCRYPTED_CLIENT_HELLO = 0xfe0d => "encrypted_client_hello",
    /// `renegotiation_info` ([RFC 5746](https://www.rfc-editor.org/rfc/rfc5746)).
    RENEGOTIATION_INFO = 0xff01 => "renegotiation_info",
}

code_point! {
    /// A named group for key exchange (`NamedGroup`, two bytes; called
    /// `elliptic_curves` before TLS 1.3).
    NamedGroup(u16), "0x{:04x}";
    /// NIST P-256.
    SECP256R1 = 0x0017 => "secp256r1",
    /// NIST P-384.
    SECP384R1 = 0x0018 => "secp384r1",
    /// NIST P-521.
    SECP521R1 = 0x0019 => "secp521r1",
    /// Curve25519 ([RFC 7748](https://www.rfc-editor.org/rfc/rfc7748)).
    X25519 = 0x001d => "x25519",
    /// Curve448 ([RFC 7748](https://www.rfc-editor.org/rfc/rfc7748)).
    X448 = 0x001e => "x448",
    /// 2048-bit finite-field group ([RFC 7919](https://www.rfc-editor.org/rfc/rfc7919)).
    FFDHE2048 = 0x0100 => "ffdhe2048",
    /// 3072-bit finite-field group.
    FFDHE3072 = 0x0101 => "ffdhe3072",
    /// 4096-bit finite-field group.
    FFDHE4096 = 0x0102 => "ffdhe4096",
    /// 6144-bit finite-field group.
    FFDHE6144 = 0x0103 => "ffdhe6144",
    /// 8192-bit finite-field group.
    FFDHE8192 = 0x0104 => "ffdhe8192",
    /// Hybrid X25519 + ML-KEM-768.
    X25519_MLKEM768 = 0x11ec => "X25519MLKEM768",
}

code_point! {
    /// A signature scheme (`SignatureScheme`, two bytes; a
    /// `SignatureAndHashAlgorithm` pair in TLS 1.2).
    SignatureScheme(u16), "0x{:04x}";
    /// RSA PKCS#1 v1.5 with SHA-1.
    RSA_PKCS1_SHA1 = 0x0201 => "rsa_pkcs1_sha1",
    /// ECDSA with SHA-1.
    ECDSA_SHA1 = 0x0203 => "ecdsa_sha1",
    /// RSA PKCS#1 v1.5 with SHA-256.
    RSA_PKCS1_SHA256 = 0x0401 => "rsa_pkcs1_sha256",
    /// RSA PKCS#1 v1.5 with SHA-384.
    RSA_PKCS1_SHA384 = 0x0501 => "rsa_pkcs1_sha384",
    /// RSA PKCS#1 v1.5 with SHA-512.
    RSA_PKCS1_SHA512 = 0x0601 => "rsa_pkcs1_sha512",
    /// ECDSA P-256 with SHA-256.
    ECDSA_SECP256R1_SHA256 = 0x0403 => "ecdsa_secp256r1_sha256",
    /// ECDSA P-384 with SHA-384.
    ECDSA_SECP384R1_SHA384 = 0x0503 => "ecdsa_secp384r1_sha384",
    /// ECDSA P-521 with SHA-512.
    ECDSA_SECP521R1_SHA512 = 0x0603 => "ecdsa_secp521r1_sha512",
    /// RSA-PSS (rsaEncryption key) with SHA-256.
    RSA_PSS_RSAE_SHA256 = 0x0804 => "rsa_pss_rsae_sha256",
    /// RSA-PSS (rsaEncryption key) with SHA-384.
    RSA_PSS_RSAE_SHA384 = 0x0805 => "rsa_pss_rsae_sha384",
    /// RSA-PSS (rsaEncryption key) with SHA-512.
    RSA_PSS_RSAE_SHA512 = 0x0806 => "rsa_pss_rsae_sha512",
    /// Ed25519.
    ED25519 = 0x0807 => "ed25519",
    /// Ed448.
    ED448 = 0x0808 => "ed448",
    /// RSA-PSS (RSASSA-PSS key) with SHA-256.
    RSA_PSS_PSS_SHA256 = 0x0809 => "rsa_pss_pss_sha256",
    /// RSA-PSS (RSASSA-PSS key) with SHA-384.
    RSA_PSS_PSS_SHA384 = 0x080a => "rsa_pss_pss_sha384",
    /// RSA-PSS (RSASSA-PSS key) with SHA-512.
    RSA_PSS_PSS_SHA512 = 0x080b => "rsa_pss_pss_sha512",
}

code_point! {
    /// A record content type (`ContentType`, one byte).
    ContentType(u8), "{}";
    /// `change_cipher_spec`.
    CHANGE_CIPHER_SPEC = 20 => "change_cipher_spec",
    /// `alert`.
    ALERT = 21 => "alert",
    /// `handshake`.
    HANDSHAKE = 22 => "handshake",
    /// `application_data`.
    APPLICATION_DATA = 23 => "application_data",
    /// `heartbeat` ([RFC 6520](https://www.rfc-editor.org/rfc/rfc6520)).
    HEARTBEAT = 24 => "heartbeat",
}

code_point! {
    /// A handshake message type (`HandshakeType`, one byte).
    HandshakeType(u8), "{}";
    /// `hello_request` (TLS 1.2 and earlier).
    HELLO_REQUEST = 0 => "hello_request",
    /// `client_hello`.
    CLIENT_HELLO = 1 => "client_hello",
    /// `server_hello` (also carries a TLS 1.3 `HelloRetryRequest`).
    SERVER_HELLO = 2 => "server_hello",
    /// `new_session_ticket`.
    NEW_SESSION_TICKET = 4 => "new_session_ticket",
    /// `end_of_early_data`.
    END_OF_EARLY_DATA = 5 => "end_of_early_data",
    /// `encrypted_extensions`.
    ENCRYPTED_EXTENSIONS = 8 => "encrypted_extensions",
    /// `certificate`.
    CERTIFICATE = 11 => "certificate",
    /// `server_key_exchange` (TLS 1.2 and earlier).
    SERVER_KEY_EXCHANGE = 12 => "server_key_exchange",
    /// `certificate_request`.
    CERTIFICATE_REQUEST = 13 => "certificate_request",
    /// `server_hello_done` (TLS 1.2 and earlier).
    SERVER_HELLO_DONE = 14 => "server_hello_done",
    /// `certificate_verify`.
    CERTIFICATE_VERIFY = 15 => "certificate_verify",
    /// `client_key_exchange` (TLS 1.2 and earlier).
    CLIENT_KEY_EXCHANGE = 16 => "client_key_exchange",
    /// `finished`.
    FINISHED = 20 => "finished",
    /// `certificate_status` (OCSP stapling, TLS 1.2 and earlier).
    CERTIFICATE_STATUS = 22 => "certificate_status",
    /// `key_update`.
    KEY_UPDATE = 24 => "key_update",
    /// `message_hash` (synthetic, used in the TLS 1.3 transcript).
    MESSAGE_HASH = 254 => "message_hash",
}

code_point! {
    /// An alert level (`AlertLevel`, one byte).
    AlertLevel(u8), "{}";
    /// `warning`.
    WARNING = 1 => "warning",
    /// `fatal`.
    FATAL = 2 => "fatal",
}

code_point! {
    /// An alert description (`AlertDescription`, one byte).
    AlertDescription(u8), "{}";
    /// `close_notify`.
    CLOSE_NOTIFY = 0 => "close_notify",
    /// `unexpected_message`.
    UNEXPECTED_MESSAGE = 10 => "unexpected_message",
    /// `bad_record_mac`.
    BAD_RECORD_MAC = 20 => "bad_record_mac",
    /// `record_overflow`.
    RECORD_OVERFLOW = 22 => "record_overflow",
    /// `decompression_failure` (TLS 1.2 and earlier).
    DECOMPRESSION_FAILURE = 30 => "decompression_failure",
    /// `handshake_failure`: often the reply to an unacceptable offer.
    HANDSHAKE_FAILURE = 40 => "handshake_failure",
    /// `no_certificate` (SSL 3.0).
    NO_CERTIFICATE = 41 => "no_certificate",
    /// `bad_certificate`.
    BAD_CERTIFICATE = 42 => "bad_certificate",
    /// `unsupported_certificate`.
    UNSUPPORTED_CERTIFICATE = 43 => "unsupported_certificate",
    /// `certificate_revoked`.
    CERTIFICATE_REVOKED = 44 => "certificate_revoked",
    /// `certificate_expired`.
    CERTIFICATE_EXPIRED = 45 => "certificate_expired",
    /// `certificate_unknown`.
    CERTIFICATE_UNKNOWN = 46 => "certificate_unknown",
    /// `illegal_parameter`.
    ILLEGAL_PARAMETER = 47 => "illegal_parameter",
    /// `unknown_ca`.
    UNKNOWN_CA = 48 => "unknown_ca",
    /// `access_denied`.
    ACCESS_DENIED = 49 => "access_denied",
    /// `decode_error`.
    DECODE_ERROR = 50 => "decode_error",
    /// `decrypt_error`.
    DECRYPT_ERROR = 51 => "decrypt_error",
    /// `export_restriction` (TLS 1.0).
    EXPORT_RESTRICTION = 60 => "export_restriction",
    /// `protocol_version`: the server rejects the offered version.
    PROTOCOL_VERSION = 70 => "protocol_version",
    /// `insufficient_security`.
    INSUFFICIENT_SECURITY = 71 => "insufficient_security",
    /// `internal_error`.
    INTERNAL_ERROR = 80 => "internal_error",
    /// `inappropriate_fallback` ([RFC 7507](https://www.rfc-editor.org/rfc/rfc7507)).
    INAPPROPRIATE_FALLBACK = 86 => "inappropriate_fallback",
    /// `user_canceled`.
    USER_CANCELED = 90 => "user_canceled",
    /// `no_renegotiation` (TLS 1.2 and earlier).
    NO_RENEGOTIATION = 100 => "no_renegotiation",
    /// `missing_extension`.
    MISSING_EXTENSION = 109 => "missing_extension",
    /// `unsupported_extension`.
    UNSUPPORTED_EXTENSION = 110 => "unsupported_extension",
    /// `unrecognized_name`.
    UNRECOGNIZED_NAME = 112 => "unrecognized_name",
    /// `bad_certificate_status_response`.
    BAD_CERTIFICATE_STATUS_RESPONSE = 113 => "bad_certificate_status_response",
    /// `unknown_psk_identity`.
    UNKNOWN_PSK_IDENTITY = 115 => "unknown_psk_identity",
    /// `certificate_required`.
    CERTIFICATE_REQUIRED = 116 => "certificate_required",
    /// `no_application_protocol`.
    NO_APPLICATION_PROTOCOL = 120 => "no_application_protocol",
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grease_values() {
        let grease: Vec<u16> = (0..=0xffff).filter(|&v| is_grease(v)).collect();
        assert_eq!(grease.len(), 16);
        assert_eq!(grease.first(), Some(&0x0a0a));
        assert_eq!(grease.last(), Some(&0xfafa));
        assert!(CipherSuite(0x2a2a).is_grease());
        assert!(!ExtensionType::SERVER_NAME.is_grease());
    }

    #[test]
    fn names_and_display() {
        assert_eq!(ProtocolVersion::TLS_1_3.to_string(), "TLSv1.3");
        assert_eq!(ProtocolVersion(0x7f1c).to_string(), "0x7f1c");
        assert_eq!(ExtensionType(43).name(), Some("supported_versions"));
        assert_eq!(ContentType(99).to_string(), "99");
        assert!(ProtocolVersion::SSL_3_0 < ProtocolVersion::TLS_1_3);
    }
}
