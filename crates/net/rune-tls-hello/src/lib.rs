//! Sans-I/O TLS record and `ClientHello`/`ServerHello` parser and builder.
//!
//! This crate reads and writes the unencrypted start of a TLS handshake:
//! records, handshake framing, and the `ClientHello` and `ServerHello` with
//! their extensions (SNI, ALPN, supported versions and groups, signature
//! algorithms, key shares, and any other extension as raw bytes). It does no
//! I/O and no cryptography: structure only. Typical uses:
//!
//! - **SNI routing.** A proxy peeks at the first bytes of a connection
//!   with [`ClientHello::parse_records`] and reads
//!   [`ClientHello::server_name`].
//! - **Fingerprinting.** Hellos keep every field in wire order, GREASE
//!   included, which is what JA3 and JA4 hash.
//! - **Probing.** [`ClientHello::new`] and its `with_*` methods build any
//!   hello, including SSL 3.0 and TLS 1.0 offers that modern TLS libraries
//!   refuse to send, and [`MessageReader`] reads the server's `ServerHello` or
//!   alert.
//!
//! Parsing then encoding gives back the same bytes, and every input is
//! bounds-checked: malformed bytes give an [`Error`], never a panic.
//!
//! Specifications: TLS 1.3 [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446),
//! TLS 1.2 [RFC 5246](https://www.rfc-editor.org/rfc/rfc5246), TLS 1.1
//! [RFC 4346](https://www.rfc-editor.org/rfc/rfc4346), TLS 1.0
//! [RFC 2246](https://www.rfc-editor.org/rfc/rfc2246), SSL 3.0
//! [RFC 6101](https://www.rfc-editor.org/rfc/rfc6101), extensions
//! [RFC 6066](https://www.rfc-editor.org/rfc/rfc6066), ALPN
//! [RFC 7301](https://www.rfc-editor.org/rfc/rfc7301), GREASE
//! [RFC 8701](https://www.rfc-editor.org/rfc/rfc8701). Not covered: SSL 2.0
//! hellos (reported as [`Error::Sslv2`]) and DTLS.
//!
//! # Example
//!
//! ```
//! use rune_tls_hello::{
//!     CipherSuite, ClientHello, Extension, NamedGroup, ProtocolVersion,
//! };
//!
//! // Build a hello, as a client or probe would send it.
//! let hello = ClientHello::new()
//!     .with_random([0x42; 32])
//!     .with_cipher_suites([CipherSuite::TLS_AES_128_GCM_SHA256, CipherSuite(0xc02f)])
//!     .with_extension(Extension::server_name("example.com")?)
//!     .with_extension(Extension::alpn(["h2", "http/1.1"])?)
//!     .with_extension(Extension::supported_groups(&[NamedGroup::X25519])?)
//!     .with_extension(Extension::supported_versions(&[
//!         ProtocolVersion::TLS_1_3,
//!         ProtocolVersion::TLS_1_2,
//!     ])?);
//! let wire = hello.to_records(ProtocolVersion::TLS_1_0, 16_384)?;
//!
//! // Parse it back from the stream, as a server or proxy would.
//! let parsed = ClientHello::parse_records(&wire)?;
//! assert_eq!(parsed, hello);
//! assert_eq!(parsed.server_name(), Some("example.com"));
//! assert_eq!(parsed.max_version(), ProtocolVersion::TLS_1_3);
//! assert_eq!(parsed.alpn_protocols(), Some(vec![b"h2".to_vec(), b"http/1.1".to_vec()]));
//!
//! // A truncated stream asks for more bytes instead of failing.
//! assert!(ClientHello::parse_records(&wire[..10]).unwrap_err().is_incomplete());
//! # Ok::<(), rune_tls_hello::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod codec;
mod error;
mod extension;
mod handshake;
mod hello;
mod record;
mod types;

pub use error::Error;
pub use extension::{Extension, ExtensionData, HelloKind, KeyShareEntry, ServerName};
pub use handshake::{
    DEFAULT_MAX_HANDSHAKE_LEN, HANDSHAKE_HEADER_LEN, HandshakeMessage, Message, MessageReader,
};
pub use hello::{
    ClientHello, DowngradeSentinel, HELLO_RETRY_REQUEST_RANDOM, MAX_SESSION_ID_LEN, ServerHello,
};
pub use record::{
    Alert, MAX_FRAGMENT_LEN, MAX_PLAINTEXT_LEN, RECORD_HEADER_LEN, Record, encode_records,
};
pub use types::{
    AlertDescription, AlertLevel, CipherSuite, ContentType, ExtensionType, HandshakeType,
    NamedGroup, ProtocolVersion, SignatureScheme, is_grease,
};
