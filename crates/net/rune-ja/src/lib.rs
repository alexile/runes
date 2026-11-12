//! JA3/JA3S and JA4/JA4S/JA4H/JA4T fingerprints of TLS, HTTP and TCP
//! clients and servers.
//!
//! Fingerprints identify the software on either end of a connection from
//! the unencrypted start of it: the TLS `ClientHello` and `ServerHello`, the
//! HTTP request headers, the TCP SYN. They are used to recognise clients
//! (browsers, libraries, scanners, malware), servers and CDN fronts, and to
//! let a scanner recognise its own traffic.
//!
//! | Scheme | Input | Function |
//! | --- | --- | --- |
//! | JA3 | [`ClientHello`](rune_tls_hello::ClientHello) | [`ja3`] |
//! | JA3S | [`ServerHello`](rune_tls_hello::ServerHello) | [`ja3s`] |
//! | JA4 | `ClientHello` | [`ja4`], [`ja4_with`] |
//! | JA4S | `ServerHello` | [`ja4s`], [`ja4s_with`] |
//! | JA4H | [`HttpRequest`] | [`ja4h`], [`ja4h_original`] |
//! | JA4T | [`TcpSyn`] | [`ja4t`] |
//!
//! Every TLS and HTTP fingerprint comes as a [`Fingerprint`] with both the
//! raw string and the hashed form. Hellos come from
//! [`rune_tls_hello`], which parses them from the wire. [`Database`] maps
//! known fingerprints to labels.
//!
//! The crate is sans-I/O: it never touches a socket or a capture file.
//! Computing a fingerprint cannot fail; only the small parsers
//! ([`HttpRequest::parse_http1`], [`TcpSyn::parse_options`],
//! [`Database::parse`]) return an [`Error`].
//!
//! Specifications: JA3 and JA3S <https://github.com/salesforce/ja3>; JA4
//! <https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md>;
//! JA4S, JA4H and JA4T, the `FoxIO` JA4+ documentation and reference
//! implementation <https://github.com/FoxIO-LLC/ja4>. JA4+ (everything but
//! JA3, JA3S and JA4) is licensed by `FoxIO` under the `FoxIO` License 1.1;
//! see the README.
//!
//! # Example
//!
//! ```
//! use rune_ja::{ja3, ja4};
//! use rune_tls_hello::{CipherSuite, ClientHello, Extension, ProtocolVersion, SignatureScheme};
//!
//! // The bytes a client sent, as a proxy or capture would see them.
//! let wire = ClientHello::new()
//!     .with_cipher_suites([CipherSuite(0x0a0a), CipherSuite(0x1301), CipherSuite(0xc02f)])
//!     .with_extension(Extension::server_name("example.com")?)
//!     .with_extension(Extension::alpn(["h2", "http/1.1"])?)
//!     .with_extension(Extension::supported_versions(&[
//!         ProtocolVersion::TLS_1_3,
//!         ProtocolVersion::TLS_1_2,
//!     ])?)
//!     .with_extension(Extension::signature_algorithms(&[SignatureScheme(0x0403)])?)
//!     .to_records(ProtocolVersion::TLS_1_0, 16_384)?;
//!
//! let hello = ClientHello::parse_records(&wire)?;
//! let fp = ja4(&hello);
//! assert_eq!(fp.raw, "t13d0204h2_1301,c02f_000d,002b_0403");
//! assert_eq!(fp.hash, "t13d0204h2_c1929292aa6b_3953dc75acc4");
//! assert_eq!(ja3(&hello).raw, "771,4865-49199,0-16-43-13,,");
//! # Ok::<(), rune_tls_hello::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod db;
mod error;
mod fingerprint;
mod ja3;
mod ja4;
mod ja4h;
mod ja4t;

pub use db::{BUILTIN, Database, Kind};
pub use error::Error;
pub use fingerprint::Fingerprint;
pub use ja3::{ja3, ja3s};
pub use ja4::{
    Ja4Options, Order, Transport, alpn_code, ja4, ja4_with, ja4s, ja4s_with, version_code,
};
pub use ja4h::{HttpRequest, HttpVersion, ja4h, ja4h_original};
pub use ja4t::{TcpSyn, ja4t};

/// The README's examples, compiled and run as doctests.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
