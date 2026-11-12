# rune-tls-hello

> Sans-I/O TLS record and ClientHello/ServerHello parser and builder (SNI, ALPN, versions, extensions)

[![crates.io](https://img.shields.io/crates/v/rune-tls-hello)](https://crates.io/crates/rune-tls-hello)
[![docs.rs](https://img.shields.io/docsrs/rune-tls-hello)](https://docs.rs/rune-tls-hello)
[![license](https://img.shields.io/crates/l/rune-tls-hello)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

Reads and writes the unencrypted start of a TLS handshake: records,
handshake framing, and the ClientHello and ServerHello with their
extensions. No I/O, no cryptography: structure only.

- **SNI routing**: peek at a connection's first bytes and read the server
  name, with a clear "need more bytes" answer for partial input.
- **Fingerprinting**: hellos keep every field in wire order, GREASE
  included, which is what JA3 and JA4 hash.
- **Probing**: build any ClientHello, including SSL 3.0, TLS 1.0 and 1.1
  offers that modern TLS libraries refuse to send, and read back the
  server's ServerHello, alert, downgrade sentinel or HelloRetryRequest.

Parsing then encoding gives back the same bytes. Every parser is
bounds-checked and property-tested: malformed input gives an
error, never a panic.

## Installation

```toml
[dependencies]
rune-tls-hello = "0.1"
```

## Usage

### Read the SNI from a client's first bytes

```rust
use rune_tls_hello::{ClientHello, Extension, ProtocolVersion};

# let first_bytes = ClientHello::new()
#     .with_extension(Extension::server_name("example.com")?)
#     .to_records(ProtocolVersion::TLS_1_0, 16_384)?;
match ClientHello::parse_records(&first_bytes) {
    Ok(hello) => assert_eq!(hello.server_name(), Some("example.com")),
    Err(err) if err.is_incomplete() => { /* read more and try again */ }
    Err(err) => return Err(err), // not a TLS ClientHello
}
# Ok::<(), rune_tls_hello::Error>(())
```

### Build a legacy ClientHello and read the reply

```rust
use rune_tls_hello::{
    CipherSuite, ClientHello, Extension, HandshakeMessage, Message, MessageReader,
    ProtocolVersion,
};

let hello = ClientHello::new()
    .with_legacy_version(ProtocolVersion::TLS_1_0)
    .with_random([0x5a; 32]) // use a real random value
    .with_cipher_suites([
        CipherSuite(0xc014), // ECDHE-RSA-AES256-SHA
        CipherSuite(0x000a), // DES-CBC3-SHA
        CipherSuite::TLS_FALLBACK_SCSV,
    ])
    .with_extension(Extension::server_name("example.com")?)
    .with_extension(Extension::renegotiation_info(&[])?);
let to_send = hello.to_records(ProtocolVersion::TLS_1_0, 16_384)?;
# let _ = to_send;

// Feed whatever the server sends back, as it arrives.
let mut reader = MessageReader::new();
# reader.feed(&[21, 3, 1, 0, 2, 2, 86]);
while let Some(message) = reader.next_message()? {
    match message {
        Message::Handshake(HandshakeMessage::ServerHello(server)) => {
            println!("accepted {} with {}", server.selected_version(), server.cipher_suite);
        }
        Message::Alert(alert) => println!("refused: {}", alert.description),
        _ => {}
    }
}
# Ok::<(), rune_tls_hello::Error>(())
```

## What is covered

| Layer | Types |
| --- | --- |
| Records ([RFC 8446 §5.1](https://www.rfc-editor.org/rfc/rfc8446#section-5.1)) | `Record`, `encode_records`, `Alert` |
| Handshake framing | `HandshakeMessage`, `MessageReader` (reassembly across records) |
| Hellos | `ClientHello`, `ServerHello` (incl. HelloRetryRequest and downgrade sentinels) |
| Typed extensions | `server_name`, `supported_groups`, `ec_point_formats`, `signature_algorithms(_cert)`, ALPN, `supported_versions`, `key_share`, `renegotiation_info`, `extended_master_secret`, `encrypt_then_mac` |
| Code points | `ProtocolVersion`, `CipherSuite`, `ExtensionType`, `NamedGroup`, `SignatureScheme`, … with IANA names and GREASE detection |

Any other extension is kept as raw bytes. SSL 2.0 hellos are detected and
rejected; DTLS is not covered.

Specifications: [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) (TLS 1.3),
[RFC 5246](https://www.rfc-editor.org/rfc/rfc5246) (TLS 1.2),
[RFC 4346](https://www.rfc-editor.org/rfc/rfc4346) (TLS 1.1),
[RFC 2246](https://www.rfc-editor.org/rfc/rfc2246) (TLS 1.0),
[RFC 6101](https://www.rfc-editor.org/rfc/rfc6101) (SSL 3.0),
[RFC 6066](https://www.rfc-editor.org/rfc/rfc6066) (extensions),
[RFC 7301](https://www.rfc-editor.org/rfc/rfc7301) (ALPN),
[RFC 7507](https://www.rfc-editor.org/rfc/rfc7507) (fallback SCSV),
[RFC 8701](https://www.rfc-editor.org/rfc/rfc8701) (GREASE).

## Testing

Besides unit tests, `tests/fixtures.rs` checks hellos captured over
loopback from OpenSSL 3.5 (TLS 1.0, 1.1, 1.2 and 1.3, a HelloRetryRequest,
a downgrade sentinel, `protocol_version` and `inappropriate_fallback`
alerts) and GnuTLS; each must re-encode to the captured bytes.
`tests/fixtures/capture.py` regenerates them. `tests/proptest.rs` holds
round-trip properties.

## License

MIT
