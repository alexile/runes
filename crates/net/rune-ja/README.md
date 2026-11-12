# rune-ja

> JA3/JA3S and JA4/JA4S/JA4H/JA4T TLS, HTTP and TCP client/server fingerprints

[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

Computes the JA3 family and the JA4+ family of fingerprints from the
unencrypted start of a connection, so you can recognise clients (browsers,
libraries, scanners, malware), servers and CDN fronts without decrypting
anything.

| Scheme | Fingerprints | From |
| --- | --- | --- |
| JA3 / JA3S | TLS client / server, MD5 | `rune_tls_hello::ClientHello` / `ServerHello` |
| JA4 / JA4S | TLS client / server | `ClientHello` / `ServerHello` |
| JA4H | HTTP client | `HttpRequest` (HTTP/1 head parser included; HTTP/2 and HTTP/3 header lists) |
| JA4T | TCP client | `TcpSyn` (TCP options parser included) |

- **Raw and hashed forms.** Every TLS and HTTP fingerprint comes with the
  string that was hashed (`JA3` full string, `JA4_r`) and the shared form
  (`JA3` MD5, `JA4`). JA4 and JA4H also have their wire-order variants
  (`JA4_o`, `JA4H_o`).
- **QUIC and DTLS** markers for JA4 and JA4S.
- **A small fingerprint database** with a lookup, a plain-text list format,
  and a few published examples built in.
- **Sans-I/O**: no sockets, no capture files. Pair it with
  `rune-tls-hello` to read hellos off the wire.

Checked against the published reference vectors: the JA3 README examples,
the JA4 technical-details worked example (sorted and original order), the
JA4H example of the FoxIO reference implementation, and the JA4, JA4S,
JA4H and JA4T values FoxIO publishes for its test captures.

## Installation

```toml
[dependencies]
rune-ja = "0.1"
rune-tls-hello = "0.1"
```

## Usage

### Fingerprint a ClientHello

```rust
use rune_ja::{ja3, ja4};
use rune_tls_hello::{CipherSuite, ClientHello, Extension, ProtocolVersion, SignatureScheme};

# let first_bytes = ClientHello::new()
#     .with_cipher_suites([CipherSuite(0x1301), CipherSuite(0xc02f)])
#     .with_extension(Extension::server_name("example.com")?)
#     .with_extension(Extension::alpn(["h2"])?)
#     .with_extension(Extension::supported_versions(&[ProtocolVersion::TLS_1_3])?)
#     .with_extension(Extension::signature_algorithms(&[SignatureScheme(0x0403)])?)
#     .to_records(ProtocolVersion::TLS_1_0, 16_384)?;
let hello = ClientHello::parse_records(&first_bytes)?;

let fp = ja4(&hello);
println!("JA4   {}", fp.hash); // t13d0204h2_c1929292aa6b_3953dc75acc4
println!("JA4_r {}", fp.raw);  // t13d0204h2_1301,c02f_000d,002b_0403
println!("JA3   {}", ja3(&hello).hash);
# assert_eq!(fp.hash, "t13d0204h2_c1929292aa6b_3953dc75acc4");
# Ok::<(), rune_tls_hello::Error>(())
```

`ja4_with(&hello, Ja4Options::default().with_transport(Transport::Quic))`
gives the QUIC form, and `.with_order(Order::Original)` the wire-order
`JA4_o`. `ja3s` and `ja4s` take a `ServerHello`.

### HTTP requests and TCP SYNs

```rust
use rune_ja::{HttpRequest, TcpSyn, ja4h, ja4t};

let request = HttpRequest::parse_http1(
    b"GET / HTTP/1.1\r\nHost: example.com\r\nAccept-Language: en-US\r\nCookie: a=1\r\n\r\n",
)?;
assert_eq!(ja4h(&request).raw, "ge11cn02enus_Host,Accept-Language_a_a=1");

// The window and option bytes of the client's SYN.
let syn = TcpSyn::parse_options(64240, &[2, 4, 0x05, 0xb4, 1, 3, 3, 8, 1, 1, 4, 2])?;
assert_eq!(ja4t(&syn), "64240_2-1-3-1-1-4_1460_8");
# Ok::<(), rune_ja::Error>(())
```

For HTTP/2 and HTTP/3, build the request from the decoded header list with
`HttpRequest::new(method, HttpVersion::Http2).with_header(name, value)`;
pseudo-headers are skipped.

### Look fingerprints up

```rust
use rune_ja::{Database, Kind};

let mut db = Database::builtin();
db.extend_from_list("\
ja4,t13d1516h2_8daaf6152771_02713d6af862,Chrome on our build agents
")?;
assert_eq!(
    db.lookup(Kind::Ja4, "t13d1516h2_8daaf6152771_e5627efa2ab1"),
    ["Chromium-based browser"]
);
# Ok::<(), rune_ja::Error>(())
```

## Notes

- **ALPN.** JA4 takes the first and last character of the first ALPN
  value, or of its hex form when either byte is not an ASCII alphanumeric,
  as the specification says. The FoxIO Rust tool instead prints `9` for
  non-ASCII characters, so a GREASE ALPN value such as `0xbaad` gives `bd`
  here and `99` there.
- **JA4H cookies** are split on `"; "` as the reference implementation
  does, and every `Cookie` field counts (HTTP/2 often sends several).
- **JA4T** keeps each `NOP` and trailing `EOL` byte in the option list, as
  captures show them (`2-1-3-1-1-8-4-0-0`).

## Licensing

This crate is MIT-licensed and contains no FoxIO code. The fingerprint
methods themselves are not all free to use, though:

- **JA3 and JA3S** (Salesforce) and **JA4** (FoxIO) are published under
  BSD-3-Clause.
- **JA4S, JA4H and JA4T** are part of FoxIO's JA4+ suite, which FoxIO
  licenses under the [FoxIO License 1.1](https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE)
  (non-commercial use; commercial use needs a licence from FoxIO) and
  describes as patent pending.

Check the FoxIO terms before using `ja4s`, `ja4h` or `ja4t` in a
commercial product or service. The crate is unpublished until that
question is settled.
