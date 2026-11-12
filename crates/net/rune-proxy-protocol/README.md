# rune-proxy-protocol

> HAProxy PROXY protocol v1 (text) and v2 (binary, TLVs) sans-I/O decoder and encoder, with an optional tokio adapter

[![crates.io](https://img.shields.io/crates/v/rune-proxy-protocol)](https://crates.io/crates/rune-proxy-protocol)
[![docs.rs](https://img.shields.io/docsrs/rune-proxy-protocol)](https://docs.rs/rune-proxy-protocol)
[![license](https://img.shields.io/crates/l/rune-proxy-protocol)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

A load balancer that relays a connection prepends a
[PROXY protocol](https://www.haproxy.org/download/3.0/doc/proxy-protocol.txt)
header so the backend can recover the real client address. This crate
decodes and encodes both versions:

- **v1**: `PROXY TCP4|TCP6|UNKNOWN …\r\n`, at most 107 bytes, strict field
  checks (single spaces, canonical ports, CRLF).
- **v2**: the binary block, for `LOCAL` and `PROXY`, IPv4/IPv6/UNIX
  addresses over stream or datagram transports, plus TLV extensions with
  typed accessors (`ALPN`, `AUTHORITY`, `UNIQUE_ID`, `NETNS`, `SSL` and its
  sub-TLVs). A `CRC32C` TLV is verified on decode and computed on encode.

The core is sans-I/O: `decode` works on a byte buffer, returns `Ok(None)`
while the header is incomplete and reports how many bytes it took. The
`tokio` feature adds `read_header` / `write_header` for async streams;
`read_header` never reads past the header.

Only accept PROXY headers from peers you trust: whoever can send one can
claim any client address.

## Installation

```toml
[dependencies]
rune-proxy-protocol = "0.1"
# or, with the async adapter:
rune-proxy-protocol = { version = "0.1", features = ["tokio"] }
```

## Usage

### Decoding

```rust
use rune_proxy_protocol::{Version, decode};

let input = b"PROXY TCP4 192.0.2.10 198.51.100.1 51234 443\r\nGET / HTTP/1.1\r\n";
let parsed = decode(input)?.expect("complete header");
assert_eq!(parsed.version, Version::V1);
assert_eq!(parsed.header.source(), Some("192.0.2.10:51234".parse()?));
let payload = &input[parsed.len..];
assert_eq!(payload, b"GET / HTTP/1.1\r\n");
# Ok::<(), Box<dyn std::error::Error>>(())
```

### Encoding v2 with TLVs

```rust
use rune_proxy_protocol::{Header, Ssl, Tlv, decode, tlv};

let ssl = Ssl::new(tlv::PP2_CLIENT_SSL, 0)
    .with_sub_tlv(Tlv::new(tlv::PP2_SUBTYPE_SSL_VERSION, "TLSv1.3"));
let header = Header::tcp("203.0.113.9:40123".parse()?, "10.0.0.5:8443".parse()?)
    .expect("same IP family")
    .with_tlv(Tlv::new(tlv::PP2_TYPE_ALPN, "h2"))
    .with_tlv(ssl.to_tlv()?)
    .with_crc32c();
let bytes = header.encode_v2()?;

let back = decode(&bytes)?.expect("complete header").header;
assert_eq!(back.alpn(), Some(&b"h2"[..]));
assert_eq!(back.ssl().transpose()?.and_then(|s| s.version().map(str::to_owned)).as_deref(), Some("TLSv1.3"));
# Ok::<(), Box<dyn std::error::Error>>(())
```

### Tokio

```rust,no_run
# async fn serve(listener: tokio::net::TcpListener) -> Result<(), Box<dyn std::error::Error>> {
use rune_proxy_protocol::tokio::read_header;
use std::time::Duration;

let (mut stream, peer) = listener.accept().await?;
let parsed = tokio::time::timeout(Duration::from_secs(5), read_header(&mut stream)).await??;
let client = parsed.header.source().unwrap_or(peer);
// `stream` now yields the application data.
# Ok(()) }
```

## License

MIT
