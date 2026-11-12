# rune-socks

> SOCKS4/4a/5 sans-I/O codecs (CONNECT, BIND, UDP ASSOCIATE, username/password, GSSAPI framing) with tokio client and server

[![crates.io](https://img.shields.io/crates/v/rune-socks)](https://crates.io/crates/rune-socks)
[![docs.rs](https://img.shields.io/docsrs/rune-socks)](https://docs.rs/rune-socks)
[![license](https://img.shields.io/crates/l/rune-socks)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

SOCKS4, SOCKS4a and SOCKS5 ([RFC 1928](https://www.rfc-editor.org/rfc/rfc1928))
for both ends of a connection.

- **Sans-I/O codecs** for every message: SOCKS4/4a requests and replies,
  SOCKS5 method negotiation, `CONNECT` / `BIND` / `UDP ASSOCIATE` requests
  and replies, the UDP datagram header, username/password authentication
  ([RFC 1929](https://www.rfc-editor.org/rfc/rfc1929)) and GSSAPI message
  framing ([RFC 1961](https://www.rfc-editor.org/rfc/rfc1961)). Decoders
  return `Decoded::Incomplete(n)` with the exact number of bytes still
  needed, so a reader never consumes tunnelled data by accident.
- **`tokio` feature**: a `Client` that dials through a proxy over any stream
  (SOCKS4/4a/5, CONNECT and UDP ASSOCIATE), and a `Server` that forwards
  through a pluggable `Connector` (allowlists, DNS pinning, chaining) with
  optional username/password authentication and a UDP relay.

GSSAPI is framed but not negotiated: the client reports a server that
selects it as `Error::UnsupportedMethod`, and the server never selects it.
`BIND` is encoded and decoded but the server refuses it.

## Installation

```toml
[dependencies]
rune-socks = "0.1"
# or, with the async client and server:
rune-socks = { version = "0.1", features = ["tokio"] }
```

## Usage

### Codecs

```rust
use rune_socks::v5::{Command, Request, UdpHeader};
use rune_socks::{Decoded, TargetAddr};

let wire = Request::new(Command::Connect, TargetAddr::domain("example.com", 443)).encode()?;
assert_eq!(&wire[..5], [5, 1, 0, 3, 11]);
// Feed a reader exactly what it asks for.
assert_eq!(Request::decode(&wire[..2])?, Decoded::Incomplete(1));
let (request, len) = Request::decode(&wire)?.complete().expect("whole request");
assert_eq!((request.target.port(), len), (443, wire.len()));

// UDP ASSOCIATE datagrams carry a small header in front of the payload.
let datagram = UdpHeader::new(TargetAddr::domain("dns.example", 53)).encode_datagram(b"query")?;
let (header, payload) = UdpHeader::decode_datagram(&datagram)?;
assert_eq!((header.target.port(), payload), (53, &b"query"[..]));
# Ok::<(), rune_socks::Error>(())
```

### Client (tokio)

```rust,no_run
# async fn demo() -> Result<(), rune_socks::Error> {
use rune_socks::TargetAddr;
use rune_socks::tokio::Client;
use rune_socks::v5::Credentials;
use tokio::net::TcpStream;

let mut stream = TcpStream::connect("127.0.0.1:1080").await?;
Client::v5()
    .with_credentials(Credentials::new("alice", "secret"))
    .connect(&mut stream, &TargetAddr::domain("example.com", 443))
    .await?;
// `stream` is now a tunnel to example.com:443.
# Ok(()) }
```

### Server (tokio)

```rust,no_run
# async fn demo() -> std::io::Result<()> {
use std::sync::Arc;
use rune_socks::tokio::{Server, TcpConnector};
use rune_socks::v5::Credentials;

let server = Arc::new(
    Server::new(TcpConnector)
        .with_authenticator(|c: &Credentials| c.username == b"alice" && c.password == b"secret")
        .with_udp_relay("127.0.0.1".parse().unwrap()),
);
let listener = tokio::net::TcpListener::bind("127.0.0.1:1080").await?;
loop {
    let (stream, _) = listener.accept().await?;
    let server = Arc::clone(&server);
    tokio::spawn(async move { server.serve_tcp(stream).await });
}
# }
```

`TcpConnector` applies no policy. Before exposing a server beyond loopback,
implement `Connector` to allowlist targets (for example with
`rune-egress-proxy`'s policy) and return `PermissionDenied` for the rest.

## License

MIT
