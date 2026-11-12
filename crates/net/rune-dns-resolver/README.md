# rune-dns-resolver

> Async DNS stub resolver over rune-dns-wire: UDP with TCP fallback, DoT and DoH, timeouts, retries and typed lookups

[![crates.io](https://img.shields.io/crates/v/rune-dns-resolver)](https://crates.io/crates/rune-dns-resolver)
[![docs.rs](https://img.shields.io/docsrs/rune-dns-resolver)](https://docs.rs/rune-dns-resolver)
[![license](https://img.shields.io/crates/l/rune-dns-resolver)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

A small async stub resolver for tools that only need lookups, without the
weight of a full resolver library. It sends questions to the recursive
resolvers you choose and keeps timeouts, retries and concurrency in your
hands. Messages are parsed and built by [`rune-dns-wire`](../rune-dns-wire).

| Transport          | Upstream text                         | Feature | Specification |
| ------------------ | ------------------------------------- | ------- | ------------- |
| UDP, TCP on `TC`   | `192.0.2.53`, `udp://[2001:db8::53]`  | `tokio` | [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035), [RFC 7766](https://www.rfc-editor.org/rfc/rfc7766) |
| TCP                | `tcp://192.0.2.53:53`                 | `tokio` | RFC 7766 |
| DNS over TLS       | `tls://1.1.1.1#cloudflare-dns.com`    | `tls`   | [RFC 7858](https://www.rfc-editor.org/rfc/rfc7858) |
| DNS over HTTPS     | `https://dns.google/dns-query`        | `doh`   | [RFC 8484](https://www.rfc-editor.org/rfc/rfc8484), HTTP/2 or HTTP/1.1 |

- Upstreams are tried in order. A timeout, socket error, mismatched answer
  or failure code (`SERVFAIL`, `REFUSED`, ...) moves on to the next one, for
  a configurable number of rounds. `NXDOMAIN` is an answer.
- Answers whose id or question do not match the query are dropped, so an
  off-path spoofer has to guess a random 16-bit id.
- A semaphore caps the queries in flight per resolver.
- Typed lookups (`A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `SOA`, `SRV`,
  `PTR`, `CAA`, and both address families at once) return `rune-dns-wire`
  record data and follow `CNAME` chains in the answer.
- TLS uses rustls with the ring provider and the webpki roots, or a
  `ClientConfig` you supply.
- The `wildcard` feature implements `rune_wildcard_dns::AsyncResolver`, so
  wildcard detection can run over this resolver.

Without features the crate is the sans-I/O core: upstream parsing,
`resolv.conf` reading, query building, response checks and answer
extraction.

Each exchange uses a new socket or connection. Connection reuse for TCP,
TLS and HTTPS is not implemented yet.

## Installation

```toml
[dependencies]
rune-dns-resolver = { version = "0.1", features = ["doh"] }
```

## Usage

```rust
use std::time::Duration;
use rune_dns_resolver::{Error, Resolver, ResolverOptions, Upstream};

async fn mail_hosts() -> Result<(), Error> {
    let options = ResolverOptions::default()
        .with_upstream(Upstream::https("https://cloudflare-dns.com/dns-query")?)
        .with_upstream("tls://9.9.9.9#dns.quad9.net".parse()?)
        .with_upstream("8.8.8.8".parse()?)
        .with_timeout(Duration::from_secs(2))
        .with_attempts(2)
        .with_concurrency(32);
    let resolver = Resolver::new(options)?;

    for mx in resolver.lookup_mx("example.com").await? {
        let addresses = resolver.lookup_ip(&mx.exchange).await?;
        println!("{} {} {addresses:?}", mx.preference, mx.exchange);
    }
    match resolver.lookup_a("does-not-exist.example.com").await {
        Err(Error::NxDomain { name }) => println!("{name}: no such name"),
        other => println!("{other:?}"),
    }
    Ok(())
}
```

## Tests

The integration tests run mock DNS servers on `127.0.0.1` (UDP, TCP, TLS
and HTTPS with a test CA) and need no network. Tests against public
resolvers are behind the `online` feature and ignored by default:

```bash
cargo test -p rune-dns-resolver --features online -- --ignored
```

## License

MIT
