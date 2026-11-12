# rune-rdap

> RDAP client for domains, IP networks and ASNs with IANA bootstrap (RFC 9224), typed responses, caching and rate limiting

[![crates.io](https://img.shields.io/crates/v/rune-rdap)](https://crates.io/crates/rune-rdap)
[![docs.rs](https://img.shields.io/docsrs/rune-rdap)](https://docs.rs/rune-rdap)
[![license](https://img.shields.io/crates/l/rune-rdap)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

RDAP is the structured, JSON successor of WHOIS. This crate finds the right
server for a query and turns its answer into typed data: registrar, dates,
nameservers, entities with their contact details, and status.

| Piece | What it does | Specification |
| --- | --- | --- |
| `Query` | Parses `example.com`, `8.8.8.8`, `2001:db8::/32`, `AS15169`, `ZG39-ARIN`; renders the RDAP path | [RFC 9082](https://www.rfc-editor.org/rfc/rfc9082) |
| `bootstrap` | Parses the IANA `dns`/`ipv4`/`ipv6`/`asn`/`object-tags` registries and routes queries (longest suffix, longest prefix, ASN range, object tag) | [RFC 9224](https://www.rfc-editor.org/rfc/rfc9224), [RFC 8521](https://www.rfc-editor.org/rfc/rfc8521) |
| `response`, `model` | Classifies responses (object, redirect, 404, 429, error body) and parses domain, IP network, autnum, nameserver and entity objects, jCard contacts included | [RFC 7480](https://www.rfc-editor.org/rfc/rfc7480), [RFC 9083](https://www.rfc-editor.org/rfc/rfc9083), [RFC 7095](https://www.rfc-editor.org/rfc/rfc7095) |
| `cache`, `ratelimit` | Clock-driven TTL cache and per-host request spacer | |
| `client` (feature) | Ties it together over any HTTP transport | |

The core is sans-I/O: parsing and routing work on bytes and values, and the
cache and rate limiter are told the time. Parsing is lenient (unknown
members are ignored, malformed list items skipped) and bounded (4 MiB
bodies). Dates are returned as the RFC 3339 strings the server sent.

Features:

- `client`: `client::Client`, which loads and caches the bootstrap files,
  prefers `https` base URLs and falls back to the others on transport
  errors, follows redirects (`http(s)` only, up to a limit), spaces requests
  per host, retries after `429 Retry-After`, and caches objects for their
  `Cache-Control: max-age` (or a default). You supply the transport by
  implementing `client::Fetcher`. Needs Tokio's timer.
- `reqwest`: `client::ReqwestFetcher`, a ready-made `Fetcher`.
- `cli`: the `rune-rdap` command-line tool.

## Installation

```toml
[dependencies]
rune-rdap = { version = "0.1", features = ["reqwest"] }
```

The `rune-rdap` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-rdap --features cli
```

## Usage

### Library

With the client:

```rust,no_run
use rune_rdap::client::{Client, Options, ReqwestFetcher};
use rune_rdap::model::Role;

# async fn demo() -> Result<(), Box<dyn std::error::Error>> {
let client = Client::new(ReqwestFetcher::new()?, Options::default());

let found = client.lookup_str("example.com").await?;
if let Some(domain) = found.object.as_domain() {
    println!("registrar: {:?}", domain.registrar_name());
    println!("expires:   {:?}", domain.expiration());
    for ns in domain.nameserver_names() {
        println!("ns:        {ns}");
    }
}

let net = client.lookup_str("8.8.8.8").await?;
if let Some(net) = net.object.as_ip_network() {
    println!("{:?} abuse: {:?}", net.name, net.abuse_email());
    println!("registrant: {:?}", net.entity_with_role(&Role::Registrant).and_then(|e| e.handle.as_deref()));
}
# Ok(())
# }
```

Sans-I/O, with your own HTTP stack:

```rust
use rune_rdap::bootstrap::{Bootstrap, Registry, RegistryKind};
use rune_rdap::response::{Outcome, Response, interpret};
use rune_rdap::Query;

let asn = br#"{"version":"1.0","services":[[["15169"],["https://rdap.arin.net/registry/"]]]}"#;
let bootstrap = Bootstrap::new().with(Registry::parse(RegistryKind::Asn, asn)?);
let url = &bootstrap.urls(&Query::parse("AS15169")?)?[0];
assert_eq!(url, "https://rdap.arin.net/registry/autnum/15169");

// GET it with `Accept: application/rdap+json`, then hand over the answer.
let body = r#"{"objectClassName":"autnum","handle":"AS15169","name":"GOOGLE",
               "startAutnum":15169,"endAutnum":15169}"#;
match interpret(&Response::new(200, body))? {
    Outcome::Object(obj) => assert_eq!(obj.as_autnum().unwrap().name.as_deref(), Some("GOOGLE")),
    Outcome::Redirect(location) => println!("follow {location}"),
    _ => {}
}
# Ok::<(), rune_rdap::Error>(())
```

### CLI

```bash
rune-rdap example.com AS15169 8.8.8.8
rune-rdap --nameserver a.iana-servers.net
```

Each query prints its class, handle, key fields, status, events and
entities.

## License

MIT
