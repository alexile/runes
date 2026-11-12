# rune-ip

> IPv4/IPv6 classification per the IANA special-purpose registries (global, private, bogon, scope) with SSRF-safe mapped-address unwrapping

[![crates.io](https://img.shields.io/crates/v/rune-ip)](https://crates.io/crates/rune-ip)
[![docs.rs](https://img.shields.io/docsrs/rune-ip)](https://docs.rs/rune-ip)
[![license](https://img.shields.io/crates/l/rune-ip)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

SSRF guards, scope checks and egress filters all need to know whether an
address is private, loopback, link-local, multicast, reserved,
documentation, carrier-grade NAT or a bogon. `rune-ip` answers from the
IANA [IPv4](https://www.iana.org/assignments/iana-ipv4-special-registry/)
and [IPv6](https://www.iana.org/assignments/iana-ipv6-special-registry/)
Special-Purpose Address Registries (RFC 6890), RFC 4291/4007 scopes and
RFC 6598. No dependencies beyond std, no I/O, no global state.

## Installation

```toml
[dependencies]
rune-ip = "0.1"
```

The `rune-ip` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-ip --features cli
```

## Usage

### Library

```rust
use std::net::IpAddr;
use rune_ip::{Category, Scope, category, is_bogon, is_global, is_private, lookup, scope};

let ip: IpAddr = "10.1.2.3".parse().unwrap();
assert!(is_private(ip) && !is_global(ip) && is_bogon(ip));
assert_eq!(category(ip), Category::Private);

// Mapped and compatible IPv6 forms are unwrapped first, and the IPv4
// address inside NAT64 / 6to4 / Teredo addresses must be global too, so
// none of these reach the cloud metadata endpoint.
for s in ["169.254.169.254", "::ffff:169.254.169.254", "64:ff9b::a9fe:a9fe"] {
    assert!(!is_global(s.parse::<IpAddr>().unwrap()));
}
assert_eq!(scope("::ffff:169.254.169.254".parse::<IpAddr>().unwrap()), Scope::Link);

// The registry block and its RFC 6890 attributes.
let block = lookup("100.64.0.1".parse::<IpAddr>().unwrap()).unwrap();
assert_eq!(block.to_string(), "100.64.0.0/10");
assert_eq!(block.rfc(), "RFC 6598");
assert_eq!(block.globally_reachable(), Some(false));
```

| API | What it does |
| --- | --- |
| `is_global` | globally reachable unicast, per the registries' "Globally Reachable" column (most specific block wins) |
| `is_private`, `is_shared`, `is_loopback`, `is_unspecified`, `is_link_local`, `is_documentation`, `is_benchmarking`, `is_multicast`, `is_reserved` | category tests |
| `is_bogon` | martian prefixes that never appear in the global routing table |
| `scope` | `Host`, `Link`, `Realm`, `Admin`, `Site`, `Organization`, `Private`, `Global` or `Reserved` (multicast scopes included) |
| `category`, `lookup`, `matching`, `registry_v4`, `registry_v6` | the registry blocks, with name, RFC and source / destination / forwardable / globally-reachable / reserved-by-protocol attributes |
| `canonical`, `embedded_ipv4` | unwrap IPv4-mapped/compatible IPv6; extract IPv4 from NAT64, 6to4 and Teredo |

Every helper accepts `Ipv4Addr`, `Ipv6Addr` or `IpAddr` and classifies the
canonical (unwrapped) address. An SSRF guard is one line, `is_global(ip)`,
applied to every resolved address before connecting to that same address;
see [`examples/ssrf_guard.rs`](examples/ssrf_guard.rs).

`is_bogon` is a routing notion and differs from `!is_global` at the edges:
`192.0.0.9` (PCP anycast) and `64:ff9b::8.8.8.8` (NAT64) sit inside
non-routed prefixes yet are globally reachable.

### CLI

```bash
rune-ip 10.0.0.1 ::ffff:169.254.169.254 1.1.1.1
# 10.0.0.1	category=private scope=private global=false bogon=true block=10.0.0.0/8 (Private-Use; RFC 1918)
# ::ffff:169.254.169.254	category=link-local scope=link global=false bogon=true canonical=169.254.169.254 embedded=169.254.169.254(Mapped) block=169.254.0.0/16 (Link Local; RFC 3927)
# 1.1.1.1	category=global scope=global global=true bogon=false

# Exit status 1 unless every address is globally reachable.
rune-ip --require-global 8.8.8.8 127.0.0.1
```

## License

MIT
