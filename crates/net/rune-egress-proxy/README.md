# rune-egress-proxy

> Allowlisted, default-deny HTTP CONNECT egress proxy: host/CIDR allowlists, SSRF guard against non-global addresses, and DNS pinning

[![crates.io](https://img.shields.io/crates/v/rune-egress-proxy)](https://crates.io/crates/rune-egress-proxy)
[![docs.rs](https://img.shields.io/docsrs/rune-egress-proxy)](https://docs.rs/rune-egress-proxy)
[![license](https://img.shields.io/crates/l/rune-egress-proxy)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

A sandboxed process (an AI coding agent, a build, a test runner) gets one
way out: an HTTP `CONNECT` proxy that only opens tunnels to targets a
`Policy` allows. Everything else gets `403`.

- **Host allowlist** ([`rune-host-match`](../../common/rune-host-match)):
  exact names and `*.suffix` for subdomains, never the apex.
  `*.github.com` allows `api.github.com`, not `github.com` or
  `evilgithub.com`.
- **IP allowlist** ([`rune-cidr`](../../common/rune-cidr)): addresses or
  CIDR ranges. An IP-literal target is allowed only through this list;
  being a public address is not enough.
- **SSRF guard and DNS pinning** ([`rune-ip`](../rune-ip)): an allowed
  hostname is resolved once, and the proxy connects to the first address
  that is globally reachable or IP-allowlisted, never re-resolving. An
  allowed name whose DNS answer points at `169.254.169.254`, loopback,
  RFC 1918 or other non-global space is refused (mapped and NAT64 forms
  included).
- Optional port allowlist; request heads bounded in size (8 KiB) and time.

The parser and the policy are sans-I/O. `Proxy` serves them over TCP or a
Unix domain socket, one thread per connection. Extracted from
`rune-secops-warden`'s network proxy.

## Installation

```toml
[dependencies]
rune-egress-proxy = "0.1"
```

The `rune-egress-proxy` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-egress-proxy --features cli
```

## Usage

### Library

```rust
use std::net::TcpListener;
use rune_egress_proxy::{Decision, Denial, Policy, Proxy, Target};

let policy = Policy::new()
    .allow_hosts(["api.anthropic.com", "*.github.com"])?
    .allow_ip("10.0.0.0/8")?
    .allow_port(443);

// The decision is plain values, no I/O.
let apex: Target = "github.com:443".parse()?;
assert_eq!(policy.decide(&apex), Decision::Deny(Denial::HostNotAllowed));
let rebind = ["169.254.169.254:443".parse()?];
assert_eq!(policy.pin(rebind), Err(Denial::NoAllowedAddress));

// Serve it.
let proxy = Proxy::new(policy).with_observer(|event| eprintln!("egress: {event}"));
proxy.serve_tcp(&TcpListener::bind("127.0.0.1:3128")?);
```

Point clients at it with `HTTPS_PROXY=http://127.0.0.1:3128`. For a hard
boundary, run the client in a network namespace with no route out and
bind-mount a Unix socket served by `Proxy::serve_unix` into it.

### CLI

```bash
rune-egress-proxy --listen 127.0.0.1:3128 \
  --allow-host api.anthropic.com --allow-host '*.github.com' \
  --allow-ip 10.0.0.0/8 --allow-port 443
# listening on 127.0.0.1:3128
# tunnel CONNECT api.github.com:443 via 140.82.112.6:443
# denied CONNECT github.com:443: host not in the host allowlist
```

## Limits

This is a tunnel, not a firewall: it constrains only clients that use it
and cannot see inside TLS. Only the `CONNECT` target is checked, not the
TLS SNI or `Host` inside the tunnel, so an allowed name on a shared CDN can
reach other sites on that CDN (domain fronting). Only `CONNECT` is
supported; plain-HTTP forwarding (`GET http://…`) gets `501`. Open tunnels
have no idle timeout.

## License

MIT
