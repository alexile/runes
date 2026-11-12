# rune-probe-ldap

> Read-only LDAP probe: rootDSE read, StartTLS offer and opt-in anonymous-bind detection

[![crates.io](https://img.shields.io/crates/v/rune-probe-ldap)](https://crates.io/crates/rune-probe-ldap)
[![docs.rs](https://img.shields.io/docsrs/rune-probe-ldap)](https://docs.rs/rune-probe-ldap)
[![license](https://img.shields.io/crates/l/rune-probe-ldap)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

LDAP probes for [`rune-service-probe`](../rune-service-probe): sans-I/O
sessions that run in memory, over tokio, over a TLS stream you opened, or
in your own I/O loop.

| Probe                            | Id               | Sends                                                    | Learns                                                                       |
| -------------------------------- | ---------------- | -------------------------------------------------------- | ---------------------------------------------------------------------------- |
| `LdapProbe`                      | `ldap`           | one root DSE search, no bind                             | product, naming contexts, LDAP versions, SASL mechanisms, StartTLS, AD functional levels, DNS host name |
| `LdapAnonymousProbe` (intrusive) | `ldap-anonymous` | root DSE search, anonymous bind, one-entry search, unbind | whether anonymous binds are accepted and the directory is readable           |

Every LDAPv3 server serves its root DSE to anonymous clients
([RFC 4512 §5.1](https://www.rfc-editor.org/rfc/rfc4512#section-5.1)), so
`LdapProbe` only asks for what the server publishes. `LdapAnonymousProbe`
binds anonymously ([RFC 4513 §5.1.1](https://www.rfc-editor.org/rfc/rfc4513#section-5.1.1))
and checks whether one entry below the default naming context is visible,
with no attributes requested. Because it authenticates it is declared
`Safety::Intrusive`, and runners refuse it unless
`Options::with_allow_intrusive(true)` is set.

Findings (check id, CWE):

- `ldap.tls_not_offered` (319): plain LDAP without StartTLS
- `ldap.ldapv2_enabled` (477): the obsolete LDAPv2 is accepted
- `ldap.anonymous_read` (306): an anonymous search returned an entry (intrusive probe)
- `ldap.anonymous_bind` (1390): anonymous binds are accepted, no entry visible (intrusive probe)

The LDAP message codec (`Message`, `parse_message`) is public and
symmetric ([RFC 4511](https://www.rfc-editor.org/rfc/rfc4511)): binds,
searches and their replies decode and encode, for packet captures, mock
servers and callback listeners.

## Installation

```bash
cargo add rune-probe-ldap
cargo add rune-service-probe --features tokio   # for the async Runner
```

## Usage

```rust
use rune_probe_ldap::{LdapAnonymousProbe, LdapProbe};
use rune_service_probe::{Options, Runner, Target};

async fn audit(addr: std::net::SocketAddr) {
    let target = Target::from_addr(addr);
    let runner = Runner::new(Options::default());
    if let Ok(info) = runner.probe(&LdapProbe::new(), &target).await {
        println!("{:?} tls={:?} {:?}", info.product, info.tls, info.details.get("ldap.naming_contexts"));
    }

    // Only with authorisation to test authentication.
    let intrusive = Runner::new(Options::default().with_allow_intrusive(true));
    if let Ok(info) = intrusive.probe(&LdapAnonymousProbe::new(), &target).await {
        for finding in &info.findings {
            println!("{} {}", finding.check_id, finding.title);
        }
    }
}
```

The codec works on bytes you already have:

```rust
use rune_probe_ldap::{LdapResult, Message, Op, ResultCode};

let bytes = [0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00];
let msg = Message::decode(&bytes).unwrap();
assert_eq!(msg.op, Op::BindResponse(LdapResult::new(ResultCode::SUCCESS)));
assert_eq!(msg.encode(), bytes);
```

## License

MIT
