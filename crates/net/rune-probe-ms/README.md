# rune-probe-ms

> Read-only SMB negotiate (dialect, signing, SMBv1) and RDP security-protocol negotiation probes

[![crates.io](https://img.shields.io/crates/v/rune-probe-ms)](https://crates.io/crates/rune-probe-ms)
[![docs.rs](https://img.shields.io/docsrs/rune-probe-ms)](https://docs.rs/rune-probe-ms)
[![license](https://img.shields.io/crates/l/rune-probe-ms)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

Handshake probes for Windows remote-access services, for
[`rune-service-probe`](../rune-service-probe). Each sends one request,
reads one answer and disconnects: no SMB session is set up and no RDP
logon starts.

| Probe       | Id     | Port     | Sends                                       | Learns                                                                  |
| ----------- | ------ | -------- | ------------------------------------------- | ----------------------------------------------------------------------- |
| `SmbProbe`  | `smb`  | 445      | SMB 2/3 `NEGOTIATE`, dialects 2.0.2 to 3.1.1 | best dialect, signing policy, server GUID, capabilities, 3.1.1 ciphers, SPNEGO mechanisms |
| `Smb1Probe` | `smb1` | 445, 139 | SMB1 `NEGOTIATE` offering only `NT LM 0.12` | whether SMBv1 is enabled, its signing policy, domain and server name     |
| `RdpProbe`  | `rdp`  | 3389     | X.224 Connection Request with `RDP_NEG_REQ` | the security protocol picked or required, NLA enforcement               |

`RdpProbe::new()` requests only Standard RDP Security: a server that
accepts it allows the legacy RC4 security layer without NLA, one that
requires TLS answers `SSL_REQUIRED_BY_SERVER`, and one that enforces NLA
answers `HYBRID_REQUIRED_BY_SERVER`. `RdpProbe::requesting(..)` offers
another set, e.g. to see which protocol the server prefers.

Findings (check id, CWE):

- `smb.signing_not_required` (345): signing is not required, so NTLM relay works
- `smb.no_encryption_dialect` (319): the best common dialect is SMB 2.x
- `smb.smb1_enabled` (477): the server accepts SMBv1
- `rdp.nla_not_required` (306): the logon screen is reachable without NLA
- `rdp.standard_security` (327): Standard RDP Security is accepted

Specifications: [MS-SMB2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5606ad47-5ee0-437a-817e-70c366052962),
[MS-CIFS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/d416ff7c-c536-406e-a951-4f04b2fd1d2b),
[MS-RDPBCGR](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/5073f4ed-1e93-45e1-b039-6e30c385867c).

## Installation

```bash
cargo add rune-probe-ms
cargo add rune-service-probe --features tokio   # for the async Runner
```

## Usage

```rust
use rune_probe_ms::probe_set;
use rune_service_probe::{Options, Runner, Target};

async fn audit(addr: std::net::SocketAddr) {
    let runner = Runner::new(Options::default());
    let target = Target::from_addr(addr);
    for probe in probe_set().for_port(addr.port()) {
        match runner.probe(probe, &target).await {
            Ok(info) => {
                println!("{} {:?}", info.service, info.details);
                for finding in &info.findings {
                    println!("  {} {}", finding.check_id, finding.title);
                }
            }
            Err(err) => eprintln!("{err}"),
        }
    }
}
```

The parsers work on bytes you already have, e.g. from a capture:

```rust
use rune_probe_ms::rdp::{FailureCode, Negotiation, parse_confirm};

let reply = [3, 0, 0, 19, 14, 0xd0, 0, 0, 0x12, 0x34, 0, 3, 0, 8, 0, 1, 0, 0, 0];
assert_eq!(parse_confirm(&reply).unwrap(), Negotiation::Failure(FailureCode::SslRequired));
```

## License

MIT
