# rune-probe-sql

> Read-only MySQL/MariaDB, PostgreSQL and MSSQL (TDS prelogin) handshake and version probes

[![crates.io](https://img.shields.io/crates/v/rune-probe-sql)](https://crates.io/crates/rune-probe-sql)
[![docs.rs](https://img.shields.io/docsrs/rune-probe-sql)](https://docs.rs/rune-probe-sql)
[![license](https://img.shields.io/crates/l/rune-probe-sql)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

Protocol probes for SQL databases, implementing
[`rune-service-probe`](../rune-service-probe)'s `ServiceProbe`. They are
sans-I/O state machines: test them in memory with `simulate`, run them
with the tokio `Runner`, or drive them from your own I/O loop.

| Probe                         | Id                | Sends                                         | Learns                                                         |
| ----------------------------- | ----------------- | --------------------------------------------- | -------------------------------------------------------------- |
| `MysqlProbe`                  | `mysql`           | nothing (the server speaks first)             | version, product (MySQL, MariaDB, TiDB), capability flags, auth plugin, TLS offered |
| `PostgresProbe`               | `postgresql`      | `SSLRequest`, then an unsupported-protocol startup | TLS offered (`S`/`N`), server version range from the error   |
| `MssqlProbe`                  | `mssql`           | TDS `PRELOGIN` with `ENCRYPT_OFF`             | version and release (2019, 2022, ...), encryption setting      |
| `PostgresAuthProbe` (intrusive) | `postgresql-auth` | `StartupMessage` for `postgres`, no password | authentication method, unauthenticated access, exact version   |

No read-only probe logs in or sends credentials. `PostgresAuthProbe`
starts a passwordless login, so it is declared `Safety::Intrusive` and
runners refuse it unless `Options::with_allow_intrusive(true)` is set.

Findings (check id, CWE):

- `mysql.tls_not_offered` (319), `mysql.old_password_auth` (328)
- `postgresql.tls_not_offered` (319)
- `postgresql.unauthenticated` (306), `postgresql.cleartext_password` (319),
  `postgresql.md5_auth` (328), from the intrusive probe
- `mssql.encryption_not_supported` (319), `mssql.unsupported_version` (1104)

Specifications: [MySQL HandshakeV10](https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_handshake_v10.html),
[PostgreSQL start-up](https://www.postgresql.org/docs/current/protocol-flow.html#PROTOCOL-FLOW-START-UP),
[MS-TDS PRELOGIN](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/60f56408-0188-4cd5-8b90-25c6f2423868).

## Installation

```bash
cargo add rune-probe-sql
cargo add rune-service-probe --features tokio   # for the async Runner
```

## Usage

```rust
use rune_probe_sql::probe_set;
use rune_service_probe::{Options, Runner, Target};

async fn audit(addr: std::net::SocketAddr) {
    let runner = Runner::new(Options::default());
    let target = Target::from_addr(addr);
    for probe in probe_set().for_port(addr.port()) {
        match runner.probe(probe, &target).await {
            Ok(info) => {
                println!("{} {:?} {:?} tls={:?}", info.service, info.product, info.version, info.tls);
                for finding in &info.findings {
                    println!("  {} {}", finding.check_id, finding.title);
                }
            }
            Err(err) => eprintln!("{err}"),
        }
    }
}
```

The parsers are public for bytes you already have, e.g. from a capture:

```rust
use rune_probe_sql::mssql::{Encryption, parse_response};

let reply = [
    0x04, 0x01, 0x00, 0x25, 0x00, 0x00, 0x01, 0x00, // TDS header
    0x00, 0x00, 0x15, 0x00, 0x06, 0x01, 0x00, 0x1b, 0x00, 0x01,
    0x02, 0x00, 0x1c, 0x00, 0x01, 0x03, 0x00, 0x1d, 0x00, 0x00, 0xff,
    0x0f, 0x00, 0x07, 0xd0, 0x00, 0x00, // 15.0.2000
    0x02,                               // ENCRYPT_NOT_SUP
    0x00,
];
let prelogin = parse_response(&reply).unwrap();
assert_eq!(prelogin.version.unwrap().to_string(), "15.0.2000");
assert_eq!(prelogin.encryption, Some(Encryption::NotSupported));
```

## License

MIT
