# rune-probe-nosql

> Read-only Redis, MongoDB, Memcached and Elasticsearch probes for unauthenticated exposure

[![crates.io](https://img.shields.io/crates/v/rune-probe-nosql)](https://crates.io/crates/rune-probe-nosql)
[![docs.rs](https://img.shields.io/docsrs/rune-probe-nosql)](https://docs.rs/rune-probe-nosql)
[![license](https://img.shields.io/crates/l/rune-probe-nosql)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

Unauthenticated data stores are the most common real network exposure.
These probes implement [`rune-service-probe`](../rune-service-probe)'s
`ServiceProbe` and tell, without credentials and without touching data,
whether a store answers anyone who connects.

| Probe                | Id              | Sends                                              | Reports                                                   |
| -------------------- | --------------- | -------------------------------------------------- | --------------------------------------------------------- |
| `RedisProbe`         | `redis`         | `INFO server`, then `PING` if `INFO` is refused    | product (Redis, Valkey, Dragonfly), version, mode, auth, protected mode, ACL-restricted default user |
| `MongodbProbe`       | `mongodb`       | `isMaster`, `buildInfo`, `listDatabases` (`nameOnly`, only counted) | version, edition, replica-set role, wire versions, auth |
| `MemcachedProbe`     | `memcached`     | `version`, `stats`                                 | version, a few counters, auth                             |
| `MemcachedUdpProbe`  | `memcached-udp` | one `version` datagram                             | UDP listener enabled (reflection/amplification)           |
| `ElasticsearchProbe` | `elasticsearch` | `GET /`, `GET /_cluster/health`                    | product (Elasticsearch, OpenSearch), version, cluster name, health, auth |

Findings, mapped to `rune-finding` with CWEs:

| Check id                        | Severity           | CWE |
| ------------------------------- | ------------------ | --- |
| `redis.unauthenticated`         | Critical (High when the default user is ACL-restricted) | 306 |
| `mongodb.unauthenticated`       | Critical           | 306 |
| `memcached.unauthenticated`     | High               | 306 |
| `memcached.udp_amplification`   | High               | 406 |
| `elasticsearch.unauthenticated` | Critical           | 306 |

All probes are `Safety::ReadOnly`: no writes, no credentials, and no data
read beyond version, configuration and health metadata. The protocol
readers (RESP, BSON, MongoDB `OP_REPLY`/`OP_MSG`, HTTP/1.1) are bounded
and public.

## Installation

```bash
cargo add rune-probe-nosql
cargo add rune-service-probe --features tokio   # for the async Runner
```

## Usage

```rust
use rune_probe_nosql::probe_set;
use rune_service_probe::{AuthRequirement, Options, Runner, Target};

async fn audit(addr: std::net::SocketAddr) {
    let runner = Runner::new(Options::default());
    let target = Target::from_addr(addr);
    for probe in probe_set().for_port(addr.port()) {
        if let Ok(info) = runner.probe(probe, &target).await {
            if info.auth == AuthRequirement::NotRequired {
                println!("{} {:?} is open", info.service, info.version);
            }
            for finding in &info.findings {
                println!("  {} ({:?})", finding.check_id, finding.severity);
            }
        }
    }
}
```

Test a probe against a captured reply, in memory:

```rust
use rune_probe_nosql::MemcachedProbe;
use rune_service_probe::{Options, Target, simulate};

let target = Target::new("cache.internal", 11211);
let sim = simulate(
    &MemcachedProbe::new(),
    &target,
    &[b"VERSION 1.6.21\r\n", b"STAT uptime 3600\r\nEND\r\n"],
    &Options::default(),
)
.unwrap();
let info = sim.result.unwrap();
assert_eq!(info.version.as_deref(), Some("1.6.21"));
assert_eq!(info.findings[0].check_id, "memcached.unauthenticated");
```

Elasticsearch 8 serves HTTPS by default: open the TLS stream yourself and
run the probe with `Runner::probe_stream`.

## License

MIT
