//! Read-only probes for the most common real exposure: data stores that
//! answer without authentication. Built on [`rune_service_probe`].
//!
//! | Probe                  | Id              | Port  | Sends                                         | Unauthenticated when                |
//! | ---------------------- | --------------- | ----- | --------------------------------------------- | ----------------------------------- |
//! | [`RedisProbe`]         | `redis`         | 6379  | `INFO server`, then `PING` if refused          | `INFO` or `PING` answers             |
//! | [`MongodbProbe`]       | `mongodb`       | 27017 | `isMaster`, `buildInfo`, `listDatabases` (names only, counted) | `listDatabases` succeeds |
//! | [`MemcachedProbe`]     | `memcached`     | 11211 | `version`, `stats`                            | `version` answers                    |
//! | [`MemcachedUdpProbe`]  | `memcached-udp` | 11211/udp | `version` in one datagram                 | it answers (amplification vector)   |
//! | [`ElasticsearchProbe`] | `elasticsearch` | 9200  | `GET /`, `GET /_cluster/health`               | `GET /` returns cluster details      |
//!
//! Every probe is read-only: no writes, no credentials, and nothing read
//! beyond version, configuration and health metadata. Unauthenticated
//! access is reported as [`AuthRequirement::NotRequired`](rune_service_probe::AuthRequirement)
//! plus a `<id>.unauthenticated` finding mapped to CWE-306 (Missing
//! Authentication for Critical Function); UDP reflection maps to CWE-406.
//!
//! Each probe is a sans-I/O [`ServiceProbe`]: run it in memory with
//! [`simulate`](rune_service_probe::simulate), over tokio with
//! `rune_service_probe::Runner` (its `tokio` feature), or in any I/O loop
//! around a [`Driver`](rune_service_probe::Driver). The protocol readers
//! ([`redis::parse_reply`], [`bson::Document::parse`],
//! [`mongodb::parse_reply`], [`http::parse_response`]) are public too.
//!
//! # Example
//!
//! ```
//! use rune_probe_nosql::{RedisProbe, probe_set};
//! use rune_service_probe::{AuthRequirement, Options, Target, simulate};
//!
//! // A captured exchange with an open Redis: INFO server returns a bulk string.
//! let info_reply = b"$54\r\n# Server\r\nredis_version:7.2.4\r\nredis_mode:standalone\r\n\r\n";
//! let target = Target::new("cache.internal", 6379);
//! let sim = simulate(&RedisProbe::new(), &target, &[info_reply], &Options::default())?;
//! assert_eq!(sim.sent, [b"*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n".to_vec()]);
//!
//! let info = sim.result?;
//! assert_eq!(info.version.as_deref(), Some("7.2.4"));
//! assert_eq!(info.auth, AuthRequirement::NotRequired);
//! assert_eq!(info.findings[0].check_id, "redis.unauthenticated");
//!
//! // Pick probes by port.
//! assert_eq!(probe_set().for_port(9200).next().map(|p| p.id()), Some("elasticsearch"));
//! # Ok::<(), rune_service_probe::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod bson;
pub mod elasticsearch;
mod error;
pub mod http;
pub mod memcached;
pub mod mongodb;
pub mod redis;
mod wire;

pub use elasticsearch::ElasticsearchProbe;
pub use error::Error;
pub use memcached::{MemcachedProbe, MemcachedUdpProbe};
pub use mongodb::MongodbProbe;
pub use redis::RedisProbe;

use rune_service_probe::{ProbeSet, ServiceProbe};

/// Every probe of this crate (all read-only), as a [`ProbeSet`].
#[must_use]
pub fn probe_set() -> ProbeSet {
    let mut set = ProbeSet::new();
    for probe in all_probes() {
        set.push_boxed(probe);
    }
    set
}

/// Every probe of this crate, boxed.
#[must_use]
pub fn all_probes() -> Vec<Box<dyn ServiceProbe>> {
    vec![
        Box::new(RedisProbe::new()),
        Box::new(MongodbProbe::new()),
        Box::new(MemcachedProbe::new()),
        Box::new(MemcachedUdpProbe::new()),
        Box::new(ElasticsearchProbe::new()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use rune_service_probe::{Safety, Transport};

    #[test]
    fn all_read_only_and_ports() {
        let set = probe_set();
        assert!(set.iter().all(|p| p.safety() == Safety::ReadOnly));
        let at_11211: Vec<_> = set.for_port(11211).map(ServiceProbe::transport).collect();
        assert_eq!(at_11211, [Transport::Tcp, Transport::Udp]);
        assert_eq!(set.for_port(27017).count(), 1);
    }
}
