//! Read-only handshake and version probes for SQL databases, built on
//! [`rune_service_probe`].
//!
//! | Probe                                  | Id                | Port | Sends                                   | Learns                                                     |
//! | -------------------------------------- | ----------------- | ---- | --------------------------------------- | ---------------------------------------------------------- |
//! | [`MysqlProbe`]                         | `mysql`           | 3306 | nothing                                 | version, capabilities, auth plugin, TLS offered            |
//! | [`PostgresProbe`]                      | `postgresql`      | 5432 | `SSLRequest`, an unsupported-protocol startup | TLS offered, version range                          |
//! | [`MssqlProbe`]                         | `mssql`           | 1433 | TDS `PRELOGIN`                          | version, release, encryption setting                       |
//! | [`PostgresAuthProbe`] (**intrusive**)  | `postgresql-auth` | 5432 | `StartupMessage`, no password           | authentication method, unauthenticated access, exact version |
//!
//! Every probe is a sans-I/O [`ServiceProbe`]: run it in memory with
//! [`simulate`](rune_service_probe::simulate), over tokio with
//! `rune_service_probe::Runner` (its `tokio` feature), or in any I/O loop around a
//! [`Driver`](rune_service_probe::Driver). None of the read-only probes
//! logs in or sends credentials; [`PostgresAuthProbe`] starts a
//! (passwordless) login and so is [`Safety::Intrusive`](rune_service_probe::Safety),
//! refused unless the caller allows intrusive probes.
//!
//! The parsers behind the probes ([`mysql::parse_greeting`],
//! [`postgres::parse_message`], [`mssql::parse_response`]) are public for
//! callers that already hold the bytes, e.g. from a packet capture.
//!
//! Findings use check ids `<protocol>.<issue>` and carry a CWE, e.g.
//! `mysql.tls_not_offered` (CWE-319) or `postgresql.unauthenticated`
//! (CWE-306).
//!
//! # Example
//!
//! ```
//! use rune_probe_sql::{MssqlProbe, MysqlProbe, probe_set};
//! use rune_service_probe::{Options, Target, TlsSupport, simulate};
//!
//! // A captured MySQL 8.0 greeting: protocol 10, "8.0.36", CLIENT_SSL set.
//! let mut payload = vec![10];
//! payload.extend_from_slice(b"8.0.36\0");
//! payload.extend_from_slice(&[7, 0, 0, 0]);            // connection id
//! payload.extend_from_slice(b"abcdefgh\0");             // scramble part 1, filler
//! payload.extend_from_slice(&[0xff, 0xff, 0xff, 2, 0]); // caps, charset, status
//! payload.extend_from_slice(&[0xff, 0xdf, 21]);         // upper caps, scramble length
//! payload.extend_from_slice(&[0; 10]);
//! payload.extend_from_slice(b"ijklmnopqrst\0caching_sha2_password\0");
//! let mut packet = vec![payload.len() as u8, 0, 0, 0];
//! packet.extend_from_slice(&payload);
//!
//! let target = Target::new("db.internal", 3306);
//! let sim = simulate(&MysqlProbe::new(), &target, &[&packet], &Options::default())?;
//! assert!(sim.sent.is_empty()); // the server speaks first; the probe only listens
//! let info = sim.result?;
//! assert_eq!(info.product.as_deref(), Some("MySQL"));
//! assert_eq!(info.version.as_deref(), Some("8.0.36"));
//! assert_eq!(info.tls, TlsSupport::Optional);
//! assert_eq!(info.details["mysql.auth_plugin"], "caching_sha2_password");
//!
//! // Pick probes by port.
//! let probes = probe_set();
//! assert_eq!(probes.for_port(1433).next().map(|p| p.id()), Some("mssql"));
//! # let _ = MssqlProbe::new();
//! # Ok::<(), rune_service_probe::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod error;
pub mod mssql;
pub mod mysql;
pub mod postgres;
mod wire;

pub use error::Error;
pub use mssql::MssqlProbe;
pub use mysql::MysqlProbe;
pub use postgres::{PostgresAuthProbe, PostgresProbe};

use rune_service_probe::{ProbeSet, ServiceProbe};

/// The read-only probes of this crate, as a [`ProbeSet`]. The intrusive
/// [`PostgresAuthProbe`] is not included.
#[must_use]
pub fn probe_set() -> ProbeSet {
    let mut set = ProbeSet::new();
    set.push(MysqlProbe::new())
        .push(PostgresProbe::new())
        .push(MssqlProbe::new());
    set
}

/// Every probe of this crate, read-only and intrusive, boxed.
#[must_use]
pub fn all_probes() -> Vec<Box<dyn ServiceProbe>> {
    vec![
        Box::new(MysqlProbe::new()),
        Box::new(PostgresProbe::new()),
        Box::new(MssqlProbe::new()),
        Box::new(PostgresAuthProbe::new()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use rune_service_probe::Safety;

    #[test]
    fn probe_set_is_read_only() {
        let set = probe_set();
        assert!(set.iter().all(|p| p.safety() == Safety::ReadOnly));
        assert_eq!(set.for_port(5432).count(), 1);
        assert_eq!(
            all_probes()
                .iter()
                .filter(|p| p.safety() == Safety::Intrusive)
                .count(),
            1
        );
    }
}
