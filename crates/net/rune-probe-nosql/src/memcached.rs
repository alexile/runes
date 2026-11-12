//! Memcached: `version` and `stats` over TCP, and `version` over UDP.
//!
//! See the [text protocol](https://github.com/memcached/memcached/blob/master/doc/protocol.txt).
//! Memcached has no authentication in its text protocol unless SASL
//! (binary protocol only) or the `-Y` auth file is configured, so an
//! answer to `version` means anyone who reaches the port can read and
//! write the cache. An answer over UDP also makes the server a
//! reflection/amplification vector (the 2018 memcached reflection attacks).

use rune_service_probe::rune_finding::{Confidence, Evidence, Remediation, Severity, TaxonomyRef};
use rune_service_probe::{
    Action, AuthRequirement, End, ProbeSession, ServiceInfo, ServiceProbe, Target, Transport,
};

use crate::wire::text;

/// The TCP `version` command.
pub const VERSION: &[u8] = b"version\r\n";
/// The TCP `stats` command. Counters only, no cache contents.
pub const STATS: &[u8] = b"stats\r\n";

/// Most bytes of `stats` output read before giving up on `END`.
const MAX_STATS: usize = 16 * 1024;

/// Statistics copied into [`ServiceInfo::details`] as `memcached.<name>`.
const STATS_KEPT: [&str; 6] = [
    "uptime",
    "threads",
    "curr_connections",
    "max_connections",
    "curr_items",
    "limit_maxbytes",
];

/// The request id the UDP probe uses.
const UDP_REQUEST_ID: u16 = 0x5255;

/// A UDP request: the 8-byte frame header (request id, sequence 0, one
/// datagram, reserved) followed by `version\r\n`.
///
/// ```
/// let req = rune_probe_nosql::memcached::udp_version_request();
/// assert_eq!(&req[2..8], &[0, 0, 0, 1, 0, 0]);
/// assert!(req.ends_with(b"version\r\n"));
/// ```
#[must_use]
pub fn udp_version_request() -> Vec<u8> {
    let mut out = UDP_REQUEST_ID.to_be_bytes().to_vec();
    out.extend_from_slice(&[0, 0, 0, 1, 0, 0]);
    out.extend_from_slice(VERSION);
    out
}

/// The version in a `VERSION <version>` line.
///
/// ```
/// assert_eq!(rune_probe_nosql::memcached::parse_version("VERSION 1.6.21"), Some("1.6.21"));
/// assert_eq!(rune_probe_nosql::memcached::parse_version("ERROR"), None);
/// ```
#[must_use]
pub fn parse_version(line: &str) -> Option<&str> {
    line.strip_prefix("VERSION ")
        .map(str::trim)
        .filter(|v| !v.is_empty())
}

/// The `STAT <name> <value>` lines of a `stats` reply, up to `END`.
#[must_use]
pub fn parse_stats(reply: &str) -> Vec<(String, String)> {
    reply
        .lines()
        .take_while(|line| line.trim_end() != "END")
        .filter_map(|line| line.strip_prefix("STAT "))
        .filter_map(|rest| rest.trim_end().split_once(' '))
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect()
}

fn first_line(buf: &[u8]) -> Option<&[u8]> {
    rune_service_probe::banner::split_line(buf).map(|(line, _)| line)
}

/// Read-only Memcached probe over TCP: `version`, then `stats`.
///
/// | Check id                    | When                                              |
/// | --------------------------- | ------------------------------------------------- |
/// | `memcached.unauthenticated` | `version` answered without credentials (CWE-306)  |
///
/// `CLIENT_ERROR unauthenticated` (the `-Y` auth file) reports
/// [`AuthRequirement::Required`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct MemcachedProbe;

impl MemcachedProbe {
    /// The probe.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl ServiceProbe for MemcachedProbe {
    fn id(&self) -> &'static str {
        "memcached"
    }

    fn default_ports(&self) -> &[u16] {
        &[11211]
    }

    fn session(&self, target: &Target) -> Box<dyn ProbeSession> {
        Box::new(TcpSession {
            target: target.clone(),
            buf: Vec::new(),
            received: false,
            version_line: None,
            stats: None,
        })
    }
}

struct TcpSession {
    target: Target,
    buf: Vec<u8>,
    received: bool,
    version_line: Option<String>,
    stats: Option<Vec<(String, String)>>,
}

impl ProbeSession for TcpSession {
    fn start(&mut self) -> Action {
        Action::Send(VERSION.to_vec())
    }

    fn on_data(&mut self, data: &[u8]) -> Action {
        self.received = true;
        self.buf.extend_from_slice(data);
        if self.version_line.is_none() {
            let Some(line) = first_line(&self.buf) else {
                return if self.buf.len() > 1024 {
                    Action::Done
                } else {
                    Action::Receive
                };
            };
            let line = text(line);
            self.buf.clear();
            let open = parse_version(&line).is_some();
            self.version_line = Some(line);
            return if open {
                Action::Send(STATS.to_vec())
            } else {
                Action::Done
            };
        }
        let done = self.buf.ends_with(b"END\r\n")
            || self.buf.starts_with(b"ERROR")
            || self.buf.starts_with(b"CLIENT_ERROR")
            || self.buf.starts_with(b"SERVER_ERROR")
            || self.buf.len() >= MAX_STATS;
        if done {
            self.stats = Some(parse_stats(&String::from_utf8_lossy(&self.buf)));
            Action::Done
        } else {
            Action::Receive
        }
    }

    fn finish(&mut self, _end: End) -> Result<ServiceInfo, rune_service_probe::Error> {
        if !self.received {
            return Err(rune_service_probe::Error::no_response("memcached"));
        }
        let Some(line) = &self.version_line else {
            return Err(rune_service_probe::Error::unrecognized(
                "memcached",
                "no reply line to version",
            ));
        };
        if line.starts_with("CLIENT_ERROR") {
            let mut info = ServiceInfo::new("memcached")
                .with_product("Memcached")
                .with_banner(line.clone());
            if line.contains("unauthenticated") {
                info = info.with_auth(AuthRequirement::Required);
            }
            return Ok(info);
        }
        let Some(version) = parse_version(line) else {
            return Err(rune_service_probe::Error::unrecognized(
                "memcached",
                format!("unexpected reply to version: {line}"),
            ));
        };
        let mut info = ServiceInfo::new("memcached")
            .with_product("Memcached")
            .with_version(version)
            .with_banner(line.clone())
            .with_auth(AuthRequirement::NotRequired);
        for (name, value) in self.stats.iter().flatten() {
            if STATS_KEPT.contains(&name.as_str()) {
                info = info.with_detail(format!("memcached.{name}"), text(value.as_bytes()));
            }
        }
        Ok(info.push_finding(
            self.target
                .finding(
                    "memcached.unauthenticated",
                    "Memcached answers without authentication",
                    Severity::High,
                    Confidence::Certain,
                )
                .push_taxonomy(TaxonomyRef::cwe(306))
                .push_evidence(Evidence::new("version", line.clone()))
                .with_remediation(Remediation::new(
                    "Bind memcached to localhost or a private interface (-l), enable SASL, \
                     and firewall the port.",
                )),
        ))
    }
}

/// Read-only Memcached probe over UDP: one `version` datagram.
///
/// An answer means the UDP listener is on, which makes the server usable
/// for reflection and amplification (memcached replies can be tens of
/// thousands of times larger than the request).
///
/// | Check id                        | When                                    |
/// | ------------------------------- | --------------------------------------- |
/// | `memcached.udp_amplification`   | `version` answered over UDP (CWE-406)   |
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct MemcachedUdpProbe;

impl MemcachedUdpProbe {
    /// The probe.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl ServiceProbe for MemcachedUdpProbe {
    fn id(&self) -> &'static str {
        "memcached-udp"
    }

    fn transport(&self) -> Transport {
        Transport::Udp
    }

    fn default_ports(&self) -> &[u16] {
        &[11211]
    }

    fn session(&self, target: &Target) -> Box<dyn ProbeSession> {
        Box::new(UdpSession {
            target: target.clone(),
            reply: None,
            received: false,
        })
    }
}

struct UdpSession {
    target: Target,
    reply: Option<Vec<u8>>,
    received: bool,
}

impl ProbeSession for UdpSession {
    fn start(&mut self) -> Action {
        Action::Send(udp_version_request())
    }

    fn on_data(&mut self, data: &[u8]) -> Action {
        self.received = true;
        // Ignore datagrams for another request id.
        if data.get(..2) == Some(&UDP_REQUEST_ID.to_be_bytes()[..]) && data.len() >= 8 {
            self.reply = Some(data.to_vec());
            Action::Done
        } else {
            Action::Receive
        }
    }

    fn finish(&mut self, _end: End) -> Result<ServiceInfo, rune_service_probe::Error> {
        const ID: &str = "memcached-udp";
        let Some(reply) = &self.reply else {
            return Err(if self.received {
                rune_service_probe::Error::unrecognized(ID, "no memcached UDP frame")
            } else {
                rune_service_probe::Error::no_response(ID)
            });
        };
        let payload = reply.get(8..).unwrap_or_default();
        let line = text(first_line(payload).unwrap_or(payload));
        let Some(version) = parse_version(&line) else {
            return Err(rune_service_probe::Error::unrecognized(
                ID,
                format!("unexpected reply to version: {line}"),
            ));
        };
        Ok(ServiceInfo::new(ID)
            .with_product("Memcached")
            .with_version(version)
            .with_banner(line.clone())
            .with_auth(AuthRequirement::NotRequired)
            .with_detail("memcached.udp", "enabled")
            .push_finding(
                self.target
                    .finding(
                        "memcached.udp_amplification",
                        "Memcached answers over UDP (amplification vector)",
                        Severity::High,
                        Confidence::Certain,
                    )
                    .push_taxonomy(TaxonomyRef::cwe(406))
                    .push_evidence(Evidence::new("udp_version", line))
                    .with_remediation(Remediation::new(
                        "Disable the UDP listener (-U 0, the default since 1.5.6) and \
                         firewall the port.",
                    )),
            ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rune_service_probe::{Options, simulate};

    fn target() -> Target {
        Target::new("cache.test", 11211)
    }

    #[test]
    fn open_memcached_with_stats() {
        let stats = b"STAT pid 1\r\nSTAT uptime 3600\r\nSTAT threads 4\r\nSTAT curr_items 12\r\nSTAT limit_maxbytes 67108864\r\nEND\r\n";
        let sim = simulate(
            &MemcachedProbe,
            &target(),
            &[b"VERSION 1.6.21\r\n", &stats[..30], &stats[30..]],
            &Options::default(),
        )
        .unwrap();
        assert_eq!(sim.sent, [VERSION.to_vec(), STATS.to_vec()]);
        assert_eq!(sim.end, End::Done);
        let info = sim.result.unwrap();
        assert_eq!(info.version.as_deref(), Some("1.6.21"));
        assert_eq!(info.details["memcached.uptime"], "3600");
        assert_eq!(info.details["memcached.curr_items"], "12");
        assert!(!info.details.contains_key("memcached.pid"));
        assert_eq!(info.auth, AuthRequirement::NotRequired);
        assert_eq!(info.findings[0].check_id, "memcached.unauthenticated");
    }

    #[test]
    fn auth_file_requires_auth() {
        let sim = simulate(
            &MemcachedProbe,
            &target(),
            &[b"CLIENT_ERROR unauthenticated\r\n"],
            &Options::default(),
        )
        .unwrap();
        let info = sim.result.unwrap();
        assert_eq!(info.auth, AuthRequirement::Required);
        assert_eq!(info.findings.len(), 0);
    }

    #[test]
    fn not_memcached() {
        let sim = simulate(
            &MemcachedProbe,
            &target(),
            &[b"-ERR unknown command 'version'\r\n"],
            &Options::default(),
        )
        .unwrap();
        assert!(matches!(
            sim.result,
            Err(rune_service_probe::Error::Unrecognized { .. })
        ));
    }

    #[test]
    fn udp_amplification() {
        let mut reply = UDP_REQUEST_ID.to_be_bytes().to_vec();
        reply.extend_from_slice(&[0, 0, 0, 1, 0, 0]);
        reply.extend_from_slice(b"VERSION 1.4.25\r\n");
        let sim = simulate(
            &MemcachedUdpProbe,
            &target(),
            &[b"\x00\x09stray", &reply],
            &Options::default(),
        )
        .unwrap();
        assert_eq!(sim.sent, [udp_version_request()]);
        let info = sim.result.unwrap();
        assert_eq!(info.version.as_deref(), Some("1.4.25"));
        assert_eq!(info.findings[0].check_id, "memcached.udp_amplification");
        assert_eq!(info.findings[0].taxonomy[0].cwe_number(), Some(406));
        let silent = simulate(&MemcachedUdpProbe, &target(), &[], &Options::default()).unwrap();
        assert!(matches!(
            silent.result,
            Err(rune_service_probe::Error::NoResponse { .. })
        ));
    }
}
