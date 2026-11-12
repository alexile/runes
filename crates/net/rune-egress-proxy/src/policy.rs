//! The sans-I/O allow/deny decision.

use std::fmt;
use std::net::{IpAddr, SocketAddr};

use rune_cidr::Cidr;
use rune_host_match::{HostAllowlist, HostPattern, Hostname};

use crate::{Error, Host, Target};

/// What a proxy may connect to. Default-deny: an empty policy allows
/// nothing.
///
/// - **Hostnames** must match the host allowlist ([`HostAllowlist`]
///   semantics: exact names, and `*.suffix` for every subdomain but never
///   the apex). A matching name is then resolved once and pinned with
///   [`Policy::pin`]: only a globally reachable address, or one inside the
///   IP allowlist, is used. That is the SSRF and DNS-rebinding guard: an
///   allowed name whose DNS answer points at `169.254.169.254`, loopback or
///   an RFC 1918 host is refused unless that range was allowlisted.
/// - **IP literals** must be inside the IP allowlist. There is no "it is a
///   public address, so allow it" fallback: a literal never passed the
///   host allowlist, so only an explicit IP entry admits it.
/// - **Ports**: any, unless at least one port was allowed with
///   [`Policy::allow_port`].
///
/// Address checks run on the [canonical](rune_ip::canonical) address too,
/// so `::ffff:10.0.0.1` matches `10.0.0.0/8` and is non-global just like
/// `10.0.0.1`.
///
/// ```
/// use rune_egress_proxy::{Decision, Denial, Policy, Target};
///
/// let policy = Policy::new()
///     .allow_host("*.github.com")?
///     .allow_ip("10.0.0.0/8")?
///     .allow_port(443);
///
/// let t: Target = "api.github.com:443".parse()?;
/// assert!(matches!(policy.decide(&t), Decision::Resolve { .. }));
/// let apex: Target = "github.com:443".parse()?;
/// assert_eq!(policy.decide(&apex), Decision::Deny(Denial::HostNotAllowed));
/// let ip: Target = "10.1.2.3:443".parse()?;
/// assert_eq!(policy.decide(&ip), Decision::Connect("10.1.2.3:443".parse().unwrap()));
/// let port: Target = "api.github.com:22".parse()?;
/// assert_eq!(policy.decide(&port), Decision::Deny(Denial::PortNotAllowed));
///
/// // DNS pinning: a rebinding answer to a metadata endpoint is refused.
/// let answer = ["169.254.169.254:443".parse().unwrap()];
/// assert_eq!(policy.pin(answer), Err(Denial::NoAllowedAddress));
/// # Ok::<(), rune_egress_proxy::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policy {
    hosts: HostAllowlist,
    cidrs: Vec<Cidr>,
    ports: Vec<u16>,
}

impl Policy {
    /// An empty, deny-everything policy.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            hosts: HostAllowlist::new(),
            cidrs: Vec::new(),
            ports: Vec::new(),
        }
    }

    /// Allows hostnames matching `pattern` (`api.example.com`,
    /// `*.example.com`, `api.*.example.com`).
    pub fn allow_host(self, pattern: &str) -> Result<Self, Error> {
        let parsed = HostPattern::parse(pattern).map_err(|source| Error::HostPattern {
            pattern: pattern.to_owned(),
            source,
        })?;
        Ok(self.with_host_pattern(parsed))
    }

    /// Allows every pattern in `patterns`; see [`Policy::allow_host`].
    pub fn allow_hosts<I>(self, patterns: I) -> Result<Self, Error>
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
    {
        patterns
            .into_iter()
            .try_fold(self, |policy, pattern| policy.allow_host(pattern.as_ref()))
    }

    /// Allows an already parsed host pattern.
    #[must_use]
    pub fn with_host_pattern(mut self, pattern: HostPattern) -> Self {
        self.hosts.push(pattern);
        self
    }

    /// Allows a bare address (`10.0.0.5`, `::1`) or CIDR range
    /// (`10.0.0.0/8`): as an IP-literal target, and as a resolved address
    /// of an allowed hostname even when it is not globally reachable.
    pub fn allow_ip(self, entry: &str) -> Result<Self, Error> {
        let cidr = Cidr::parse(entry).map_err(|err| Error::Cidr {
            entry: entry.to_owned(),
            reason: err.to_string(),
        })?;
        Ok(self.with_cidr(cidr))
    }

    /// Allows every entry in `entries`; see [`Policy::allow_ip`].
    pub fn allow_ips<I>(self, entries: I) -> Result<Self, Error>
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
    {
        entries
            .into_iter()
            .try_fold(self, |policy, entry| policy.allow_ip(entry.as_ref()))
    }

    /// Allows an already parsed CIDR range.
    #[must_use]
    pub fn with_cidr(mut self, cidr: Cidr) -> Self {
        self.cidrs.push(cidr);
        self
    }

    /// Restricts targets to the allowed ports. Until the first call every
    /// port is allowed.
    #[must_use]
    pub fn allow_port(mut self, port: u16) -> Self {
        if !self.ports.contains(&port) {
            self.ports.push(port);
        }
        self
    }

    /// The host allowlist.
    #[must_use]
    pub const fn hosts(&self) -> &HostAllowlist {
        &self.hosts
    }

    /// The IP allowlist.
    #[must_use]
    pub fn cidrs(&self) -> &[Cidr] {
        &self.cidrs
    }

    /// The allowed ports; empty means every port.
    #[must_use]
    pub fn ports(&self) -> &[u16] {
        &self.ports
    }

    /// Whether `port` is allowed.
    #[must_use]
    pub fn port_allowed(&self, port: u16) -> bool {
        self.ports.is_empty() || self.ports.contains(&port)
    }

    /// Whether `ip`, or its canonical IPv4 form, is in the IP allowlist.
    #[must_use]
    pub fn ip_allowed(&self, ip: IpAddr) -> bool {
        let canonical = rune_ip::canonical(ip);
        self.cidrs
            .iter()
            .any(|cidr| cidr.contains(ip) || cidr.contains(canonical))
    }

    /// Whether a resolved address of an allowed hostname may be used: it is
    /// globally reachable, or explicitly allowlisted.
    #[must_use]
    pub fn resolved_ip_allowed(&self, ip: IpAddr) -> bool {
        rune_ip::is_global(ip) || self.ip_allowed(ip)
    }

    /// Decides what to do with a CONNECT target.
    #[must_use]
    pub fn decide(&self, target: &Target) -> Decision {
        if !self.port_allowed(target.port) {
            return Decision::Deny(Denial::PortNotAllowed);
        }
        match &target.host {
            Host::Ip(ip) if self.ip_allowed(*ip) => {
                Decision::Connect(SocketAddr::new(*ip, target.port))
            }
            Host::Ip(_) => Decision::Deny(Denial::IpNotAllowed),
            Host::Name(name) if self.hosts.matching_hostname(name).is_some() => Decision::Resolve {
                host: name.clone(),
                port: target.port,
            },
            Host::Name(_) => Decision::Deny(Denial::HostNotAllowed),
        }
    }

    /// DNS pinning: picks the first resolved address that
    /// [`Policy::resolved_ip_allowed`] accepts. Connect to exactly that
    /// address; resolving the name again would reopen the rebinding race.
    pub fn pin<I>(&self, candidates: I) -> Result<SocketAddr, Denial>
    where
        I: IntoIterator<Item = SocketAddr>,
    {
        candidates
            .into_iter()
            .find(|addr| self.resolved_ip_allowed(addr.ip()))
            .ok_or(Denial::NoAllowedAddress)
    }
}

/// The outcome of [`Policy::decide`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Decision {
    /// An allowlisted IP literal: connect to this address.
    Connect(SocketAddr),
    /// An allowlisted hostname: resolve it once, then [`Policy::pin`].
    Resolve {
        /// The name to resolve.
        host: Hostname,
        /// The target port.
        port: u16,
    },
    /// Refused.
    Deny(Denial),
}

/// Why a target was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Denial {
    /// The port is not in the port allowlist.
    PortNotAllowed,
    /// The hostname matches no host pattern.
    HostNotAllowed,
    /// The IP literal is outside the IP allowlist.
    IpNotAllowed,
    /// Every resolved address is non-global (private, loopback,
    /// link-local, reserved, ...) and outside the IP allowlist: possible
    /// DNS rebinding.
    NoAllowedAddress,
    /// Resolving an allowed hostname failed or returned nothing.
    ResolveFailed,
}

impl Denial {
    /// The HTTP status code a proxy answers with: 502 when resolution
    /// failed, 403 otherwise.
    #[must_use]
    pub const fn status(self) -> u16 {
        match self {
            Self::ResolveFailed => 502,
            _ => 403,
        }
    }
}

impl fmt::Display for Denial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::PortNotAllowed => "port not in the port allowlist",
            Self::HostNotAllowed => "host not in the host allowlist",
            Self::IpNotAllowed => "IP literal not in the IP allowlist",
            Self::NoAllowedAddress => {
                "resolved only to non-global addresses outside the IP allowlist (possible DNS rebinding)"
            }
            Self::ResolveFailed => "name resolution failed",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(s: &str) -> Target {
        s.parse().unwrap()
    }

    fn sock(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    // Ported from rune-secops-warden `network_proxy` (domain matching).
    #[test]
    fn exact_domain_matches() {
        let p = Policy::new().allow_host("api.anthropic.com").unwrap();
        assert!(matches!(
            p.decide(&target("api.anthropic.com:443")),
            Decision::Resolve { .. }
        ));
        assert_eq!(
            p.decide(&target("evil.com:443")),
            Decision::Deny(Denial::HostNotAllowed)
        );
    }

    #[test]
    fn wildcard_matches_subdomains_only() {
        let p = Policy::new().allow_host("*.anthropic.com").unwrap();
        for ok in ["api.anthropic.com:443", "deep.sub.anthropic.com:443"] {
            assert!(
                matches!(p.decide(&target(ok)), Decision::Resolve { .. }),
                "{ok}"
            );
        }
        // A wildcard does not match the bare apex domain, and suffix
        // matching respects the label boundary.
        for bad in ["anthropic.com:443", "evilanthropic.com:443"] {
            assert_eq!(
                p.decide(&target(bad)),
                Decision::Deny(Denial::HostNotAllowed),
                "{bad}"
            );
        }
    }

    #[test]
    fn no_patterns_means_nothing_allowed() {
        let p = Policy::new();
        assert_eq!(
            p.decide(&target("api.anthropic.com:443")),
            Decision::Deny(Denial::HostNotAllowed)
        );
        assert_eq!(
            p.decide(&target("8.8.8.8:443")),
            Decision::Deny(Denial::IpNotAllowed)
        );
    }

    #[test]
    fn ip_literals_need_an_explicit_entry() {
        let p = Policy::new().allow_ip("10.0.0.0/8").unwrap();
        // Public but not allowlisted: still refused.
        assert_eq!(
            p.decide(&target("8.8.8.8:443")),
            Decision::Deny(Denial::IpNotAllowed)
        );
        assert_eq!(
            p.decide(&target("10.9.9.9:22")),
            Decision::Connect(sock("10.9.9.9:22"))
        );
        // The mapped form of an allowlisted address is allowed, and the
        // mapped form of a refused one is refused.
        assert_eq!(
            p.decide(&target("[::ffff:10.0.0.1]:443")),
            Decision::Connect(sock("[::ffff:10.0.0.1]:443"))
        );
        assert_eq!(
            p.decide(&target("[::ffff:127.0.0.1]:443")),
            Decision::Deny(Denial::IpNotAllowed)
        );
    }

    #[test]
    fn port_allowlist_applies_to_every_target() {
        let p = Policy::new()
            .allow_host("a.example")
            .unwrap()
            .allow_ip("10.0.0.1")
            .unwrap()
            .allow_port(443)
            .allow_port(443);
        assert_eq!(p.ports(), &[443]);
        for bad in ["a.example:80", "10.0.0.1:80"] {
            assert_eq!(
                p.decide(&target(bad)),
                Decision::Deny(Denial::PortNotAllowed)
            );
        }
        assert!(p.port_allowed(443));
        assert!(Policy::new().port_allowed(1));
    }

    // Ported from rune-secops-warden `network_proxy::pick_allowed_addr`.
    #[test]
    fn pin_skips_private_addresses_by_default() {
        let addrs = [sock("127.0.0.1:443"), sock("93.184.216.34:443")];
        assert_eq!(Policy::new().pin(addrs), Ok(sock("93.184.216.34:443")));
    }

    #[test]
    fn pin_refuses_when_every_candidate_is_private_and_unallowlisted() {
        for bad in [
            "169.254.169.254:80",
            "10.0.0.1:80",
            "100.64.0.1:80",
            "0.0.0.0:80",
            "[::1]:80",
            "[fd00::1]:80",
            "[::ffff:192.168.1.1]:80",
            "[64:ff9b::a9fe:a9fe]:80",
        ] {
            assert_eq!(
                Policy::new().pin([sock(bad)]),
                Err(Denial::NoAllowedAddress),
                "{bad}"
            );
        }
        assert_eq!(Policy::new().pin([]), Err(Denial::NoAllowedAddress));
    }

    #[test]
    fn pin_accepts_a_private_candidate_explicitly_allowlisted() {
        let p = Policy::new().allow_ip("10.0.0.0/24").unwrap();
        assert_eq!(p.pin([sock("10.0.0.5:443")]), Ok(sock("10.0.0.5:443")));
    }

    #[test]
    fn invalid_entries_are_errors() {
        assert!(matches!(
            Policy::new().allow_host("exa mple.com"),
            Err(Error::HostPattern { .. })
        ));
        assert!(matches!(
            Policy::new().allow_ip("10.0.0.0/33"),
            Err(Error::Cidr { .. })
        ));
        assert!(
            Policy::new()
                .allow_hosts(["a.example", "*.b.example"])
                .is_ok()
        );
        assert!(Policy::new().allow_ips(["10.0.0.0/8", "nope"]).is_err());
    }

    #[test]
    fn denial_statuses() {
        assert_eq!(Denial::ResolveFailed.status(), 502);
        assert_eq!(Denial::HostNotAllowed.status(), 403);
        assert!(Denial::NoAllowedAddress.to_string().contains("rebinding"));
    }
}
