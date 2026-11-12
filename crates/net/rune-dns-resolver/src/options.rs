//! Resolver configuration.

use std::time::Duration;

use crate::Upstream;

/// Upstreams and policy for a resolver.
///
/// For each query the upstreams are tried in order; a timeout, a socket
/// error, a mismatched answer or a failure code (`SERVFAIL`, `REFUSED`,
/// ...) moves on to the next one. After the last, the round starts over,
/// up to [`ResolverOptions::attempts`] rounds.
///
/// ```
/// use std::time::Duration;
/// use rune_dns_resolver::ResolverOptions;
///
/// let options = ResolverOptions::default()
///     .with_upstream("192.0.2.53".parse()?)
///     .with_timeout(Duration::from_millis(500))
///     .with_attempts(3)
///     .with_concurrency(16)
///     .with_dnssec_ok(true);
/// assert_eq!(options.upstreams.len(), 1);
/// assert_eq!(options.udp_payload_size, Some(1232));
/// # Ok::<(), rune_dns_resolver::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ResolverOptions {
    /// Servers to query, in order of preference.
    pub upstreams: Vec<Upstream>,
    /// Longest wait for one exchange with one upstream, TCP fallback
    /// included (default 2 s).
    pub timeout: Duration,
    /// Rounds over all upstreams before giving up (default 2, at least 1).
    pub attempts: u32,
    /// Most queries in flight at once per resolver (default 64, at least
    /// 1).
    pub concurrency: usize,
    /// EDNS(0) UDP payload size to advertise (default 1232, the DNS flag
    /// day 2020 value); `None` sends no `OPT` record, which limits UDP
    /// answers to 512 octets.
    pub udp_payload_size: Option<u16>,
    /// Ask the upstream to recurse (`RD`; default true).
    pub recursion_desired: bool,
    /// Ask for DNSSEC records (`DO`; default false). Needs EDNS.
    pub dnssec_ok: bool,
    /// Longest `CNAME` chain to follow inside an answer (default 8).
    pub max_cname_chain: usize,
}

impl Default for ResolverOptions {
    fn default() -> Self {
        Self {
            upstreams: Vec::new(),
            timeout: Duration::from_secs(2),
            attempts: 2,
            concurrency: 64,
            udp_payload_size: Some(1232),
            recursion_desired: true,
            dnssec_ok: false,
            max_cname_chain: 8,
        }
    }
}

impl ResolverOptions {
    /// Adds an upstream after the existing ones.
    #[must_use]
    pub fn with_upstream(mut self, upstream: Upstream) -> Self {
        self.upstreams.push(upstream);
        self
    }

    /// Replaces the upstreams.
    #[must_use]
    pub fn with_upstreams(mut self, upstreams: impl IntoIterator<Item = Upstream>) -> Self {
        self.upstreams = upstreams.into_iter().collect();
        self
    }

    /// Sets the per-exchange timeout.
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Sets the number of rounds over the upstreams.
    #[must_use]
    pub const fn with_attempts(mut self, attempts: u32) -> Self {
        self.attempts = attempts;
        self
    }

    /// Sets the cap on concurrent queries.
    #[must_use]
    pub const fn with_concurrency(mut self, concurrency: usize) -> Self {
        self.concurrency = concurrency;
        self
    }

    /// Sets the advertised EDNS(0) payload size, or disables EDNS.
    #[must_use]
    pub const fn with_udp_payload_size(mut self, size: Option<u16>) -> Self {
        self.udp_payload_size = size;
        self
    }

    /// Sets `RD`.
    #[must_use]
    pub const fn with_recursion_desired(mut self, recursion_desired: bool) -> Self {
        self.recursion_desired = recursion_desired;
        self
    }

    /// Sets `DO`.
    #[must_use]
    pub const fn with_dnssec_ok(mut self, dnssec_ok: bool) -> Self {
        self.dnssec_ok = dnssec_ok;
        self
    }

    /// Sets the `CNAME` chain limit.
    #[must_use]
    pub const fn with_max_cname_chain(mut self, max: usize) -> Self {
        self.max_cname_chain = max;
        self
    }
}
