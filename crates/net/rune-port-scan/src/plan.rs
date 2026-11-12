//! Scan options, pacing, and the report model: everything except sockets.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::time::{Duration, Instant};

use crate::error::{Error, Result};
use crate::hint::{OsHint, ServiceHint};

/// Timing presets, loosely modelled on nmap's `-T0` … `-T4`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum Timing {
    /// One connection at a time, 1 attempt per second, 5 s timeout.
    Paranoid,
    /// One connection at a time, 5 attempts per second, 3 s timeout.
    Sneaky,
    /// 16 at once, 50 attempts per second, 2 s timeout.
    Polite,
    /// 256 at once, 1000 attempts per second, 1 s timeout (the default).
    #[default]
    Normal,
    /// 1024 at once, 5000 attempts per second, 500 ms timeout.
    Aggressive,
}

/// Scan settings. Start from [`Options::default`] or [`Options::timing`]
/// and adjust with the `with_*` methods.
///
/// ```
/// use std::time::Duration;
/// use rune_port_scan::{Options, Timing};
///
/// let options = Options::timing(Timing::Polite)
///     .with_rate(Some(20))
///     .with_banners(true)
///     .with_connect_timeout(Duration::from_millis(800));
/// assert_eq!(options.concurrency, 16);
/// assert_eq!(options.rate.map(|r| r.get()), Some(20));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Options {
    /// Most connection attempts in flight at once (at least 1).
    pub concurrency: usize,
    /// Most connection attempts started per second; `None` is unlimited.
    /// Attempts are spaced evenly rather than sent in bursts.
    pub rate: Option<NonZeroU32>,
    /// How long a connect may take before the port counts as filtered.
    pub connect_timeout: Duration,
    /// Read what an open port sends first (read-only: nothing is sent).
    pub banners: bool,
    /// How long to wait for a banner after connecting.
    pub banner_timeout: Duration,
    /// Most banner bytes kept per port.
    pub max_banner: usize,
    /// Most host/port pairs a single scan may cover, a guard against
    /// accidentally huge sweeps.
    pub max_targets: u64,
}

impl Default for Options {
    fn default() -> Self {
        Self::timing(Timing::Normal)
    }
}

impl Options {
    /// The preset for `timing`; banners off, 512-byte banner limit,
    /// 1 Mi target limit.
    #[must_use]
    pub const fn timing(timing: Timing) -> Self {
        let (concurrency, rate, timeout_ms) = match timing {
            Timing::Paranoid => (1, 1, 5000),
            Timing::Sneaky => (1, 5, 3000),
            Timing::Polite => (16, 50, 2000),
            Timing::Normal => (256, 1000, 1000),
            Timing::Aggressive => (1024, 5000, 500),
        };
        Self {
            concurrency,
            rate: NonZeroU32::new(rate),
            connect_timeout: Duration::from_millis(timeout_ms),
            banners: false,
            banner_timeout: Duration::from_millis(1500),
            max_banner: 512,
            max_targets: 1 << 20,
        }
    }

    /// Sets [`concurrency`](Self::concurrency).
    #[must_use]
    pub const fn with_concurrency(mut self, concurrency: usize) -> Self {
        self.concurrency = concurrency;
        self
    }

    /// Sets [`rate`](Self::rate) in attempts per second; `None` or
    /// `Some(0)` removes the limit.
    #[must_use]
    pub const fn with_rate(mut self, per_second: Option<u32>) -> Self {
        self.rate = match per_second {
            Some(rate) => NonZeroU32::new(rate),
            None => None,
        };
        self
    }

    /// Sets [`connect_timeout`](Self::connect_timeout).
    #[must_use]
    pub const fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Sets [`banners`](Self::banners).
    #[must_use]
    pub const fn with_banners(mut self, on: bool) -> Self {
        self.banners = on;
        self
    }

    /// Sets [`banner_timeout`](Self::banner_timeout).
    #[must_use]
    pub const fn with_banner_timeout(mut self, timeout: Duration) -> Self {
        self.banner_timeout = timeout;
        self
    }

    /// Sets [`max_banner`](Self::max_banner).
    #[must_use]
    pub const fn with_max_banner(mut self, bytes: usize) -> Self {
        self.max_banner = bytes;
        self
    }

    /// Sets [`max_targets`](Self::max_targets).
    #[must_use]
    pub const fn with_max_targets(mut self, max: u64) -> Self {
        self.max_targets = max;
        self
    }

    /// Checks a scan of `hosts` × `ports` against
    /// [`max_targets`](Self::max_targets) and returns the pair count.
    ///
    /// # Errors
    ///
    /// [`Error::TooManyTargets`] when the scan is too large.
    pub const fn check_size(&self, hosts: usize, ports: usize) -> Result<u64> {
        let count = (hosts as u64).saturating_mul(ports as u64);
        if count > self.max_targets {
            return Err(Error::TooManyTargets {
                count,
                max: self.max_targets,
            });
        }
        Ok(count)
    }
}

/// Spaces events evenly at a fixed rate. Sans-I/O: the caller supplies
/// the clock and sleeps until the returned instant.
///
/// ```
/// use std::num::NonZeroU32;
/// use std::time::{Duration, Instant};
/// use rune_port_scan::Pacer;
///
/// let mut pacer = Pacer::new(NonZeroU32::new(10));
/// let t0 = Instant::now();
/// assert_eq!(pacer.reserve(t0), t0);
/// assert_eq!(pacer.reserve(t0), t0 + Duration::from_millis(100));
/// assert_eq!(pacer.reserve(t0), t0 + Duration::from_millis(200));
/// ```
#[derive(Debug, Clone)]
pub struct Pacer {
    interval: Option<Duration>,
    next: Option<Instant>,
}

impl Pacer {
    /// A pacer allowing `per_second` events per second; `None` never waits.
    #[must_use]
    pub fn new(per_second: Option<NonZeroU32>) -> Self {
        Self {
            interval: per_second.map(|rate| Duration::from_secs(1) / rate.get()),
            next: None,
        }
    }

    /// Reserves the next slot at or after `now` and returns when it starts.
    /// Unused time does not accumulate: after an idle spell the next event
    /// starts at `now`, not in a catch-up burst.
    pub fn reserve(&mut self, now: Instant) -> Instant {
        let Some(interval) = self.interval else {
            return now;
        };
        let at = self.next.map_or(now, |next| next.max(now));
        self.next = at.checked_add(interval);
        at
    }
}

/// What a connect attempt found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum PortState {
    /// The connection was accepted.
    Open,
    /// The host refused the connection (TCP RST).
    Closed,
    /// No answer before the connect timeout: dropped by a firewall, or the
    /// host is down.
    Filtered,
    /// The network or host was reported unreachable (ICMP).
    Unreachable,
    /// A local error prevented the attempt (out of sockets, permission
    /// denied, ...); see [`PortResult::error`].
    Error,
}

/// The outcome for one host/port pair.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct PortResult {
    /// The address that was tried.
    pub addr: SocketAddr,
    /// What the attempt found.
    pub state: PortState,
    /// Time from starting the connect to its outcome.
    pub rtt: Duration,
    /// What an open port sent first, when banners are on (bounded by
    /// [`Options::max_banner`]; may be empty).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub banner: Option<Vec<u8>>,
    /// The service guess for open ports.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub service: Option<ServiceHint>,
    /// The OS family suggested by the banner.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub os: Option<OsHint>,
    /// The error text for [`PortState::Error`].
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub error: Option<String>,
}

impl PortResult {
    /// A result with no banner, hint or error.
    #[must_use]
    pub const fn new(addr: SocketAddr, state: PortState, rtt: Duration) -> Self {
        Self {
            addr,
            state,
            rtt,
            banner: None,
            service: None,
            os: None,
            error: None,
        }
    }

    /// Fills in [`service`](Self::service) and [`os`](Self::os) from the
    /// port number and the banner. Only open ports get hints.
    #[must_use]
    pub fn with_hints(mut self) -> Self {
        if self.state == PortState::Open {
            let banner = self.banner.as_deref().filter(|b| !b.is_empty());
            self.service = crate::hint::hint(self.addr.port(), banner);
            self.os = banner.and_then(crate::hint::os_hint);
        }
        self
    }

    /// The banner as printable text: control characters other than tab
    /// are dropped and invalid UTF-8 is replaced.
    #[must_use]
    pub fn banner_text(&self) -> Option<String> {
        self.banner.as_deref().map(|banner| {
            String::from_utf8_lossy(banner)
                .chars()
                .map(|c| if c == '\r' || c == '\n' { ' ' } else { c })
                .filter(|&c| c == '\t' || !c.is_control())
                .collect::<String>()
                .trim()
                .to_owned()
        })
    }
}

/// Counts by state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct Stats {
    /// Host/port pairs tried.
    pub attempted: u64,
    /// [`PortState::Open`].
    pub open: u64,
    /// [`PortState::Closed`].
    pub closed: u64,
    /// [`PortState::Filtered`].
    pub filtered: u64,
    /// [`PortState::Unreachable`].
    pub unreachable: u64,
    /// [`PortState::Error`].
    pub errors: u64,
}

/// The result of a scan.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct Report {
    /// One entry per host/port pair, sorted by address then port.
    pub results: Vec<PortResult>,
    /// Counts by state.
    pub stats: Stats,
    /// Wall-clock duration of the scan.
    pub elapsed: Duration,
}

impl Report {
    /// Builds a report from results in any order.
    #[must_use]
    pub fn new(mut results: Vec<PortResult>, elapsed: Duration) -> Self {
        results.sort_by_key(|r| (r.addr.ip(), r.addr.port()));
        let mut stats = Stats {
            attempted: results.len() as u64,
            ..Stats::default()
        };
        for result in &results {
            let counter = match result.state {
                PortState::Open => &mut stats.open,
                PortState::Closed => &mut stats.closed,
                PortState::Filtered => &mut stats.filtered,
                PortState::Unreachable => &mut stats.unreachable,
                PortState::Error => &mut stats.errors,
            };
            *counter += 1;
        }
        Self {
            results,
            stats,
            elapsed,
        }
    }

    /// The open ports.
    pub fn open(&self) -> impl Iterator<Item = &PortResult> {
        self.results.iter().filter(|r| r.state == PortState::Open)
    }

    /// The OS family most of `ip`'s banners point to, if any do.
    #[must_use]
    pub fn os_hint(&self, ip: IpAddr) -> Option<OsHint> {
        let mut votes = BTreeMap::new();
        for os in self
            .results
            .iter()
            .filter(|r| r.addr.ip() == ip)
            .filter_map(|r| r.os)
        {
            *votes.entry(os).or_insert(0_u32) += 1;
        }
        votes
            .into_iter()
            .max_by_key(|&(_, count)| count)
            .map(|(os, _)| os)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pacer_spaces_and_does_not_burst_after_idle() {
        let mut pacer = Pacer::new(NonZeroU32::new(4));
        let t0 = Instant::now();
        let slots: Vec<_> = (0..3).map(|_| pacer.reserve(t0)).collect();
        assert_eq!(
            slots,
            [
                t0,
                t0 + Duration::from_millis(250),
                t0 + Duration::from_millis(500)
            ]
        );
        let later = t0 + Duration::from_secs(10);
        assert_eq!(pacer.reserve(later), later);
        assert_eq!(pacer.reserve(later), later + Duration::from_millis(250));
        let mut free = Pacer::new(None);
        assert_eq!(free.reserve(t0), t0);
        assert_eq!(free.reserve(t0), t0);
    }

    #[test]
    fn options_and_size_guard() {
        let options = Options::default().with_rate(Some(0)).with_max_targets(10);
        assert_eq!(options.rate, None);
        assert_eq!(options.check_size(2, 5), Ok(10));
        assert_eq!(
            options.check_size(3, 4),
            Err(Error::TooManyTargets { count: 12, max: 10 })
        );
        assert!(Options::timing(Timing::Paranoid).connect_timeout > options.connect_timeout);
    }

    #[test]
    fn report_sorts_counts_and_votes() {
        let a: SocketAddr = "10.0.0.2:22".parse().unwrap();
        let b: SocketAddr = "10.0.0.1:80".parse().unwrap();
        let c: SocketAddr = "10.0.0.2:21".parse().unwrap();
        let mut ssh = PortResult::new(a, PortState::Open, Duration::ZERO);
        ssh.banner = Some(b"SSH-2.0-OpenSSH_9.2p1 Debian-2\r\n".to_vec());
        let mut ftp = PortResult::new(c, PortState::Open, Duration::ZERO);
        ftp.banner = Some(b"220 (vsFTPd 3.0.3)\r\n".to_vec());
        let report = Report::new(
            vec![
                ssh.with_hints(),
                PortResult::new(b, PortState::Closed, Duration::ZERO).with_hints(),
                ftp.with_hints(),
            ],
            Duration::from_secs(1),
        );
        let order: Vec<_> = report.results.iter().map(|r| r.addr).collect();
        assert_eq!(order, [b, c, a]);
        assert_eq!((report.stats.open, report.stats.closed), (2, 1));
        assert_eq!(report.open().count(), 2);
        assert_eq!(report.results[0].service, None);
        assert_eq!(report.results[1].service.as_ref().unwrap().service, "ftp");
        assert_eq!(report.os_hint(a.ip()), Some(OsHint::Linux));
        assert_eq!(report.os_hint(b.ip()), None);
        assert_eq!(
            report.results[2].banner_text().as_deref(),
            Some("SSH-2.0-OpenSSH_9.2p1 Debian-2")
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_round_trip() {
        let addr: SocketAddr = "[2001:db8::1]:22".parse().unwrap();
        let mut open = PortResult::new(addr, PortState::Open, Duration::from_millis(2));
        open.banner = Some(b"SSH-2.0-OpenSSH_9.6 FreeBSD\r\n".to_vec());
        let report = Report::new(vec![open.with_hints()], Duration::from_secs(1));
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"state\":\"open\"") && json.contains("\"os\":\"bsd\""));
        assert_eq!(serde_json::from_str::<Report>(&json).unwrap(), report);

        let ports = crate::PortSet::parse("80,8000-8010").unwrap();
        let json = serde_json::to_string(&ports).unwrap();
        assert_eq!(json, "\"80,8000-8010\"");
        assert_eq!(
            serde_json::from_str::<crate::PortSet>(&json).unwrap(),
            ports
        );
        assert!(serde_json::from_str::<crate::PortSet>("\"0\"").is_err());
    }
}
