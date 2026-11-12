//! The probe trait and the sans-I/O session protocol.

use std::fmt;
use std::net::SocketAddr;

use rune_finding::{Confidence, Finding, Location, Severity};

use crate::{Error, ServiceInfo};

/// The transport a probe speaks over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum Transport {
    /// A TCP byte stream (or any stream the caller wraps, e.g. TLS).
    Tcp,
    /// UDP datagrams: every [`Action::Send`] is one datagram and every
    /// [`ProbeSession::on_data`] call one reply datagram.
    Udp,
}

impl fmt::Display for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        })
    }
}

/// How safe a probe is to run against a service.
///
/// Runners refuse [`Safety::Intrusive`] probes unless
/// [`Options::allow_intrusive`](crate::Options::allow_intrusive) is set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum Safety {
    /// Reads banners and answers to read-only requests (handshakes,
    /// version and capability queries). Changes no state on the server,
    /// sends no credentials and starts no login.
    ReadOnly,
    /// Can change server state or touch authentication, e.g. confirming an
    /// anonymous FTP login. Off by default.
    Intrusive,
}

/// The endpoint a probe runs against.
///
/// The runner connects to [`Target::addr`] when set, and otherwise
/// resolves [`Target::host`]. Scope policy (which targets may be probed) is
/// the caller's: resolve and check addresses first, then pass them in with
/// [`Target::with_addr`] so that name resolution cannot change the answer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct Target {
    /// Host name or IP literal, as reported in findings (and usable as a
    /// TLS server name by callers that wrap the stream).
    pub host: String,
    /// TCP or UDP port.
    pub port: u16,
    /// Address to connect to, bypassing name resolution.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub addr: Option<SocketAddr>,
}

impl Target {
    /// A target at `host:port`, resolved when connecting.
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            addr: None,
        }
    }

    /// A target at a socket address, reported under its IP.
    #[must_use]
    pub fn from_addr(addr: SocketAddr) -> Self {
        Self {
            host: addr.ip().to_string(),
            port: addr.port(),
            addr: Some(addr),
        }
    }

    /// Connect to `addr` instead of resolving [`Target::host`].
    #[must_use]
    pub const fn with_addr(mut self, addr: SocketAddr) -> Self {
        self.addr = Some(addr);
        self
    }

    /// The finding location for this endpoint.
    #[must_use]
    pub fn location(&self) -> Location {
        Location::network(self.host.clone(), self.port)
    }

    /// Start a finding located at this endpoint. Check ids follow
    /// `<service>.<issue>`, e.g. `redis.unauthenticated`.
    ///
    /// ```
    /// use rune_finding::{Confidence, Severity, TaxonomyRef};
    /// use rune_service_probe::Target;
    ///
    /// let finding = Target::new("cache.internal", 6379)
    ///     .finding(
    ///         "redis.unauthenticated",
    ///         "Redis answers without authentication",
    ///         Severity::Critical,
    ///         Confidence::Certain,
    ///     )
    ///     .push_taxonomy(TaxonomyRef::cwe(306));
    /// assert_eq!(finding.check_id, "redis.unauthenticated");
    /// ```
    pub fn finding(
        &self,
        check_id: impl Into<String>,
        title: impl Into<String>,
        severity: Severity,
        confidence: Confidence,
    ) -> Finding {
        Finding::new(check_id, title, severity, confidence, self.location())
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

/// What a [`ProbeSession`] wants to do next.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Action {
    /// Write these bytes (over UDP: send them as one datagram), then wait
    /// for the reply.
    Send(Vec<u8>),
    /// Wait for more bytes without sending anything. Server-speaks-first
    /// protocols (SSH, SMTP, FTP) start with this.
    Receive,
    /// Stop: the session has what it needs.
    Done,
}

/// Why a session ended. Passed to [`ProbeSession::finish`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum End {
    /// The session returned [`Action::Done`].
    Done,
    /// The peer closed the connection, or a read or write failed.
    Closed,
    /// No reply arrived within the I/O timeout, or the total timeout ran out.
    Timeout,
    /// The session read [`Options::max_read_bytes`](crate::Options::max_read_bytes).
    ReadLimit,
    /// The session took [`Options::max_exchanges`](crate::Options::max_exchanges) steps.
    ExchangeLimit,
}

/// One conversation with one service: a sans-I/O state machine.
///
/// A driver (the tokio [`Runner`](crate::Runner), [`simulate`](crate::simulate)
/// or the caller's own loop around a [`Driver`](crate::Driver)) calls
/// [`start`](Self::start) once, performs each returned [`Action`] and feeds
/// the bytes it receives to [`on_data`](Self::on_data), until the session
/// returns [`Action::Done`] or the conversation ends for another reason.
/// It then calls [`finish`](Self::finish) exactly once.
///
/// Over TCP, `on_data` gets whatever one read returned: a message may arrive
/// split over several calls, or several messages in one. Sessions buffer
/// until they have a whole frame and return [`Action::Receive`] meanwhile.
pub trait ProbeSession: Send {
    /// The first action.
    fn start(&mut self) -> Action;

    /// Bytes arrived from the service. Never called with an empty slice.
    fn on_data(&mut self, data: &[u8]) -> Action;

    /// The conversation is over: report what was learned.
    ///
    /// Return partial information when there is some, even if `end` is not
    /// [`End::Done`]: a banner read before a timeout is still a banner.
    ///
    /// # Errors
    ///
    /// [`Error::NoResponse`] when nothing arrived, and
    /// [`Error::Unrecognized`] when the peer does not speak the protocol.
    fn finish(&mut self, end: End) -> Result<ServiceInfo, Error>;
}

/// A read-only probe for one protocol.
///
/// The probe is the reusable, configured part (an SNMP community list, a
/// payload); [`session`](Self::session) creates the per-connection state.
/// Probes are object safe, so runners and [`ProbeSet`](crate::ProbeSet)s
/// hold any mix of them as `dyn ServiceProbe`.
pub trait ServiceProbe: Send + Sync {
    /// Stable, lowercase identifier: `ssh`, `mysql`, `redis`, `smb`. Used as
    /// [`ServiceInfo::service`] and as the prefix of finding check ids.
    fn id(&self) -> &str;

    /// The transport the probe needs. TCP unless overridden.
    fn transport(&self) -> Transport {
        Transport::Tcp
    }

    /// How safe the probe is. Read-only unless overridden.
    fn safety(&self) -> Safety {
        Safety::ReadOnly
    }

    /// Well-known ports of the service, for port-to-probe hints. Empty
    /// unless overridden.
    fn default_ports(&self) -> &[u16] {
        &[]
    }

    /// Start a session against `target`. The target is there for findings
    /// ([`Target::finding`]) and for protocols that name the host.
    fn session(&self, target: &Target) -> Box<dyn ProbeSession>;
}
