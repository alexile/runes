//! Budgets and the sans-I/O driver shared by every runner.

use std::time::Duration;

use crate::{Action, End, Error, ProbeSession, Safety, ServiceInfo, ServiceProbe, Target};

/// Limits and policy for running probes.
///
/// The byte and step budgets apply everywhere a [`Driver`] runs; the
/// timeouts and the concurrency bound apply to the tokio
/// [`Runner`](crate::Runner).
///
/// ```
/// use std::time::Duration;
/// use rune_service_probe::Options;
///
/// let options = Options::default()
///     .with_io_timeout(Duration::from_secs(2))
///     .with_max_concurrency(32);
/// assert!(!options.allow_intrusive);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Options {
    /// Longest wait for name resolution plus the TCP handshake.
    pub connect_timeout: Duration,
    /// Longest wait for one read or write.
    pub io_timeout: Duration,
    /// Longest time one probe may take in all, connecting included.
    pub total_timeout: Duration,
    /// Most bytes one session may read. Bytes past the limit are dropped
    /// and the session ends with [`End::ReadLimit`].
    pub max_read_bytes: usize,
    /// Most [`Action::Send`]/[`Action::Receive`] steps one session may take
    /// before it ends with [`End::ExchangeLimit`].
    pub max_exchanges: usize,
    /// Most probes one [`Runner`](crate::Runner) runs at the same time.
    pub max_concurrency: usize,
    /// Run [`Safety::Intrusive`] probes. Off by default.
    pub allow_intrusive: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(3),
            io_timeout: Duration::from_secs(3),
            total_timeout: Duration::from_secs(10),
            max_read_bytes: 64 * 1024,
            max_exchanges: 32,
            max_concurrency: 8,
            allow_intrusive: false,
        }
    }
}

impl Options {
    /// Set [`Options::connect_timeout`].
    #[must_use]
    pub const fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Set [`Options::io_timeout`].
    #[must_use]
    pub const fn with_io_timeout(mut self, timeout: Duration) -> Self {
        self.io_timeout = timeout;
        self
    }

    /// Set [`Options::total_timeout`].
    #[must_use]
    pub const fn with_total_timeout(mut self, timeout: Duration) -> Self {
        self.total_timeout = timeout;
        self
    }

    /// Set [`Options::max_read_bytes`].
    #[must_use]
    pub const fn with_max_read_bytes(mut self, max: usize) -> Self {
        self.max_read_bytes = max;
        self
    }

    /// Set [`Options::max_exchanges`].
    #[must_use]
    pub const fn with_max_exchanges(mut self, max: usize) -> Self {
        self.max_exchanges = max;
        self
    }

    /// Set [`Options::max_concurrency`]. Zero is treated as one.
    #[must_use]
    pub const fn with_max_concurrency(mut self, max: usize) -> Self {
        self.max_concurrency = max;
        self
    }

    /// Set [`Options::allow_intrusive`].
    #[must_use]
    pub const fn with_allow_intrusive(mut self, allow: bool) -> Self {
        self.allow_intrusive = allow;
        self
    }
}

/// What the I/O loop around a [`Driver`] does next.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Next {
    /// Write `data` (over UDP: one datagram), then read at most `read_max`
    /// bytes and pass them to [`Driver::on_data`].
    Send {
        /// Bytes to write.
        data: Vec<u8>,
        /// Size of the read that follows.
        read_max: usize,
    },
    /// Read at most `read_max` bytes and pass them to [`Driver::on_data`].
    Receive {
        /// Size of the read.
        read_max: usize,
    },
    /// Stop and call [`Driver::finish`] with this reason.
    Finish(End),
}

/// Runs one [`ProbeSession`] within the [`Options`] budgets, without doing
/// any I/O itself.
///
/// The tokio [`Runner`](crate::Runner) and [`simulate`] are loops around a
/// driver; callers with their own runtime, a TLS stream or a blocking socket
/// write the same loop:
///
/// ```
/// use rune_service_probe::banner::BannerProbe;
/// use rune_service_probe::{Driver, End, Next, Options, Target};
///
/// let probe = BannerProbe::new();
/// let mut driver = Driver::new(&probe, &Target::new("ftp.test", 21), &Options::default())?;
/// let mut replies = [&b"220 ProFTPD Server ready.\r\n"[..]].into_iter();
/// let mut next = driver.start();
/// let end = loop {
///     match next {
///         Next::Send { .. } | Next::Receive { .. } => match replies.next() {
///             Some(reply) => next = driver.on_data(reply),
///             None => break End::Closed,
///         },
///         Next::Finish(end) => break end,
///         _ => break End::Closed,
///     }
/// };
/// let info = driver.finish(end)?;
/// assert_eq!(info.banner.as_deref(), Some("220 ProFTPD Server ready."));
/// # Ok::<(), rune_service_probe::Error>(())
/// ```
pub struct Driver {
    session: Box<dyn ProbeSession>,
    max_read_bytes: usize,
    max_exchanges: usize,
    read: usize,
    exchanges: usize,
}

impl std::fmt::Debug for Driver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Driver")
            .field("max_read_bytes", &self.max_read_bytes)
            .field("max_exchanges", &self.max_exchanges)
            .field("read", &self.read)
            .field("exchanges", &self.exchanges)
            .finish_non_exhaustive()
    }
}

impl Driver {
    /// Start a session of `probe` against `target`.
    ///
    /// # Errors
    ///
    /// [`Error::IntrusiveNotAllowed`] when the probe is
    /// [`Safety::Intrusive`] and [`Options::allow_intrusive`] is off.
    pub fn new(
        probe: &dyn ServiceProbe,
        target: &Target,
        options: &Options,
    ) -> Result<Self, Error> {
        check_allowed(probe, options)?;
        Ok(Self {
            session: probe.session(target),
            max_read_bytes: options.max_read_bytes,
            max_exchanges: options.max_exchanges,
            read: 0,
            exchanges: 0,
        })
    }

    /// The first step. Call once.
    pub fn start(&mut self) -> Next {
        let action = self.session.start();
        self.step(action)
    }

    /// Feed bytes the service sent. An empty slice means the peer closed
    /// the connection. Bytes past [`Options::max_read_bytes`] are dropped.
    pub fn on_data(&mut self, data: &[u8]) -> Next {
        if data.is_empty() {
            return Next::Finish(End::Closed);
        }
        let room = self.max_read_bytes.saturating_sub(self.read);
        let data = data.get(..room.min(data.len())).unwrap_or_default();
        if data.is_empty() {
            return Next::Finish(End::ReadLimit);
        }
        self.read += data.len();
        let action = self.session.on_data(data);
        self.step(action)
    }

    /// End the session and collect the result.
    ///
    /// # Errors
    ///
    /// Whatever [`ProbeSession::finish`] returns.
    pub fn finish(mut self, end: End) -> Result<ServiceInfo, Error> {
        self.session.finish(end)
    }

    /// Bytes read so far.
    #[must_use]
    pub const fn bytes_read(&self) -> usize {
        self.read
    }

    fn step(&mut self, action: Action) -> Next {
        let data = match action {
            Action::Send(data) => Some(data),
            Action::Receive => None,
            Action::Done => return Next::Finish(End::Done),
        };
        if self.exchanges >= self.max_exchanges {
            return Next::Finish(End::ExchangeLimit);
        }
        self.exchanges += 1;
        let read_max = self.max_read_bytes.saturating_sub(self.read);
        if read_max == 0 {
            return Next::Finish(End::ReadLimit);
        }
        data.map_or(Next::Receive { read_max }, |data| Next::Send {
            data,
            read_max,
        })
    }
}

/// Check the safety policy for `probe`.
fn check_allowed(probe: &dyn ServiceProbe, options: &Options) -> Result<(), Error> {
    if probe.safety() == Safety::Intrusive && !options.allow_intrusive {
        return Err(Error::IntrusiveNotAllowed {
            probe: probe.id().to_owned(),
        });
    }
    Ok(())
}

/// The record of a [`simulate`] run.
#[derive(Debug)]
#[non_exhaustive]
pub struct Simulation {
    /// Every payload the session sent, in order.
    pub sent: Vec<Vec<u8>>,
    /// Why the session ended.
    pub end: End,
    /// What [`ProbeSession::finish`] returned.
    pub result: Result<ServiceInfo, Error>,
}

/// Run `probe` against scripted server replies, in memory.
///
/// Each read the session asks for consumes the next reply; an empty reply
/// or running out of replies acts as the peer closing the connection. The
/// budgets in `options` apply as they do on a socket. This is how probe
/// crates test their sessions without a server, and what their fuzz
/// targets drive.
///
/// ```
/// use rune_service_probe::banner::BannerProbe;
/// use rune_service_probe::{End, Options, Target, simulate};
///
/// let probe = BannerProbe::new().with_payload(b"\r\n".to_vec());
/// let sim = simulate(&probe, &Target::new("mx.test", 25), &[b"220 mx.test ESMTP\r\n"], &Options::default())?;
/// assert_eq!(sim.sent, vec![b"\r\n".to_vec()]);
/// assert_eq!(sim.end, End::Done);
/// assert_eq!(sim.result?.banner.as_deref(), Some("220 mx.test ESMTP"));
/// # Ok::<(), rune_service_probe::Error>(())
/// ```
///
/// # Errors
///
/// [`Error::IntrusiveNotAllowed`], as for [`Driver::new`]. Errors from the
/// session itself are in [`Simulation::result`].
pub fn simulate(
    probe: &dyn ServiceProbe,
    target: &Target,
    replies: &[&[u8]],
    options: &Options,
) -> Result<Simulation, Error> {
    let mut driver = Driver::new(probe, target, options)?;
    let mut replies = replies.iter();
    let mut sent = Vec::new();
    let mut next = driver.start();
    let end = loop {
        match next {
            Next::Send { data, .. } => {
                sent.push(data);
            }
            Next::Receive { .. } => {}
            Next::Finish(end) => break end,
        }
        match replies.next() {
            Some(reply) => next = driver.on_data(reply),
            None => break End::Closed,
        }
    };
    Ok(Simulation {
        sent,
        end,
        result: driver.finish(end),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sends a request for every reply, forever.
    struct Chatty;
    struct ChattySession(usize);

    impl ServiceProbe for Chatty {
        fn id(&self) -> &'static str {
            "chatty"
        }
        fn safety(&self) -> Safety {
            Safety::Intrusive
        }
        fn session(&self, _target: &Target) -> Box<dyn ProbeSession> {
            Box::new(ChattySession(0))
        }
    }

    impl ProbeSession for ChattySession {
        fn start(&mut self) -> Action {
            Action::Send(b"?".to_vec())
        }
        fn on_data(&mut self, data: &[u8]) -> Action {
            self.0 += data.len();
            Action::Send(b"?".to_vec())
        }
        fn finish(&mut self, _end: End) -> Result<ServiceInfo, Error> {
            Ok(ServiceInfo::new("chatty").with_detail("chatty.read", self.0.to_string()))
        }
    }

    fn options() -> Options {
        Options::default().with_allow_intrusive(true)
    }

    #[test]
    fn exchange_limit_stops_a_session_that_never_finishes() {
        let replies = vec![&b"x"[..]; 100];
        let sim = simulate(
            &Chatty,
            &Target::new("h", 1),
            &replies,
            &options().with_max_exchanges(5),
        )
        .unwrap();
        assert_eq!(sim.end, End::ExchangeLimit);
        assert_eq!(sim.sent.len(), 5);
        assert_eq!(sim.result.unwrap().details["chatty.read"], "5");
    }

    #[test]
    fn read_limit_truncates_and_stops() {
        let sim = simulate(
            &Chatty,
            &Target::new("h", 1),
            &[b"abcd", b"efgh", b"ijkl"],
            &options().with_max_read_bytes(6),
        )
        .unwrap();
        assert_eq!(sim.end, End::ReadLimit);
        assert_eq!(sim.result.unwrap().details["chatty.read"], "6");
    }

    #[test]
    fn empty_reply_is_a_close() {
        let sim = simulate(&Chatty, &Target::new("h", 1), &[b"a", b""], &options()).unwrap();
        assert_eq!(sim.end, End::Closed);
    }

    #[test]
    fn intrusive_probes_are_refused_by_default() {
        let err = simulate(&Chatty, &Target::new("h", 1), &[], &Options::default()).unwrap_err();
        assert!(matches!(err, Error::IntrusiveNotAllowed { ref probe } if probe == "chatty"));
        let driver = Driver::new(&Chatty, &Target::new("h", 1), &options()).unwrap();
        assert_eq!(driver.bytes_read(), 0);
    }

    #[test]
    fn target_display_brackets_ipv6() {
        assert_eq!(Target::new("::1", 22).to_string(), "[::1]:22");
        assert_eq!(Target::new("host", 22).to_string(), "host:22");
        let addr = "[::1]:8080".parse().unwrap();
        assert_eq!(Target::from_addr(addr).host, "::1");
    }
}
