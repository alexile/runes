//! The tokio connect scanner.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};

use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::{Instant, sleep_until, timeout};

use crate::error::Result;
use crate::plan::{Options, Pacer, PortResult, PortState, Report};
use crate::ports::PortSet;

/// An async TCP connect scanner.
///
/// Each host/port pair gets a full TCP connect (no raw sockets, no
/// privileges). At most [`Options::concurrency`] attempts are in flight,
/// attempts start no faster than [`Options::rate`], and each is bounded by
/// [`Options::connect_timeout`]. With [`Options::banners`] on, open ports
/// are read (never written) for up to [`Options::banner_timeout`].
///
/// The scanner applies no scope policy and does no name resolution: it
/// connects to exactly the addresses it is given. Only scan hosts you are
/// authorised to test, and resolve and scope-check names before calling.
///
/// ```no_run
/// use std::net::{IpAddr, Ipv4Addr};
/// use rune_port_scan::{Options, PortSet, Scanner};
///
/// # async fn demo() -> Result<(), rune_port_scan::Error> {
/// let scanner = Scanner::new(Options::default().with_banners(true));
/// let hosts = [IpAddr::V4(Ipv4Addr::LOCALHOST)];
/// let report = scanner.scan(&hosts, &"top-20,8000-8100".parse::<PortSet>()?).await?;
/// for open in report.open() {
///     println!("{} {:?}", open.addr, open.service);
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct Scanner {
    options: Arc<Options>,
    permits: Arc<Semaphore>,
    pacer: Arc<Mutex<Pacer>>,
}

impl Scanner {
    /// A scanner with these settings. Clones share the concurrency bound
    /// and the rate limit.
    #[must_use]
    pub fn new(options: Options) -> Self {
        let permits = Arc::new(Semaphore::new(
            options.concurrency.clamp(1, Semaphore::MAX_PERMITS),
        ));
        let pacer = Arc::new(Mutex::new(Pacer::new(options.rate)));
        Self {
            options: Arc::new(options),
            permits,
            pacer,
        }
    }

    /// The scanner's settings.
    #[must_use]
    pub fn options(&self) -> &Options {
        &self.options
    }

    /// Scans every port of `ports` on every host of `hosts`.
    ///
    /// Ports are taken in [`PortSet`] order, each across all hosts in turn,
    /// so a multi-host scan spreads its load. Must be called inside a tokio
    /// runtime.
    ///
    /// # Errors
    ///
    /// [`Error::TooManyTargets`](crate::Error::TooManyTargets) before any
    /// connection is made. Per-port failures are reported in the
    /// [`Report`], not as errors.
    pub async fn scan(&self, hosts: &[IpAddr], ports: &PortSet) -> Result<Report> {
        let count = self.options.check_size(hosts.len(), ports.len())?;
        let started = Instant::now();
        let mut tasks = JoinSet::new();
        let mut results = Vec::with_capacity(usize::try_from(count).unwrap_or(0));
        for port in ports {
            for &ip in hosts {
                // Acquire before spawning, so at most `concurrency` tasks
                // exist at once however large the scan is.
                let Ok(permit) = Arc::clone(&self.permits).acquire_owned().await else {
                    break;
                };
                let scanner = self.clone();
                tasks.spawn(async move {
                    let result = scanner.attempt(SocketAddr::new(ip, port)).await;
                    drop(permit);
                    result
                });
                while let Some(done) = tasks.try_join_next() {
                    results.extend(done.ok());
                }
            }
        }
        while let Some(done) = tasks.join_next().await {
            results.extend(done.ok());
        }
        Ok(Report::new(results, started.elapsed()))
    }

    /// Tries one address, respecting the concurrency bound and the rate.
    pub async fn scan_addr(&self, addr: SocketAddr) -> PortResult {
        let _permit = self.permits.acquire().await.ok();
        self.attempt(addr).await
    }

    async fn attempt(&self, addr: SocketAddr) -> PortResult {
        let slot = self
            .pacer
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .reserve(Instant::now().into_std());
        sleep_until(Instant::from_std(slot)).await;

        let started = Instant::now();
        let outcome = timeout(self.options.connect_timeout, TcpStream::connect(addr)).await;
        let rtt = started.elapsed();
        let result = match outcome {
            Ok(Ok(mut stream)) => {
                let mut result = PortResult::new(addr, PortState::Open, rtt);
                if self.options.banners {
                    result.banner = Some(self.read_banner(&mut stream).await);
                }
                result
            }
            Ok(Err(err)) => {
                let state = classify(&err);
                let mut result = PortResult::new(addr, state, rtt);
                if state == PortState::Error {
                    result.error = Some(err.to_string());
                }
                result
            }
            Err(_) => PortResult::new(addr, PortState::Filtered, rtt),
        };
        result.with_hints()
    }

    /// Reads what the service sends first, up to the limits.
    async fn read_banner(&self, stream: &mut TcpStream) -> Vec<u8> {
        let max = self.options.max_banner;
        let mut banner = Vec::new();
        let mut chunk = vec![0; max.clamp(1, 4096)];
        let deadline = Instant::now() + self.options.banner_timeout;
        while banner.len() < max {
            let want = (max - banner.len()).min(chunk.len());
            let Some(buf) = chunk.get_mut(..want) else {
                break;
            };
            match tokio::time::timeout_at(deadline, stream.read(buf)).await {
                Ok(Ok(n)) if n > 0 => banner.extend_from_slice(buf.get(..n).unwrap_or_default()),
                _ => break,
            }
            // Text greetings end in a line break: stop there rather than
            // wait out the timeout on services that now expect the client.
            if banner.last() == Some(&b'\n') {
                break;
            }
        }
        banner
    }
}

fn classify(err: &io::Error) -> PortState {
    match err.kind() {
        io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionReset => PortState::Closed,
        io::ErrorKind::TimedOut => PortState::Filtered,
        io::ErrorKind::HostUnreachable | io::ErrorKind::NetworkUnreachable => {
            PortState::Unreachable
        }
        _ => PortState::Error,
    }
}
