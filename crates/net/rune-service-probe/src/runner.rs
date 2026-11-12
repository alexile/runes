//! The tokio runner: sockets, timeouts and the concurrency bound.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tokio::time::{Instant, timeout_at};

use crate::{Driver, End, Error, Next, Options, ServiceInfo, ServiceProbe, Target, Transport};

/// Largest single read from a stream.
const READ_CHUNK: usize = 8 * 1024;
/// Largest UDP datagram.
const MAX_DATAGRAM: usize = 65_535;

/// Runs probes over tokio TCP and UDP sockets.
///
/// Every probe is bounded: name resolution plus connect by
/// [`Options::connect_timeout`], each read and write by
/// [`Options::io_timeout`], the whole probe by [`Options::total_timeout`],
/// and the bytes read and steps taken by the [`Driver`] budgets. At most
/// [`Options::max_concurrency`] probes run at once across every clone of
/// the runner.
///
/// The runner applies no scope policy: it probes whatever target it is
/// given. Check targets first, and pin the checked address with
/// [`Target::with_addr`].
///
/// ```no_run
/// use rune_service_probe::banner::BannerProbe;
/// use rune_service_probe::{Options, Runner, Target};
///
/// # async fn demo() -> Result<(), rune_service_probe::Error> {
/// let runner = Runner::new(Options::default());
/// let info = runner.probe(&BannerProbe::new(), &Target::new("192.0.2.10", 22)).await?;
/// println!("{:?}", info.banner);
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct Runner {
    options: Options,
    permits: Arc<Semaphore>,
}

impl Runner {
    /// A runner with these limits.
    #[must_use]
    pub fn new(options: Options) -> Self {
        let permits = Arc::new(Semaphore::new(options.max_concurrency.max(1)));
        Self { options, permits }
    }

    /// The runner's limits.
    #[must_use]
    pub const fn options(&self) -> &Options {
        &self.options
    }

    /// Connect to `target` over the probe's transport and run it.
    ///
    /// # Errors
    ///
    /// [`Error::IntrusiveNotAllowed`] before any connection is made;
    /// [`Error::Resolve`], [`Error::ConnectTimeout`] or [`Error::Connect`]
    /// when the target is unreachable; otherwise what the session's
    /// [`finish`](crate::ProbeSession::finish) returns.
    pub async fn probe(
        &self,
        probe: &dyn ServiceProbe,
        target: &Target,
    ) -> Result<ServiceInfo, Error> {
        let driver = Driver::new(probe, target, &self.options)?;
        let _permit = self.permits.acquire().await.ok();
        let deadline = Instant::now() + self.options.total_timeout;
        match probe.transport() {
            Transport::Tcp => {
                let mut stream = self.connect_tcp(target, deadline).await?;
                self.drive_stream(driver, &mut stream, deadline).await
            }
            Transport::Udp => {
                let socket = self.connect_udp(target, deadline).await?;
                self.drive_udp(driver, &socket, deadline).await
            }
        }
    }

    /// Run a TCP-style probe over a stream the caller already opened, e.g.
    /// a TLS stream for SMTPS or LDAPS. The stream is left open.
    ///
    /// # Errors
    ///
    /// [`Error::TransportMismatch`] for a UDP probe,
    /// [`Error::IntrusiveNotAllowed`], or what the session returns.
    pub async fn probe_stream<S>(
        &self,
        probe: &dyn ServiceProbe,
        target: &Target,
        stream: &mut S,
    ) -> Result<ServiceInfo, Error>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        if probe.transport() != Transport::Tcp {
            return Err(Error::TransportMismatch {
                probe: probe.id().to_owned(),
                expected: probe.transport(),
                actual: Transport::Tcp,
            });
        }
        let driver = Driver::new(probe, target, &self.options)?;
        let _permit = self.permits.acquire().await.ok();
        let deadline = Instant::now() + self.options.total_timeout;
        self.drive_stream(driver, stream, deadline).await
    }

    /// Run many probes, at most [`Options::max_concurrency`] at a time.
    /// Results are in input order.
    pub async fn probe_all<'a, I>(&self, jobs: I) -> Vec<Result<ServiceInfo, Error>>
    where
        I: IntoIterator<Item = (&'a dyn ServiceProbe, &'a Target)>,
    {
        futures::future::join_all(
            jobs.into_iter()
                .map(|(probe, target)| self.probe(probe, target)),
        )
        .await
    }

    fn io_deadline(&self, deadline: Instant) -> Instant {
        deadline.min(Instant::now() + self.options.io_timeout)
    }

    async fn resolve(&self, target: &Target, deadline: Instant) -> Result<SocketAddr, Error> {
        if let Some(addr) = target.addr {
            return Ok(addr);
        }
        let lookup = tokio::net::lookup_host((target.host.as_str(), target.port));
        let mut addrs = match timeout_at(deadline, lookup).await {
            Ok(Ok(addrs)) => addrs,
            Ok(Err(source)) => {
                return Err(Error::Connect {
                    host: target.host.clone(),
                    port: target.port,
                    source,
                });
            }
            Err(_) => return Err(connect_timeout(target)),
        };
        addrs.next().ok_or_else(|| Error::Resolve {
            host: target.host.clone(),
        })
    }

    async fn connect_tcp(&self, target: &Target, deadline: Instant) -> Result<TcpStream, Error> {
        let deadline = deadline.min(Instant::now() + self.options.connect_timeout);
        let addr = self.resolve(target, deadline).await?;
        match timeout_at(deadline, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => Ok(stream),
            Ok(Err(source)) => Err(Error::Connect {
                host: target.host.clone(),
                port: target.port,
                source,
            }),
            Err(_) => Err(connect_timeout(target)),
        }
    }

    async fn connect_udp(&self, target: &Target, deadline: Instant) -> Result<UdpSocket, Error> {
        let deadline = deadline.min(Instant::now() + self.options.connect_timeout);
        let addr = self.resolve(target, deadline).await?;
        let local: SocketAddr = if addr.is_ipv4() {
            (Ipv4Addr::UNSPECIFIED, 0).into()
        } else {
            (Ipv6Addr::UNSPECIFIED, 0).into()
        };
        let socket = async {
            let socket = UdpSocket::bind(local).await?;
            socket.connect(addr).await?;
            Ok::<_, std::io::Error>(socket)
        };
        match timeout_at(deadline, socket).await {
            Ok(Ok(socket)) => Ok(socket),
            Ok(Err(source)) => Err(Error::Connect {
                host: target.host.clone(),
                port: target.port,
                source,
            }),
            Err(_) => Err(connect_timeout(target)),
        }
    }

    async fn drive_stream<S>(
        &self,
        mut driver: Driver,
        stream: &mut S,
        deadline: Instant,
    ) -> Result<ServiceInfo, Error>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let mut buf = Vec::new();
        let mut next = driver.start();
        let end = loop {
            let read_max = match next {
                Next::Send { data, read_max } => {
                    let write = async {
                        stream.write_all(&data).await?;
                        stream.flush().await
                    };
                    match timeout_at(self.io_deadline(deadline), write).await {
                        Ok(Ok(())) => read_max,
                        Ok(Err(_)) => break End::Closed,
                        Err(_) => break End::Timeout,
                    }
                }
                Next::Receive { read_max } => read_max,
                Next::Finish(end) => break end,
            };
            buf.resize(read_max.min(READ_CHUNK), 0);
            match timeout_at(self.io_deadline(deadline), stream.read(&mut buf)).await {
                Ok(Ok(n)) => next = driver.on_data(buf.get(..n).unwrap_or_default()),
                Ok(Err(_)) => break End::Closed,
                Err(_) => break End::Timeout,
            }
        };
        driver.finish(end)
    }

    async fn drive_udp(
        &self,
        mut driver: Driver,
        socket: &UdpSocket,
        deadline: Instant,
    ) -> Result<ServiceInfo, Error> {
        let mut buf = Vec::new();
        let mut next = driver.start();
        let end = loop {
            let read_max = match next {
                Next::Send { data, read_max } => {
                    match timeout_at(self.io_deadline(deadline), socket.send(&data)).await {
                        Ok(Ok(_)) => read_max,
                        Ok(Err(_)) => break End::Closed,
                        Err(_) => break End::Timeout,
                    }
                }
                Next::Receive { read_max } => read_max,
                Next::Finish(end) => break end,
            };
            buf.resize(read_max.min(MAX_DATAGRAM), 0);
            match timeout_at(self.io_deadline(deadline), socket.recv(&mut buf)).await {
                // UDP has no close: skip an empty datagram and keep waiting
                // (the total timeout still bounds the wait).
                Ok(Ok(0)) => next = Next::Receive { read_max },
                Ok(Ok(n)) => next = driver.on_data(buf.get(..n).unwrap_or_default()),
                Ok(Err(_)) => break End::Closed,
                Err(_) => break End::Timeout,
            }
        };
        driver.finish(end)
    }
}

fn connect_timeout(target: &Target) -> Error {
    Error::ConnectTimeout {
        host: target.host.clone(),
        port: target.port,
    }
}
