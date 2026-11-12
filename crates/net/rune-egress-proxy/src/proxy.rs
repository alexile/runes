//! Blocking, thread-per-connection CONNECT proxy built on the sans-I/O core.

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rune_host_match::Hostname;

use crate::{DEFAULT_MAX_HEAD_LEN, Decision, Denial, Error, Policy, Target, parse_request};

/// Resolves an allowed hostname to candidate addresses.
///
/// [`SystemResolver`] uses the operating system's resolver. Any
/// `Fn(&Hostname, u16) -> io::Result<Vec<SocketAddr>>` closure works too,
/// which is how tests and callers with their own DNS (a pinned hosts map,
/// a `DoH` client) plug in.
pub trait Resolve: Send + Sync {
    /// The addresses `host` resolves to. The proxy replaces the port of
    /// every returned address with `port`.
    fn resolve(&self, host: &Hostname, port: u16) -> io::Result<Vec<SocketAddr>>;
}

impl<F> Resolve for F
where
    F: Fn(&Hostname, u16) -> io::Result<Vec<SocketAddr>> + Send + Sync,
{
    fn resolve(&self, host: &Hostname, port: u16) -> io::Result<Vec<SocketAddr>> {
        self(host, port)
    }
}

/// The operating system's resolver, through [`ToSocketAddrs`].
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemResolver;

impl Resolve for SystemResolver {
    fn resolve(&self, host: &Hostname, port: u16) -> io::Result<Vec<SocketAddr>> {
        Ok((host.as_str(), port).to_socket_addrs()?.collect())
    }
}

/// A client connection the proxy can serve: [`TcpStream`] and, on Unix,
/// [`UnixStream`](std::os::unix::net::UnixStream).
pub trait Stream: Read + Write + Send + Sized + 'static {
    /// Another handle to the same connection.
    fn try_clone(&self) -> io::Result<Self>;
    /// Sets or clears the read timeout.
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
    /// Shuts down one or both halves of the connection.
    fn shutdown(&self, how: Shutdown) -> io::Result<()>;
}

impl Stream for TcpStream {
    fn try_clone(&self) -> io::Result<Self> {
        Self::try_clone(self)
    }
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        Self::set_read_timeout(self, timeout)
    }
    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        Self::shutdown(self, how)
    }
}

#[cfg(unix)]
impl Stream for std::os::unix::net::UnixStream {
    fn try_clone(&self) -> io::Result<Self> {
        Self::try_clone(self)
    }
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        Self::set_read_timeout(self, timeout)
    }
    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        Self::shutdown(self, how)
    }
}

/// What happened to one client connection, for logging and metrics.
#[derive(Debug)]
#[non_exhaustive]
pub enum Event<'a> {
    /// The request head was invalid; the client got a 400, 431 or 501.
    Rejected {
        /// Why.
        error: &'a Error,
    },
    /// The policy refused the target; the client got a 403 or 502.
    Denied {
        /// The requested target.
        target: &'a Target,
        /// Why.
        denial: Denial,
    },
    /// Connecting to the pinned address failed; the client got a 502 or 504.
    UpstreamFailed {
        /// The requested target.
        target: &'a Target,
        /// The address the proxy tried.
        addr: SocketAddr,
        /// The connect error.
        error: &'a io::Error,
    },
    /// The tunnel is open; the client got a 200.
    Tunnel {
        /// The requested target.
        target: &'a Target,
        /// The pinned upstream address.
        addr: SocketAddr,
    },
}

impl fmt::Display for Event<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected { error } => write!(f, "rejected request: {error}"),
            Self::Denied { target, denial } => write!(f, "denied CONNECT {target}: {denial}"),
            Self::UpstreamFailed {
                target,
                addr,
                error,
            } => write!(f, "CONNECT {target} via {addr} failed: {error}"),
            Self::Tunnel { target, addr } => write!(f, "tunnel CONNECT {target} via {addr}"),
        }
    }
}

type Observer = Arc<dyn Fn(&Event<'_>) + Send + Sync>;

/// An allowlisting HTTP `CONNECT` proxy.
///
/// Each connection is handled on its own thread: read the request head
/// (bounded by size and time), [`Policy::decide`], resolve and
/// [`Policy::pin`] hostnames, connect to the pinned address only, answer
/// `200`, and relay bytes both ways until both sides close. Anything other
/// than a valid CONNECT to an allowed target gets an error status and the
/// connection is closed.
///
/// The proxy only tunnels: it does not see inside TLS, and it constrains
/// only clients that use it. Pair it with a network namespace that has no
/// other route out (as `rune-secops-warden` does) for a hard boundary.
///
/// ```no_run
/// use std::net::TcpListener;
/// use rune_egress_proxy::{Policy, Proxy};
///
/// let policy = Policy::new().allow_host("*.crates.io")?.allow_port(443);
/// let proxy = Proxy::new(policy).with_observer(|event| eprintln!("{event}"));
/// let listener = TcpListener::bind("127.0.0.1:3128")?;
/// proxy.serve_tcp(&listener);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone)]
pub struct Proxy {
    policy: Arc<Policy>,
    resolver: Arc<dyn Resolve>,
    observer: Option<Observer>,
    max_head_len: usize,
    head_timeout: Option<Duration>,
    connect_timeout: Duration,
}

impl fmt::Debug for Proxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Proxy")
            .field("policy", &self.policy)
            .field("max_head_len", &self.max_head_len)
            .field("head_timeout", &self.head_timeout)
            .field("connect_timeout", &self.connect_timeout)
            .finish_non_exhaustive()
    }
}

impl Proxy {
    /// Default time a client has to send its whole request head.
    pub const DEFAULT_HEAD_TIMEOUT: Duration = Duration::from_secs(30);
    /// Default upstream connect timeout.
    pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

    /// A proxy enforcing `policy`, with the [`SystemResolver`] and default
    /// limits.
    #[must_use]
    pub fn new(policy: Policy) -> Self {
        Self {
            policy: Arc::new(policy),
            resolver: Arc::new(SystemResolver),
            observer: None,
            max_head_len: DEFAULT_MAX_HEAD_LEN,
            head_timeout: Some(Self::DEFAULT_HEAD_TIMEOUT),
            connect_timeout: Self::DEFAULT_CONNECT_TIMEOUT,
        }
    }

    /// Uses `resolver` for allowed hostnames.
    #[must_use]
    pub fn with_resolver(mut self, resolver: impl Resolve + 'static) -> Self {
        self.resolver = Arc::new(resolver);
        self
    }

    /// Calls `observer` for every connection outcome.
    #[must_use]
    pub fn with_observer(mut self, observer: impl Fn(&Event<'_>) + Send + Sync + 'static) -> Self {
        self.observer = Some(Arc::new(observer));
        self
    }

    /// Limits the request head to `max` bytes (default
    /// [`DEFAULT_MAX_HEAD_LEN`]).
    #[must_use]
    pub const fn with_max_head_len(mut self, max: usize) -> Self {
        self.max_head_len = max;
        self
    }

    /// Time a client has for each read of its request head; `None` waits
    /// forever. Default [`Proxy::DEFAULT_HEAD_TIMEOUT`].
    #[must_use]
    pub const fn with_head_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.head_timeout = timeout;
        self
    }

    /// Upstream connect timeout. Default [`Proxy::DEFAULT_CONNECT_TIMEOUT`].
    #[must_use]
    pub const fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// The policy this proxy enforces.
    #[must_use]
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Accepts connections forever, serving each on its own thread.
    pub fn serve_tcp(&self, listener: &TcpListener) -> ! {
        loop {
            if let Ok((stream, _)) = listener.accept() {
                self.spawn_handler(stream);
            }
        }
    }

    /// Accepts Unix domain socket connections forever, serving each on its
    /// own thread. A socket file can be bind-mounted into a sandbox whose
    /// network namespace has no other way out.
    #[cfg(unix)]
    pub fn serve_unix(&self, listener: &std::os::unix::net::UnixListener) -> ! {
        loop {
            if let Ok((stream, _)) = listener.accept() {
                self.spawn_handler(stream);
            }
        }
    }

    fn spawn_handler<S: Stream>(&self, stream: S) {
        let proxy = self.clone();
        // A failed spawn drops the stream, which closes the connection.
        let _ = thread::Builder::new()
            .name("egress-proxy-conn".into())
            .spawn(move || proxy.handle(stream));
    }

    /// Serves one client connection on the calling thread, until the tunnel
    /// closes or the request is refused.
    ///
    /// A refused request is not an error: the client gets an HTTP status
    /// and the [observer](Proxy::with_observer) an [`Event`]. Errors are
    /// I/O failures on the client connection.
    pub fn handle<S: Stream>(&self, mut client: S) -> io::Result<()> {
        client.set_read_timeout(self.head_timeout)?;
        let mut buf = Vec::with_capacity(1024);
        let mut chunk = [0u8; 1024];
        let request = loop {
            match parse_request(&buf, self.max_head_len) {
                Ok(Some(request)) => break request,
                Ok(None) => {}
                Err(error) => {
                    self.emit(&Event::Rejected { error: &error });
                    return reply(&mut client, error.status().unwrap_or(400));
                }
            }
            let n = match client.read(&mut chunk) {
                Ok(0) => return Ok(()),
                Ok(n) => n,
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) => return Err(err),
            };
            buf.extend_from_slice(&chunk[..n]);
        };
        let target = &request.target;

        let addr = match self.policy.decide(target) {
            Decision::Connect(addr) => Ok(addr),
            Decision::Resolve { host, port } => match self.resolver.resolve(&host, port) {
                Ok(addrs) if !addrs.is_empty() => self
                    .policy
                    .pin(addrs.into_iter().map(|a| SocketAddr::new(a.ip(), port))),
                _ => Err(Denial::ResolveFailed),
            },
            Decision::Deny(denial) => Err(denial),
        };
        let addr = match addr {
            Ok(addr) => addr,
            Err(denial) => {
                self.emit(&Event::Denied { target, denial });
                return reply(&mut client, denial.status());
            }
        };

        // Connect to exactly the pinned address; never re-resolve.
        let mut upstream = match TcpStream::connect_timeout(&addr, self.connect_timeout) {
            Ok(upstream) => upstream,
            Err(error) => {
                self.emit(&Event::UpstreamFailed {
                    target,
                    addr,
                    error: &error,
                });
                let status = if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) {
                    504
                } else {
                    502
                };
                return reply(&mut client, status);
            }
        };
        client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
        self.emit(&Event::Tunnel { target, addr });
        client.set_read_timeout(None)?;
        upstream.write_all(&buf[request.head_len..])?;
        relay(client, upstream)
    }

    fn emit(&self, event: &Event<'_>) {
        if let Some(observer) = &self.observer {
            observer(event);
        }
    }
}

/// Copies both directions until both are done, propagating half-closes so
/// that each side sees the other's EOF. An error in either direction tears
/// the whole tunnel down.
fn relay<S: Stream>(client: S, upstream: TcpStream) -> io::Result<()> {
    let mut client_rx = client.try_clone()?;
    let mut upstream_tx = upstream.try_clone()?;
    let uploader = thread::Builder::new()
        .name("egress-proxy-up".into())
        .spawn(move || {
            if io::copy(&mut client_rx, &mut upstream_tx).is_ok() {
                let _ = upstream_tx.shutdown(Shutdown::Write);
            } else {
                let _ = upstream_tx.shutdown(Shutdown::Both);
                let _ = client_rx.shutdown(Shutdown::Both);
            }
        })?;
    let (mut upstream_rx, mut client_tx) = (upstream, client);
    if io::copy(&mut upstream_rx, &mut client_tx).is_ok() {
        let _ = client_tx.shutdown(Shutdown::Write);
    } else {
        let _ = client_tx.shutdown(Shutdown::Both);
        let _ = upstream_rx.shutdown(Shutdown::Both);
    }
    let _ = uploader.join();
    Ok(())
}

fn reply<S: Stream>(client: &mut S, status: u16) -> io::Result<()> {
    let reason = match status {
        400 => "Bad Request",
        403 => "Forbidden",
        431 => "Request Header Fields Too Large",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        504 => "Gateway Timeout",
        _ => "Error",
    };
    write!(
        client,
        "HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )?;
    client.flush()?;
    let _ = client.shutdown(Shutdown::Write);
    Ok(())
}
