//! Bidirectional byte relay between two stream halves, plus a ready-made
//! TCP-listener-to-Unix-domain-socket bridge built on it.
//!
//! The crate has three layers, all blocking and thread-based:
//!
//! - [`relay`] joins two full-duplex sockets ([`TcpStream`], [`UnixStream`], or
//!   anything implementing [`DuplexStream`]). It copies bytes both ways at once
//!   and **propagates half-closes**: when one peer shuts down its write side, the
//!   relay shuts down the write side towards the other peer, so request/response
//!   protocols that signal "end of request" with `shutdown(Write)` work through it.
//!   If either direction fails (a reset, a broken pipe), both sockets are shut
//!   down so the other direction ends too.
//! - [`pipe_both_directions`] is the generic core for arbitrary readers and
//!   writers that have no notion of a half-close (in-memory buffers, pipes,
//!   wrappers). It returns once **both** readers reach end-of-file or fail.
//! - [`relay_tcp_to_uds`] and [`serve_tcp_to_uds`] are the case this crate was
//!   pulled out to support: bridging a TCP port to a Unix domain socket, for
//!   programs that can only dial TCP but need to reach a service that only
//!   listens on a UDS path (for example a sandboxed process whose private
//!   loopback needs a way out through a bind-mounted socket).
//!
//! The relay has no protocol awareness at all — it doesn't know or care whether
//! the bytes are HTTP, a database wire protocol, or anything else.
//!
//! # Example
//!
//! [`relay`] between two in-process Unix socket pairs. The client half-closes
//! after its request, the server answers once it sees end-of-file:
//!
//! ```
//! use std::io::{Read, Write};
//! use std::net::Shutdown;
//! use std::os::unix::net::UnixStream;
//! use std::thread;
//!
//! let (mut client, client_side) = UnixStream::pair()?;
//! let (server_side, mut server) = UnixStream::pair()?;
//!
//! let relay = thread::spawn(move || rune_relay::relay(client_side, server_side));
//! let server = thread::spawn(move || -> std::io::Result<()> {
//!     let mut request = String::new();
//!     server.read_to_string(&mut request)?; // ends at the client's half-close
//!     server.write_all(request.to_uppercase().as_bytes())
//! });
//!
//! client.write_all(b"ping")?;
//! client.shutdown(Shutdown::Write)?;
//! let mut response = String::new();
//! client.read_to_string(&mut response)?;
//! assert_eq!(response, "PING");
//! drop(client);
//!
//! server.join().expect("server thread")?;
//! let transferred = relay.join().expect("relay thread")?;
//! assert_eq!((transferred.a_to_b, transferred.b_to_a), (4, 4));
//! # Ok::<(), std::io::Error>(())
//! ```
//!
//! [`pipe_both_directions`] accepts any readers and writers. Here side A is an
//! in-memory client (a request buffer and a response buffer):
//!
//! ```
//! use std::io::{Cursor, Read, Write};
//! use std::os::unix::net::UnixStream;
//! use std::thread;
//!
//! use rune_relay::pipe_both_directions;
//!
//! let (relay_end, mut server_end) = UnixStream::pair()?;
//! let server = thread::spawn(move || -> std::io::Result<()> {
//!     let mut request = [0u8; 4];
//!     server_end.read_exact(&mut request)?;
//!     assert_eq!(&request, b"PING");
//!     server_end.write_all(b"PONG")
//!     // Dropping `server_end` closes the connection and ends the relay.
//! });
//!
//! let request = Cursor::new(b"PING".to_vec());
//! let mut response = Vec::new();
//! pipe_both_directions(request, &mut response, relay_end.try_clone()?, relay_end)?;
//!
//! server.join().expect("server thread")?;
//! assert_eq!(response, b"PONG");
//! # Ok::<(), std::io::Error>(())
//! ```
//!
//! Bridging a TCP port to a Unix domain socket:
//!
//! ```no_run
//! use std::net::TcpListener;
//! use std::path::Path;
//!
//! let listener = TcpListener::bind("127.0.0.1:8080")?;
//! rune_relay::serve_tcp_to_uds(&listener, Path::new("/run/some.sock"))?;
//! # Ok::<(), std::io::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::io::{self, ErrorKind, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::thread;
use std::time::Duration;

/// Number of bytes a relay copied in each direction.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Transferred {
    /// Bytes read from side A and written to side B.
    pub a_to_b: u64,
    /// Bytes read from side B and written to side A.
    pub b_to_a: u64,
}

/// A full-duplex byte stream that can be duplicated into independent reader
/// and writer handles and shut down one direction at a time.
///
/// Implemented for [`TcpStream`] and [`UnixStream`]; implement it for other
/// socket types to use them with [`relay`].
pub trait DuplexStream: Read + Write + Send + Sized + 'static {
    /// Returns a new handle to the same underlying stream
    /// (like [`TcpStream::try_clone`]).
    ///
    /// # Errors
    ///
    /// Returns the operating-system error if the handle cannot be duplicated.
    fn try_clone_stream(&self) -> io::Result<Self>;

    /// Shuts down the read half, the write half, or both halves of the stream,
    /// for every handle to it (like [`TcpStream::shutdown`]).
    ///
    /// # Errors
    ///
    /// Returns the operating-system error, for example `NotConnected` when the
    /// peer has already gone. [`relay`] ignores these errors.
    fn shutdown_stream(&self, how: Shutdown) -> io::Result<()>;
}

impl DuplexStream for TcpStream {
    fn try_clone_stream(&self) -> io::Result<Self> {
        self.try_clone()
    }

    fn shutdown_stream(&self, how: Shutdown) -> io::Result<()> {
        self.shutdown(how)
    }
}

impl DuplexStream for UnixStream {
    fn try_clone_stream(&self) -> io::Result<Self> {
        self.try_clone()
    }

    fn shutdown_stream(&self, how: Shutdown) -> io::Result<()> {
        self.shutdown(how)
    }
}

/// Copies `reader` into `writer` until end-of-file or an error, retrying
/// interrupted reads and writes, then flushes `writer`.
///
/// Unlike [`io::copy`], the byte count survives an error: the count of bytes
/// fully written so far is returned alongside it.
fn copy_counted(reader: &mut impl Read, writer: &mut impl Write) -> (u64, Option<io::Error>) {
    let mut buf = [0u8; 16 * 1024];
    let mut total = 0u64;
    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return (total, Some(e)),
        };
        // `write_all` already retries `Interrupted`.
        if let Err(e) = buf.get(..n).map_or(Ok(()), |chunk| writer.write_all(chunk)) {
            return (total, Some(e));
        }
        total += n as u64;
    }
    match writer.flush() {
        Ok(()) => (total, None),
        Err(e) => (total, Some(e)),
    }
}

/// Spawns a named relay thread, reporting spawn failure as an error instead of
/// panicking like [`thread::spawn`].
fn spawn<T: Send + 'static>(
    name: &str,
    f: impl FnOnce() -> T + Send + 'static,
) -> io::Result<thread::JoinHandle<T>> {
    thread::Builder::new().name(name.to_owned()).spawn(f)
}

/// Relay bytes between two peers, each already split into a reader and
/// writer half.
///
/// Copies `side_a_read` into `side_b_write` on a background thread while
/// copying `side_b_read` into `side_a_write` on the calling thread, and returns
/// once **both** copies have finished, i.e. once each reader has reached
/// end-of-file or failed. Each writer is flushed when its copy ends and dropped
/// when the function returns.
///
/// Read and write errors end the affected direction and are otherwise dropped
/// rather than propagated — a relay's job ends when the connection ends,
/// however that happens. The returned [`Transferred`] counts the bytes that
/// were written in each direction.
///
/// Generic writers cannot be half-closed, so nothing tells side B that side A
/// has finished until the writer is dropped. With socket halves obtained from
/// `try_clone`, dropping one handle does not close the socket: use [`relay`]
/// instead, which shuts the write side down explicitly.
///
/// # Errors
///
/// Returns an error only if the background thread cannot be spawned.
#[allow(clippy::similar_names, reason = "side A/B naming is deliberate")]
pub fn pipe_both_directions(
    mut side_a_read: impl Read + Send + 'static,
    mut side_a_write: impl Write,
    mut side_b_read: impl Read,
    mut side_b_write: impl Write + Send + 'static,
) -> io::Result<Transferred> {
    let uploader = spawn("rune-relay a->b", move || {
        copy_counted(&mut side_a_read, &mut side_b_write).0
    })?;
    let (b_to_a, _) = copy_counted(&mut side_b_read, &mut side_a_write);
    // A panic can only come from a caller-supplied reader or writer; the
    // relay treats it like any other failure of that direction.
    let a_to_b = uploader.join().unwrap_or(0);
    Ok(Transferred { a_to_b, b_to_a })
}

/// Ends one direction of a [`relay`]: after a clean end-of-file, half-close
/// the destination so its peer sees end-of-file too; after an error, shut both
/// sockets down completely so the opposite direction stops as well.
fn finish_direction(
    from: &impl DuplexStream,
    to: &impl DuplexStream,
    outcome: (u64, Option<io::Error>),
) -> u64 {
    let (count, error) = outcome;
    // Shutdown errors (typically `NotConnected` once a peer is gone) carry no
    // information the relay could act on.
    if error.is_none() {
        let _ = to.shutdown_stream(Shutdown::Write);
    } else {
        let _ = from.shutdown_stream(Shutdown::Both);
        let _ = to.shutdown_stream(Shutdown::Both);
    }
    count
}

/// Relay bytes between two full-duplex streams until both directions have
/// ended.
///
/// Each direction is copied on its own thread (the calling thread and one
/// spawned thread). When a peer half-closes (its read side reaches
/// end-of-file), the relay shuts down the write side towards the other peer,
/// preserving the half-close end to end. When a direction fails, both streams
/// are shut down completely so that the other direction ends promptly instead
/// of blocking forever. A peer that half-closes but never closes its other
/// half keeps the relay running, exactly as it would keep a direct connection
/// open.
///
/// # Errors
///
/// Returns an error if a stream handle cannot be duplicated or the background
/// thread cannot be spawned. Errors while copying end the relay normally and
/// are reflected only in the byte counts.
pub fn relay<A: DuplexStream, B: DuplexStream>(a: A, b: B) -> io::Result<Transferred> {
    let mut a_read = a.try_clone_stream()?;
    let mut b_read = b.try_clone_stream()?;
    let mut b_write = b;
    let mut a_write = a;

    let uploader = spawn("rune-relay a->b", move || {
        let outcome = copy_counted(&mut a_read, &mut b_write);
        finish_direction(&a_read, &b_write, outcome)
    });
    let uploader = match uploader {
        Ok(handle) => handle,
        Err(e) => {
            let _ = a_write.shutdown_stream(Shutdown::Both);
            let _ = b_read.shutdown_stream(Shutdown::Both);
            return Err(e);
        }
    };

    let outcome = copy_counted(&mut b_read, &mut a_write);
    let b_to_a = finish_direction(&b_read, &a_write, outcome);
    // The thread body cannot panic (it only does I/O on std sockets or the
    // caller's `DuplexStream`); treat a panic as zero bytes copied.
    let a_to_b = uploader.join().unwrap_or(0);
    Ok(Transferred { a_to_b, b_to_a })
}

/// Relay one TCP connection to a Unix domain socket at `uds_path`,
/// blocking until both directions have ended (see [`relay`]).
///
/// # Errors
///
/// Returns an error if `uds_path` cannot be connected to (the TCP connection
/// is then closed), or if [`relay`] cannot start.
pub fn relay_tcp_to_uds(tcp: TcpStream, uds_path: &Path) -> io::Result<Transferred> {
    let uds = UnixStream::connect(uds_path)?;
    relay(tcp, uds)
}

/// What the accept loop does after a failed `accept`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AcceptFailure {
    /// The failure concerned a single pending connection; accept the next one.
    Retry,
    /// The process or system is out of a resource (descriptors, memory,
    /// threads) or the listener is non-blocking; wait before retrying so the
    /// loop doesn't spin at 100% CPU.
    Backoff,
    /// The listener itself is unusable; retrying can never succeed.
    Fatal,
}

fn classify_accept_error(e: &io::Error) -> AcceptFailure {
    match e.kind() {
        ErrorKind::ConnectionAborted
        | ErrorKind::ConnectionReset
        | ErrorKind::ConnectionRefused
        | ErrorKind::Interrupted
        | ErrorKind::TimedOut
        | ErrorKind::PermissionDenied => AcceptFailure::Retry,
        // EINVAL: the socket is not listening. Also what `accept` on a socket
        // that was shut down returns.
        ErrorKind::InvalidInput => AcceptFailure::Fatal,
        // EMFILE / ENFILE / ENOBUFS / ENOMEM / EAGAIN and anything unknown.
        _ => AcceptFailure::Backoff,
    }
}

/// Shortest pause after a resource-exhaustion accept failure.
const MIN_BACKOFF: Duration = Duration::from_millis(5);
/// Longest pause after repeated resource-exhaustion accept failures.
const MAX_BACKOFF: Duration = Duration::from_secs(1);

/// The accept loop behind [`serve_tcp_to_uds`], with the connection source,
/// handler and sleep injected so its error handling can be tested without
/// sockets. Returns `Ok(())` when `incoming` ends and `Err` on a fatal accept
/// error. A handler error (e.g. no thread could be spawned) drops that
/// connection and backs off like an accept failure.
fn accept_loop<S>(
    incoming: impl IntoIterator<Item = io::Result<S>>,
    mut handle: impl FnMut(S) -> io::Result<()>,
    mut sleep: impl FnMut(Duration),
) -> io::Result<()> {
    let mut backoff = MIN_BACKOFF;
    for conn in incoming {
        let failure = match conn {
            Ok(stream) => match handle(stream) {
                Ok(()) => {
                    backoff = MIN_BACKOFF;
                    continue;
                }
                Err(_) => AcceptFailure::Backoff,
            },
            Err(e) => match classify_accept_error(&e) {
                AcceptFailure::Fatal => return Err(e),
                other => other,
            },
        };
        if failure == AcceptFailure::Backoff {
            sleep(backoff);
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }
    }
    Ok(())
}

/// Accept connections on `listener` forever, relaying each one to
/// `uds_path` on its own thread via [`relay_tcp_to_uds`].
///
/// Failures that concern a single connection (it was reset before it could
/// be accepted, the Unix socket refused it, …) are skipped. When the process
/// runs out of file descriptors, memory or threads, the loop sleeps with
/// exponential backoff (5 ms doubling up to 1 s) instead of spinning, and
/// resumes once resources free up.
///
/// # Errors
///
/// Does not return under normal operation. Returns an error only if the
/// listener itself becomes unusable (`accept` fails with `InvalidInput`,
/// e.g. the socket is not listening).
pub fn serve_tcp_to_uds(listener: &TcpListener, uds_path: &Path) -> io::Result<()> {
    accept_loop(
        listener.incoming(),
        |stream| {
            let uds_path = uds_path.to_path_buf();
            spawn("rune-relay conn", move || {
                let _ = relay_tcp_to_uds(stream, &uds_path);
            })
            .map(drop)
        },
        thread::sleep,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn err(kind: ErrorKind) -> io::Result<u32> {
        Err(io::Error::from(kind))
    }

    /// Runs `accept_loop` over `incoming`, returning (handled ids, sleeps, result).
    fn run_loop(
        incoming: Vec<io::Result<u32>>,
        fail_handler_for: &[u32],
    ) -> (Vec<u32>, Vec<Duration>, io::Result<()>) {
        let handled = RefCell::new(Vec::new());
        let mut sleeps = Vec::new();
        let result = accept_loop(
            incoming,
            |id| {
                handled.borrow_mut().push(id);
                if fail_handler_for.contains(&id) {
                    Err(io::Error::from(ErrorKind::WouldBlock))
                } else {
                    Ok(())
                }
            },
            |d| sleeps.push(d),
        );
        (handled.into_inner(), sleeps, result)
    }

    #[test]
    fn accept_loop_handles_every_connection_and_ends_with_the_source() {
        let (handled, sleeps, result) = run_loop(vec![Ok(1), Ok(2), Ok(3)], &[]);
        assert_eq!(handled, [1, 2, 3]);
        assert_eq!(sleeps, []);
        assert!(result.is_ok());
    }

    #[test]
    fn per_connection_accept_errors_are_skipped_without_sleeping() {
        let incoming = vec![
            Ok(1),
            err(ErrorKind::ConnectionAborted),
            err(ErrorKind::ConnectionReset),
            err(ErrorKind::Interrupted),
            err(ErrorKind::PermissionDenied),
            Ok(2),
        ];
        let (handled, sleeps, result) = run_loop(incoming, &[]);
        assert_eq!(handled, [1, 2]);
        assert_eq!(sleeps, []);
        assert!(result.is_ok());
    }

    #[test]
    fn resource_exhaustion_backs_off_exponentially_and_resets() {
        // Regression: `listener.incoming().flatten()` silently skipped every
        // error, so EMFILE (which repeats until a descriptor frees up) made
        // the accept loop spin at 100% CPU.
        let mut incoming: Vec<io::Result<u32>> = (0..10)
            .map(|_| Err(io::Error::other("Too many open files")))
            .collect();
        incoming.push(Ok(7));
        incoming.push(err(ErrorKind::OutOfMemory));
        let (handled, sleeps, result) = run_loop(incoming, &[]);
        assert_eq!(handled, [7]);
        let ms: Vec<u128> = sleeps.iter().map(Duration::as_millis).collect();
        assert_eq!(ms, [5, 10, 20, 40, 80, 160, 320, 640, 1000, 1000, 5]);
        assert!(result.is_ok());
    }

    #[test]
    fn handler_failure_drops_the_connection_and_backs_off() {
        let (handled, sleeps, result) = run_loop(vec![Ok(1), Ok(2), Ok(3)], &[1, 2]);
        assert_eq!(handled, [1, 2, 3]);
        assert_eq!(sleeps, [MIN_BACKOFF, MIN_BACKOFF * 2]);
        assert!(result.is_ok());
    }

    #[test]
    fn unusable_listener_is_fatal() {
        let incoming = vec![Ok(1), err(ErrorKind::InvalidInput), Ok(2)];
        let (handled, _, result) = run_loop(incoming, &[]);
        assert_eq!(handled, [1]);
        assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidInput);
    }

    /// Reader that yields its chunks one `read` at a time, interleaved with
    /// `Interrupted`, then optionally fails instead of reporting end-of-file.
    struct Flaky {
        chunks: Vec<&'static [u8]>,
        interrupt_next: bool,
        fail_at_end: bool,
    }

    impl Read for Flaky {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if std::mem::replace(&mut self.interrupt_next, false) {
                return Err(io::Error::from(ErrorKind::Interrupted));
            }
            self.interrupt_next = true;
            if self.chunks.is_empty() {
                return if self.fail_at_end {
                    Err(io::Error::from(ErrorKind::ConnectionReset))
                } else {
                    Ok(0)
                };
            }
            let chunk = self.chunks.remove(0);
            buf[..chunk.len()].copy_from_slice(chunk);
            Ok(chunk.len())
        }
    }

    #[test]
    fn copy_counted_retries_interrupts_and_counts() {
        let mut reader = Flaky {
            chunks: vec![b"abc", b"", b"defg"],
            interrupt_next: true,
            fail_at_end: false,
        };
        // An empty chunk reads as end-of-file, so only "abc" is copied.
        let mut out = Vec::new();
        let (n, e) = copy_counted(&mut reader, &mut out);
        assert_eq!((n, out.as_slice()), (3, b"abc".as_slice()));
        assert!(e.is_none());
    }

    #[test]
    fn copy_counted_keeps_the_count_on_read_error() {
        let mut reader = Flaky {
            chunks: vec![b"hello", b"world"],
            interrupt_next: false,
            fail_at_end: true,
        };
        let mut out = Vec::new();
        let (n, e) = copy_counted(&mut reader, &mut out);
        assert_eq!(n, 10);
        assert_eq!(out, b"helloworld");
        assert_eq!(e.map(|e| e.kind()), Some(ErrorKind::ConnectionReset));
    }

    #[test]
    fn copy_counted_reports_write_errors() {
        struct Full(usize);
        impl Write for Full {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                if self.0 == 0 {
                    return Err(io::Error::from(ErrorKind::BrokenPipe));
                }
                let n = buf.len().min(self.0);
                self.0 -= n;
                Ok(n)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut reader: &[u8] = b"0123456789";
        let (n, e) = copy_counted(&mut reader, &mut Full(4));
        // The single 10-byte chunk was only partly written, so it doesn't count.
        assert_eq!(n, 0);
        assert_eq!(e.map(|e| e.kind()), Some(ErrorKind::BrokenPipe));
    }

    #[test]
    fn copy_counted_reports_flush_errors() {
        struct NoFlush(Vec<u8>);
        impl Write for NoFlush {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.0.write(buf)
            }
            fn flush(&mut self) -> io::Result<()> {
                Err(io::Error::from(ErrorKind::WriteZero))
            }
        }
        let mut reader: &[u8] = b"abc";
        let mut w = NoFlush(Vec::new());
        let (n, e) = copy_counted(&mut reader, &mut w);
        assert_eq!(n, 3);
        assert_eq!(e.map(|e| e.kind()), Some(ErrorKind::WriteZero));
    }
}
