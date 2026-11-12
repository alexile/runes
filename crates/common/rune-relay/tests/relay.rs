//! Behavioural tests for `rune-relay` over real sockets. Unix socket pairs are
//! used wherever possible; the TCP tests only touch the loopback interface.
//! Every blocking scenario runs under a deadline so a regression fails the
//! test instead of hanging the suite.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers fail loudly"
)]

use std::io::{self, Cursor, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use rune_relay::{Transferred, pipe_both_directions, relay, relay_tcp_to_uds, serve_tcp_to_uds};

const DEADLINE: Duration = Duration::from_secs(10);

/// Runs `f` on its own thread and returns its result, failing the test if it
/// takes longer than [`DEADLINE`].
fn within_deadline<T: Send + 'static>(what: &str, f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(DEADLINE)
        .unwrap_or_else(|_| panic!("{what}: did not finish within {DEADLINE:?} (hang?)"))
}

/// Deterministic pseudo-random payload.
fn payload(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x.to_le_bytes()[0]
        })
        .collect()
}

/// A temporary Unix socket path that is removed on drop.
struct SocketPath(PathBuf);

impl SocketPath {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "rune-relay-{tag}-{}-{:?}.sock",
            std::process::id(),
            thread::current().id()
        ));
        let _ = std::fs::remove_file(&path);
        Self(path)
    }
}

impl Drop for SocketPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// `client <-> [relay] <-> server` over two Unix socket pairs. Returns the
/// client end, the server end and the relay's join handle.
fn relayed_pair() -> (
    UnixStream,
    UnixStream,
    thread::JoinHandle<io::Result<Transferred>>,
) {
    let (client, client_side) = UnixStream::pair().unwrap();
    let (server_side, server) = UnixStream::pair().unwrap();
    let handle = thread::spawn(move || relay(client_side, server_side));
    (client, server, handle)
}

// ------------------------------------------------------------------- relay

#[test]
fn half_close_is_propagated_to_the_server() {
    // Regression: the relay only dropped its cloned write handle when the
    // client finished sending. Dropping one clone doesn't close a socket, so
    // the server never saw end-of-file, never answered, and the relay hung.
    let transferred = within_deadline("half-close request/response", || {
        let (mut client, mut server, relay) = relayed_pair();
        let server = thread::spawn(move || {
            let mut request = Vec::new();
            server.read_to_end(&mut request).unwrap();
            server.write_all(&request.repeat(2)).unwrap();
        });
        client.write_all(b"request").unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        assert_eq!(response, b"requestrequest");
        drop(client);
        server.join().unwrap();
        relay.join().unwrap().unwrap()
    });
    assert_eq!(transferred.a_to_b, 7);
    assert_eq!(transferred.b_to_a, 14);
}

#[test]
fn server_close_reaches_the_client_while_it_is_still_open_for_writing() {
    // Regression: when the server closed, the relay waited for the client to
    // close before releasing its handle on the client socket, so a client
    // reading to end-of-file waited forever.
    within_deadline("server closes first", || {
        let (mut client, mut server, relay) = relayed_pair();
        server.write_all(b"bye").unwrap();
        drop(server);
        let mut got = Vec::new();
        client.read_to_end(&mut got).unwrap();
        assert_eq!(got, b"bye");
        // The client's write side is still open; closing it ends the relay.
        drop(client);
        let t = relay.join().unwrap().unwrap();
        assert_eq!((t.a_to_b, t.b_to_a), (0, 3));
    });
}

#[test]
fn half_closed_connection_keeps_flowing_the_other_way() {
    within_deadline("traffic after half-close", || {
        let (mut client, mut server, relay) = relayed_pair();
        client.shutdown(Shutdown::Write).unwrap();
        let mut eof = Vec::new();
        server.read_to_end(&mut eof).unwrap();
        assert_eq!(eof, b"");
        for i in 0..5u8 {
            server.write_all(&[i; 100]).unwrap();
            let mut chunk = [0u8; 100];
            client.read_exact(&mut chunk).unwrap();
            assert_eq!(chunk, [i; 100]);
        }
        drop(server);
        drop(client);
        assert_eq!(relay.join().unwrap().unwrap().b_to_a, 500);
    });
}

#[test]
fn large_payloads_cross_simultaneously_in_both_directions() {
    // Both peers write 4 MiB before reading anything. That only completes if
    // the two directions are pumped concurrently.
    const LEN: usize = 4 << 20;
    let t = within_deadline("full-duplex bulk transfer", || {
        let (client, server, relay) = relayed_pair();
        let peer = |mut s: UnixStream, out: Vec<u8>| {
            thread::spawn(move || {
                let mut reader = s.try_clone().unwrap();
                let rx = thread::spawn(move || {
                    let mut got = Vec::new();
                    reader.read_to_end(&mut got).unwrap();
                    got
                });
                s.write_all(&out).unwrap();
                s.shutdown(Shutdown::Write).unwrap();
                rx.join().unwrap()
            })
        };
        let up = payload(LEN, 1);
        let down = payload(LEN, 2);
        let c = peer(client, up.clone());
        let s = peer(server, down.clone());
        assert!(c.join().unwrap() == down, "client received corrupted data");
        assert!(s.join().unwrap() == up, "server received corrupted data");
        relay.join().unwrap().unwrap()
    });
    assert_eq!((t.a_to_b, t.b_to_a), (LEN as u64, LEN as u64));
}

#[test]
fn abrupt_disconnect_tears_down_the_other_direction() {
    // The client vanishes with unread data in flight, which resets the
    // connection. The relay must shut the server side down rather than leave
    // the server blocked forever.
    within_deadline("reset propagation", || {
        let (client, mut server, relay) = relayed_pair();
        // Server floods the client, which never reads and then disappears.
        let flood = thread::spawn(move || {
            let chunk = vec![0u8; 64 * 1024];
            loop {
                if server.write_all(&chunk).is_err() {
                    break;
                }
            }
            server
        });
        thread::sleep(Duration::from_millis(50));
        drop(client);
        let mut server = flood.join().unwrap();
        // The relay shut the server's socket down: reading sees end-of-file.
        let mut rest = Vec::new();
        let _ = server.read_to_end(&mut rest);
        relay.join().unwrap().unwrap();
    });
}

#[test]
fn empty_connection_relays_nothing() {
    let t = within_deadline("empty connection", || {
        let (client, server, relay) = relayed_pair();
        drop(client);
        drop(server);
        relay.join().unwrap().unwrap()
    });
    assert_eq!(t, Transferred::default());
}

#[test]
fn relay_works_between_tcp_and_unix_streams() {
    within_deadline("tcp <-> unix relay", || {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (tcp_side, _) = listener.accept().unwrap();
        let (unix_side, mut server) = UnixStream::pair().unwrap();
        let relay = thread::spawn(move || relay(tcp_side, unix_side));

        client.write_all(b"over tcp").unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut got = String::new();
        server.read_to_string(&mut got).unwrap();
        assert_eq!(got, "over tcp");
        server.write_all(b"over unix").unwrap();
        drop(server);
        let mut back = String::new();
        client.read_to_string(&mut back).unwrap();
        assert_eq!(back, "over unix");
        drop(client);
        let t = relay.join().unwrap().unwrap();
        assert_eq!((t.a_to_b, t.b_to_a), (8, 9));
    });
}

// ----------------------------------------------------- pipe_both_directions

/// `pipe_both_directions` can't half-close a generic writer, but it does flush
/// each writer when its copy ends; this wrapper turns that flush into a
/// half-close so the peer sees end-of-file.
struct ShutdownOnFlush(UnixStream);

impl Write for ShutdownOnFlush {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.shutdown(Shutdown::Write)
    }
}

/// Buffered writer that reports its contents on a channel whenever flushed.
struct ReportOnFlush(io::BufWriter<Vec<u8>>, mpsc::Sender<Vec<u8>>);

impl Write for ReportOnFlush {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()?;
        let _ = self.1.send(self.0.get_ref().clone());
        Ok(())
    }
}

#[test]
fn pipe_both_directions_with_in_memory_peers() {
    let t = within_deadline("in-memory pipe", || {
        let (relay_end, mut server_end) = UnixStream::pair().unwrap();
        let server = thread::spawn(move || {
            let mut request = Vec::new();
            server_end.read_to_end(&mut request).unwrap();
            server_end.write_all(&request).unwrap();
            server_end.write_all(b"!").unwrap();
        });
        let mut response = Vec::new();
        let t = pipe_both_directions(
            Cursor::new(payload(100_000, 3)),
            &mut response,
            relay_end.try_clone().unwrap(),
            ShutdownOnFlush(relay_end),
        )
        .unwrap();
        server.join().unwrap();
        let mut expected = payload(100_000, 3);
        expected.push(b'!');
        assert_eq!(response, expected);
        t
    });
    assert_eq!((t.a_to_b, t.b_to_a), (100_000, 100_001));
}

#[test]
fn pipe_both_directions_flushes_buffered_writers() {
    let (left, right) = (
        Cursor::new(b"left".to_vec()),
        Cursor::new(b"right".to_vec()),
    );
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let mut a_out = io::BufWriter::new(Vec::new());
    let t = pipe_both_directions(
        left,
        &mut a_out,
        right,
        ReportOnFlush(io::BufWriter::new(Vec::new()), tx),
    )
    .unwrap();
    assert_eq!(a_out.get_ref(), b"right");
    assert_eq!(rx.recv().unwrap(), b"left");
    assert_eq!((t.a_to_b, t.b_to_a), (4, 5));
}

#[test]
fn pipe_both_directions_swallows_copy_errors() {
    struct Broken;
    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::ConnectionReset))
        }
    }
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let t = pipe_both_directions(Broken, Broken, Cursor::new(b"data".to_vec()), Broken).unwrap();
    assert_eq!(t, Transferred::default());
}

// ------------------------------------------------------------- TCP -> UDS

#[test]
fn relay_tcp_to_uds_bridges_to_a_unix_listener() {
    within_deadline("relay_tcp_to_uds", || {
        let path = SocketPath::new("bridge");
        let uds = UnixListener::bind(&path.0).unwrap();
        let echo = thread::spawn(move || {
            let (mut s, _) = uds.accept().unwrap();
            let mut buf = Vec::new();
            s.read_to_end(&mut buf).unwrap();
            s.write_all(&buf).unwrap();
        });
        let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = tcp.local_addr().unwrap();
        let uds_path = path.0.clone();
        let relay = thread::spawn(move || {
            let (stream, _) = tcp.accept().unwrap();
            relay_tcp_to_uds(stream, &uds_path)
        });
        let mut client = TcpStream::connect(addr).unwrap();
        client.write_all(b"hello").unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut echoed = Vec::new();
        client.read_to_end(&mut echoed).unwrap();
        assert_eq!(echoed, b"hello");
        drop(client);
        echo.join().unwrap();
        let t = relay.join().unwrap().unwrap();
        assert_eq!((t.a_to_b, t.b_to_a), (5, 5));
    });
}

#[test]
fn relay_tcp_to_uds_reports_a_missing_socket_and_closes_the_client() {
    within_deadline("missing socket", || {
        let path = SocketPath::new("missing");
        let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(tcp.local_addr().unwrap()).unwrap();
        let (stream, _) = tcp.accept().unwrap();
        let err = relay_tcp_to_uds(stream, &path.0).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        let mut rest = Vec::new();
        assert_eq!(client.read_to_end(&mut rest).unwrap(), 0);
    });
}

#[test]
fn serve_tcp_to_uds_relays_concurrent_connections() {
    let path = SocketPath::new("serve");
    let uds = UnixListener::bind(&path.0).unwrap();
    // Echo server that handles each connection on its own thread.
    thread::spawn(move || {
        for s in uds.incoming() {
            let mut s = s.unwrap();
            thread::spawn(move || {
                let mut buf = Vec::new();
                s.read_to_end(&mut buf).unwrap();
                s.write_all(&buf).unwrap();
            });
        }
    });
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = tcp.local_addr().unwrap();
    let uds_path = path.0.clone();
    // Runs for the rest of the test process; the listener is never closed.
    thread::spawn(move || serve_tcp_to_uds(&tcp, &uds_path));

    within_deadline("serve_tcp_to_uds", move || {
        // Open all connections first so they are in flight at the same time.
        let clients: Vec<(TcpStream, Vec<u8>)> = (0..8)
            .map(|i| {
                let mut c = TcpStream::connect(addr).unwrap();
                let data = payload(10_000 + i, i as u64 + 10);
                c.write_all(&data).unwrap();
                (c, data)
            })
            .collect();
        for (mut c, data) in clients {
            c.shutdown(Shutdown::Write).unwrap();
            let mut echoed = Vec::new();
            c.read_to_end(&mut echoed).unwrap();
            assert!(echoed == data, "connection echoed wrong bytes");
        }
    });
    drop(path);
}

#[test]
fn serve_tcp_to_uds_survives_an_unreachable_socket() {
    // A connection whose Unix socket is missing is dropped; the server keeps
    // accepting and serves the next one once the socket exists.
    let path = SocketPath::new("late");
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = tcp.local_addr().unwrap();
    let uds_path = path.0.clone();
    thread::spawn(move || serve_tcp_to_uds(&tcp, &uds_path));

    within_deadline("serve with late socket", move || {
        let mut first = TcpStream::connect(addr).unwrap();
        let mut rest = Vec::new();
        assert_eq!(
            first.read_to_end(&mut rest).unwrap(),
            0,
            "first connection should be closed"
        );

        let uds = UnixListener::bind(&path.0).unwrap();
        let server = thread::spawn(move || {
            let (mut s, _) = uds.accept().unwrap();
            s.write_all(b"up").unwrap();
        });
        let mut second = TcpStream::connect(addr).unwrap();
        let mut got = Vec::new();
        second.read_to_end(&mut got).unwrap();
        assert_eq!(got, b"up");
        server.join().unwrap();
    });
}
