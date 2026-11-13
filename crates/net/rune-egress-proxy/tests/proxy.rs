//! End-to-end tests over loopback only: a real proxy, real sockets, and
//! local listeners standing in for upstream servers. Hostnames resolve
//! through an in-process resolver, never real DNS.

#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use rune_egress_proxy::{Event, Hostname, Policy, Proxy};

/// Resolves every name ending in `.test` to 127.0.0.1, anything else fails.
fn loopback_resolver(host: &Hostname, port: u16) -> io::Result<Vec<SocketAddr>> {
    if host.labels().next_back() == Some("test") {
        Ok(vec![SocketAddr::from(([127, 0, 0, 1], port))])
    } else {
        Err(io::Error::new(io::ErrorKind::NotFound, "no such host"))
    }
}

/// Starts `proxy` on an ephemeral loopback port.
fn start_tcp(proxy: Proxy) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || proxy.serve_tcp(&listener));
    addr
}

/// Starts `proxy` on a fresh Unix socket.
fn start_unix(proxy: Proxy) -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let path = std::env::temp_dir().join(format!(
        "rune-egress-proxy-test-{}-{}.sock",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).unwrap();
    thread::spawn(move || proxy.serve_unix(&listener));
    path
}

/// A one-shot upstream that echoes everything until EOF, then closes.
fn echo_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut data = Vec::new();
            let _ = stream.read_to_end(&mut data);
            let _ = stream.write_all(&data);
        }
    });
    port
}

/// Sends `head` and returns the response status line and a reader
/// positioned after the response head.
fn connect<S: Read + Write>(mut stream: S, head: &str) -> (String, BufReader<S>) {
    stream.write_all(head.as_bytes()).unwrap();
    let mut reader = BufReader::new(stream);
    let mut status = String::new();
    reader.read_line(&mut status).unwrap();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
            break;
        }
    }
    (status, reader)
}

fn tcp(addr: SocketAddr) -> TcpStream {
    let stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
}

/// Tunnels `payload` through an open CONNECT and returns what came back
/// after the client half-closed.
fn round_trip(reader: BufReader<TcpStream>, payload: &[u8]) -> Vec<u8> {
    let mut stream = reader.get_ref().try_clone().unwrap();
    stream.write_all(payload).unwrap();
    stream.shutdown(Shutdown::Write).unwrap();
    let mut reader = reader;
    let mut echoed = Vec::new();
    reader.read_to_end(&mut echoed).unwrap();
    echoed
}

// Ported from rune-secops-warden `proxy_allows_a_permitted_connect_and_relays_bytes`.
#[test]
fn unix_proxy_allows_a_permitted_connect_and_relays_bytes() {
    let port = echo_server();
    let path = start_unix(Proxy::new(Policy::new().allow_ip("127.0.0.1").unwrap()));
    let client = UnixStream::connect(&path).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let (status, mut reader) = connect(
        client.try_clone().unwrap(),
        &format!("CONNECT 127.0.0.1:{port} HTTP/1.1\r\n\r\n"),
    );
    assert!(status.starts_with("HTTP/1.1 200"), "got: {status}");
    let mut client = client;
    client.write_all(b"hello").unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let mut echoed = Vec::new();
    reader.read_to_end(&mut echoed).unwrap();
    assert_eq!(echoed, b"hello");
    let _ = std::fs::remove_file(path);
}

// Ported from rune-secops-warden `proxy_rejects_a_domain_not_in_the_allowlist`.
#[test]
fn unix_proxy_rejects_a_domain_not_in_the_allowlist() {
    let path = start_unix(Proxy::new(
        Policy::new().allow_host("allowed.example").unwrap(),
    ));
    let (status, _) = connect(
        UnixStream::connect(&path).unwrap(),
        "CONNECT not-allowed.example:443 HTTP/1.1\r\n\r\n",
    );
    assert!(status.starts_with("HTTP/1.1 403"), "got: {status}");
    let _ = std::fs::remove_file(path);
}

// Ported from rune-secops-warden `proxy_allows_a_bare_ip_covered_by_a_cidr_range`.
#[test]
fn bare_ip_covered_by_a_cidr_range_is_tunnelled() {
    let port = echo_server();
    let proxy = start_tcp(Proxy::new(Policy::new().allow_ip("127.0.0.0/8").unwrap()));
    let (status, reader) = connect(
        tcp(proxy),
        &format!("CONNECT 127.0.0.1:{port} HTTP/1.1\r\n\r\n"),
    );
    assert!(status.starts_with("HTTP/1.1 200"), "got: {status}");
    assert_eq!(round_trip(reader, b"abc"), b"abc");
}

// Ported from rune-secops-warden `proxy_rejects_a_bare_ip_not_in_allowed_ips`:
// a public address gets no "it is public" fallback. Refused before any
// connect, so no network is touched.
#[test]
fn bare_ip_outside_the_ip_allowlist_is_refused() {
    let proxy = start_tcp(Proxy::new(Policy::new().allow_ip("10.0.0.0/8").unwrap()));
    let (status, _) = connect(tcp(proxy), "CONNECT 8.8.8.8:443 HTTP/1.1\r\n\r\n");
    assert!(status.starts_with("HTTP/1.1 403"), "got: {status}");
}

#[test]
fn wildcard_allows_subdomains_but_not_the_apex() {
    let port = echo_server();
    let policy = Policy::new()
        .allow_host("*.example.test")
        .unwrap()
        .allow_ip("127.0.0.0/8")
        .unwrap();
    let proxy = start_tcp(Proxy::new(policy).with_resolver(loopback_resolver));

    let (status, reader) = connect(
        tcp(proxy),
        &format!("CONNECT API.example.test:{port} HTTP/1.1\r\nHost: api.example.test\r\n\r\n"),
    );
    assert!(status.starts_with("HTTP/1.1 200"), "got: {status}");
    assert_eq!(round_trip(reader, b"sub"), b"sub");

    for denied in ["example.test", "evilexample.test"] {
        let (status, _) = connect(
            tcp(proxy),
            &format!("CONNECT {denied}:{port} HTTP/1.1\r\n\r\n"),
        );
        assert!(status.starts_with("HTTP/1.1 403"), "{denied}: {status}");
    }
}

/// SSRF / DNS rebinding: an allowed hostname that resolves to loopback is
/// refused unless loopback is IP-allowlisted.
#[test]
fn allowed_name_resolving_to_a_private_address_is_refused() {
    let port = echo_server();
    let events = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&events);
    let proxy = start_tcp(
        Proxy::new(Policy::new().allow_host("rebind.test").unwrap())
            .with_resolver(loopback_resolver)
            .with_observer(move |event| log.lock().unwrap().push(event.to_string())),
    );
    let (status, _) = connect(
        tcp(proxy),
        &format!("CONNECT rebind.test:{port} HTTP/1.1\r\n\r\n"),
    );
    assert!(status.starts_with("HTTP/1.1 403"), "got: {status}");
    let events = events.lock().unwrap().clone();
    assert!(events[0].contains("rebinding"), "{events:?}");
}

/// The proxy resolves once and connects to the pinned address, ignoring
/// whatever port the resolver returned.
#[test]
fn hostnames_are_resolved_once_and_pinned() {
    let port = echo_server();
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    let resolver = move |_: &Hostname, _: u16| {
        counter.fetch_add(1, Ordering::SeqCst);
        // A non-global address first (refused), then the allowlisted one,
        // both with a wrong port.
        Ok(vec![
            SocketAddr::from(([169, 254, 169, 254], 1)),
            SocketAddr::from(([127, 0, 0, 1], 1)),
        ])
    };
    let policy = Policy::new()
        .allow_host("pinned.test")
        .unwrap()
        .allow_ip("127.0.0.1")
        .unwrap();
    let events = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&events);
    let proxy = start_tcp(
        Proxy::new(policy)
            .with_resolver(resolver)
            .with_observer(move |event| {
                if let Event::Tunnel { addr, .. } = event {
                    log.lock().unwrap().push(*addr);
                }
            }),
    );
    let (status, reader) = connect(
        tcp(proxy),
        &format!("CONNECT pinned.test:{port} HTTP/1.1\r\n\r\n"),
    );
    assert!(status.starts_with("HTTP/1.1 200"), "got: {status}");
    assert_eq!(round_trip(reader, b"pin"), b"pin");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        *events.lock().unwrap(),
        [SocketAddr::from(([127, 0, 0, 1], port))]
    );
}

/// Bytes the client sends right behind the head (a TLS `ClientHello`, say)
/// reach upstream.
#[test]
fn early_payload_is_forwarded() {
    let port = echo_server();
    let proxy = start_tcp(Proxy::new(Policy::new().allow_ip("127.0.0.1").unwrap()));
    let mut stream = tcp(proxy);
    stream
        .write_all(format!("CONNECT 127.0.0.1:{port} HTTP/1.1\r\n\r\nearly-").as_bytes())
        .unwrap();
    let (status, reader) = connect(stream, "");
    assert!(status.starts_with("HTTP/1.1 200"), "got: {status}");
    assert_eq!(round_trip(reader, b"late"), b"early-late");
}

#[test]
fn port_allowlist_is_enforced() {
    let port = echo_server();
    let proxy = start_tcp(Proxy::new(
        Policy::new().allow_ip("127.0.0.1").unwrap().allow_port(443),
    ));
    let (status, _) = connect(
        tcp(proxy),
        &format!("CONNECT 127.0.0.1:{port} HTTP/1.1\r\n\r\n"),
    );
    assert!(status.starts_with("HTTP/1.1 403"), "got: {status}");
}

#[test]
fn bad_requests_get_error_statuses() {
    let proxy = start_tcp(
        Proxy::new(Policy::new().allow_host("*.test").unwrap())
            .with_resolver(loopback_resolver)
            .with_max_head_len(256),
    );
    for (head, expected) in [
        ("GET http://a.test/ HTTP/1.1\r\n\r\n".to_owned(), "501"),
        ("CONNECT a.test HTTP/1.1\r\n\r\n".to_owned(), "400"),
        (
            format!(
                "CONNECT a.test:443 HTTP/1.1\r\nX: {}\r\n\r\n",
                "a".repeat(300)
            ),
            "431",
        ),
        // Outside the host allowlist.
        ("CONNECT a.invalid:443 HTTP/1.1\r\n\r\n".to_owned(), "403"),
    ] {
        let (status, _) = connect(tcp(proxy), &head);
        assert!(
            status.starts_with(&format!("HTTP/1.1 {expected}")),
            "{head:?}: {status}"
        );
    }
}

#[test]
fn resolver_failure_is_a_bad_gateway() {
    let proxy = start_tcp(
        Proxy::new(Policy::new().allow_host("missing.example").unwrap())
            .with_resolver(loopback_resolver),
    );
    let (status, _) = connect(tcp(proxy), "CONNECT missing.example:443 HTTP/1.1\r\n\r\n");
    assert!(status.starts_with("HTTP/1.1 502"), "got: {status}");
}

#[test]
fn refused_upstream_is_a_bad_gateway() {
    let closed = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = closed.local_addr().unwrap().port();
    drop(closed);
    let proxy = start_tcp(Proxy::new(Policy::new().allow_ip("127.0.0.1").unwrap()));
    let (status, _) = connect(
        tcp(proxy),
        &format!("CONNECT 127.0.0.1:{port} HTTP/1.1\r\n\r\n"),
    );
    assert!(status.starts_with("HTTP/1.1 502"), "got: {status}");
}

#[test]
fn slow_clients_time_out() {
    let proxy =
        start_tcp(Proxy::new(Policy::new()).with_head_timeout(Some(Duration::from_millis(100))));
    let mut stream = tcp(proxy);
    stream
        .write_all(b"CONNECT a.test:443 HTTP/1.1\r\n")
        .unwrap();
    let mut rest = Vec::new();
    // The proxy gives up and closes without a response.
    assert_eq!(stream.read_to_end(&mut rest).unwrap(), 0);
}

// Regression: the head timeout applied to each read, so a client sending a
// byte just under every timeout held its connection (and thread) open for
// as long as it liked. It now bounds the whole head.
#[test]
fn trickling_clients_time_out_on_the_whole_head() {
    let proxy =
        start_tcp(Proxy::new(Policy::new()).with_head_timeout(Some(Duration::from_millis(300))));
    let stream = tcp(proxy);
    let mut writer = stream.try_clone().unwrap();
    let trickle = thread::spawn(move || {
        // 40 bytes at 50 ms each: 2 s in total, never 300 ms apart.
        for byte in b"CONNECT a.test:443 HTTP/1.1\r\nX-Pad: abc" {
            if writer.write_all(&[*byte]).is_err() {
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }
    });
    let started = std::time::Instant::now();
    let mut reader = stream;
    let mut rest = Vec::new();
    let _ = reader.read_to_end(&mut rest);
    let took = started.elapsed();
    assert!(took < Duration::from_millis(1500), "closed after {took:?}");
    trickle.join().unwrap();
}
