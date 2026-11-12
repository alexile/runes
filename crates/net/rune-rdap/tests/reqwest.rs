//! `Client` + `ReqwestFetcher` against a loopback server that replays
//! captured responses (no external network).
#![cfg(feature = "reqwest")]
#![allow(
    clippy::unwrap_used,
    reason = "test helpers outside #[test] fns: any failure fails the test"
)]

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

use rune_rdap::Error;
use rune_rdap::client::{Client, Options, ReqwestFetcher};

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

/// Serves the responses `make(origin)` returns, one per connection, in
/// order; the handle yields each request line with its `Accept` header.
fn serve(
    make: impl FnOnce(&str) -> Vec<Vec<u8>>,
) -> (String, thread::JoinHandle<Vec<(String, String)>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let responses = make(&origin);
    let handle = thread::spawn(move || {
        let mut seen = Vec::new();
        for response in responses {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let mut accept = String::new();
            loop {
                let mut header = String::new();
                if reader.read_line(&mut header).unwrap() == 0 || header == "\r\n" {
                    break;
                }
                if let Some((name, value)) = header.split_once(':')
                    && name.eq_ignore_ascii_case("accept")
                {
                    value.trim().clone_into(&mut accept);
                }
            }
            seen.push((line.trim_end().to_owned(), accept));
            stream.write_all(&response).unwrap();
        }
        seen
    });
    (origin, handle)
}

fn http(status: &str, headers: &str, body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

fn fetcher() -> ReqwestFetcher {
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    ReqwestFetcher::from_client(client)
}

#[tokio::test]
async fn bootstrap_redirect_and_object_over_loopback() {
    let (origin, server) = serve(|origin| {
        let ipv4 = format!(
            r#"{{"version":"1.0","publication":"2026-01-01T00:00:00Z","services":[[["193.0.0.0/8"],["{origin}/arin/"]]]}}"#
        );
        vec![
            http(
                "200 OK",
                "Content-Type: application/json\r\n",
                ipv4.as_bytes(),
            ),
            // ARIN's real answer for a RIPE address: 303 to the RIPE server.
            http(
                "303 See Other",
                &format!("Location: {origin}/ripe/ip/193.0.6.139\r\n"),
                b"",
            ),
            http(
                "200 OK",
                "Content-Type: application/rdap+json\r\n",
                &fixture("ip-ripe-193.0.6.139.json"),
            ),
        ]
    });
    let client = Client::new(
        fetcher(),
        Options::default()
            .with_bootstrap_base(format!("{origin}/iana"))
            .with_min_interval(Duration::ZERO),
    );
    let found = client.lookup_str("193.0.6.139").await.unwrap();
    assert_eq!(found.final_url, format!("{origin}/ripe/ip/193.0.6.139"));
    let net = found.object.as_ip_network().unwrap();
    assert_eq!(net.country.as_deref(), Some("NL"));

    let seen = server.join().unwrap();
    let lines: Vec<&str> = seen.iter().map(|(l, _)| l.as_str()).collect();
    assert_eq!(
        lines,
        [
            "GET /iana/ipv4.json HTTP/1.1",
            "GET /arin/ip/193.0.6.139 HTTP/1.1",
            "GET /ripe/ip/193.0.6.139 HTTP/1.1",
        ]
    );
    assert!(
        seen.iter()
            .all(|(_, accept)| accept == "application/rdap+json")
    );
}

#[tokio::test]
async fn oversized_bodies_are_rejected() {
    let (origin, server) = serve(|origin| {
        let asn = format!(r#"{{"version":"1.0","services":[[["1-10"],["{origin}/"]]]}}"#);
        vec![
            http("200 OK", "", asn.as_bytes()),
            http("200 OK", "", &[b' '; 256]),
        ]
    });
    let client = Client::new(
        fetcher().with_max_body(128),
        Options::default()
            .with_bootstrap_base(&origin)
            .with_min_interval(Duration::ZERO),
    );
    // The bootstrap file fits; the 256-byte object is cut at 129 bytes
    // and fails to parse.
    let err = client.lookup_str("AS5").await.unwrap_err();
    assert!(matches!(err, Error::InvalidResponse(_)), "{err:?}");
    server.join().unwrap();
}

#[tokio::test]
async fn connection_refused_is_a_transport_error() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let client = Client::new(fetcher(), Options::default().with_bootstrap_base(origin));
    assert!(matches!(
        client.lookup_str("example.com").await,
        Err(Error::Transport(_))
    ));
}
