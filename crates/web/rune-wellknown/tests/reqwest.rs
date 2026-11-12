//! `ReqwestFetcher` against a loopback server that replays canned
//! responses (no external network).
#![cfg(feature = "reqwest")]

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::thread;

use rune_wellknown::fetch::{FetchError, ReqwestFetcher, fetch};
use rune_wellknown::{ChangePassword, Resource};

/// Serves one raw HTTP response per connection, in order; returns the
/// origin and a handle yielding the request lines.
#[allow(
    clippy::unwrap_used,
    reason = "test helper: any I/O failure fails the test"
)]
fn serve(responses: Vec<Vec<u8>>) -> (String, thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let handle = thread::spawn(move || {
        let mut lines = Vec::new();
        for response in responses {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            lines.push(line.trim_end().to_owned());
            loop {
                let mut header = String::new();
                if reader.read_line(&mut header).unwrap() == 0 || header == "\r\n" {
                    break;
                }
            }
            stream.write_all(&response).unwrap();
        }
        lines
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

#[allow(
    clippy::unwrap_used,
    reason = "test helper: a client build failure fails the test"
)]
fn fetcher() -> ReqwestFetcher {
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    ReqwestFetcher::from_client(client).with_max_body(64)
}

#[tokio::test]
async fn fetches_over_loopback() {
    let (origin, server) = serve(vec![
        http(
            "200 OK",
            "Content-Type: text/plain\r\n",
            b"version: STSv1\nmode: none\nmax_age: 86400\n",
        ),
        http("302 Found", "Location: /me/password\r\n", b""),
        http("200 OK", "", &[b'#'; 100]),
    ]);
    let f = fetcher();
    let mta = fetch(&f, &origin, "/.well-known/mta-sts.txt")
        .await
        .unwrap();
    assert!(matches!(mta, Resource::MtaSts(_)));
    let cp = fetch(&f, &origin, "/.well-known/change-password")
        .await
        .unwrap();
    assert_eq!(
        cp,
        Resource::ChangePassword(ChangePassword::Redirect {
            status: 302,
            location: "/me/password".to_owned()
        })
    );
    // The body is read up to the configured limit + 1 bytes, no further.
    let raw = fetch(&f, &origin, "/.well-known/big").await.unwrap();
    let Resource::Unknown(raw) = raw else {
        unreachable!()
    };
    assert_eq!(raw.body.len(), 65);
    assert_eq!(
        server.join().unwrap(),
        [
            "GET /.well-known/mta-sts.txt HTTP/1.1",
            "GET /.well-known/change-password HTTP/1.1",
            "GET /.well-known/big HTTP/1.1"
        ]
    );
}

#[tokio::test]
async fn transport_errors() {
    // Bind and drop: nothing listens on the port any more.
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let r = fetch(
        &fetcher(),
        &format!("http://127.0.0.1:{port}"),
        "/.well-known/security.txt",
    )
    .await;
    assert!(matches!(r, Err(FetchError::Transport(_))));
}
