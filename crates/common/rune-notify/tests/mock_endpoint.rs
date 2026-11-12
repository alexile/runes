//! Every sink against a loopback mock endpoint, through a real (plain
//! HTTP/1.1) transport. Nothing leaves 127.0.0.1.

#![allow(
    clippy::expect_used,
    reason = "mock server and client helpers fail the test on I/O errors"
)]

use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use rune_finding::{Confidence, Finding, Location, Remediation, Severity, TaxonomyRef};
use rune_notify::{
    DiscordSink, HttpRequest, HttpResponse, JiraAuth, JiraSink, Message, Notifier, Sink, SlackSink,
    Status, Transport, TransportError, WebhookSink,
};
use rune_retry_queue::BackoffPolicy;
use rune_secret_ref::SecretValue;
use serde_json::{Value, json};

/// A request as the mock endpoint received it.
#[derive(Debug)]
struct Captured {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Captured {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("JSON body")
    }
}

/// One canned reply: status, extra headers, body.
type Reply = (u16, Vec<(&'static str, &'static str)>, &'static str);

/// A loopback server that answers each connection with the next reply and
/// reports what it received.
struct MockServer {
    port: u16,
    captured: mpsc::Receiver<Captured>,
}

impl MockServer {
    fn start(replies: Vec<Reply>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let port = listener.local_addr().expect("addr").port();
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            for (status, headers, body) in replies {
                let Ok((stream, _)) = listener.accept() else {
                    return;
                };
                let captured = read_request(&stream);
                let mut stream = stream;
                let mut head = format!(
                    "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n",
                    body.len()
                );
                for (k, v) in headers {
                    let _ = write!(head, "{k}: {v}\r\n");
                }
                head.push_str("\r\n");
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(body.as_bytes());
                let _ = stream.flush();
                if tx.send(captured).is_err() {
                    return;
                }
            }
        });
        Self { port, captured: rx }
    }

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }

    fn next(&self) -> Captured {
        self.captured
            .recv_timeout(Duration::from_secs(5))
            .expect("request reached the mock endpoint")
    }
}

fn read_request(stream: &TcpStream) -> Captured {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).expect("request line");
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_owned();
    let path = parts.next().unwrap_or_default().to_owned();
    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).expect("header line");
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_owned(), v.trim().to_owned()));
        }
    }
    let len = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0; len];
    reader.read_exact(&mut body).expect("body");
    Captured {
        method,
        path,
        headers,
        body,
    }
}

/// A minimal blocking HTTP/1.1 client for `http://127.0.0.1` URLs only.
struct LoopbackTransport;

impl Transport for LoopbackTransport {
    fn send(&self, request: &HttpRequest) -> Result<HttpResponse, TransportError> {
        let url = url::Url::parse(request.url.expose())
            .map_err(|_| TransportError::permanent("bad url"))?;
        if url.scheme() != "http" || url.host_str() != Some("127.0.0.1") {
            return Err(TransportError::permanent("loopback only"));
        }
        let port = url
            .port()
            .ok_or_else(|| TransportError::permanent("no port"))?;
        let mut stream = TcpStream::connect(("127.0.0.1", port))
            .map_err(|e| TransportError::retryable(e.to_string()))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| TransportError::retryable(e.to_string()))?;
        let target = url
            .query()
            .map_or_else(|| url.path().to_owned(), |q| format!("{}?{q}", url.path()));
        let mut head = format!(
            "{} {target} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Length: {}\r\nConnection: close\r\n",
            request.method,
            request.body.len()
        );
        for (name, value) in &request.headers {
            let _ = write!(head, "{name}: {}\r\n", value.expose());
        }
        head.push_str("\r\n");
        stream
            .write_all(head.as_bytes())
            .and_then(|()| stream.write_all(&request.body))
            .map_err(|e| TransportError::retryable(e.to_string()))?;

        let mut raw = Vec::new();
        stream
            .read_to_end(&mut raw)
            .map_err(|e| TransportError::retryable(e.to_string()))?;
        let split = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or_else(|| TransportError::retryable("truncated response"))?;
        let head = String::from_utf8_lossy(&raw[..split]).into_owned();
        let mut lines = head.split("\r\n");
        let status = lines
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| TransportError::retryable("bad status line"))?;
        let mut response = HttpResponse::new(status).with_body(raw[split + 4..].to_vec());
        for line in lines {
            if let Some((k, v)) = line.split_once(':') {
                response = response.with_header(k.trim(), v.trim());
            }
        }
        Ok(response)
    }
}

fn finding() -> Finding {
    Finding::<()>::new(
        "web.xss.reflected",
        "Reflected XSS in <search>",
        Severity::High,
        Confidence::Certain,
        Location::url("https://shop.example.test/search").with_parameter("q"),
    )
    .push_taxonomy(TaxonomyRef::cwe(79))
    .with_remediation(Remediation::new("Encode output for the HTML context"))
}

#[test]
fn slack_incoming_webhook() {
    let server = MockServer::start(vec![(200, vec![], "ok")]);
    let slack = SlackSink::new(SecretValue::new(server.url("/services/T000/B000/XXXX"))).unwrap();
    let delivery = slack
        .send(&Message::from_finding(&finding()), &LoopbackTransport)
        .unwrap();
    assert_eq!(delivery.status, 200);

    let req = server.next();
    assert_eq!(req.method, "POST");
    assert_eq!(req.path, "/services/T000/B000/XXXX");
    assert!(
        req.header("content-type")
            .unwrap()
            .starts_with("application/json")
    );
    let body = req.json();
    // Block Kit: top-level text fallback plus typed blocks.
    assert!(body["text"].is_string());
    let blocks = body["blocks"].as_array().unwrap();
    let types: Vec<_> = blocks.iter().map(|b| b["type"].as_str().unwrap()).collect();
    assert_eq!(types, ["header", "section", "section", "context"]);
    assert_eq!(
        blocks[0]["text"],
        json!({"type": "plain_text", "text": "[HIGH] Reflected XSS in <search>", "emoji": true})
    );
    assert_eq!(blocks[1]["text"]["type"], "mrkdwn");
    for field in blocks[2]["fields"].as_array().unwrap() {
        assert_eq!(field["type"], "mrkdwn");
    }
    assert_eq!(
        blocks[3]["elements"][0]["text"],
        "<https://shop.example.test/search|Details>"
    );
}

#[test]
fn slack_error_codes() {
    let server = MockServer::start(vec![
        (404, vec![], "no_service"),
        (429, vec![("Retry-After", "30")], ""),
    ]);
    let slack = SlackSink::new(SecretValue::new(server.url("/services/T/B/X"))).unwrap();
    let message = Message::new("t", "b");
    let err = slack.send(&message, &LoopbackTransport).unwrap_err();
    assert!(!err.is_retryable());
    assert!(err.to_string().contains("no_service"));
    assert!(!err.to_string().contains("/services/"), "URL leaked: {err}");
    let err = slack.send(&message, &LoopbackTransport).unwrap_err();
    assert_eq!(err.retry_after(), Some(Duration::from_secs(30)));
}

#[test]
fn discord_execute_webhook() {
    let server = MockServer::start(vec![
        (204, vec![], ""),
        (
            200,
            vec![("Content-Type", "application/json")],
            r#"{"id":"1188","channel_id":"9","content":""}"#,
        ),
    ]);
    let discord = DiscordSink::new(SecretValue::new(
        server.url("/api/webhooks/42/tok?thread_id=7"),
    ))
    .unwrap()
    .with_username("runes");
    let message = Message::from_finding(&finding());
    assert_eq!(
        discord.send(&message, &LoopbackTransport).unwrap().status,
        204
    );

    let req = server.next();
    assert_eq!(req.method, "POST");
    assert_eq!(req.path, "/api/webhooks/42/tok?thread_id=7");
    let body = req.json();
    assert_eq!(body["username"], "runes");
    assert_eq!(body["allowed_mentions"], json!({"parse": []}));
    let embed = &body["embeds"][0];
    assert_eq!(embed["title"], "[HIGH] Reflected XSS in <search>");
    assert_eq!(embed["color"], 0x00E6_7E22);
    assert_eq!(embed["url"], "https://shop.example.test/search");
    for field in embed["fields"].as_array().unwrap() {
        assert!(field["name"].is_string() && field["value"].is_string());
        assert!(field["inline"].is_boolean());
    }
    assert!(
        embed["footer"]["text"]
            .as_str()
            .unwrap()
            .starts_with("fingerprint ")
    );

    let waiting = discord.with_wait(true);
    let delivery = waiting.send(&message, &LoopbackTransport).unwrap();
    assert_eq!(delivery.id.as_deref(), Some("1188"));
    assert_eq!(
        server.next().path,
        "/api/webhooks/42/tok?thread_id=7&wait=true"
    );
}

#[test]
fn generic_webhook() {
    let server = MockServer::start(vec![(202, vec![], "")]);
    let hook = WebhookSink::new(SecretValue::new(server.url("/ingest")))
        .unwrap()
        .with_bearer_token(&SecretValue::new("s3cret"))
        .with_header("X-Source", "runes")
        .unwrap();
    let message = Message::from_finding(&finding());
    assert_eq!(hook.send(&message, &LoopbackTransport).unwrap().status, 202);

    let req = server.next();
    assert_eq!(req.path, "/ingest");
    assert_eq!(req.header("authorization"), Some("Bearer s3cret"));
    assert_eq!(req.header("x-source"), Some("runes"));
    let body = req.json();
    assert_eq!(body["version"], 1);
    assert_eq!(body["title"], message.title);
    assert_eq!(body["severity"], "high");
    assert_eq!(body["fingerprint"], finding().fingerprint());
    assert_eq!(
        body["labels"],
        json!(["severity-high", "web.xss.reflected"])
    );
}

#[test]
fn jira_create_issue() {
    let server = MockServer::start(vec![
        (
            201,
            vec![],
            r#"{"id":"10042","key":"SEC-7","self":"http://127.0.0.1/rest/api/2/issue/10042"}"#,
        ),
        (401, vec![], ""),
    ]);
    let base = server.url("/jira");
    let jira = JiraSink::new(
        &base,
        "SEC",
        JiraAuth::basic("bot@example.test", SecretValue::new("api-token")),
    )
    .unwrap()
    .with_issue_type("Vulnerability")
    .with_priorities(true);
    let message = Message::from_finding(&finding());
    let delivery = jira.send(&message, &LoopbackTransport).unwrap();
    assert_eq!(delivery.status, 201);
    assert_eq!(delivery.id.as_deref(), Some("SEC-7"));
    assert_eq!(delivery.url, Some(format!("{base}/browse/SEC-7")));

    let req = server.next();
    assert_eq!(req.method, "POST");
    assert_eq!(req.path, "/jira/rest/api/2/issue");
    assert_eq!(
        req.header("authorization"),
        Some(format!("Basic {}", rune_base64_of("bot@example.test:api-token")).as_str())
    );
    assert_eq!(req.header("accept"), Some("application/json"));
    let fields = &req.json()["fields"];
    assert_eq!(fields["project"], json!({"key": "SEC"}));
    assert_eq!(fields["issuetype"], json!({"name": "Vulnerability"}));
    assert_eq!(fields["priority"], json!({"name": "High"}));
    assert_eq!(fields["summary"], "[HIGH] Reflected XSS in <search>");
    assert!(
        fields["description"]
            .as_str()
            .unwrap()
            .contains("*Severity:* high")
    );
    let labels = fields["labels"].as_array().unwrap();
    assert!(labels.iter().all(|l| !l.as_str().unwrap().contains(' ')));
    assert!(
        labels
            .iter()
            .any(|l| l.as_str().unwrap().starts_with("fp-"))
    );

    let err = jira.send(&message, &LoopbackTransport).unwrap_err();
    assert!(!err.is_retryable());
    assert!(!format!("{err:?}").contains("api-token"));
}

/// Standard base64, written out so the test does not trust the crate's own
/// encoder.
fn rune_base64_of(text: &str) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = text.as_bytes();
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[test]
fn notifier_retries_over_loopback() {
    let server = MockServer::start(vec![(503, vec![], "upstream down"), (200, vec![], "ok")]);
    let mut notifier = Notifier::new(BackoffPolicy::Fixed(Duration::from_secs(10)), 3);
    notifier.add(SlackSink::new(SecretValue::new(server.url("/services/T/B/X"))).unwrap());
    let t0 = Instant::now();

    let first = notifier.notify(&Message::from_finding(&finding()), &LoopbackTransport, t0);
    assert!(matches!(first[0].status, Status::Retrying(_)));
    let _ = server.next();

    let retried = notifier.retry_due(&LoopbackTransport, t0 + Duration::from_secs(10));
    assert_eq!(retried.len(), 1);
    assert_eq!(retried[0].attempt, 1);
    assert!(matches!(retried[0].status, Status::Delivered(_)));
    assert_eq!(server.next().path, "/services/T/B/X");
    assert_eq!(notifier.pending(), 0);
}

#[test]
fn unreachable_endpoint_is_retryable() {
    // Bind and drop a listener so the port is closed.
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let hook = WebhookSink::new(SecretValue::new(format!("http://127.0.0.1:{port}/x"))).unwrap();
    let err = hook
        .send(&Message::new("t", ""), &LoopbackTransport)
        .unwrap_err();
    assert!(err.is_retryable(), "{err}");
}
