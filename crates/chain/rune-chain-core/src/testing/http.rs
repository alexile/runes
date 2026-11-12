//! A loopback HTTP/1.1 server that replays canned responses, for testing
//! HTTP-backed providers without touching the network.
//!
//! [`MockServer`] binds `127.0.0.1` on a free port and answers one connection
//! per queued [`MockResponse`], in order, recording every request it reads.
//! It uses only the standard library (a blocking listener on a background
//! thread), so it works under any async runtime the client happens to use.
//!
//! Responses are sent with `Transfer-Encoding: chunked`; split a body with
//! [`MockResponse::chunked`] to deliver it in small pieces and exercise a
//! streaming parser across chunk boundaries.
//!
//! # Example
//!
//! ```rust
//! use std::io::{Read, Write};
//! use rune_chain_core::testing::http::{MockResponse, MockServer};
//!
//! let server = MockServer::start([MockResponse::json(200, r#"{"ok":true}"#)])?;
//!
//! // Any HTTP client works; a raw socket keeps the example dependency-free.
//! let addr = server.base_url().trim_start_matches("http://");
//! let mut socket = std::net::TcpStream::connect(addr)?;
//! socket.write_all(b"POST /v1/x HTTP/1.1\r\nHost: t\r\nContent-Length: 2\r\n\r\n{}")?;
//! let mut reply = String::new();
//! socket.read_to_string(&mut reply)?;
//! assert!(reply.starts_with("HTTP/1.1 200 OK"));
//!
//! let requests = server.finish()?;
//! assert_eq!(requests[0].path, "/v1/x");
//! assert_eq!(requests[0].body, b"{}");
//! # Ok::<(), std::io::Error>(())
//! ```

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// How long the server waits for each expected connection, and for each read
/// on it, before giving up.
const TIMEOUT: Duration = Duration::from_secs(10);
/// Largest request head (request line plus headers) the server accepts.
const MAX_HEAD: usize = 64 * 1024;

/// A canned HTTP response for [`MockServer`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MockResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    chunk_size: usize,
}

impl MockResponse {
    /// A response with `status`, a `Content-Type` and a body.
    pub fn new(status: u16, content_type: &str, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            headers: vec![("Content-Type".to_string(), content_type.to_string())],
            body: body.into(),
            chunk_size: 0,
        }
    }

    /// An `application/json` response.
    pub fn json(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self::new(status, "application/json", body)
    }

    /// A `200 OK` `text/event-stream` (Server-Sent Events) response.
    pub fn event_stream(body: impl Into<Vec<u8>>) -> Self {
        Self::new(200, "text/event-stream", body)
    }

    /// A `200 OK` `application/x-ndjson` (newline-delimited JSON) response.
    pub fn ndjson(body: impl Into<Vec<u8>>) -> Self {
        Self::new(200, "application/x-ndjson", body)
    }

    /// Add a response header.
    #[must_use]
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    /// Send the body in HTTP chunks of at most `size` bytes, flushing after
    /// each one. `0` (the default) sends the whole body as a single chunk.
    #[must_use]
    pub const fn chunked(mut self, size: usize) -> Self {
        self.chunk_size = size;
        self
    }

    fn write_to(&self, out: &mut impl Write) -> io::Result<()> {
        let mut head = format!("HTTP/1.1 {} {}\r\n", self.status, reason(self.status));
        for (name, value) in &self.headers {
            head.extend([name.as_str(), ": ", value.as_str(), "\r\n"]);
        }
        head.push_str("Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n");
        out.write_all(head.as_bytes())?;
        out.flush()?;
        let size = if self.chunk_size == 0 {
            self.body.len().max(1)
        } else {
            self.chunk_size
        };
        for chunk in self.body.chunks(size) {
            out.write_all(format!("{:x}\r\n", chunk.len()).as_bytes())?;
            out.write_all(chunk)?;
            out.write_all(b"\r\n")?;
            out.flush()?;
        }
        out.write_all(b"0\r\n\r\n")?;
        out.flush()
    }
}

/// A request read by [`MockServer`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedRequest {
    /// The method, e.g. `"POST"`.
    pub method: String,
    /// The request target, e.g. `"/v1/messages"`.
    pub path: String,
    /// Header names (as sent) and values, in order.
    pub headers: Vec<(String, String)>,
    /// The body (read by `Content-Length`; empty when there is none).
    pub body: Vec<u8>,
}

impl RecordedRequest {
    /// The first value of the header `name`, matched case-insensitively.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The body parsed as JSON.
    ///
    /// # Errors
    ///
    /// Returns the parse error when the body is not valid JSON.
    pub fn json(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::from_slice(&self.body)
    }
}

/// A loopback HTTP server that replays [`MockResponse`]s; see the
/// [module docs](self).
#[derive(Debug)]
pub struct MockServer {
    base_url: String,
    handle: JoinHandle<io::Result<Vec<RecordedRequest>>>,
}

impl MockServer {
    /// Bind `127.0.0.1` on a free port and serve `responses`, one connection
    /// each, in order.
    ///
    /// # Errors
    ///
    /// Returns an error when the listener cannot be bound.
    pub fn start(responses: impl IntoIterator<Item = MockResponse>) -> io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        listener.set_nonblocking(true)?;
        let base_url = format!("http://{}", listener.local_addr()?);
        let responses: Vec<MockResponse> = responses.into_iter().collect();
        let handle = std::thread::spawn(move || serve(&listener, &responses));
        Ok(Self { base_url, handle })
    }

    /// The server's base URL, `http://127.0.0.1:<port>`, without a trailing
    /// slash.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Wait until every queued response has been served and return the
    /// recorded requests, in order.
    ///
    /// # Errors
    ///
    /// Returns an error when an expected connection did not arrive within ten
    /// seconds, a request could not be read, or a response could not be
    /// written.
    pub fn finish(self) -> io::Result<Vec<RecordedRequest>> {
        self.handle
            .join()
            .map_err(|_| io::Error::other("mock server thread panicked"))?
    }
}

fn serve(listener: &TcpListener, responses: &[MockResponse]) -> io::Result<Vec<RecordedRequest>> {
    let mut recorded = Vec::with_capacity(responses.len());
    for response in responses {
        let mut stream = accept(listener)?;
        stream.set_nonblocking(false)?;
        stream.set_read_timeout(Some(TIMEOUT))?;
        recorded.push(read_request(&mut stream)?);
        response.write_to(&mut stream)?;
        // The client may already have closed its end; nothing to report then.
        let _ = stream.shutdown(std::net::Shutdown::Both);
    }
    Ok(recorded)
}

fn accept(listener: &TcpListener) -> io::Result<TcpStream> {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        match listener.accept() {
            Ok((stream, _)) => return Ok(stream),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "no connection for a queued mock response",
                    ));
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(e) => return Err(e),
        }
    }
}

fn read_request(stream: &mut TcpStream) -> io::Result<RecordedRequest> {
    let mut reader = BufReader::new(stream);
    let mut head_len = 0;
    let mut line = String::new();
    let mut read_line = |reader: &mut BufReader<&mut TcpStream>| -> io::Result<String> {
        line.clear();
        head_len += reader.read_line(&mut line)?;
        if head_len > MAX_HEAD {
            return Err(invalid("request head too large"));
        }
        Ok(line.trim_end_matches(['\r', '\n']).to_string())
    };

    let request_line = read_line(&mut reader)?;
    let mut parts = request_line.split_whitespace();
    let (Some(method), Some(path)) = (parts.next(), parts.next()) else {
        return Err(invalid("malformed request line"));
    };
    let (method, path) = (method.to_string(), path.to_string());

    let mut headers = Vec::new();
    loop {
        let header = read_line(&mut reader)?;
        if header.is_empty() {
            break;
        }
        let Some((name, value)) = header.split_once(':') else {
            return Err(invalid("malformed header line"));
        };
        headers.push((name.trim().to_string(), value.trim().to_string()));
    }

    let length = headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("content-length"))
        .map(|(_, v)| v.parse::<usize>())
        .transpose()
        .map_err(|_| invalid("invalid Content-Length"))?
        .unwrap_or(0);
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;

    Ok(RecordedRequest {
        method,
        path,
        headers,
        body,
    })
}

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

const fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        529 => "Overloaded",
        _ => "Status",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(server: &MockServer, request: &[u8]) -> String {
        let addr = server.base_url().trim_start_matches("http://");
        let mut socket = TcpStream::connect(addr).unwrap();
        socket.write_all(request).unwrap();
        let mut reply = String::new();
        socket.read_to_string(&mut reply).unwrap();
        reply
    }

    #[test]
    fn serves_in_order_and_records_requests() {
        let server = MockServer::start([
            MockResponse::json(201, "{}").with_header("X-Id", "1"),
            MockResponse::event_stream("data: abcdef\n\n").chunked(4),
        ])
        .unwrap();
        let first = roundtrip(
            &server,
            b"POST /a HTTP/1.1\r\nX-Key: k\r\ncontent-length: 7\r\n\r\n{\"a\":1}",
        );
        assert!(first.starts_with("HTTP/1.1 201 Status\r\n"), "{first}");
        assert!(first.contains("X-Id: 1\r\n"));
        assert!(first.ends_with("2\r\n{}\r\n0\r\n\r\n"));

        let second = roundtrip(&server, b"GET /b HTTP/1.1\r\n\r\n");
        assert!(second.contains("Content-Type: text/event-stream"));
        assert!(second.ends_with("4\r\ndata\r\n4\r\n: ab\r\n4\r\ncdef\r\n2\r\n\n\n\r\n0\r\n\r\n"));

        let recorded = server.finish().unwrap();
        assert_eq!(recorded.len(), 2);
        assert_eq!(recorded[0].method, "POST");
        assert_eq!(recorded[0].header("x-key"), Some("k"));
        assert_eq!(recorded[0].json().unwrap()["a"], 1);
        assert_eq!(recorded[1].path, "/b");
        assert_eq!(recorded[1].body, b"");
        assert!(recorded[1].header("x-key").is_none());
    }

    #[test]
    fn malformed_request_is_an_error() {
        let server = MockServer::start([MockResponse::json(200, "{}")]).unwrap();
        let addr = server.base_url().trim_start_matches("http://").to_string();
        let mut socket = TcpStream::connect(addr).unwrap();
        socket.write_all(b"GARBAGE\r\n\r\n").unwrap();
        drop(socket);
        assert_eq!(
            server.finish().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
