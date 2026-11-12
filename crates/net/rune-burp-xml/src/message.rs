//! Raw HTTP/1.x-style messages, as Burp stores them.
//!
//! Burp keeps each request and response as the bytes it saw (HTTP/2
//! traffic is shown in the same text form, with `HTTP/2` as the version).
//! Parsing is tolerant: bare `\n` line ends, folded header lines, missing
//! versions and spaces inside the request target are accepted.

use rune_http_model::{HeaderEntry, HttpBody, HttpRequest, HttpResponse, HttpVersion};

/// A parsed message head and its body bytes.
struct Head<'a> {
    start_line: &'a str,
    headers: Vec<HeaderEntry>,
    body: &'a [u8],
}

/// Splits a message at the blank line that ends its head.
fn split_head(raw: &[u8]) -> (&[u8], &[u8]) {
    let mut index = 0;
    while index < raw.len() {
        if raw[index] == b'\n' {
            if raw.get(index + 1) == Some(&b'\n') {
                return (&raw[..index], &raw[index + 2..]);
            }
            if raw.get(index + 1) == Some(&b'\r') && raw.get(index + 2) == Some(&b'\n') {
                return (&raw[..index], &raw[index + 3..]);
            }
        }
        index += 1;
    }
    (raw, &[])
}

fn parse_head(raw: &[u8]) -> Option<Head<'_>> {
    let (head, body) = split_head(raw);
    let head = std::str::from_utf8(head).ok()?;
    let mut lines = head
        .split('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line));
    let start_line = lines.next()?.trim();
    if start_line.is_empty() {
        return None;
    }
    let mut headers: Vec<HeaderEntry> = Vec::new();
    for line in lines {
        if line.starts_with([' ', '\t']) {
            // obs-fold: a continuation of the previous header's value.
            if let Some(last) = headers.last_mut()
                && !line.trim().is_empty()
            {
                if !last.value.is_empty() {
                    last.value.push(' ');
                }
                last.value.push_str(line.trim());
            }
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim_end();
            if !name.is_empty() {
                headers.push(HeaderEntry::new(name, value.trim()));
            }
        }
    }
    Some(Head {
        start_line,
        headers,
        body,
    })
}

/// Undoes `Transfer-Encoding: chunked`; `None` when the framing is invalid.
fn dechunk(mut body: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(body.len());
    loop {
        let line_end = body.iter().position(|&byte| byte == b'\n')?;
        let line = std::str::from_utf8(&body[..line_end]).ok()?;
        let size = line.split(';').next()?.trim();
        let size = usize::from_str_radix(size, 16).ok()?;
        body = &body[line_end + 1..];
        if size == 0 {
            // Trailer fields are ignored.
            return Some(out);
        }
        let chunk = body.get(..size)?;
        out.extend_from_slice(chunk);
        body = &body[size..];
        body = body
            .strip_prefix(b"\r\n")
            .or_else(|| body.strip_prefix(b"\n"))?;
    }
}

fn is_chunked(headers: &[HeaderEntry]) -> bool {
    rune_http_model::header_values(headers, "Transfer-Encoding").any(|value| {
        value
            .rsplit(',')
            .next()
            .is_some_and(|last| last.trim().eq_ignore_ascii_case("chunked"))
    })
}

/// The body of a message: de-chunked when `decode_chunked` and the framing
/// is valid, with the content coding from `Content-Encoding`.
fn body(headers: &[HeaderEntry], bytes: &[u8], decode_chunked: bool) -> HttpBody {
    let bytes = if decode_chunked && is_chunked(headers) {
        dechunk(bytes).unwrap_or_else(|| bytes.to_vec())
    } else {
        bytes.to_vec()
    };
    let mut body = HttpBody::new(bytes);
    if let Some(coding) = rune_http_model::header_value(headers, "Content-Encoding")
        .map(str::trim)
        .filter(|coding| !coding.is_empty() && !coding.eq_ignore_ascii_case("identity"))
    {
        body.content_encoding = Some(coding.to_owned());
    }
    body
}

/// A parsed request line and message; the URL is the request target as
/// written, for the caller to make absolute.
pub struct ParsedRequest {
    pub request: HttpRequest,
    /// The request target from the request line.
    pub target: String,
}

/// Parses a raw request.
pub fn parse_request(raw: &[u8], decode_chunked: bool) -> Option<ParsedRequest> {
    let head = parse_head(raw)?;
    let mut parts: Vec<&str> = head.start_line.split_whitespace().collect();
    let version = match parts.last() {
        Some(last) if parts.len() > 2 && last.to_ascii_uppercase().starts_with("HTTP/") => {
            let version = HttpVersion::parse(last).unwrap_or_default();
            parts.pop();
            version
        }
        _ => HttpVersion::Http09,
    };
    let (method, target) = match parts.as_slice() {
        [method, target @ ..] if !target.is_empty() => (*method, target.join(" ")),
        _ => return None,
    };
    if !method.bytes().all(|byte| byte.is_ascii_graphic()) {
        return None;
    }
    // Origin, absolute, asterisk or (for CONNECT) authority form.
    let target_ok = target.starts_with(['/', '*'])
        || target.contains("://")
        || method.eq_ignore_ascii_case("CONNECT");
    if !target_ok {
        return None;
    }
    let mut request = HttpRequest::new(method, target.clone());
    request.http_version = version;
    request.body = body(&head.headers, head.body, decode_chunked);
    request.headers = head.headers;
    Some(ParsedRequest { request, target })
}

/// Parses a raw response.
pub fn parse_response(raw: &[u8], decode_chunked: bool) -> Option<HttpResponse> {
    let head = parse_head(raw)?;
    let mut parts = head.start_line.splitn(3, [' ', '\t']);
    let version = parts.next()?;
    if !version.to_ascii_uppercase().starts_with("HTTP/") {
        return None;
    }
    let status: u16 = parts.next()?.trim().parse().ok()?;
    let reason = parts
        .next()
        .map(str::trim)
        .filter(|reason| !reason.is_empty());
    let mut response = HttpResponse::new(status);
    response.http_version = HttpVersion::parse(version).unwrap_or_default();
    response.reason = reason.map(str::to_owned);
    response.body = body(&head.headers, head.body, decode_chunked);
    response.headers = head.headers;
    Some(response)
}

fn push_headers(out: &mut Vec<u8>, headers: &[HeaderEntry]) {
    for header in headers {
        out.extend_from_slice(header.name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(header.value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
}

/// The body as it goes on the wire: one chunk when the headers say
/// `chunked`, so that reading it back de-chunks to the same bytes.
fn push_body(out: &mut Vec<u8>, headers: &[HeaderEntry], body: &HttpBody) {
    if is_chunked(headers) {
        if !body.is_empty() {
            out.extend_from_slice(format!("{:x}\r\n", body.len()).as_bytes());
            out.extend_from_slice(body.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"0\r\n\r\n");
    } else {
        out.extend_from_slice(body.as_bytes());
    }
}

/// Serializes a request with `target` on the request line.
pub fn write_request(request: &HttpRequest, target: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + request.body.len());
    out.extend_from_slice(request.method.as_bytes());
    out.push(b' ');
    out.extend_from_slice(target.as_bytes());
    out.push(b' ');
    out.extend_from_slice(request.http_version.as_str().as_bytes());
    out.extend_from_slice(b"\r\n");
    push_headers(&mut out, &request.headers);
    push_body(&mut out, &request.headers, &request.body);
    out
}

/// Serializes a response.
pub fn write_response(response: &HttpResponse) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + response.body.len());
    out.extend_from_slice(response.http_version.as_str().as_bytes());
    out.extend_from_slice(format!(" {} ", response.status).as_bytes());
    if let Some(reason) = &response.reason {
        out.extend_from_slice(reason.as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    push_headers(&mut out, &response.headers);
    push_body(&mut out, &response.headers, &response.body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_requests_tolerantly() {
        let parsed = parse_request(
            b"POST /a b?q=1 HTTP/1.1\nHost: h.test\nX-Long: one\n\ttwo\nbad line\n\nbody",
            true,
        )
        .unwrap();
        assert_eq!(parsed.target, "/a b?q=1");
        assert_eq!(parsed.request.method, "POST");
        assert_eq!(parsed.request.header("X-Long"), Some("one two"));
        assert_eq!(parsed.request.headers.len(), 2);
        assert_eq!(parsed.request.body.as_bytes(), b"body");

        // Regression: an empty folded line left
        // a trailing space that a re-read trimmed away.
        let folded = parse_request(b"GET / HTTP/1.1\nX: a\n \nY: b\n\n", true).unwrap();
        assert_eq!(folded.request.header("X"), Some("a"));

        let simple = parse_request(b"GET /", true).unwrap();
        assert_eq!(simple.request.http_version, HttpVersion::Http09);
        let h2 = parse_request(b"GET / HTTP/2\r\n:authority: x\r\n\r\n", true).unwrap();
        assert_eq!(h2.request.http_version, HttpVersion::Http2);

        for bad in [
            &b""[..],
            b"\r\n\r\n",
            b"GET",
            b"G\x01T / HTTP/1.1",
            b"\xff / HTTP/1.1",
            b"not http",
            b"OPTIONS relative HTTP/1.1",
        ] {
            assert!(parse_request(bad, true).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn parses_responses() {
        let response = parse_response(
            b"HTTP/1.1 404 Not Found\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2;x=1\r\nde\r\n0\r\nTrailer: 1\r\n\r\n",
            true,
        )
        .unwrap();
        assert_eq!(response.status, 404);
        assert_eq!(response.reason.as_deref(), Some("Not Found"));
        assert_eq!(response.body.as_bytes(), b"abcde");
        assert_eq!(response.body.content_encoding.as_deref(), Some("gzip"));

        let raw = parse_response(
            b"HTTP/1.1 200\r\nTransfer-Encoding: chunked\r\n\r\nzz",
            true,
        )
        .unwrap();
        assert_eq!(raw.reason, None);
        assert_eq!(raw.body.as_bytes(), b"zz", "invalid framing kept as is");

        assert!(parse_response(b"HTTP/1.1 abc OK\r\n\r\n", true).is_none());
        assert!(parse_response(b"FTP/1.1 200 OK\r\n\r\n", true).is_none());
    }

    #[test]
    fn writes_and_reads_back() {
        let request = HttpRequest::post("http://h.test/x")
            .with_header("Transfer-Encoding", "chunked")
            .with_body("hello");
        let raw = write_request(&request, "/x");
        assert_eq!(
            raw,
            b"POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
        );
        let parsed = parse_request(&raw, true).unwrap();
        assert_eq!(parsed.request.body.as_bytes(), b"hello");

        let response = HttpResponse::new(204);
        assert_eq!(write_response(&response), b"HTTP/1.1 204 \r\n\r\n");
        assert_eq!(
            parse_response(&write_response(&response), true).unwrap(),
            response
        );
    }
}
