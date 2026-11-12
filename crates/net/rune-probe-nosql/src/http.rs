//! A small, bounded HTTP/1.1 response reader for the Elasticsearch probe
//! ([RFC 9112](https://www.rfc-editor.org/rfc/rfc9112)).

use crate::Error;
use crate::wire::text;

const WHAT: &str = "http response";

/// Longest header block accepted.
const MAX_HEAD: usize = 16 * 1024;
/// Largest body accepted.
const MAX_BODY: usize = 256 * 1024;

/// A parsed HTTP response.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Response {
    /// The status line, printable and bounded, e.g. `HTTP/1.1 200 OK`.
    pub status_line: String,
    /// The status code.
    pub status: u16,
    /// Header fields in order, names as sent; values printable and bounded.
    pub headers: Vec<(String, String)>,
    /// The body, de-chunked.
    pub body: Vec<u8>,
}

impl Response {
    /// The first header named `name`, ignoring case.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// A `GET` request for `path` on `host`. Control characters are dropped
/// from `host` and `path` so they cannot inject header lines.
///
/// ```
/// let req = rune_probe_nosql::http::get_request("es.test:9200", "/");
/// assert!(req.starts_with(b"GET / HTTP/1.1\r\nHost: es.test:9200\r\n"));
/// ```
#[must_use]
pub fn get_request(host: &str, path: &str) -> Vec<u8> {
    let clean = |s: &str| s.chars().filter(|c| !c.is_control()).collect::<String>();
    format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: rune-probe-nosql\r\nAccept: application/json\r\nConnection: keep-alive\r\n\r\n",
        clean(path),
        clean(host)
    )
    .into_bytes()
}

/// Parse one response from the start of `buf`. `eof` says the peer has
/// closed, which completes a body delimited by the connection close.
///
/// # Errors
///
/// [`Error::Truncated`] until the response is complete, and
/// [`Error::Malformed`] when `buf` is not an HTTP/1.x response or exceeds
/// the size limits.
pub fn parse_response(buf: &[u8], eof: bool) -> Result<Response, Error> {
    if !b"HTTP/".starts_with(buf.get(..5.min(buf.len())).unwrap_or_default()) {
        return Err(Error::malformed(WHAT, "not an HTTP response"));
    }
    let Some(head_end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
        if buf.len() > MAX_HEAD {
            return Err(Error::malformed(WHAT, "header block too long"));
        }
        return Err(Error::Truncated { what: WHAT });
    };
    let head = String::from_utf8_lossy(buf.get(..head_end).unwrap_or_default());
    let rest = buf.get(head_end + 4..).unwrap_or_default();
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let status = status_line
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| Error::malformed(WHAT, "bad status line"))?;
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(k, v)| (text(k.trim().as_bytes()), text(v.trim().as_bytes())))
        .collect();
    let mut response = Response {
        status_line: text(status_line.as_bytes()),
        status,
        headers,
        body: Vec::new(),
    };
    let chunked = response
        .header("transfer-encoding")
        .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
    if chunked {
        response.body = dechunk(rest)?;
    } else if let Some(len) = response.header("content-length") {
        let len: usize = len
            .parse()
            .map_err(|_| Error::malformed(WHAT, "bad Content-Length"))?;
        if len > MAX_BODY {
            return Err(Error::malformed(WHAT, "body too long"));
        }
        response.body = rest
            .get(..len)
            .ok_or(Error::Truncated { what: WHAT })?
            .to_vec();
    } else if status == 204 || status == 304 || (100..200).contains(&status) {
        // No body.
    } else if eof {
        response.body = rest
            .get(..MAX_BODY.min(rest.len()))
            .unwrap_or_default()
            .to_vec();
    } else {
        return Err(Error::Truncated { what: WHAT });
    }
    Ok(response)
}

fn dechunk(mut rest: &[u8]) -> Result<Vec<u8>, Error> {
    let mut body = Vec::new();
    loop {
        let Some(end) = rest.windows(2).position(|w| w == b"\r\n") else {
            if rest.len() > 64 {
                return Err(Error::malformed(WHAT, "chunk size line too long"));
            }
            return Err(Error::Truncated { what: WHAT });
        };
        let line = String::from_utf8_lossy(rest.get(..end).unwrap_or_default()).into_owned();
        let size_text = line.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|_| Error::malformed(WHAT, "bad chunk size"))?;
        rest = rest.get(end + 2..).unwrap_or_default();
        if size == 0 {
            return Ok(body);
        }
        if body.len().saturating_add(size) > MAX_BODY {
            return Err(Error::malformed(WHAT, "body too long"));
        }
        let chunk = rest.get(..size).ok_or(Error::Truncated { what: WHAT })?;
        body.extend_from_slice(chunk);
        match rest.get(size..size + 2) {
            Some(b"\r\n") => rest = rest.get(size + 2..).unwrap_or_default(),
            Some(_) => return Err(Error::malformed(WHAT, "chunk without CRLF")),
            None => return Err(Error::Truncated { what: WHAT }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_length_and_chunked() {
        let r = parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}", false).unwrap();
        assert_eq!((r.status, r.body.as_slice()), (200, &b"{}"[..]));
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2;x=y\r\nde\r\n0\r\n\r\n";
        assert_eq!(parse_response(raw, false).unwrap().body, b"abcde");
        assert!(
            parse_response(&raw[..50], false)
                .unwrap_err()
                .is_truncated()
        );
    }

    #[test]
    fn close_delimited_body_needs_eof() {
        let raw = b"HTTP/1.0 200 OK\r\n\r\nhello";
        assert!(parse_response(raw, false).unwrap_err().is_truncated());
        assert_eq!(parse_response(raw, true).unwrap().body, b"hello");
    }

    #[test]
    fn rejects_non_http() {
        assert!(matches!(
            parse_response(b"SSH-2.0-x\r\n", false),
            Err(Error::Malformed { .. })
        ));
        assert!(parse_response(b"HT", false).unwrap_err().is_truncated());
        assert!(matches!(
            parse_response(b"HTTP/1.1 abc\r\n\r\n", false),
            Err(Error::Malformed { .. })
        ));
    }

    #[test]
    fn request_drops_control_characters() {
        let req = get_request("evil\r\nX: y", "/");
        assert!(req.windows(9).any(|w| w == b"evilX: y\r"));
    }
}
