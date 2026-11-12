//! JA4H, the HTTP client fingerprint.
//!
//! Specification: <https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4H.md>
//! and the `FoxIO` reference implementation. JA4H is part of JA4+ (`FoxIO`
//! License 1.1).

use crate::Error;
use crate::fingerprint::{Fingerprint, count2, hash12, join};

/// The HTTP version of a request.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum HttpVersion {
    /// HTTP/1.0: `10`.
    Http10,
    /// HTTP/1.1: `11`.
    #[default]
    Http11,
    /// HTTP/2: `20`.
    Http2,
    /// HTTP/3: `30`.
    Http3,
}

impl HttpVersion {
    /// The two-digit JA4H code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Http10 => "10",
            Self::Http11 => "11",
            Self::Http2 => "20",
            Self::Http3 => "30",
        }
    }
}

/// The parts of an HTTP request that JA4H reads: method, version, and the
/// header fields in the order they were sent.
///
/// Build one from a decoded HTTP/2 or HTTP/3 header list with
/// [`HttpRequest::new`] and [`HttpRequest::with_header`], or read an
/// HTTP/1 request head with [`HttpRequest::parse_http1`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct HttpRequest {
    /// The request method, e.g. `GET`.
    pub method: String,
    /// The protocol version.
    pub version: HttpVersion,
    /// Header fields as `(name, value)` in wire order, names as sent.
    /// HTTP/2 and HTTP/3 pseudo-headers (`:method`, …) may be included;
    /// JA4H skips them.
    pub headers: Vec<(String, String)>,
}

impl HttpRequest {
    /// A request with no headers.
    #[must_use]
    pub fn new(method: impl Into<String>, version: HttpVersion) -> Self {
        Self {
            method: method.into(),
            version,
            headers: Vec::new(),
        }
    }

    /// Appends a header field.
    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Reads an HTTP/1.0 or HTTP/1.1 request head: the request line and the
    /// header lines, up to the first empty line or the end of the input.
    /// Lines end in CRLF or a bare LF. Header lines without a colon count as
    /// a header with that name and an empty value; continuation lines
    /// (obsolete line folding) are appended to the previous value.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidHttpRequest`] if the request line is not
    /// `METHOD SP target SP HTTP/1.x` or the head is not UTF-8.
    pub fn parse_http1(head: &[u8]) -> Result<Self, Error> {
        let invalid = |reason| Error::InvalidHttpRequest { reason };
        let head = std::str::from_utf8(head).map_err(|_| invalid("not UTF-8"))?;
        let mut lines = head.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l));
        let request_line = lines.next().unwrap_or_default();
        let mut parts = request_line.split(' ');
        let (Some(method), Some(_target), Some(version), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(invalid("request line is not `METHOD target VERSION`"));
        };
        if method.is_empty() || !method.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(invalid("bad method"));
        }
        let version = match version {
            "HTTP/1.0" => HttpVersion::Http10,
            "HTTP/1.1" => HttpVersion::Http11,
            _ => return Err(invalid("version is not HTTP/1.0 or HTTP/1.1")),
        };
        let mut request = Self::new(method, version);
        for line in lines {
            if line.is_empty() {
                break;
            }
            if line.starts_with([' ', '\t']) {
                if let Some((_, value)) = request.headers.last_mut() {
                    value.push(' ');
                    value.push_str(line.trim());
                }
                continue;
            }
            let (name, value) = line.split_once(':').unwrap_or((line, ""));
            request
                .headers
                .push((name.to_owned(), value.trim().to_owned()));
        }
        Ok(request)
    }

    fn values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.headers
            .iter()
            .filter(move |(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// The JA4H fingerprint of a request, with cookies sorted: the form
/// normally shared.
///
/// ```
/// use rune_ja::{HttpRequest, ja4h};
///
/// let request = HttpRequest::parse_http1(
///     b"GET / HTTP/1.1\r\nHost: example.com\r\nAccept-Language: en-US,en;q=0.9\r\n\
///       Cookie: b=2; a=1\r\n\r\n",
/// )?;
/// let fp = ja4h(&request);
/// assert_eq!(fp.raw, "ge11cn02enus_Host,Accept-Language_a,b_a=1,b=2");
/// # Ok::<(), rune_ja::Error>(())
/// ```
#[must_use]
pub fn ja4h(request: &HttpRequest) -> Fingerprint {
    ja4h_inner(request, true)
}

/// The JA4H fingerprint with cookies in wire order (`JA4H_o`, `JA4H_ro`).
#[must_use]
pub fn ja4h_original(request: &HttpRequest) -> Fingerprint {
    ja4h_inner(request, false)
}

fn ja4h_inner(request: &HttpRequest, sorted: bool) -> Fingerprint {
    let mut has_cookie = false;
    let mut has_referer = false;
    let mut names = Vec::new();
    for (name, _) in &request.headers {
        if name.starts_with(':') {
            continue;
        }
        if name.eq_ignore_ascii_case("cookie") {
            has_cookie = true;
        } else if name.eq_ignore_ascii_case("referer") {
            has_referer = true;
        } else {
            names.push(name.as_str());
        }
    }

    let language = request
        .values("accept-language")
        .next()
        .map(primary_language)
        .unwrap_or_default();
    let a = format!(
        "{}{}{}{}{}{}",
        method_code(&request.method),
        request.version.code(),
        if has_cookie { 'c' } else { 'n' },
        if has_referer { 'r' } else { 'n' },
        count2(names.len()),
        pad4(&language),
    );
    let b = names.join(",");

    let mut cookies: Vec<(&str, Option<&str>)> = request
        .values("cookie")
        .flat_map(|value| value.split("; "))
        .filter(|cookie| !cookie.is_empty())
        .map(|cookie| match cookie.split_once('=') {
            Some((name, value)) => (name, Some(value)),
            None => (cookie, None),
        })
        .collect();
    if sorted {
        cookies.sort_unstable();
    }
    let c = join(&cookies, ",", |out, (name, _)| out.push_str(name));
    let d = join(&cookies, ",", |out, (name, value)| {
        out.push_str(name);
        if let Some(value) = value {
            out.push('=');
            out.push_str(value);
        }
    });

    Fingerprint {
        hash: format!("{a}_{}_{}_{}", hash12(&b), hash12(&c), hash12(&d)),
        raw: format!("{a}_{b}_{c}_{d}"),
    }
}

/// The first two characters of the method, lowercased (`GET` → `ge`),
/// padded with `0`.
fn method_code(method: &str) -> String {
    let mut code: String = method
        .chars()
        .take(2)
        .flat_map(char::to_lowercase)
        .collect();
    while code.chars().count() < 2 {
        code.push('0');
    }
    code
}

/// The first `Accept-Language` entry without dashes, lowercased
/// (`en-US,en;q=0.9` → `enus`).
fn primary_language(value: &str) -> String {
    value
        .trim_start()
        .split(',')
        .next()
        .unwrap_or_default()
        .chars()
        .filter(|&c| c != '-')
        .flat_map(char::to_lowercase)
        .collect()
}

/// The first four characters, padded with `0`.
fn pad4(s: &str) -> String {
    let mut out: String = s.chars().take(4).collect();
    while out.chars().count() < 4 {
        out.push('0');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The worked example of the `FoxIO` reference implementation's JA4H
    /// unit test (a Chrome request to www.cnn.com).
    fn cnn() -> HttpRequest {
        let mut request = HttpRequest::new("GET", HttpVersion::Http11);
        for (name, value) in [
            ("Host", "www.cnn.com"),
            (
                "Cookie",
                "FastAB=0=6859,1=8174,2=4183,3=3319,4=3917,5=2557,6=4259,7=6070,8=0804,9=6453,10=1942,11=4435,12=4143,13=9445,14=6957,15=8682,16=1885,17=1825,18=3760,19=0929; sato=1; countryCode=US; stateCode=VA; geoData=purcellville|VA|20132|US|NA|-400|broadband|39.160|-77.700|511; usprivacy=1---; umto=1; _dd_s=logs=1&id=b5c2d770-eaba-4847-8202-390c4552ff9a&created=1686159462724&expire=1686160422726",
            ),
            ("Sec-Ch-Ua", ""),
            ("Sec-Ch-Ua-Mobile", "?0"),
            (
                "User-Agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.110 Safari/537.36",
            ),
            ("Sec-Ch-Ua-Platform", "\"\""),
            ("Accept", "*/*"),
            ("Sec-Fetch-Site", "same-origin"),
            ("Sec-Fetch-Mode", "cors"),
            ("Sec-Fetch-Dest", "empty"),
            ("Sec-Fetch-Mode", "cors"),
            ("Sec-Fetch-Dest", "empty"),
            ("Referer", "https://www.cnn.com/"),
            ("Accept-Encoding", "gzip, deflate"),
            ("Accept-Language", "en-US,en;q=0.9"),
        ] {
            request = request.with_header(name, value);
        }
        request
    }

    #[test]
    fn reference_example_sorted() {
        let fp = ja4h(&cnn());
        assert_eq!(
            fp.hash,
            "ge11cr13enus_88d2d584d47f_0f2659b474bf_161698816dab"
        );
        assert!(fp.raw.starts_with(
            "ge11cr13enus_Host,Sec-Ch-Ua,Sec-Ch-Ua-Mobile,User-Agent,Sec-Ch-Ua-Platform,Accept,Sec-Fetch-Site,Sec-Fetch-Mode,Sec-Fetch-Dest,Sec-Fetch-Mode,Sec-Fetch-Dest,Accept-Encoding,Accept-Language_FastAB,_dd_s,countryCode,geoData,sato,stateCode,umto,usprivacy_FastAB=0=6859,"
        ));
    }

    #[test]
    fn reference_example_original() {
        let fp = ja4h_original(&cnn());
        assert_eq!(
            fp.hash,
            "ge11cr13enus_88d2d584d47f_457935509480_ff4b0b83634b"
        );
    }

    #[test]
    fn http2_pseudo_headers_are_skipped() {
        let request = HttpRequest::new("GET", HttpVersion::Http2)
            .with_header(":method", "GET")
            .with_header(":path", "/")
            .with_header("user-agent", "x")
            .with_header("cookie", "a=1")
            .with_header("cookie", "b");
        let fp = ja4h(&request);
        assert_eq!(fp.raw, "ge20cn010000_user-agent_a,b_a=1,b");
    }

    #[test]
    fn no_headers_and_odd_methods() {
        let fp = ja4h(&HttpRequest::new("X", HttpVersion::Http10));
        assert_eq!(
            fp.hash,
            "x010nn000000_000000000000_000000000000_000000000000"
        );
        assert_eq!(method_code("PROPFIND"), "pr");
        assert_eq!(pad4("da"), "da00");
        assert_eq!(primary_language(" da, en-GB;q=0.8"), "da");
    }

    #[test]
    fn parse_http1_head() {
        let request = HttpRequest::parse_http1(
            b"POST /x HTTP/1.0\nHost: a\r\nX-Folded: one\r\n two\r\nNoColon\r\n\r\nbody: ignored",
        )
        .unwrap();
        assert_eq!(request.method, "POST");
        assert_eq!(request.version, HttpVersion::Http10);
        assert_eq!(
            request.headers,
            [
                ("Host".to_owned(), "a".to_owned()),
                ("X-Folded".to_owned(), "one two".to_owned()),
                ("NoColon".to_owned(), String::new()),
            ]
        );
        for bad in [
            &b""[..],
            b"GET /\r\n",
            b"GET / HTTP/2\r\n",
            b"GET / HTTP/1.1 extra\r\n",
            b" / HTTP/1.1\r\n",
            b"GET / HTTP/1.1\r\nX: \xff\r\n",
        ] {
            assert!(HttpRequest::parse_http1(bad).is_err(), "{bad:?}");
        }
    }
}
