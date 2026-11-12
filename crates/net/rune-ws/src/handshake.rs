//! The opening handshake (RFC 6455 §4): HTTP/1.1 upgrade heads, key and
//! accept computation, and protocol/extension negotiation.

use crate::error::{Error, Result};

/// The GUID appended to `Sec-WebSocket-Key` (RFC 6455 §1.3).
pub const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Default limit on the size of an HTTP upgrade head.
pub const DEFAULT_MAX_HEAD: usize = 16 * 1024;

/// Computes `Sec-WebSocket-Accept` for a `Sec-WebSocket-Key`:
/// `base64(sha1(key ++ GUID))`.
///
/// ```
/// assert_eq!(
///     rune_ws::accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
///     "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
/// );
/// ```
#[must_use]
pub fn accept_key(key: &str) -> String {
    let mut input = String::with_capacity(key.len() + GUID.len());
    input.push_str(key);
    input.push_str(GUID);
    rune_base64::encode(&rune_sha1::hash_raw(input.as_bytes()))
}

/// Builds a `Sec-WebSocket-Key` from a 16-byte nonce. The nonce must be
/// freshly random for every connection (RFC 6455 §4.1); the async adapter
/// draws it from the OS RNG.
#[must_use]
pub fn key_from_nonce(nonce: [u8; 16]) -> String {
    rune_base64::encode(&nonce)
}

/// Ordered HTTP header fields, as they appeared on the wire.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Headers(pub Vec<(String, String)>);

impl Headers {
    /// The first value of `name` (case-insensitive).
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.all(name).next()
    }

    /// Every value of `name` (case-insensitive), in order.
    pub fn all<'s, 'n>(&'s self, name: &'n str) -> impl Iterator<Item = &'s str> + use<'s, 'n> {
        self.0
            .iter()
            .filter(move |(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// Comma-separated list items across every `name` field, trimmed and
    /// with empty items dropped.
    pub fn list<'s, 'n>(&'s self, name: &'n str) -> impl Iterator<Item = &'s str> + use<'s, 'n> {
        self.all(name)
            .flat_map(|value| value.split(','))
            .map(str::trim)
            .filter(|item| !item.is_empty())
    }

    /// Whether the comma-separated list `name` contains `token`
    /// (case-insensitive).
    #[must_use]
    pub fn has_token(&self, name: &str, token: &str) -> bool {
        self.list(name).any(|item| item.eq_ignore_ascii_case(token))
    }

    /// Appends a field.
    pub fn push(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.0.push((name.into(), value.into()));
    }
}

/// A parsed HTTP/1.1 request head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The method, e.g. `GET`.
    pub method: String,
    /// The request target, e.g. `/chat?room=1`.
    pub target: String,
    /// The version, e.g. `HTTP/1.1`.
    pub version: String,
    /// Header fields.
    pub headers: Headers,
}

/// A parsed HTTP/1.1 response head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// The version, e.g. `HTTP/1.1`.
    pub version: String,
    /// The status code.
    pub status: u16,
    /// The reason phrase.
    pub reason: String,
    /// Header fields.
    pub headers: Headers,
}

/// Splits a complete head (`\r\n\r\n`-terminated) off the front of `buf`.
fn split_head(buf: &[u8], max: usize) -> Result<Option<(&str, usize)>> {
    let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
        if buf.len() > max {
            return Err(Error::HeadTooLarge(max));
        }
        return Ok(None);
    };
    if end + 4 > max {
        return Err(Error::HeadTooLarge(max));
    }
    let head = std::str::from_utf8(&buf[..end]).map_err(|_| Error::MalformedHead("not UTF-8"))?;
    Ok(Some((head, end + 4)))
}

fn parse_fields<'a>(lines: impl Iterator<Item = &'a str>) -> Result<Headers> {
    let mut headers = Headers::default();
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or(Error::MalformedHead("header line without ':'"))?;
        let valid_name = !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b));
        if !valid_name {
            return Err(Error::MalformedHead("invalid header name"));
        }
        headers.push(name, value.trim_matches([' ', '\t']));
    }
    Ok(headers)
}

/// Parses an HTTP/1.1 request head from the front of `buf`.
///
/// Returns `Ok(None)` until the blank line that ends the head has arrived,
/// and then the request and the number of bytes it used; anything after
/// that is WebSocket frame data.
///
/// # Errors
///
/// [`Error::HeadTooLarge`] once more than `max` bytes arrive without the
/// end of the head, and [`Error::MalformedHead`] for a syntax error.
pub fn parse_request(buf: &[u8], max: usize) -> Result<Option<(Request, usize)>> {
    let Some((head, used)) = split_head(buf, max)? else {
        return Ok(None);
    };
    let mut lines = head.split("\r\n");
    let start = lines.next().unwrap_or_default();
    let mut parts = start.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Error::MalformedHead("request line"));
    };
    if method.is_empty() || target.is_empty() || !version.starts_with("HTTP/") {
        return Err(Error::MalformedHead("request line"));
    }
    let request = Request {
        method: method.to_owned(),
        target: target.to_owned(),
        version: version.to_owned(),
        headers: parse_fields(lines)?,
    };
    Ok(Some((request, used)))
}

/// Parses an HTTP/1.1 response head from the front of `buf`; see
/// [`parse_request`].
///
/// # Errors
///
/// As for [`parse_request`].
pub fn parse_response(buf: &[u8], max: usize) -> Result<Option<(Response, usize)>> {
    let Some((head, used)) = split_head(buf, max)? else {
        return Ok(None);
    };
    let mut lines = head.split("\r\n");
    let start = lines.next().unwrap_or_default();
    let mut parts = start.splitn(3, ' ');
    let (Some(version), Some(status)) = (parts.next(), parts.next()) else {
        return Err(Error::MalformedHead("status line"));
    };
    let status = status
        .parse::<u16>()
        .ok()
        .filter(|s| (100..1000).contains(s) && status.len() == 3)
        .ok_or(Error::MalformedHead("status code"))?;
    if !version.starts_with("HTTP/") {
        return Err(Error::MalformedHead("status line"));
    }
    let response = Response {
        version: version.to_owned(),
        status,
        reason: parts.next().unwrap_or_default().to_owned(),
        headers: parse_fields(lines)?,
    };
    Ok(Some((response, used)))
}

fn write_head(start: &str, headers: &[(String, String)]) -> Vec<u8> {
    let mut out = String::with_capacity(256);
    out.push_str(start);
    out.push_str("\r\n");
    for (name, value) in headers {
        out.push_str(name);
        out.push_str(": ");
        out.push_str(value);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    out.into_bytes()
}

fn is_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// What both sides agreed on during the handshake.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Negotiated {
    /// The selected subprotocol (`Sec-WebSocket-Protocol`), if any.
    pub protocol: Option<String>,
    /// The negotiated permessage-deflate parameters, if any.
    #[cfg(feature = "deflate")]
    pub deflate: Option<crate::deflate::DeflateParams>,
}

/// The client side of the opening handshake.
///
/// ```
/// use rune_ws::{ClientHandshake, accept_key, parse_response};
///
/// let client = ClientHandshake::new("example.com", "/chat", [7; 16]).with_protocol("chat");
/// let request = client.request_bytes();
/// assert!(request.starts_with(b"GET /chat HTTP/1.1\r\n"));
///
/// let reply = format!(
///     "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
///      Sec-WebSocket-Accept: {}\r\nSec-WebSocket-Protocol: chat\r\n\r\n",
///     accept_key(client.key()),
/// );
/// let (response, _) = parse_response(reply.as_bytes(), 16 * 1024)?.unwrap();
/// let agreed = client.verify(&response)?;
/// assert_eq!(agreed.protocol.as_deref(), Some("chat"));
/// # Ok::<(), rune_ws::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct ClientHandshake {
    host: String,
    path: String,
    key: String,
    protocols: Vec<String>,
    headers: Vec<(String, String)>,
    #[cfg(feature = "deflate")]
    deflate: Option<crate::deflate::DeflateConfig>,
}

impl ClientHandshake {
    /// A handshake for `path` on `host` (the `Host` header value, including
    /// a non-default port). `nonce` must be random; see [`key_from_nonce`].
    pub fn new(host: impl Into<String>, path: impl Into<String>, nonce: [u8; 16]) -> Self {
        Self {
            host: host.into(),
            path: path.into(),
            key: key_from_nonce(nonce),
            protocols: Vec::new(),
            headers: Vec::new(),
            #[cfg(feature = "deflate")]
            deflate: None,
        }
    }

    /// Offers a subprotocol; call repeatedly to offer several, in order of
    /// preference.
    #[must_use]
    pub fn with_protocol(mut self, protocol: impl Into<String>) -> Self {
        self.protocols.push(protocol.into());
        self
    }

    /// Adds an extra request header (`Origin`, `Cookie`, `Authorization`…).
    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Offers permessage-deflate with the given configuration.
    #[cfg(feature = "deflate")]
    #[must_use]
    pub const fn with_deflate(mut self, config: crate::deflate::DeflateConfig) -> Self {
        self.deflate = Some(config);
        self
    }

    /// The `Sec-WebSocket-Key` sent.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// The request head to send.
    #[must_use]
    pub fn request_bytes(&self) -> Vec<u8> {
        let mut headers = vec![
            ("Host".to_owned(), self.host.clone()),
            ("Upgrade".to_owned(), "websocket".to_owned()),
            ("Connection".to_owned(), "Upgrade".to_owned()),
            ("Sec-WebSocket-Key".to_owned(), self.key.clone()),
            ("Sec-WebSocket-Version".to_owned(), "13".to_owned()),
        ];
        if !self.protocols.is_empty() {
            headers.push((
                "Sec-WebSocket-Protocol".to_owned(),
                self.protocols.join(", "),
            ));
        }
        #[cfg(feature = "deflate")]
        if let Some(config) = &self.deflate {
            headers.push(("Sec-WebSocket-Extensions".to_owned(), config.offer()));
        }
        headers.extend(self.headers.iter().cloned());
        write_head(&format!("GET {} HTTP/1.1", self.path), &headers)
    }

    /// Validates the server's response (RFC 6455 §4.1, client steps 1–6)
    /// and returns what was negotiated.
    ///
    /// # Errors
    ///
    /// [`Error::Rejected`] for a status other than 101,
    /// [`Error::AcceptMismatch`] for a wrong accept value,
    /// [`Error::Handshake`] for missing or unexpected headers and
    /// [`Error::Extension`] for an extension that was not offered.
    pub fn verify(&self, response: &Response) -> Result<Negotiated> {
        if response.status != 101 {
            return Err(Error::Rejected(response.status));
        }
        let headers = &response.headers;
        if !headers.has_token("Upgrade", "websocket") {
            return Err(Error::Handshake("missing Upgrade: websocket"));
        }
        if !headers.has_token("Connection", "upgrade") {
            return Err(Error::Handshake("missing Connection: Upgrade"));
        }
        if headers.get("Sec-WebSocket-Accept") != Some(accept_key(&self.key).as_str()) {
            return Err(Error::AcceptMismatch);
        }
        let protocol = match headers.list("Sec-WebSocket-Protocol").collect::<Vec<_>>()[..] {
            [] => None,
            [chosen] if self.protocols.iter().any(|p| p == chosen) => Some(chosen.to_owned()),
            _ => return Err(Error::Handshake("unexpected Sec-WebSocket-Protocol")),
        };
        let extensions: Vec<&str> = headers.all("Sec-WebSocket-Extensions").collect();
        #[cfg(feature = "deflate")]
        let deflate = crate::deflate::client_verify(self.deflate.as_ref(), &extensions)?;
        #[cfg(not(feature = "deflate"))]
        if extensions.iter().any(|value| !value.trim().is_empty()) {
            return Err(Error::Extension(
                "server selected an extension that was not offered".into(),
            ));
        }
        Ok(Negotiated {
            protocol,
            #[cfg(feature = "deflate")]
            deflate,
        })
    }
}

/// The server side of the opening handshake.
///
/// ```
/// use rune_ws::{ServerHandshake, parse_request};
///
/// let raw = b"GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\n\
///             Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
///             Sec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: superchat, chat\r\n\r\n";
/// let (request, _) = parse_request(raw, 16 * 1024)?.unwrap();
/// let (response, agreed) = ServerHandshake::default().with_protocol("chat").accept(&request)?;
/// assert_eq!(agreed.protocol.as_deref(), Some("chat"));
/// let text = String::from_utf8(response).unwrap();
/// assert!(text.contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"));
/// # Ok::<(), rune_ws::Error>(())
/// ```
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct ServerHandshake {
    protocols: Vec<String>,
    headers: Vec<(String, String)>,
    #[cfg(feature = "deflate")]
    deflate: Option<crate::deflate::DeflateConfig>,
}

impl ServerHandshake {
    /// Supports a subprotocol. The server picks the client's most preferred
    /// offer among the supported ones.
    #[must_use]
    pub fn with_protocol(mut self, protocol: impl Into<String>) -> Self {
        self.protocols.push(protocol.into());
        self
    }

    /// Adds an extra response header.
    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Accepts permessage-deflate offers compatible with `config`.
    #[cfg(feature = "deflate")]
    #[must_use]
    pub const fn with_deflate(mut self, config: crate::deflate::DeflateConfig) -> Self {
        self.deflate = Some(config);
        self
    }

    /// Checks that `request` is a valid WebSocket upgrade (RFC 6455 §4.2.1)
    /// and returns its `Sec-WebSocket-Key`.
    ///
    /// # Errors
    ///
    /// [`Error::Handshake`] for a missing or malformed requirement and
    /// [`Error::UnsupportedVersion`] for a version other than 13 (answer it
    /// with [`reject_version`]).
    pub fn validate(request: &Request) -> Result<&str> {
        if request.method != "GET" {
            return Err(Error::Handshake("method is not GET"));
        }
        if request.version != "HTTP/1.1" {
            return Err(Error::Handshake("version is not HTTP/1.1"));
        }
        let headers = &request.headers;
        if headers.get("Host").is_none() {
            return Err(Error::Handshake("missing Host"));
        }
        if !headers.has_token("Upgrade", "websocket") {
            return Err(Error::Handshake("missing Upgrade: websocket"));
        }
        if !headers.has_token("Connection", "upgrade") {
            return Err(Error::Handshake("missing Connection: Upgrade"));
        }
        match headers.get("Sec-WebSocket-Version") {
            Some("13") => {}
            other => {
                return Err(Error::UnsupportedVersion(
                    other.unwrap_or_default().to_owned(),
                ));
            }
        }
        let key = headers
            .get("Sec-WebSocket-Key")
            .ok_or(Error::Handshake("missing Sec-WebSocket-Key"))?;
        let decoded_len = rune_base64::decode(key).map_or(0, |k| k.len());
        if key.len() != 24 || decoded_len != 16 {
            return Err(Error::Handshake("Sec-WebSocket-Key is not 16 base64 bytes"));
        }
        Ok(key)
    }

    /// Validates `request` and builds the `101 Switching Protocols`
    /// response, choosing a subprotocol and extensions.
    ///
    /// # Errors
    ///
    /// As for [`validate`](Self::validate), plus [`Error::Extension`] for a
    /// malformed `Sec-WebSocket-Extensions` header.
    pub fn accept(&self, request: &Request) -> Result<(Vec<u8>, Negotiated)> {
        let key = Self::validate(request)?;
        let mut headers = vec![
            ("Upgrade".to_owned(), "websocket".to_owned()),
            ("Connection".to_owned(), "Upgrade".to_owned()),
            ("Sec-WebSocket-Accept".to_owned(), accept_key(key)),
        ];
        let protocol = request
            .headers
            .list("Sec-WebSocket-Protocol")
            .find(|offer| is_token(offer) && self.protocols.iter().any(|p| p == offer))
            .map(str::to_owned);
        if let Some(protocol) = &protocol {
            headers.push(("Sec-WebSocket-Protocol".to_owned(), protocol.clone()));
        }
        #[cfg(feature = "deflate")]
        let deflate = match &self.deflate {
            Some(config) => {
                let offers: Vec<&str> = request.headers.all("Sec-WebSocket-Extensions").collect();
                let chosen = crate::deflate::server_negotiate(config, &offers)?;
                if let Some((params, header)) = &chosen {
                    headers.push(("Sec-WebSocket-Extensions".to_owned(), header.clone()));
                    Some(*params)
                } else {
                    None
                }
            }
            None => None,
        };
        headers.extend(self.headers.iter().cloned());
        let response = write_head("HTTP/1.1 101 Switching Protocols", &headers);
        Ok((
            response,
            Negotiated {
                protocol,
                #[cfg(feature = "deflate")]
                deflate,
            },
        ))
    }
}

/// A `426 Upgrade Required` response advertising version 13, for a request
/// that failed with [`Error::UnsupportedVersion`] (RFC 6455 §4.4).
#[must_use]
pub fn reject_version() -> Vec<u8> {
    write_head(
        "HTTP/1.1 426 Upgrade Required",
        &[
            ("Sec-WebSocket-Version".to_owned(), "13".to_owned()),
            ("Content-Length".to_owned(), "0".to_owned()),
        ],
    )
}

/// A `400 Bad Request` response for any other failed upgrade.
#[must_use]
pub fn reject_bad_request() -> Vec<u8> {
    write_head(
        "HTTP/1.1 400 Bad Request",
        &[("Content-Length".to_owned(), "0".to_owned())],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC_REQUEST: &[u8] = b"GET /chat HTTP/1.1\r\nHost: server.example.com\r\n\
        Upgrade: websocket\r\nConnection: Upgrade\r\n\
        Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nOrigin: http://example.com\r\n\
        Sec-WebSocket-Protocol: chat, superchat\r\nSec-WebSocket-Version: 13\r\n\r\n";

    #[test]
    fn rfc_accept_key() {
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
        assert_eq!(
            key_from_nonce(*b"the sample nonce"),
            "dGhlIHNhbXBsZSBub25jZQ=="
        );
    }

    #[test]
    fn parse_request_waits_and_reports_length() {
        for cut in 0..RFC_REQUEST.len() {
            assert!(
                parse_request(&RFC_REQUEST[..cut], DEFAULT_MAX_HEAD)
                    .unwrap()
                    .is_none()
            );
        }
        let mut with_frame = RFC_REQUEST.to_vec();
        with_frame.extend([0x81, 0x80, 0, 0, 0, 0]);
        let (request, used) = parse_request(&with_frame, DEFAULT_MAX_HEAD)
            .unwrap()
            .unwrap();
        assert_eq!(used, RFC_REQUEST.len());
        assert_eq!(request.target, "/chat");
        assert_eq!(request.headers.get("origin"), Some("http://example.com"));
        assert_eq!(
            request
                .headers
                .list("Sec-WebSocket-Protocol")
                .collect::<Vec<_>>(),
            ["chat", "superchat"]
        );
    }

    #[test]
    fn head_limits_and_syntax() {
        assert!(matches!(
            parse_request(&[b'a'; 100], 64),
            Err(Error::HeadTooLarge(64))
        ));
        assert!(matches!(
            parse_request(b"GET /\r\n\r\n", 64),
            Err(Error::MalformedHead(_))
        ));
        assert!(matches!(
            parse_request(b"GET / HTTP/1.1\r\nbad header\r\n\r\n", 64),
            Err(Error::MalformedHead(_))
        ));
        assert!(matches!(
            parse_response(b"HTTP/1.1 1010 x\r\n\r\n", 64),
            Err(Error::MalformedHead(_))
        ));
    }

    #[test]
    fn server_accepts_rfc_request() {
        let (request, _) = parse_request(RFC_REQUEST, DEFAULT_MAX_HEAD)
            .unwrap()
            .unwrap();
        let server = ServerHandshake::default().with_protocol("superchat");
        let (response, agreed) = server.accept(&request).unwrap();
        assert_eq!(agreed.protocol.as_deref(), Some("superchat"));
        let (response, _) = parse_response(&response, DEFAULT_MAX_HEAD)
            .unwrap()
            .unwrap();
        assert_eq!(response.status, 101);
        assert_eq!(
            response.headers.get("Sec-WebSocket-Accept"),
            Some("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
        );
    }

    #[test]
    fn server_rejects_bad_requests() {
        let check = |from: &str, to: &str| {
            let text = String::from_utf8(RFC_REQUEST.to_vec())
                .unwrap()
                .replace(from, to);
            let (request, _) = parse_request(text.as_bytes(), DEFAULT_MAX_HEAD)
                .unwrap()
                .unwrap();
            ServerHandshake::validate(&request).unwrap_err()
        };
        assert!(matches!(check("GET", "POST"), Error::Handshake(_)));
        assert!(matches!(
            check("Upgrade: websocket", "Upgrade: h2c"),
            Error::Handshake(_)
        ));
        assert!(matches!(
            check("Connection: Upgrade", "Connection: close"),
            Error::Handshake(_)
        ));
        assert!(
            matches!(check("Version: 13", "Version: 8"), Error::UnsupportedVersion(v) if v == "8")
        );
        assert!(matches!(
            check("dGhlIHNhbXBsZSBub25jZQ==", "c2hvcnQ="),
            Error::Handshake(_)
        ));
        assert!(
            String::from_utf8(reject_version())
                .unwrap()
                .contains("Sec-WebSocket-Version: 13")
        );
    }

    #[test]
    fn client_round_trip_and_failures() {
        let client = ClientHandshake::new("h", "/", [1; 16])
            .with_protocol("a")
            .with_header("Origin", "o");
        let (request, _) = parse_request(&client.request_bytes(), DEFAULT_MAX_HEAD)
            .unwrap()
            .unwrap();
        assert_eq!(request.headers.get("Origin"), Some("o"));
        let (bytes, _) = ServerHandshake::default()
            .with_protocol("a")
            .accept(&request)
            .unwrap();
        let (response, _) = parse_response(&bytes, DEFAULT_MAX_HEAD).unwrap().unwrap();
        assert_eq!(
            client.verify(&response).unwrap().protocol.as_deref(),
            Some("a")
        );

        let mut wrong = response.clone();
        wrong.headers.0.retain(|(n, _)| n != "Sec-WebSocket-Accept");
        wrong.headers.push("Sec-WebSocket-Accept", "nope");
        assert!(matches!(client.verify(&wrong), Err(Error::AcceptMismatch)));

        let mut unoffered = response.clone();
        unoffered.headers.push("Sec-WebSocket-Protocol", "b");
        assert!(matches!(
            client.verify(&unoffered),
            Err(Error::Handshake(_))
        ));

        let mut status = response;
        status.status = 403;
        assert!(matches!(client.verify(&status), Err(Error::Rejected(403))));
    }
}
