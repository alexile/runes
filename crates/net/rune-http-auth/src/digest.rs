//! Digest access authentication ([RFC 7616], with the [RFC 2617] and
//! RFC 2069 forms it keeps compatible).
//!
//! Sans-I/O: the caller supplies the client nonce (`cnonce`) and the nonce
//! count, and on the server side checks nonce freshness itself.
//!
//! [RFC 7616]: https://www.rfc-editor.org/rfc/rfc7616
//! [RFC 2617]: https://www.rfc-editor.org/rfc/rfc2617

use std::fmt;

use sha2::{Digest as _, Sha256, Sha512_256};

use crate::challenge::push_param;
use crate::{AuthError, Challenge, constant_time_eq};

/// A Digest hash algorithm (RFC 7616 §3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum DigestAlgorithm {
    /// `MD5`, the default when the challenge names none.
    #[default]
    Md5,
    /// `MD5-sess`.
    Md5Sess,
    /// `SHA-256`.
    Sha256,
    /// `SHA-256-sess`.
    Sha256Sess,
    /// `SHA-512-256`.
    Sha512_256,
    /// `SHA-512-256-sess`.
    Sha512_256Sess,
}

impl DigestAlgorithm {
    /// Parses an `algorithm` value, ignoring case.
    ///
    /// # Errors
    ///
    /// [`AuthError::UnsupportedAlgorithm`].
    pub fn parse(name: &str) -> Result<Self, AuthError> {
        const ALL: [DigestAlgorithm; 6] = [
            DigestAlgorithm::Md5,
            DigestAlgorithm::Md5Sess,
            DigestAlgorithm::Sha256,
            DigestAlgorithm::Sha256Sess,
            DigestAlgorithm::Sha512_256,
            DigestAlgorithm::Sha512_256Sess,
        ];
        ALL.into_iter()
            .find(|alg| alg.name().eq_ignore_ascii_case(name))
            .ok_or_else(|| AuthError::UnsupportedAlgorithm(name.to_owned()))
    }

    /// The registered name (`SHA-256-sess`).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Md5 => "MD5",
            Self::Md5Sess => "MD5-sess",
            Self::Sha256 => "SHA-256",
            Self::Sha256Sess => "SHA-256-sess",
            Self::Sha512_256 => "SHA-512-256",
            Self::Sha512_256Sess => "SHA-512-256-sess",
        }
    }

    /// `true` for the `-sess` variants.
    #[must_use]
    pub const fn is_session(self) -> bool {
        matches!(
            self,
            Self::Md5Sess | Self::Sha256Sess | Self::Sha512_256Sess
        )
    }

    /// The hash of `data` as lowercase hex.
    #[must_use]
    pub fn hash(self, data: &[u8]) -> String {
        match self {
            Self::Md5 | Self::Md5Sess => rune_md5::hash_bytes(data),
            Self::Sha256 | Self::Sha256Sess => hex(&Sha256::digest(data)),
            Self::Sha512_256 | Self::Sha512_256Sess => hex(&Sha512_256::digest(data)),
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    use fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// A quality of protection (RFC 7616 §3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Qop {
    /// `auth`: authenticates the method and URI.
    Auth,
    /// `auth-int`: also covers the hash of the body.
    AuthInt,
}

impl Qop {
    /// The wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Auth => "auth",
            Self::AuthInt => "auth-int",
        }
    }

    fn parse(name: &str) -> Option<Self> {
        if name.eq_ignore_ascii_case("auth") {
            Some(Self::Auth)
        } else if name.eq_ignore_ascii_case("auth-int") {
            Some(Self::AuthInt)
        } else {
            None
        }
    }
}

/// A parsed `WWW-Authenticate: Digest …` challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DigestChallenge {
    /// The protection space.
    pub realm: String,
    /// The server nonce.
    pub nonce: String,
    /// The opaque value to echo back.
    pub opaque: Option<String>,
    /// URIs of the protection space (`domain`, space-separated).
    pub domain: Vec<String>,
    /// `true` if the previous request failed only because the nonce is
    /// stale (retry without asking for a new password).
    pub stale: bool,
    /// The hash algorithm.
    pub algorithm: DigestAlgorithm,
    /// The qop values offered that this crate supports. Empty for an
    /// RFC 2069 challenge without `qop`.
    pub qop: Vec<Qop>,
    /// `charset=UTF-8` was sent.
    pub charset_utf8: bool,
    /// `userhash=true` was sent: the client should hash its username.
    pub userhash: bool,
}

impl DigestChallenge {
    /// A challenge for `realm` and `nonce` with the default (MD5, `auth`).
    #[must_use]
    pub fn new(realm: impl Into<String>, nonce: impl Into<String>) -> Self {
        Self {
            realm: realm.into(),
            nonce: nonce.into(),
            opaque: None,
            domain: Vec::new(),
            stale: false,
            algorithm: DigestAlgorithm::Md5,
            qop: vec![Qop::Auth],
            charset_utf8: false,
            userhash: false,
        }
    }

    /// Finds the first Digest challenge in a `WWW-Authenticate` value.
    ///
    /// # Errors
    ///
    /// A syntax error, [`AuthError::WrongScheme`] if there is no Digest
    /// challenge, or any error of [`from_challenge`](Self::from_challenge).
    pub fn parse(header: &str) -> Result<Self, AuthError> {
        let list = Challenge::parse_list(header)?;
        let digest =
            list.iter()
                .find(|c| c.is_scheme("Digest"))
                .ok_or_else(|| AuthError::WrongScheme {
                    expected: "Digest",
                    found: list.first().map(|c| c.scheme.clone()).unwrap_or_default(),
                })?;
        Self::from_challenge(digest)
    }

    /// Reads a parsed Digest challenge.
    ///
    /// # Errors
    ///
    /// [`AuthError::MissingParam`] without `realm` or `nonce`,
    /// [`AuthError::UnsupportedAlgorithm`], or [`AuthError::UnsupportedQop`]
    /// when `qop` offers neither `auth` nor `auth-int`.
    pub fn from_challenge(challenge: &Challenge) -> Result<Self, AuthError> {
        if !challenge.is_scheme("Digest") {
            return Err(AuthError::WrongScheme {
                expected: "Digest",
                found: challenge.scheme.clone(),
            });
        }
        let realm = challenge
            .param("realm")
            .ok_or(AuthError::MissingParam("realm"))?;
        let nonce = challenge
            .param("nonce")
            .ok_or(AuthError::MissingParam("nonce"))?;
        let algorithm = challenge
            .param("algorithm")
            .map_or(Ok(DigestAlgorithm::Md5), DigestAlgorithm::parse)?;
        let qop = match challenge.param("qop") {
            None => Vec::new(),
            Some(list) => {
                let qop: Vec<Qop> = list
                    .split(',')
                    .filter_map(|q| Qop::parse(q.trim()))
                    .collect();
                if qop.is_empty() {
                    return Err(AuthError::UnsupportedQop(list.to_owned()));
                }
                qop
            }
        };
        let flag = |name| {
            challenge
                .param(name)
                .is_some_and(|v| v.eq_ignore_ascii_case("true"))
        };
        Ok(Self {
            realm: realm.to_owned(),
            nonce: nonce.to_owned(),
            opaque: challenge.param("opaque").map(str::to_owned),
            domain: challenge
                .param("domain")
                .map(|d| d.split_whitespace().map(str::to_owned).collect())
                .unwrap_or_default(),
            stale: flag("stale"),
            algorithm,
            qop,
            charset_utf8: challenge
                .param("charset")
                .is_some_and(|c| c.eq_ignore_ascii_case("utf-8")),
            userhash: flag("userhash"),
        })
    }

    /// Computes the `Authorization` response for `username` / `password`.
    /// `auth` is preferred over `auth-int` when both are offered.
    ///
    /// ```
    /// use rune_http_auth::{DigestChallenge, DigestRequest};
    ///
    /// // RFC 7616 §3.9.1, SHA-256.
    /// let challenge = DigestChallenge::parse(
    ///     "Digest realm=\"http-auth@example.org\", qop=\"auth, auth-int\", algorithm=SHA-256, \
    ///      nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\", \
    ///      opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\"",
    /// )
    /// .unwrap();
    /// let request = DigestRequest::new("GET", "/dir/index.html")
    ///     .with_cnonce("f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ");
    /// let response = challenge.respond("Mufasa", "Circle of Life", &request);
    /// assert_eq!(
    ///     response.response,
    ///     "753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1"
    /// );
    /// assert!(response.to_string().starts_with("Digest username=\"Mufasa\""));
    /// ```
    #[must_use]
    pub fn respond(
        &self,
        username: &str,
        password: &str,
        request: &DigestRequest<'_>,
    ) -> DigestResponse {
        let qop = if self.qop.contains(&Qop::Auth) {
            Some(Qop::Auth)
        } else {
            self.qop.first().copied()
        };
        let mut response = DigestResponse {
            username: if self.userhash {
                self.algorithm
                    .hash(format!("{username}:{}", self.realm).as_bytes())
            } else {
                username.to_owned()
            },
            userhash: self.userhash,
            realm: self.realm.clone(),
            nonce: self.nonce.clone(),
            uri: request.uri.to_owned(),
            algorithm: self.algorithm,
            algorithm_sent: true,
            qop,
            nc: qop.map(|_| request.nc),
            cnonce: (qop.is_some() || self.algorithm.is_session())
                .then(|| request.cnonce.to_owned()),
            opaque: self.opaque.clone(),
            response: String::new(),
        };
        response.response = response.compute(username, password, request.method, request.body);
        response
    }
}

impl fmt::Display for DigestChallenge {
    /// The `WWW-Authenticate` value.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut out = String::from("Digest");
        let mut first = true;
        push_param(&mut out, &mut first, "realm", &self.realm, true);
        if !self.domain.is_empty() {
            push_param(&mut out, &mut first, "domain", &self.domain.join(" "), true);
        }
        if !self.qop.is_empty() {
            let qop: Vec<_> = self.qop.iter().map(|q| q.name()).collect();
            push_param(&mut out, &mut first, "qop", &qop.join(", "), true);
        }
        push_param(
            &mut out,
            &mut first,
            "algorithm",
            self.algorithm.name(),
            false,
        );
        push_param(&mut out, &mut first, "nonce", &self.nonce, true);
        if let Some(opaque) = &self.opaque {
            push_param(&mut out, &mut first, "opaque", opaque, true);
        }
        if self.stale {
            push_param(&mut out, &mut first, "stale", "true", false);
        }
        if self.charset_utf8 {
            push_param(&mut out, &mut first, "charset", "UTF-8", false);
        }
        if self.userhash {
            push_param(&mut out, &mut first, "userhash", "true", false);
        }
        f.write_str(&out)
    }
}

/// The per-request inputs of a Digest response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct DigestRequest<'a> {
    /// The request method.
    pub method: &'a str,
    /// The request-target as sent (`/dir/index.html?x=1`).
    pub uri: &'a str,
    /// The body, hashed for `auth-int`.
    pub body: &'a [u8],
    /// The client nonce. Must be unpredictable; the caller generates it.
    pub cnonce: &'a str,
    /// The nonce count: how many requests used this nonce, starting at 1.
    pub nc: u32,
}

impl<'a> DigestRequest<'a> {
    /// Inputs for `method` and `uri`, with an empty body, an empty cnonce
    /// and `nc` 1.
    #[must_use]
    pub const fn new(method: &'a str, uri: &'a str) -> Self {
        Self {
            method,
            uri,
            body: &[],
            cnonce: "",
            nc: 1,
        }
    }

    /// Sets the body (for `auth-int`).
    #[must_use]
    pub const fn with_body(mut self, body: &'a [u8]) -> Self {
        self.body = body;
        self
    }

    /// Sets the client nonce.
    #[must_use]
    pub const fn with_cnonce(mut self, cnonce: &'a str) -> Self {
        self.cnonce = cnonce;
        self
    }

    /// Sets the nonce count.
    #[must_use]
    pub const fn with_nc(mut self, nc: u32) -> Self {
        self.nc = nc;
        self
    }
}

/// A Digest `Authorization` value: built by
/// [`DigestChallenge::respond`], or parsed and verified on the server.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DigestResponse {
    /// The username, or its hash when [`userhash`](Self::userhash) is set.
    pub username: String,
    /// `true` if `username` is `H(username:realm)`.
    pub userhash: bool,
    /// The realm.
    pub realm: String,
    /// The server nonce.
    pub nonce: String,
    /// The request-target.
    pub uri: String,
    /// The hash algorithm.
    pub algorithm: DigestAlgorithm,
    /// `true` if `algorithm` is written out (RFC 2069 responses omit it).
    pub algorithm_sent: bool,
    /// The chosen qop; `None` for the RFC 2069 form.
    pub qop: Option<Qop>,
    /// The nonce count, with a qop.
    pub nc: Option<u32>,
    /// The client nonce, with a qop or a `-sess` algorithm.
    pub cnonce: Option<String>,
    /// The echoed opaque value.
    pub opaque: Option<String>,
    /// The request digest, lowercase hex.
    pub response: String,
}

impl DigestResponse {
    /// Parses an `Authorization: Digest …` value. `username*`
    /// (RFC 8187) is decoded into [`username`](Self::username).
    ///
    /// # Errors
    ///
    /// A syntax error, [`AuthError::WrongScheme`],
    /// [`AuthError::MissingParam`], [`AuthError::UnsupportedAlgorithm`],
    /// [`AuthError::UnsupportedQop`] or [`AuthError::InvalidParam`].
    pub fn parse(header: &str) -> Result<Self, AuthError> {
        let c = Challenge::parse(header)?;
        if !c.is_scheme("Digest") {
            return Err(AuthError::WrongScheme {
                expected: "Digest",
                found: c.scheme,
            });
        }
        let required = |name: &'static str| {
            c.param(name)
                .map(str::to_owned)
                .ok_or(AuthError::MissingParam(name))
        };
        let username = match (c.param("username"), c.param("username*")) {
            (_, Some(ext)) => decode_ext_value(ext).ok_or(AuthError::InvalidParam("username*"))?,
            (Some(plain), None) => plain.to_owned(),
            (None, None) => return Err(AuthError::MissingParam("username")),
        };
        let qop = c
            .param("qop")
            .map(|q| Qop::parse(q).ok_or_else(|| AuthError::UnsupportedQop(q.to_owned())))
            .transpose()?;
        let nc = c
            .param("nc")
            .map(|nc| {
                (nc.len() == 8)
                    .then(|| u32::from_str_radix(nc, 16).ok())
                    .flatten()
                    .ok_or(AuthError::InvalidParam("nc"))
            })
            .transpose()?;
        if qop.is_some() && (nc.is_none() || c.param("cnonce").is_none()) {
            return Err(AuthError::MissingParam(if nc.is_none() {
                "nc"
            } else {
                "cnonce"
            }));
        }
        Ok(Self {
            username,
            userhash: c
                .param("userhash")
                .is_some_and(|v| v.eq_ignore_ascii_case("true")),
            realm: required("realm")?,
            nonce: required("nonce")?,
            uri: required("uri")?,
            algorithm: c
                .param("algorithm")
                .map_or(Ok(DigestAlgorithm::Md5), DigestAlgorithm::parse)?,
            algorithm_sent: c.param("algorithm").is_some(),
            qop,
            nc,
            cnonce: c.param("cnonce").map(str::to_owned),
            opaque: c.param("opaque").map(str::to_owned),
            response: required("response")?,
        })
    }

    /// Server side: `true` if this response was computed with `username`
    /// and `password` for a request with `method` and `body` (the body
    /// matters for `auth-int` only). The digest is compared in constant
    /// time. Checking that the nonce is one the server issued, is fresh,
    /// and that `nc` increases is the caller's job, as is checking that
    /// [`uri`](Self::uri) matches the request-target.
    ///
    /// ```
    /// use rune_http_auth::DigestResponse;
    ///
    /// // RFC 2617 §3.5.
    /// let response = DigestResponse::parse(
    ///     "Digest username=\"Mufasa\", realm=\"testrealm@host.com\", \
    ///      nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", uri=\"/dir/index.html\", \
    ///      qop=auth, nc=00000001, cnonce=\"0a4f113b\", \
    ///      response=\"6629fae49393a05397450978507c4ef1\", \
    ///      opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"",
    /// )
    /// .unwrap();
    /// assert!(response.verify("Mufasa", "Circle Of Life", "GET", b""));
    /// assert!(!response.verify("Mufasa", "circle of life", "GET", b""));
    /// ```
    #[must_use]
    pub fn verify(&self, username: &str, password: &str, method: &str, body: &[u8]) -> bool {
        let expected_user = if self.userhash {
            self.algorithm
                .hash(format!("{username}:{}", self.realm).as_bytes())
        } else {
            username.to_owned()
        };
        let user_ok = constant_time_eq(expected_user.as_bytes(), self.username.as_bytes());
        let expected = self.compute(username, password, method, body);
        let digest_ok = constant_time_eq(
            expected.as_bytes(),
            self.response.to_ascii_lowercase().as_bytes(),
        );
        user_ok & digest_ok
    }

    /// The request digest of RFC 7616 §3.4.1 for these parameters.
    fn compute(&self, username: &str, password: &str, method: &str, body: &[u8]) -> String {
        let alg = self.algorithm;
        let cnonce = self.cnonce.as_deref().unwrap_or_default();
        let mut ha1 = alg.hash(format!("{username}:{}:{password}", self.realm).as_bytes());
        if alg.is_session() {
            ha1 = alg.hash(format!("{ha1}:{}:{cnonce}", self.nonce).as_bytes());
        }
        let ha2 = match self.qop {
            Some(Qop::AuthInt) => {
                alg.hash(format!("{method}:{}:{}", self.uri, alg.hash(body)).as_bytes())
            }
            _ => alg.hash(format!("{method}:{}", self.uri).as_bytes()),
        };
        let data = self.qop.map_or_else(
            || format!("{ha1}:{}:{ha2}", self.nonce),
            |qop| {
                format!(
                    "{ha1}:{}:{:08x}:{cnonce}:{}:{ha2}",
                    self.nonce,
                    self.nc.unwrap_or(1),
                    qop.name()
                )
            },
        );
        alg.hash(data.as_bytes())
    }
}

impl fmt::Display for DigestResponse {
    /// The `Authorization` value, quoting exactly the parameters RFC 7616
    /// §3.4 quotes. A username that a quoted string cannot carry as ASCII
    /// is sent as `username*=UTF-8''…` (RFC 7616 §3.4.4).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut out = String::from("Digest");
        let mut first = true;
        let plain_ascii = self
            .username
            .chars()
            .all(|c| c == ' ' || c == '\t' || c.is_ascii_graphic());
        if plain_ascii {
            push_param(&mut out, &mut first, "username", &self.username, true);
        } else {
            push_param(
                &mut out,
                &mut first,
                "username*",
                &encode_ext_value(&self.username),
                false,
            );
        }
        push_param(&mut out, &mut first, "realm", &self.realm, true);
        push_param(&mut out, &mut first, "uri", &self.uri, true);
        if self.algorithm_sent {
            push_param(
                &mut out,
                &mut first,
                "algorithm",
                self.algorithm.name(),
                false,
            );
        }
        push_param(&mut out, &mut first, "nonce", &self.nonce, true);
        // A qop requires nc and cnonce; without one they are written only
        // when present (cnonce for `-sess`).
        if let Some(nc) = self.nc.or_else(|| self.qop.map(|_| 1)) {
            push_param(&mut out, &mut first, "nc", &format!("{nc:08x}"), false);
        }
        if let Some(cnonce) = self.cnonce.as_deref().or_else(|| self.qop.map(|_| "")) {
            push_param(&mut out, &mut first, "cnonce", cnonce, true);
        }
        if let Some(qop) = self.qop {
            push_param(&mut out, &mut first, "qop", qop.name(), false);
        }
        push_param(&mut out, &mut first, "response", &self.response, true);
        if let Some(opaque) = &self.opaque {
            push_param(&mut out, &mut first, "opaque", opaque, true);
        }
        if self.userhash {
            push_param(&mut out, &mut first, "userhash", "true", false);
        }
        f.write_str(&out)
    }
}

/// `UTF-8''` + percent-encoding of every byte outside RFC 8187 `attr-char`.
fn encode_ext_value(value: &str) -> String {
    use fmt::Write as _;
    let mut out = String::from("UTF-8''");
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'!' | b'#' | b'$' | b'&' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
            )
        {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

/// Decodes an RFC 8187 `ext-value` in UTF-8.
fn decode_ext_value(value: &str) -> Option<String> {
    let mut pieces = value.splitn(3, '\'');
    let charset = pieces.next()?;
    let _language = pieces.next()?;
    let encoded = pieces.next()?;
    if !charset.eq_ignore_ascii_case("utf-8") {
        return None;
    }
    let bytes = encoded.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&byte) = bytes.get(i) {
        if byte == b'%' {
            let hex = encoded.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(byte);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONCE: &str = "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v";
    const CNONCE: &str = "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ";
    const OPAQUE: &str = "FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS";

    fn rfc7616_challenge(algorithm: &str) -> DigestChallenge {
        DigestChallenge::parse(&format!(
            "Digest realm=\"http-auth@example.org\", qop=\"auth, auth-int\", \
             algorithm={algorithm}, nonce=\"{NONCE}\", opaque=\"{OPAQUE}\""
        ))
        .unwrap()
    }

    #[test]
    fn rfc7616_md5_and_sha256() {
        let request = DigestRequest::new("GET", "/dir/index.html").with_cnonce(CNONCE);
        for (algorithm, expected) in [
            ("MD5", "8ca523f5e9506fed4657c9700eebdbec"),
            (
                "SHA-256",
                "753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1",
            ),
        ] {
            let challenge = rfc7616_challenge(algorithm);
            assert_eq!(challenge.qop, [Qop::Auth, Qop::AuthInt]);
            let response = challenge.respond("Mufasa", "Circle of Life", &request);
            assert_eq!(response.response, expected, "{algorithm}");
            let header = response.to_string();
            assert!(header.contains("nc=00000001, cnonce=\""), "{header}");
            assert!(
                header.contains(&format!("algorithm={algorithm},")),
                "{header}"
            );
            let parsed = DigestResponse::parse(&header).unwrap();
            assert_eq!(parsed, response);
            assert!(parsed.verify("Mufasa", "Circle of Life", "GET", b""));
            assert!(!parsed.verify("Mufasa", "Circle of Life", "POST", b""));
            assert!(!parsed.verify("mufasa", "Circle of Life", "GET", b""));
        }
    }

    /// RFC 7616 §3.9.2 inputs (SHA-512-256, userhash, non-ASCII username).
    /// Expected values are computed per §3.4; the RFC's printed values for
    /// this example are known to be inconsistent (errata).
    #[test]
    fn rfc7616_sha512_256_userhash() {
        let challenge = DigestChallenge::parse(
            "Digest realm=\"api@example.org\", qop=\"auth\", algorithm=SHA-512-256, \
             nonce=\"5TsQWLVdgBdmrQ0XsxbDODV+57QdFR34I9HAbC/RVvkK\", \
             opaque=\"HRPCssKJSGjCrkzDg8OhwpzCiGPChXYjwrI2QmXDnsOS\", charset=UTF-8, userhash=true",
        )
        .unwrap();
        assert!(challenge.userhash && challenge.charset_utf8);
        let request = DigestRequest::new("GET", "/doe.json")
            .with_cnonce("NTg6RKcb9boFIAS3KrFK9BGeh+iDa/sm6jUMp2wds69v");
        let response = challenge.respond("J\u{e4}s\u{f8}n Doe", "Secret, or not?", &request);
        assert_eq!(
            response.username,
            "793263caabb707a56211940d90411ea4a575adeccb7e360aeb624ed06ece9b0b"
        );
        assert_eq!(
            response.response,
            "3798d4131c277846293534c3edc11bd8a5e4cdcbff78b05db9d95eeb1cec68a5"
        );
        let parsed = DigestResponse::parse(&response.to_string()).unwrap();
        assert!(parsed.verify("J\u{e4}s\u{f8}n Doe", "Secret, or not?", "GET", b""));
    }

    #[test]
    fn non_ascii_username_uses_ext_value() {
        let challenge = DigestChallenge::new("r", "n");
        let request = DigestRequest::new("GET", "/").with_cnonce("c");
        let response = challenge.respond("J\u{e4}s\u{f8}n", "pw", &request);
        let header = response.to_string();
        assert!(
            header.contains("username*=UTF-8''J%C3%A4s%C3%B8n"),
            "{header}"
        );
        let parsed = DigestResponse::parse(&header).unwrap();
        assert_eq!(parsed.username, "J\u{e4}s\u{f8}n");
        assert!(parsed.verify("J\u{e4}s\u{f8}n", "pw", "GET", b""));
    }

    #[test]
    fn auth_int_sess_and_legacy() {
        let mut challenge = DigestChallenge::new("r", "n");
        challenge.qop = vec![Qop::AuthInt];
        challenge.algorithm = DigestAlgorithm::Sha256Sess;
        let request = DigestRequest::new("POST", "/x")
            .with_body(b"payload")
            .with_cnonce("c")
            .with_nc(7);
        let response = challenge.respond("u", "p", &request);
        assert_eq!(response.qop, Some(Qop::AuthInt));
        let parsed = DigestResponse::parse(&response.to_string()).unwrap();
        assert_eq!(parsed.nc, Some(7));
        assert!(parsed.verify("u", "p", "POST", b"payload"));
        assert!(!parsed.verify("u", "p", "POST", b"tampered"));

        // RFC 2069: no qop, response = H(HA1:nonce:HA2).
        let legacy = DigestChallenge::parse("Digest realm=\"r\", nonce=\"n\"").unwrap();
        let response = legacy.respond("u", "p", &DigestRequest::new("GET", "/"));
        let ha1 = rune_md5::hash_bytes(b"u:r:p");
        let ha2 = rune_md5::hash_bytes(b"GET:/");
        assert_eq!(
            response.response,
            rune_md5::hash_bytes(format!("{ha1}:n:{ha2}").as_bytes())
        );
        assert!(!response.to_string().contains("qop"));
    }

    #[test]
    fn challenge_round_trip_and_errors() {
        let mut challenge = rfc7616_challenge("SHA-512-256-sess");
        challenge.domain = vec!["/a".into(), "/b".into()];
        challenge.stale = true;
        assert_eq!(
            DigestChallenge::parse(&challenge.to_string()).unwrap(),
            challenge
        );

        assert_eq!(
            DigestChallenge::parse("Digest nonce=\"n\""),
            Err(AuthError::MissingParam("realm"))
        );
        assert!(matches!(
            DigestChallenge::parse("Digest realm=r, nonce=n, algorithm=SHA-1"),
            Err(AuthError::UnsupportedAlgorithm(_))
        ));
        assert!(matches!(
            DigestChallenge::parse("Digest realm=r, nonce=n, qop=\"auth-conf\""),
            Err(AuthError::UnsupportedQop(_))
        ));
        assert!(matches!(
            DigestChallenge::parse("Basic realm=r"),
            Err(AuthError::WrongScheme { .. })
        ));
        assert_eq!(
            DigestResponse::parse(
                "Digest username=u, realm=r, nonce=n, uri=\"/\", qop=auth, nc=1, cnonce=c, response=x"
            ),
            Err(AuthError::InvalidParam("nc"))
        );
    }
}
