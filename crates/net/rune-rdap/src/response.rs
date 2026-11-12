//! Interpreting HTTP responses from RDAP servers, sans I/O
//! ([RFC 7480 §5](https://www.rfc-editor.org/rfc/rfc7480#section-5)).

use std::time::Duration;

use serde::Deserialize;

use crate::Error;
use crate::model::{Autnum, Domain, Entity, ErrorResponse, IpNetwork, Nameserver, Object};

/// Largest RDAP response body accepted by [`interpret`].
pub const MAX_BODY_LEN: usize = 4 * 1024 * 1024;

/// An HTTP response as received: status, headers and body.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Response {
    /// The status code.
    pub status: u16,
    /// Header names and values, in order.
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: Vec<u8>,
}

impl Response {
    /// A response with no headers.
    #[must_use]
    pub fn new(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: body.into(),
        }
    }

    /// Adds a header.
    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// The first value of header `name` (case-insensitive).
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// How long the response may be cached, from `Cache-Control`:
    /// `Some(ZERO)` for `no-store` / `no-cache` / `private`, `Some(max-age)`
    /// when given, `None` when the header says nothing.
    #[must_use]
    pub fn max_age(&self) -> Option<Duration> {
        let mut max_age = None;
        for (name, value) in &self.headers {
            if !name.eq_ignore_ascii_case("cache-control") {
                continue;
            }
            for directive in value.split(',') {
                let directive = directive.trim();
                let (key, arg) = directive.split_once('=').unwrap_or((directive, ""));
                let key = key.trim().to_ascii_lowercase();
                match key.as_str() {
                    "no-store" | "no-cache" | "private" => return Some(Duration::ZERO),
                    "max-age" | "s-maxage" if max_age.is_none() => {
                        max_age = arg
                            .trim()
                            .trim_matches('"')
                            .parse::<u64>()
                            .ok()
                            .map(Duration::from_secs);
                    }
                    _ => {}
                }
            }
        }
        max_age
    }

    /// The `Retry-After` delay, when given in seconds.
    #[must_use]
    pub fn retry_after(&self) -> Option<Duration> {
        self.header("retry-after")?
            .trim()
            .parse::<u64>()
            .ok()
            .map(Duration::from_secs)
    }
}

/// What a response means for the lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Outcome {
    /// The object asked for.
    Object(Object),
    /// Ask again at this URL (absolute or relative, as sent).
    Redirect(String),
}

/// Classifies a response as an object, a redirect or an [`Error`].
///
/// Redirects are 301, 302, 303, 307 and 308 with a `Location`. 404 is
/// [`Error::NotFound`], 429 is [`Error::RateLimited`], and other failures
/// are [`Error::Server`] with the RDAP error body when there is one.
///
/// ```
/// use rune_rdap::response::{Outcome, Response, interpret};
///
/// let r = Response::new(303, "").with_header("Location", "https://rdap.db.ripe.example/ip/193.0.6.139");
/// assert_eq!(
///     interpret(&r)?,
///     Outcome::Redirect("https://rdap.db.ripe.example/ip/193.0.6.139".into())
/// );
/// let r = Response::new(200, r#"{"objectClassName":"autnum","handle":"AS64496","startAutnum":64496}"#);
/// let Outcome::Object(obj) = interpret(&r)? else { unreachable!() };
/// assert_eq!(obj.as_autnum().unwrap().start_autnum, Some(64496));
/// # Ok::<(), rune_rdap::Error>(())
/// ```
pub fn interpret(response: &Response) -> Result<Outcome, Error> {
    match response.status {
        200..=299 => parse_object(&response.body).map(Outcome::Object),
        301 | 302 | 303 | 307 | 308 => response
            .header("location")
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(|l| Outcome::Redirect(l.to_owned()))
            .ok_or_else(|| Error::Redirect(format!("{} without Location", response.status))),
        404 => Err(Error::NotFound),
        429 => Err(Error::RateLimited {
            retry_after: response.retry_after(),
        }),
        status => {
            let body = (response.body.len() <= MAX_BODY_LEN)
                .then(|| serde_json::from_slice::<ErrorResponse>(&response.body).ok())
                .flatten()
                .unwrap_or_default();
            Err(Error::Server {
                status,
                error_code: body.error_code,
                title: body.title,
                description: body.description,
            })
        }
    }
}

#[derive(Deserialize)]
struct ClassName {
    #[serde(rename = "objectClassName")]
    class: Option<String>,
}

/// Parses an RDAP object body, dispatching on `objectClassName`.
///
/// ```
/// use rune_rdap::{Object, parse_object};
///
/// let obj = parse_object(br#"{"objectClassName":"nameserver","ldhName":"NS1.EXAMPLE.NET"}"#)?;
/// assert_eq!(obj.as_nameserver().unwrap().name(), Some("NS1.EXAMPLE.NET"));
/// assert!(parse_object(br#"{"errorCode":400}"#).is_err());
/// # Ok::<(), rune_rdap::Error>(())
/// ```
pub fn parse_object(body: &[u8]) -> Result<Object, Error> {
    if body.len() > MAX_BODY_LEN {
        return Err(Error::TooLarge {
            limit: MAX_BODY_LEN,
        });
    }
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| Error::InvalidResponse(e.to_string()))?;
    let ClassName { class } =
        ClassName::deserialize(&value).map_err(|e| Error::InvalidResponse(e.to_string()))?;
    let class = class
        .ok_or_else(|| Error::InvalidResponse("missing objectClassName".into()))?
        .to_ascii_lowercase();
    let bad = |e: serde_json::Error| Error::InvalidResponse(e.to_string());
    Ok(match class.as_str() {
        "domain" => Object::Domain(Box::new(Domain::deserialize(&value).map_err(bad)?)),
        "ip network" => Object::IpNetwork(Box::new(IpNetwork::deserialize(&value).map_err(bad)?)),
        "autnum" => Object::Autnum(Box::new(Autnum::deserialize(&value).map_err(bad)?)),
        "nameserver" => Object::Nameserver(Box::new(Nameserver::deserialize(&value).map_err(bad)?)),
        "entity" => Object::Entity(Box::new(Entity::deserialize(&value).map_err(bad)?)),
        other => {
            return Err(Error::InvalidResponse(format!(
                "unsupported objectClassName {other:?}"
            )));
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_control() {
        let r = |v: &str| Response::new(200, "").with_header("Cache-Control", v);
        assert_eq!(
            r("public, max-age=600").max_age(),
            Some(Duration::from_secs(600))
        );
        assert_eq!(r("max-age=\"60\"").max_age(), Some(Duration::from_secs(60)));
        assert_eq!(r("max-age=60, no-store").max_age(), Some(Duration::ZERO));
        assert_eq!(r("public").max_age(), None);
        assert_eq!(Response::new(200, "").max_age(), None);
    }

    #[test]
    fn statuses() {
        assert!(matches!(
            interpret(&Response::new(404, "")),
            Err(Error::NotFound)
        ));
        let limited = Response::new(429, "").with_header("Retry-After", " 7 ");
        assert!(matches!(
            interpret(&limited),
            Err(Error::RateLimited { retry_after: Some(d) }) if d == Duration::from_secs(7)
        ));
        let dated =
            Response::new(429, "").with_header("Retry-After", "Wed, 21 Oct 2015 07:28:00 GMT");
        assert!(matches!(
            interpret(&dated),
            Err(Error::RateLimited { retry_after: None })
        ));
        assert!(matches!(
            interpret(&Response::new(302, "")),
            Err(Error::Redirect(_))
        ));
        match interpret(&Response::new(500, "<html>oops</html>")) {
            Err(Error::Server {
                status: 500,
                error_code: None,
                ..
            }) => {}
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn rejects_bad_bodies() {
        for body in [
            &b""[..],
            b"[]",
            b"{}",
            br#"{"objectClassName":7}"#,
            br#"{"objectClassName":"help"}"#,
            br#"{"objectClassName":"autnum","startAutnum":"x"}"#,
        ] {
            assert!(
                parse_object(body).is_err(),
                "{}",
                String::from_utf8_lossy(body)
            );
        }
        let big = vec![b' '; MAX_BODY_LEN + 1];
        assert!(matches!(parse_object(&big), Err(Error::TooLarge { .. })));
    }
}
