//! The [`ReputationProvider`] trait and helpers shared by the adapters.

// With only some adapters enabled, some shared helpers go unused.
#![cfg_attr(
    not(all(
        feature = "abuseipdb",
        feature = "greynoise",
        feature = "shodan",
        feature = "censys"
    )),
    allow(dead_code, reason = "helpers shared by the optional adapters")
)]

use std::net::IpAddr;

use serde_json::Value;

use crate::http::{HttpRequest, HttpResponse, Transport};
use crate::{Classification, Error, Verdict};

/// A source of IP reputation, split into a sans-I/O request builder and a
/// response parser so it works with any HTTP client, sync or async.
///
/// [`check`](Self::check) runs both around a [`Transport`]. Implement the
/// trait for your own feeds to put them behind the same interface.
pub trait ReputationProvider {
    /// Short, stable provider name (`abuseipdb`, `greynoise`, ...).
    fn name(&self) -> &'static str;

    /// Builds the request that looks `ip` up.
    fn request(&self, ip: IpAddr) -> HttpRequest;

    /// Reads the provider's answer to [`request`](Self::request).
    ///
    /// # Errors
    ///
    /// [`Error::Auth`], [`Error::RateLimited`], [`Error::Status`] or
    /// [`Error::InvalidResponse`] when the answer is not a result.
    fn parse(&self, ip: IpAddr, response: &HttpResponse) -> Result<Verdict, Error>;

    /// Looks `ip` up through `transport`.
    ///
    /// # Errors
    ///
    /// [`Error::Transport`] when no response arrived, plus those of
    /// [`parse`](Self::parse).
    fn check(&self, ip: IpAddr, transport: &dyn Transport) -> Result<Verdict, Error> {
        let response = transport.send(&self.request(ip))?;
        self.parse(ip, &response)
    }
}

/// Tags that make an address malicious.
pub const MALICIOUS_TAGS: [&str; 4] = ["c2", "malware", "compromised", "botnet"];
/// Tags that make an address suspicious.
pub const SUSPICIOUS_TAGS: [&str; 3] = ["tor", "proxy", "scanner"];

/// Classifies by tags: [`MALICIOUS_TAGS`], then [`SUSPICIOUS_TAGS`].
pub fn classify_tags(tags: &[String]) -> Classification {
    let has = |set: &[&str]| {
        tags.iter()
            .any(|t| set.contains(&t.to_ascii_lowercase().as_str()))
    };
    if has(&MALICIOUS_TAGS) {
        Classification::Malicious
    } else if has(&SUSPICIOUS_TAGS) {
        Classification::Suspicious
    } else {
        Classification::Unknown
    }
}

/// Longest provider message kept in an [`Error::Status`].
const MESSAGE_LIMIT: usize = 200;

/// The start of a body as text, for error messages.
pub fn snippet(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    let mut end = text.len().min(MESSAGE_LIMIT);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].trim().to_owned()
}

/// Maps the statuses every provider shares onto errors. Returns `Ok` for
/// 2xx and for 404 when `not_found_is_answer` (the provider has no data).
pub fn check_status(
    provider: &'static str,
    response: &HttpResponse,
    not_found_is_answer: bool,
) -> Result<(), Error> {
    match response.status {
        200..=299 => Ok(()),
        404 if not_found_is_answer => Ok(()),
        401 | 403 => Err(Error::Auth {
            provider,
            status: response.status,
        }),
        429 => Err(Error::RateLimited {
            provider,
            retry_after: response.retry_after(),
        }),
        status => Err(Error::Status {
            provider,
            status,
            message: snippet(&response.body),
        }),
    }
}

/// Parses a JSON body.
pub fn json(provider: &'static str, response: &HttpResponse) -> Result<Value, Error> {
    serde_json::from_slice(&response.body).map_err(|e| Error::InvalidResponse {
        provider,
        reason: format!("body is not JSON: {e}"),
    })
}

/// The string items of a JSON array (others skipped).
pub fn strings(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// A JSON string field, when non-empty.
pub fn string(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

/// Parses the timestamps providers send (`2024-01-15`,
/// `2024-01-15T14:30:00Z`, `2024-01-15T14:30:00.123+02:00`) into Unix
/// seconds, applying the offset.
pub fn parse_time(text: &str) -> Option<i64> {
    let text = text.trim();
    let date = text.get(..10)?;
    let rest = &text[10..];
    if rest.is_empty() {
        return rune_epoch::from_utc_string(&format!("{date}T00:00:00Z")).ok();
    }
    if !rest.starts_with(['T', 't', ' ']) {
        return None;
    }
    let time = rest.get(1..9)?;
    let mut tail = &rest[9..];
    if let Some(fraction) = tail.strip_prefix('.') {
        let digits = fraction.bytes().take_while(u8::is_ascii_digit).count();
        tail = &fraction[digits..];
    }
    let offset = match tail {
        "" | "Z" | "z" => 0,
        _ => {
            let sign = match tail.as_bytes().first()? {
                b'+' => 1,
                b'-' => -1,
                _ => return None,
            };
            let (h, m) = tail.get(1..)?.split_once(':')?;
            let (h, m) = (h.parse::<i64>().ok()?, m.parse::<i64>().ok()?);
            if h > 23 || m > 59 {
                return None;
            }
            sign * (h * 3600 + m * 60)
        }
    };
    let utc = rune_epoch::from_utc_string(&format!("{date}T{time}Z")).ok()?;
    Some(utc - offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_provider_timestamps() {
        assert_eq!(parse_time("2024-01-01"), Some(1_704_067_200));
        assert_eq!(parse_time("2024-01-01T00:00:00Z"), Some(1_704_067_200));
        assert_eq!(
            parse_time("2024-01-01T00:00:00.123456Z"),
            Some(1_704_067_200)
        );
        assert_eq!(parse_time("2024-01-01T02:00:00+02:00"), Some(1_704_067_200));
        assert_eq!(parse_time("2023-12-31T23:00:00-01:00"), Some(1_704_067_200));
        assert_eq!(parse_time("2024-01-01T00:00:00"), Some(1_704_067_200));
        for bad in [
            "",
            "2024",
            "2024-01-01X",
            "2024-01-01T00:00",
            "2024-01-01T00:00:00+2",
            "é2024-01-01",
        ] {
            assert_eq!(parse_time(bad), None, "{bad}");
        }
    }

    #[test]
    fn maps_shared_statuses() {
        let ok = HttpResponse::new(200);
        assert!(check_status("p", &ok, false).is_ok());
        assert!(check_status("p", &HttpResponse::new(404), true).is_ok());
        assert!(matches!(
            check_status("p", &HttpResponse::new(404), false),
            Err(Error::Status { status: 404, .. })
        ));
        assert_eq!(
            check_status("p", &HttpResponse::new(403), false),
            Err(Error::Auth {
                provider: "p",
                status: 403
            })
        );
        let limited = HttpResponse::new(429).with_header("Retry-After", "30");
        assert_eq!(
            check_status("p", &limited, false),
            Err(Error::RateLimited {
                provider: "p",
                retry_after: Some(std::time::Duration::from_secs(30))
            })
        );
        let long = HttpResponse::new(500).with_body("é".repeat(300));
        let Err(Error::Status { message, .. }) = check_status("p", &long, false) else {
            panic!("not a status error");
        };
        assert!(message.len() <= MESSAGE_LIMIT);
    }
}
