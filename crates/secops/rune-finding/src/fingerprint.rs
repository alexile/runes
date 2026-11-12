//! The stable finding fingerprint.

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

use crate::Location;

/// Domain-separation prefix of the v1 algorithm. Never changed, so stored
/// fingerprints stay valid.
const PREFIX_V1: &[u8] = b"netsec-fingerprint/v1";

/// The fingerprint of a check id at a location. See
/// [`Finding::fingerprint`](crate::Finding::fingerprint).
pub fn fingerprint(check_id: &str, location: &Location) -> String {
    let (location, parameter) = normalize_location(location);
    let mut hasher = Sha256::new();
    hasher.update(PREFIX_V1);
    for part in [check_id, &location, &parameter] {
        hasher.update([0x1F]);
        hasher.update(part.as_bytes());
    }
    hex_lower(&hasher.finalize())
}

/// The normalized location and parameter that enter the fingerprint.
fn normalize_location(location: &Location) -> (String, String) {
    match location {
        Location::Url { url, parameter } => {
            (normalize_url(url), parameter.clone().unwrap_or_default())
        }
        Location::Network { host, port } => (
            format!("tcp://{}:{port}", host.to_ascii_lowercase()),
            String::new(),
        ),
        Location::File {
            path, start_line, ..
        } => (
            start_line.map_or_else(
                || format!("file:{path}"),
                |line| format!("file:{path}:{line}"),
            ),
            String::new(),
        ),
        Location::ClusterObject {
            namespace,
            kind,
            name,
        } => (format!("k8s://{namespace}/{kind}/{name}"), String::new()),
        Location::Artifact { path, offset } => (
            offset.map_or_else(
                || format!("artifact:{path}"),
                |offset| format!("artifact:{path}@{offset:#x}"),
            ),
            String::new(),
        ),
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0F)]));
    }
    out
}

/// Normalize a URL for the fingerprint.
pub fn normalize_url(raw: &str) -> String {
    let trimmed = raw.trim();
    if let Ok(url) = url::Url::parse(trimmed)
        && let Some(host) = url.host_str()
    {
        // `Url::port` is `None` when the port is the scheme's default.
        let port = url
            .port()
            .map(|port| format!(":{port}"))
            .unwrap_or_default();
        let prefix = format!(
            "{}://{}{port}",
            url.scheme().to_ascii_lowercase(),
            host.to_ascii_lowercase()
        );
        let keys: BTreeSet<String> = url
            .query_pairs()
            .map(|(key, _)| key.into_owned())
            .filter(|key| !key.is_empty())
            .collect();
        return assemble(&prefix, url.path(), &keys);
    }

    let without_fragment = trimmed.split('#').next().unwrap_or_default();
    let (path, query) = without_fragment
        .split_once('?')
        .unwrap_or((without_fragment, ""));
    // Decode keys exactly as `Url::query_pairs` does on the parseable path,
    // so `a%62=1` and `ab=1` normalize alike either way.
    let keys: BTreeSet<String> = url::form_urlencoded::parse(query.as_bytes())
        .map(|(key, _)| key.into_owned())
        .filter(|key| !key.is_empty())
        .collect();
    assemble("", path, &keys)
}

fn assemble(prefix: &str, path: &str, keys: &BTreeSet<String>) -> String {
    let path = path
        .split('/')
        .map(normalize_segment)
        .collect::<Vec<_>>()
        .join("/");
    let mut out = format!("{prefix}{}", path.trim_end_matches('/'));
    if !keys.is_empty() {
        out.push('?');
        out.push_str(
            &keys
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join("&"),
        );
    }
    out
}

fn normalize_segment(segment: &str) -> &str {
    if !segment.is_empty() && segment.bytes().all(|byte| byte.is_ascii_digit()) {
        "{id}"
    } else if is_uuid(segment) {
        "{uuid}"
    } else {
        segment
    }
}

fn is_uuid(segment: &str) -> bool {
    let bytes = segment.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                *byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_urls() {
        assert_eq!(
            normalize_url("HTTPS://Example.TEST:443/users/42/?b=2&a=1&b=3#frag"),
            "https://example.test/users/{id}?a&b"
        );
        assert_eq!(
            normalize_url("http://example.test:8080/o/123e4567-E89B-12d3-a456-426614174000/"),
            "http://example.test:8080/o/{uuid}"
        );
        assert_eq!(
            normalize_url("https://example.test/"),
            "https://example.test"
        );
        assert_eq!(normalize_url("/api/7?x=1#f"), "/api/{id}?x");
        assert_eq!(normalize_url("/search?a%62=1"), "/search?ab");
        assert_eq!(
            normalize_url("mailto:x@example.test"),
            "mailto:x@example.test"
        );
    }

    #[test]
    fn normalizes_other_locations() {
        let cases = [
            (
                Location::network("Example.TEST", 443),
                "tcp://example.test:443",
            ),
            (Location::file("src/a.rs"), "file:src/a.rs"),
            (
                Location::file("src/a.rs")
                    .with_lines(7, 9)
                    .with_columns(1, 2),
                "file:src/a.rs:7",
            ),
            (
                Location::cluster_object("prod", "Ingress", "web"),
                "k8s://prod/Ingress/web",
            ),
            (Location::artifact("bin/app", None), "artifact:bin/app"),
            (
                Location::artifact("bin/app", Some(4096)),
                "artifact:bin/app@0x1000",
            ),
        ];
        for (location, expected) in cases {
            assert_eq!(
                normalize_location(&location),
                (expected.to_owned(), String::new())
            );
        }
    }

    /// Pins the v1 algorithm to a known value:
    /// sha256("netsec-fingerprint/v1\x1fxss.reflected\x1fhttps://example.test/api/users/{id}?a&b\x1fq").
    #[test]
    fn golden_value() {
        let location =
            Location::url("https://Example.test/api/users/42/?b=2&a=1#x").with_parameter("q");
        assert_eq!(
            fingerprint("xss.reflected", &location),
            "2849606b401e41664ae7e34af3346a93943b8e3f34db93f9446c60d6261750b1"
        );
    }
}
