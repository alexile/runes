//! Security-focused regex patterns for detecting secrets, credentials, and PII.
//!
//! A curated library of compiled regular expressions for finding security-relevant
//! text: IP addresses, CVE identifiers, hash digests, API keys, AWS credentials,
//! JWT tokens, private keys, email addresses, and more. All patterns are compiled
//! once at startup via [`std::sync::OnceLock`] and reused.
//!
//! # Categories
//!
//! | Module / function | Detects |
//! |---|---|
//! | [`match_ipv4`] | IPv4 addresses |
//! | [`match_ipv6`] | IPv6 addresses |
//! | [`match_cve`] | CVE identifiers (`CVE-YYYY-NNNN`) |
//! | [`match_md5`] | 32-char hex (MD5-like digests) |
//! | [`match_sha256`] | 64-char hex (SHA-256-like digests) |
//! | [`match_sha1`] | 40-char hex (SHA-1-like digests) |
//! | [`match_jwt`] | JSON Web Tokens |
//! | [`match_aws_key`] | AWS access key IDs |
//! | [`match_private_key`] | PEM private key blocks |
//! | [`match_email`] | Email addresses |
//! | [`match_url`] | HTTP/HTTPS URLs |
//! | [`match_uuid`] | UUID v4 |
//! | [`match_base64_secret`] | Long Base64-looking strings (≥40 chars) |
//! | [`scan`] | Run all patterns on a text block |
//!
//! # Quick Start
//!
//! ```rust
//! use rune_regex_sec::{match_ipv4, match_cve, scan};
//!
//! let text = "Found CVE-2024-1234 at 192.168.1.1";
//!
//! let ips = match_ipv4(text);
//! assert_eq!(ips, vec!["192.168.1.1"]);
//!
//! let cves = match_cve(text);
//! assert_eq!(cves, vec!["CVE-2024-1234"]);
//!
//! let findings = scan(text);
//! assert!(!findings.is_empty());
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-regex-sec file.txt          # scan a file
//! cat config.env | rune-regex-sec - # scan stdin
//! ```

use regex::Regex;
use std::sync::OnceLock;

/// Defines a lazily compiled pattern accessor.
///
/// Every pattern is a literal in this file and the `all_patterns_compile`
/// test proves it valid, so `None` is unreachable in practice. Returning it
/// instead of panicking keeps the library panic-free.
macro_rules! pattern {
    ($name:ident, $re:expr) => {
        fn $name() -> Option<&'static Regex> {
            static RE: OnceLock<Option<Regex>> = OnceLock::new();
            RE.get_or_init(|| Regex::new($re).ok()).as_ref()
        }
    };
}

pattern!(
    re_ipv4,
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
);
pattern!(
    re_ipv6,
    r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}"
);
pattern!(re_cve, r"\bCVE-\d{4}-\d{4,7}\b");
pattern!(re_md5, r"\b[0-9a-fA-F]{32}\b");
pattern!(re_sha1, r"\b[0-9a-fA-F]{40}\b");
pattern!(re_sha256, r"\b[0-9a-fA-F]{64}\b");
pattern!(
    re_jwt,
    r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*\b"
);
pattern!(re_aws_key, r"\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b");
pattern!(
    re_private_key,
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
);
pattern!(
    re_email,
    r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"
);
pattern!(re_url, r#"\bhttps?://[^\s"'<>]+"#);
pattern!(
    re_uuid,
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b"
);
pattern!(re_base64_secret, r"\b[A-Za-z0-9+/]{40,}={0,2}\b");

/// A single match found by [`scan`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The category of the detected pattern (e.g. `"ipv4"`, `"cve"`, `"jwt"`).
    pub category: &'static str,
    /// The matched text.
    pub value: String,
}

fn all_matches<'a>(re: Option<&Regex>, text: &'a str) -> Vec<&'a str> {
    re.map_or_else(Vec::new, |re| {
        re.find_iter(text).map(|m| m.as_str()).collect()
    })
}

/// Finds all IPv4 addresses in `text`.
///
/// # Examples
///
/// ```rust
/// use rune_regex_sec::match_ipv4;
///
/// let hits = match_ipv4("server at 10.0.0.1 and 192.168.1.100");
/// assert_eq!(hits, vec!["10.0.0.1", "192.168.1.100"]);
/// ```
#[must_use]
pub fn match_ipv4(text: &str) -> Vec<&str> {
    all_matches(re_ipv4(), text)
}

/// Finds all IPv6 addresses in `text`.
///
/// # Examples
///
/// ```rust
/// use rune_regex_sec::match_ipv6;
///
/// let hits = match_ipv6("addr: 2001:0db8:85a3:0000:0000:8a2e:0370:7334");
/// assert!(!hits.is_empty());
/// ```
#[must_use]
pub fn match_ipv6(text: &str) -> Vec<&str> {
    all_matches(re_ipv6(), text)
}

/// Finds all CVE identifiers in `text`.
///
/// # Examples
///
/// ```rust
/// use rune_regex_sec::match_cve;
///
/// let hits = match_cve("Affects CVE-2021-44228 and CVE-2023-1234");
/// assert_eq!(hits, vec!["CVE-2021-44228", "CVE-2023-1234"]);
/// ```
#[must_use]
pub fn match_cve(text: &str) -> Vec<&str> {
    all_matches(re_cve(), text)
}

/// Finds all 32-character hex strings (MD5-like digests) in `text`.
///
/// # Examples
///
/// ```rust
/// use rune_regex_sec::match_md5;
///
/// let hits = match_md5("hash: d41d8cd98f00b204e9800998ecf8427e");
/// assert_eq!(hits, vec!["d41d8cd98f00b204e9800998ecf8427e"]);
/// ```
#[must_use]
pub fn match_md5(text: &str) -> Vec<&str> {
    all_matches(re_md5(), text)
}

/// Finds all 40-character hex strings (SHA-1-like digests) in `text`.
///
/// # Examples
///
/// ```rust
/// use rune_regex_sec::match_sha1;
///
/// let hits = match_sha1("sha1: da39a3ee5e6b4b0d3255bfef95601890afd80709");
/// assert_eq!(hits, vec!["da39a3ee5e6b4b0d3255bfef95601890afd80709"]);
/// ```
#[must_use]
pub fn match_sha1(text: &str) -> Vec<&str> {
    all_matches(re_sha1(), text)
}

/// Finds all 64-character hex strings (SHA-256-like digests) in `text`.
///
/// # Examples
///
/// ```rust
/// use rune_regex_sec::match_sha256;
///
/// let hits = match_sha256("sha: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
/// assert_eq!(hits, vec!["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]);
/// ```
#[must_use]
pub fn match_sha256(text: &str) -> Vec<&str> {
    all_matches(re_sha256(), text)
}

/// Finds all JWT tokens in `text`.
///
/// # Examples
///
/// ```rust
/// use rune_regex_sec::match_jwt;
///
/// let token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.abc123";
/// let hits = match_jwt(token);
/// assert!(!hits.is_empty());
/// ```
#[must_use]
pub fn match_jwt(text: &str) -> Vec<&str> {
    all_matches(re_jwt(), text)
}

/// Finds all AWS access key IDs in `text`.
///
/// Matches keys starting with `AKIA`, `ABIA`, `ACCA`, or `ASIA` followed by
/// 16 uppercase alphanumeric characters.
///
/// # Examples
///
/// ```rust
/// use rune_regex_sec::match_aws_key;
///
/// let hits = match_aws_key("key: AKIAIOSFODNN7EXAMPLE");
/// assert_eq!(hits, vec!["AKIAIOSFODNN7EXAMPLE"]);
/// ```
#[must_use]
pub fn match_aws_key(text: &str) -> Vec<&str> {
    all_matches(re_aws_key(), text)
}

/// Finds all PEM private key header lines in `text`.
///
/// # Examples
///
/// ```rust
/// use rune_regex_sec::match_private_key;
///
/// let hits = match_private_key("-----BEGIN RSA PRIVATE KEY-----\nMIIE...");
/// assert!(!hits.is_empty());
/// ```
#[must_use]
pub fn match_private_key(text: &str) -> Vec<&str> {
    all_matches(re_private_key(), text)
}

/// Finds all email addresses in `text`.
///
/// # Examples
///
/// ```rust
/// use rune_regex_sec::match_email;
///
/// let hits = match_email("contact: admin@example.com");
/// assert_eq!(hits, vec!["admin@example.com"]);
/// ```
#[must_use]
pub fn match_email(text: &str) -> Vec<&str> {
    all_matches(re_email(), text)
}

/// Finds all HTTP/HTTPS URLs in `text`.
///
/// # Examples
///
/// ```rust
/// use rune_regex_sec::match_url;
///
/// let hits = match_url("see https://example.com/api?k=v");
/// assert_eq!(hits, vec!["https://example.com/api?k=v"]);
/// ```
#[must_use]
pub fn match_url(text: &str) -> Vec<&str> {
    all_matches(re_url(), text)
}

/// Finds all UUID v4 values in `text`.
///
/// # Examples
///
/// ```rust
/// use rune_regex_sec::match_uuid;
///
/// let hits = match_uuid("id: 550e8400-e29b-41d4-a716-446655440000");
/// assert_eq!(hits, vec!["550e8400-e29b-41d4-a716-446655440000"]);
/// ```
#[must_use]
pub fn match_uuid(text: &str) -> Vec<&str> {
    all_matches(re_uuid(), text)
}

/// Finds long Base64-looking strings (40+ characters) that may be secrets or tokens.
///
/// # Examples
///
/// ```rust
/// use rune_regex_sec::match_base64_secret;
///
/// let hits = match_base64_secret("secret: QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZn");
/// assert!(!hits.is_empty());
/// ```
#[must_use]
pub fn match_base64_secret(text: &str) -> Vec<&str> {
    all_matches(re_base64_secret(), text)
}

/// Runs all security patterns against `text` and returns all findings.
///
/// # Examples
///
/// ```rust
/// use rune_regex_sec::scan;
///
/// let text = "CVE-2024-1234 at 192.168.1.1, email: user@example.com";
/// let findings = scan(text);
/// let categories: Vec<&str> = findings.iter().map(|f| f.category).collect();
/// assert!(categories.contains(&"ipv4"));
/// assert!(categories.contains(&"cve"));
/// assert!(categories.contains(&"email"));
/// ```
#[must_use]
pub fn scan(text: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for value in match_ipv4(text) {
        findings.push(Finding {
            category: "ipv4",
            value: value.to_owned(),
        });
    }
    for value in match_ipv6(text) {
        findings.push(Finding {
            category: "ipv6",
            value: value.to_owned(),
        });
    }
    for value in match_cve(text) {
        findings.push(Finding {
            category: "cve",
            value: value.to_owned(),
        });
    }
    for value in match_jwt(text) {
        findings.push(Finding {
            category: "jwt",
            value: value.to_owned(),
        });
    }
    for value in match_aws_key(text) {
        findings.push(Finding {
            category: "aws_key",
            value: value.to_owned(),
        });
    }
    for value in match_private_key(text) {
        findings.push(Finding {
            category: "private_key",
            value: value.to_owned(),
        });
    }
    for value in match_email(text) {
        findings.push(Finding {
            category: "email",
            value: value.to_owned(),
        });
    }
    for value in match_url(text) {
        findings.push(Finding {
            category: "url",
            value: value.to_owned(),
        });
    }
    for value in match_uuid(text) {
        findings.push(Finding {
            category: "uuid",
            value: value.to_owned(),
        });
    }
    for value in match_sha256(text) {
        findings.push(Finding {
            category: "sha256",
            value: value.to_owned(),
        });
    }
    for value in match_sha1(text) {
        findings.push(Finding {
            category: "sha1",
            value: value.to_owned(),
        });
    }
    for value in match_md5(text) {
        findings.push(Finding {
            category: "md5",
            value: value.to_owned(),
        });
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_patterns_compile() {
        for re in [
            re_ipv4(),
            re_ipv6(),
            re_cve(),
            re_md5(),
            re_sha1(),
            re_sha256(),
            re_jwt(),
            re_aws_key(),
            re_private_key(),
            re_email(),
            re_url(),
            re_uuid(),
            re_base64_secret(),
        ] {
            assert!(re.is_some());
        }
    }

    #[test]
    fn ipv4_basic() {
        assert_eq!(match_ipv4("10.0.0.1"), vec!["10.0.0.1"]);
    }

    #[test]
    fn ipv4_multiple() {
        let hits = match_ipv4("10.0.0.1 and 192.168.100.200");
        assert_eq!(hits, vec!["10.0.0.1", "192.168.100.200"]);
    }

    #[test]
    fn ipv4_rejects_invalid_octets() {
        let hits = match_ipv4("bad 999.999.999.999 address");
        assert_eq!(hits, [] as [&str; 0]);
    }

    #[test]
    fn cve_standard() {
        let hits = match_cve("CVE-2021-44228 and CVE-2023-1234");
        assert_eq!(hits, vec!["CVE-2021-44228", "CVE-2023-1234"]);
    }

    #[test]
    fn cve_long_number() {
        let hits = match_cve("CVE-2023-1234567");
        assert_eq!(hits, vec!["CVE-2023-1234567"]);
    }

    #[test]
    fn sha256_detection() {
        let hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let hits = match_sha256(hash);
        assert_eq!(hits, vec![hash]);
    }

    #[test]
    fn md5_detection() {
        let hash = "d41d8cd98f00b204e9800998ecf8427e";
        let hits = match_md5(hash);
        assert_eq!(hits, vec![hash]);
    }

    #[test]
    fn jwt_detection() {
        let token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.abc123";
        let hits = match_jwt(token);
        assert_ne!(hits, [] as [&str; 0]);
    }

    #[test]
    fn aws_key_detection() {
        let hits = match_aws_key("AKIAIOSFODNN7EXAMPLE");
        assert_eq!(hits, vec!["AKIAIOSFODNN7EXAMPLE"]);
    }

    #[test]
    fn private_key_detection() {
        let hits = match_private_key("-----BEGIN RSA PRIVATE KEY-----\nstuff");
        assert_ne!(hits, [] as [&str; 0]);
    }

    #[test]
    fn email_detection() {
        let hits = match_email("user@example.com");
        assert_eq!(hits, vec!["user@example.com"]);
    }

    #[test]
    fn url_detection() {
        let hits = match_url("see https://example.com/path?k=v");
        assert_eq!(hits, vec!["https://example.com/path?k=v"]);
    }

    #[test]
    fn uuid_detection() {
        let hits = match_uuid("550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(hits, vec!["550e8400-e29b-41d4-a716-446655440000"]);
    }

    #[test]
    fn scan_combined() {
        let text = "CVE-2024-1234 at 192.168.1.1, email: user@example.com";
        let findings = scan(text);
        let categories: Vec<&str> = findings.iter().map(|f| f.category).collect();
        assert!(categories.contains(&"ipv4"));
        assert!(categories.contains(&"cve"));
        assert!(categories.contains(&"email"));
    }

    #[test]
    fn empty_text_returns_no_findings() {
        assert_eq!(scan(""), [] as [Finding; 0]);
    }
}
