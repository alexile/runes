//! Pure helpers shared by both engines: redaction, entropy tokens and the
//! false-positive filters (data URIs, UUIDs, subresource-integrity hashes).

/// Number of leading characters of a secret kept in redacted evidence.
const REDACT_PREFIX: usize = 4;

/// Minimum length of a token considered by entropy detection.
pub const ENTROPY_MIN_LEN: usize = 20;

/// Redacts a secret to a short prefix plus its length. Never returns the full
/// secret: values of [`REDACT_PREFIX`] characters or fewer keep no prefix.
#[must_use]
pub fn redact(secret: &str) -> String {
    let count = secret.chars().count();
    let keep = if count > REDACT_PREFIX * 2 {
        REDACT_PREFIX
    } else {
        0
    };
    let prefix: String = secret.chars().take(keep).collect();
    format!("{prefix}… (redacted, {count} chars)")
}

/// Whether a byte may appear inside a secret-like token (base64, base64url or
/// hex).
pub const fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'_' | b'-')
}

/// Calls `f(start, token)` for every key-like token in `line`: at least
/// [`ENTROPY_MIN_LEN`] token bytes, mixing letters and digits.
pub fn for_each_keylike_token<'a>(line: &'a str, mut f: impl FnMut(usize, &'a str)) {
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if !is_token_byte(bytes[i]) {
            i += 1;
            continue;
        }
        let start = i;
        let (mut digit, mut alpha) = (false, false);
        while i < bytes.len() && is_token_byte(bytes[i]) {
            digit |= bytes[i].is_ascii_digit();
            alpha |= bytes[i].is_ascii_alphabetic();
            i += 1;
        }
        // Token bytes are ASCII, so `start..i` is on char boundaries.
        if i - start >= ENTROPY_MIN_LEN
            && digit
            && alpha
            && let Some(token) = line.get(start..i)
        {
            f(start, token);
        }
    }
}

/// Whether `token` is a UUID (`8-4-4-4-12` hex digits).
pub fn is_uuid(token: &str) -> bool {
    let b = token.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_hexdigit(),
        })
}

/// Whether `token` looks like a URL or file path rather than base64: at
/// least two `/` and a word-like segment (5+ lowercase letters or `-`, as in
/// `mitre-attack`). Random base64 rarely has either.
pub fn is_path_like(token: &str) -> bool {
    token.bytes().filter(|b| *b == b'/').count() >= 2
        && token
            .split('/')
            .any(|seg| seg.len() >= 5 && seg.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'))
}

/// Whether the token starting at byte `start` of `line` is part of a URL's
/// host or path: a `://` precedes it with no whitespace, quote or `?` in
/// between. Secrets in query strings are still reported.
pub fn in_url_path(line: &str, start: usize) -> bool {
    let Some(before) = line.get(..start) else {
        return false;
    };
    before.rfind("://").is_some_and(|scheme| {
        !before[scheme..].bytes().any(|b| {
            b.is_ascii_whitespace() || matches!(b, b'"' | b'\'' | b'?' | b'#' | b'<' | b'>')
        })
    })
}

/// Whether `token` is a subresource-integrity digest (`sha512-<base64>`), as
/// found in lockfiles and `<script integrity=…>`.
pub fn is_sri_digest(token: &str) -> bool {
    ["sha256-", "sha384-", "sha512-"]
        .iter()
        .any(|p| token.len() > p.len() && token[..p.len()].eq_ignore_ascii_case(p))
}

/// Fills `out` with the byte ranges of every base64 data-URI payload in
/// `line` (`data:image/png;base64,<payload>`). Inline images and fonts are
/// high-entropy base64 but never credentials.
pub fn data_uri_payloads(line: &str, out: &mut Vec<(usize, usize)>) {
    out.clear();
    let bytes = line.as_bytes();
    for (comma, _) in line.match_indices(',') {
        let Some(marker) = comma.checked_sub(7) else {
            continue;
        };
        if !bytes[marker..comma].eq_ignore_ascii_case(b";base64")
            || !contains_ignore_ascii_case(&bytes[..marker], b"data:")
        {
            continue;
        }
        let start = comma + 1;
        let len = bytes[start..]
            .iter()
            .take_while(|b| is_token_byte(**b) || **b == b'%')
            .count();
        out.push((start, start + len));
    }
}

/// Whether the byte range `start..end` lies inside one of `ranges`.
pub fn within(ranges: &[(usize, usize)], start: usize, end: usize) -> bool {
    ranges.iter().any(|&(s, e)| start >= s && end <= e)
}

/// Whether the byte range `start..end` overlaps one of `ranges`.
pub fn overlaps(ranges: &[(usize, usize)], start: usize, end: usize) -> bool {
    ranges.iter().any(|&(s, e)| start < e && s < end)
}

fn contains_ignore_ascii_case(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w.eq_ignore_ascii_case(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redaction_keeps_prefix_and_length_only() {
        let red = redact("AKIAIOSFODNN7EXAMPLE");
        assert_eq!(red, "AKIA… (redacted, 20 chars)");
        // Short values keep no prefix at all.
        assert_eq!(redact("abcdef"), "… (redacted, 6 chars)");
    }

    #[test]
    fn keylike_tokens_need_length_and_mixed_classes() {
        let mut seen = Vec::new();
        for_each_keylike_token(
            "a = aGVsbG8xMjM0NTY3ODkwYWJj12 b = abcdefghijklmnopqrstuvwxyz short1",
            |start, t| seen.push((start, t.to_owned())),
        );
        assert_eq!(seen, vec![(4, "aGVsbG8xMjM0NTY3ODkwYWJj12".to_owned())]);
    }

    #[test]
    fn uuid_and_sri_shapes() {
        assert!(is_uuid("550e8400-e29b-41d4-a716-446655440000"));
        assert!(!is_uuid("550e8400e29b41d4a716446655440000"));
        assert!(is_sri_digest(
            "sha512-z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP"
        ));
        assert!(!is_sri_digest("sha512-"));
        assert!(is_path_like(
            "com/mitre-attack/attack-stix-data/f59b03ecf828579d5f9e93683ce25b7e2e5fd9d7/enterprise-attack"
        ));
        assert!(!is_path_like("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"));
        let url =
            "u = \"https://a.test/OWASP/3a31f35346c3f4e90f350395124382fa53af2afe/x?k=Zm9vYmFy\" t";
        assert!(in_url_path(url, url.find("OWASP").unwrap()));
        assert!(
            !in_url_path(url, url.find("Zm9v").unwrap()),
            "query strings still count"
        );
        assert!(!in_url_path(url, url.len() - 1));
    }

    #[test]
    fn data_uri_payload_ranges() {
        let line = "x = 'DATA:image/png;BASE64,iVBORw0KGgo=' + y";
        let mut out = Vec::new();
        data_uri_payloads(line, &mut out);
        assert_eq!(out.len(), 1);
        let (s, e) = out[0];
        assert_eq!(&line[s..e], "iVBORw0KGgo=");
        data_uri_payloads("plain;base64,abc", &mut out);
        assert!(out.is_empty(), "needs a data: scheme");
    }
}
