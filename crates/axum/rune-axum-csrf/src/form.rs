//! Minimal `application/x-www-form-urlencoded` field lookup.

const fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Percent-decodes (`+` → space); invalid escapes are kept literally.
fn decode(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        match raw[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < raw.len() => match (hex_val(raw[i + 1]), hex_val(raw[i + 2])) {
                (Some(h), Some(l)) => {
                    out.push((h << 4) | l);
                    i += 2;
                }
                _ => out.push(b'%'),
            },
            c => out.push(c),
        }
        i += 1;
    }
    out
}

/// Returns the first value of `field` in a urlencoded body.
pub fn find_field(body: &[u8], field: &str) -> Option<String> {
    body.split(|&b| b == b'&').find_map(|pair| {
        let (name, value) = pair
            .iter()
            .position(|&b| b == b'=')
            .map_or((pair, &[][..]), |i| (&pair[..i], &pair[i + 1..]));
        (decode(name) == field.as_bytes())
            .then(|| String::from_utf8(decode(value)).ok())
            .flatten()
    })
}

/// `true` for `application/x-www-form-urlencoded` (parameters ignored).
pub fn is_urlencoded(content_type: &str) -> bool {
    content_type.split(';').next().is_some_and(|m| {
        m.trim()
            .eq_ignore_ascii_case("application/x-www-form-urlencoded")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_field() {
        assert_eq!(
            find_field(b"a=1&csrf_token=abc.1.def&b=2", "csrf_token").as_deref(),
            Some("abc.1.def")
        );
        assert_eq!(find_field(b"a=1", "csrf_token"), None);
        assert_eq!(find_field(b"", "csrf_token"), None);
        assert_eq!(find_field(b"csrf_token", "csrf_token").as_deref(), Some(""));
    }

    #[test]
    fn decodes() {
        assert_eq!(
            find_field(b"csrf%5Ftoken=a%2Eb+c", "csrf_token").as_deref(),
            Some("a.b c")
        );
        assert_eq!(find_field(b"x=%&x2=%4", "x").as_deref(), Some("%"));
        assert_eq!(find_field(b"x2=%4", "x2").as_deref(), Some("%4"));
        assert_eq!(find_field(b"x=%zz", "x").as_deref(), Some("%zz"));
    }

    #[test]
    fn first_value_wins() {
        assert_eq!(find_field(b"t=1&t=2", "t").as_deref(), Some("1"));
    }

    #[test]
    fn content_type() {
        assert!(is_urlencoded("application/x-www-form-urlencoded"));
        assert!(is_urlencoded(
            "Application/X-WWW-Form-Urlencoded; charset=UTF-8"
        ));
        assert!(!is_urlencoded("multipart/form-data; boundary=x"));
        assert!(!is_urlencoded("application/json"));
    }
}
