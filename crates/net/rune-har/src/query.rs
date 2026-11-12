//! Query strings, form bodies and cookie headers, as HAR lists them.

use crate::model::{Cookie, NameValue};

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Decodes `%XX` escapes, keeping malformed ones and `+` as they are.
/// Bytes that are not UTF-8 become U+FFFD.
pub fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while let Some(&byte) = bytes.get(index) {
        let escaped = (byte == b'%')
            .then(|| {
                let high = hex_value(*bytes.get(index + 1)?)?;
                let low = hex_value(*bytes.get(index + 2)?)?;
                Some((high << 4) | low)
            })
            .flatten();
        if let Some(decoded) = escaped {
            out.push(decoded);
            index += 3;
        } else {
            out.push(byte);
            index += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Encodes text for an `application/x-www-form-urlencoded` body.
pub fn form_encode(text: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(text.len());
    for &byte in text.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'*' => {
                out.push(char::from(byte));
            }
            b' ' => out.push('+'),
            _ => {
                out.push('%');
                out.push(char::from(HEX[usize::from(byte >> 4)]));
                out.push(char::from(HEX[usize::from(byte & 0xf)]));
            }
        }
    }
    out
}

/// The query parameters of a URL, percent-decoded, as browsers list them.
pub fn query_string(url: &str) -> Vec<NameValue> {
    let Some((_, query)) = url.split_once('?') else {
        return Vec::new();
    };
    let query = query.split_once('#').map_or(query, |(query, _)| query);
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            NameValue::new(percent_decode(name), percent_decode(value))
        })
        .collect()
}

/// The cookies of `Cookie` request headers.
pub fn request_cookies<'a>(values: impl Iterator<Item = &'a str>) -> Vec<Cookie> {
    values
        .flat_map(|value| value.split(';'))
        .map(str::trim)
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or(("", pair));
            cookie(name.trim(), value.trim())
        })
        .collect()
}

fn cookie(name: &str, value: &str) -> Cookie {
    Cookie {
        name: name.to_owned(),
        value: value.to_owned(),
        ..Cookie::default()
    }
}

/// The cookie a `Set-Cookie` response header sets, with its attributes.
pub fn response_cookie(header: &str) -> Option<Cookie> {
    let mut parts = header.split(';');
    let (name, value) = parts.next()?.split_once('=')?;
    let mut cookie = cookie(name.trim(), value.trim());
    for attribute in parts {
        let (key, value) = attribute.split_once('=').unwrap_or((attribute, ""));
        let value = value.trim();
        match key.trim().to_ascii_lowercase().as_str() {
            "path" => cookie.path = Some(value.to_owned()),
            "domain" => cookie.domain = Some(value.to_owned()),
            "expires" => {
                cookie.expires = Some(value.to_owned());
            }
            "httponly" => cookie.http_only = Some(true),
            "secure" => cookie.secure = Some(true),
            "samesite" => {
                cookie
                    .extra
                    .insert("sameSite".to_owned(), value.to_owned().into());
            }
            _ => {}
        }
    }
    Some(cookie)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_decoding_is_lenient() {
        assert_eq!(percent_decode("a%20b+c"), "a b+c");
        assert_eq!(percent_decode("%E2%9C%93%"), "\u{2713}%");
        assert_eq!(percent_decode("%zz%4"), "%zz%4");
        assert_eq!(percent_decode("%ff"), "\u{fffd}");
    }

    #[test]
    fn form_encoding() {
        assert_eq!(form_encode("a b&c=d/é"), "a+b%26c%3Dd%2F%C3%A9");
        assert_eq!(percent_decode(&form_encode("x/y?")), "x/y?");
    }

    #[test]
    fn query_pairs() {
        let pairs = query_string("http://h/p?a=1&b&&c=%3D=x#frag?z=9");
        let pairs: Vec<_> = pairs.iter().map(|p| (&*p.name, &*p.value)).collect();
        assert_eq!(pairs, vec![("a", "1"), ("b", ""), ("c", "==x")]);
        assert_eq!(query_string("http://h/p"), []);
    }

    #[test]
    fn cookies() {
        let sent = request_cookies(["a=1; b=x=y", "flag"].into_iter());
        let sent: Vec<_> = sent.iter().map(|c| (&*c.name, &*c.value)).collect();
        assert_eq!(sent, vec![("a", "1"), ("b", "x=y"), ("", "flag")]);

        let cookie = response_cookie(
            "sid=abc; Path=/; Domain=.example.test; Expires=Wed, 21 Oct 2026 07:28:00 GMT; \
             HttpOnly; Secure; SameSite=Lax",
        )
        .unwrap();
        assert_eq!(
            (cookie.name.as_str(), cookie.value.as_str()),
            ("sid", "abc")
        );
        assert_eq!(cookie.path.as_deref(), Some("/"));
        assert_eq!(cookie.domain.as_deref(), Some(".example.test"));
        assert_eq!(
            cookie.expires.as_deref(),
            Some("Wed, 21 Oct 2026 07:28:00 GMT")
        );
        assert_eq!((cookie.http_only, cookie.secure), (Some(true), Some(true)));
        assert_eq!(cookie.extra.get("sameSite"), Some(&"Lax".into()));
        assert_eq!(response_cookie("no-equals-sign"), None);
    }
}
