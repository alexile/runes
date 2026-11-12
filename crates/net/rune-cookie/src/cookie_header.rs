//! The `Cookie` request header ([RFC 6265 §4.2], §5.4) and the strict
//! cookie grammar of §4.1.1.
//!
//! [RFC 6265 §4.2]: https://www.rfc-editor.org/rfc/rfc6265#section-4.2

use std::fmt;

use crate::set_cookie::trim_wsp;

/// One `name=value` pair of a `Cookie` request header.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CookiePair {
    /// The cookie name. Empty for a pair written without `=`.
    pub name: String,
    /// The cookie value.
    pub value: String,
}

impl CookiePair {
    /// A pair.
    #[must_use]
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}

/// `name=value`, or just `value` when the name is empty (`=value` if the
/// value contains `=`, so that it parses back the same).
impl fmt::Display for CookiePair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.name.is_empty() && !self.value.contains('=') {
            f.write_str(&self.value)
        } else {
            write!(f, "{}={}", self.name, self.value)
        }
    }
}

/// Parses a `Cookie` request header value into its pairs, in order.
///
/// Servers see what clients actually send, so this is lenient: pairs are
/// split at `;`, whitespace around names and values is trimmed, empty
/// pieces (and a bare `=`) are skipped and a piece without `=` becomes a pair with an empty
/// name (as browsers send it). Duplicate names are kept.
///
/// ```
/// use rune_cookie::{CookiePair, parse_cookie_header};
///
/// let pairs = parse_cookie_header("sid=abc; theme=dark;; flag");
/// assert_eq!(pairs, [
///     CookiePair::new("sid", "abc"),
///     CookiePair::new("theme", "dark"),
///     CookiePair::new("", "flag"),
/// ]);
/// ```
#[must_use]
pub fn parse_cookie_header(header: &str) -> Vec<CookiePair> {
    header
        .split(';')
        .filter_map(|piece| {
            let piece = trim_wsp(piece);
            if piece.is_empty() {
                return None;
            }
            let pair = match piece.split_once('=') {
                Some((name, value)) => CookiePair::new(trim_wsp(name), trim_wsp(value)),
                None => CookiePair::new("", piece),
            };
            (!(pair.name.is_empty() && pair.value.is_empty())).then_some(pair)
        })
        .collect()
}

/// Joins pairs into a `Cookie` header value (`a=1; b=2`), in the given
/// order.
///
/// ```
/// use rune_cookie::{CookiePair, serialize_cookie_header};
///
/// let header = serialize_cookie_header([CookiePair::new("a", "1"), CookiePair::new("b", "2")].iter());
/// assert_eq!(header, "a=1; b=2");
/// ```
#[must_use]
pub fn serialize_cookie_header<'a>(pairs: impl IntoIterator<Item = &'a CookiePair>) -> String {
    let mut out = String::new();
    for pair in pairs {
        if !out.is_empty() {
            out.push_str("; ");
        }
        out.push_str(&pair.to_string());
    }
    out
}

/// Whether `name` is a `token` ([RFC 9110 §5.6.2]), the strict
/// `cookie-name` grammar of RFC 6265 §4.1.1.
///
/// Parsing accepts far more than this; servers SHOULD only send names that
/// pass.
///
/// [RFC 9110 §5.6.2]: https://www.rfc-editor.org/rfc/rfc9110#section-5.6.2
#[must_use]
pub fn is_valid_name(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(is_tchar)
}

/// Whether `value` matches the strict `cookie-value` grammar of RFC 6265
/// §4.1.1: `*cookie-octet` or the same wrapped in double quotes, where a
/// `cookie-octet` is printable US-ASCII except space, `"`, `,`, `;` and `\`.
#[must_use]
pub fn is_valid_value(value: &str) -> bool {
    let inner = value
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .unwrap_or(value);
    inner.bytes().all(is_cookie_octet)
}

const fn is_tchar(b: u8) -> bool {
    matches!(b,
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_'
        | b'`' | b'|' | b'~' | b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z')
}

const fn is_cookie_octet(b: u8) -> bool {
    matches!(b, 0x21 | 0x23..=0x2B | 0x2D..=0x3A | 0x3C..=0x5B | 0x5D..=0x7E)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_serialize() {
        let pairs = parse_cookie_header(" a = 1 ;b=2=3;\t;c=");
        assert_eq!(
            pairs,
            [
                CookiePair::new("a", "1"),
                CookiePair::new("b", "2=3"),
                CookiePair::new("c", ""),
            ]
        );
        assert_eq!(serialize_cookie_header(&pairs), "a=1; b=2=3; c=");
        assert_eq!(parse_cookie_header(""), Vec::<CookiePair>::new());
        // Regression (fuzz): a bare `=` vanished on re-serialization.
        assert_eq!(
            parse_cookie_header("a=1; =; b"),
            [CookiePair::new("a", "1"), CookiePair::new("", "b")]
        );
        let odd = [CookiePair::new("", "x=y")];
        assert_eq!(serialize_cookie_header(&odd), "=x=y");
        assert_eq!(parse_cookie_header("=x=y"), odd);
        assert_eq!(serialize_cookie_header(&[]), "");
    }

    #[test]
    fn grammar() {
        assert!(is_valid_name("SID_1-x"));
        assert!(!is_valid_name(""));
        assert!(!is_valid_name("a b"));
        assert!(!is_valid_name("a=b"));
        assert!(!is_valid_name("(a)"));
        assert!(is_valid_value(""));
        assert!(is_valid_value("\"\""));
        assert!(is_valid_value("\"abc\""));
        assert!(is_valid_value("a/b:c"));
        assert!(!is_valid_value("a b"));
        assert!(!is_valid_value("a,b"));
        assert!(!is_valid_value("\"a"));
        assert!(!is_valid_value("ä"));
    }
}
