//! Percent-encoding normalization
//! ([RFC 3986 §6.2.2.2](https://www.rfc-editor.org/rfc/rfc3986#section-6.2.2.2)).

/// Whether `byte` is in the RFC 3986 `unreserved` set
/// (`ALPHA / DIGIT / "-" / "." / "_" / "~"`).
pub const fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Normalizes the percent-encoding of one URL component.
///
/// Escapes of unreserved characters are decoded (`%7E` → `~`, `%41` → `A`)
/// and the hex digits of every other escape are uppercased (`%2f` → `%2F`).
/// Everything else, including a `%` that does not start a valid escape, is
/// kept as it is, so the result means the same thing as the input.
///
/// ```
/// use rune_url::normalize_percent_encoding;
///
/// assert_eq!(normalize_percent_encoding("%7efoo%2fbar%41"), "~foo%2FbarA");
/// assert_eq!(normalize_percent_encoding("100%"), "100%");
/// ```
#[must_use]
pub fn normalize_percent_encoding(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    // `%` and hex digits are ASCII, so every split below is on a char boundary.
    while let Some(pos) = rest.find('%') {
        out.push_str(&rest[..pos]);
        let tail = &rest[pos..];
        let bytes = tail.as_bytes();
        let escape = match (bytes.get(1), bytes.get(2)) {
            (Some(&hi), Some(&lo)) => hex_value(hi).zip(hex_value(lo)),
            _ => None,
        };
        if let Some((hi, lo)) = escape {
            let value = (hi << 4) | lo;
            // Decoding a hex digit right after a stray `%` would create a
            // new escape (`%4%41` → `%4A`), so such escapes stay encoded.
            if is_unreserved(value) && !(value.is_ascii_hexdigit() && ends_with_stray_percent(&out))
            {
                out.push(char::from(value));
            } else {
                out.push('%');
                out.push(char::from(bytes[1].to_ascii_uppercase()));
                out.push(char::from(bytes[2].to_ascii_uppercase()));
            }
            rest = &tail[3..];
        } else {
            out.push('%');
            rest = &tail[1..];
        }
    }
    out.push_str(rest);
    out
}

/// Whether `out` ends in `%` or `%` plus one hex digit. Every complete
/// escape in the output has two characters after its `%`, so such a `%` is
/// a stray one.
const fn ends_with_stray_percent(out: &str) -> bool {
    let bytes = out.as_bytes();
    match bytes {
        [.., b'%'] => true,
        [.., b'%', last] => last.is_ascii_hexdigit(),
        _ => false,
    }
}

/// Lowercases ASCII letters outside percent escapes, and uppercases the hex
/// digits inside them.
pub fn lowercase_preserving_escapes(input: &str) -> String {
    let lowered = input.to_ascii_lowercase();
    let mut out = String::with_capacity(lowered.len());
    let mut rest = lowered.as_str();
    while let Some(pos) = rest.find('%') {
        out.push_str(&rest[..pos]);
        let tail = &rest[pos..];
        let bytes = tail.as_bytes();
        match (bytes.get(1), bytes.get(2)) {
            (Some(&hi), Some(&lo)) if hi.is_ascii_hexdigit() && lo.is_ascii_hexdigit() => {
                out.push('%');
                out.push(char::from(hi.to_ascii_uppercase()));
                out.push(char::from(lo.to_ascii_uppercase()));
                rest = &tail[3..];
            }
            _ => {
                out.push('%');
                rest = &tail[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_unreserved_and_uppercases_the_rest() {
        assert_eq!(normalize_percent_encoding("%61%62%63"), "abc");
        assert_eq!(normalize_percent_encoding("%2d%2E%5f%7e"), "-._~");
        assert_eq!(normalize_percent_encoding("%2f%3a%c3%a9"), "%2F%3A%C3%A9");
        assert_eq!(normalize_percent_encoding("%20"), "%20");
    }

    #[test]
    fn keeps_malformed_escapes() {
        assert_eq!(normalize_percent_encoding("%"), "%");
        assert_eq!(normalize_percent_encoding("%4"), "%4");
        assert_eq!(normalize_percent_encoding("%zz%41"), "%zzA");
        assert_eq!(normalize_percent_encoding("%%41"), "%%41");
        assert_eq!(normalize_percent_encoding("é%41é"), "éAé");
    }

    #[test]
    fn is_idempotent_on_tricky_input() {
        // `%25` stays an escape, so `%2541` does not become `%41` then `A`.
        let once = normalize_percent_encoding("%2541");
        assert_eq!(once, "%2541");
        assert_eq!(normalize_percent_encoding(&once), once);
    }

    #[test]
    fn decoding_never_creates_an_escape() {
        // Regression: fuzzer found `%4%41` → `%4A` → `J`.
        assert_eq!(normalize_percent_encoding("ma%4%41i"), "ma%4%41i");
        assert_eq!(normalize_percent_encoding("%%34%31"), "%%341");
        assert_eq!(normalize_percent_encoding("%%4A"), "%J");
        assert_eq!(normalize_percent_encoding("%4%47"), "%4G");
    }

    #[test]
    fn lowercases_outside_escapes() {
        assert_eq!(lowercase_preserving_escapes("HoSt%c3%A9"), "host%C3%A9");
        assert_eq!(lowercase_preserving_escapes("A%"), "a%");
    }
}
