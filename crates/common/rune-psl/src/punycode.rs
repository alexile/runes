//! Punycode decoding ([RFC 3492](https://www.rfc-editor.org/rfc/rfc3492)),
//! enough to compare `xn--` A-labels with the Unicode rules of the list.

const BASE: u32 = 36;
const T_MIN: u32 = 1;
const T_MAX: u32 = 26;
const SKEW: u32 = 38;
const DAMP: u32 = 700;
const INITIAL_BIAS: u32 = 72;
const INITIAL_N: u32 = 0x80;

/// Decodes the Punycode part of an A-label (the text after `xn--`).
///
/// Returns `None` for malformed input: a non-ASCII basic code point, a
/// character that is not a base-36 digit, a truncated variable-length
/// integer, an overflow, or a decoded value that is not a Unicode scalar.
pub fn decode(input: &str) -> Option<String> {
    if !input.is_ascii() {
        return None;
    }
    let (basic, deltas) = input.rsplit_once('-').unwrap_or(("", input));
    let mut output: Vec<char> = basic.chars().collect();
    let mut n = INITIAL_N;
    let mut i: u32 = 0;
    let mut bias = INITIAL_BIAS;
    let mut digits = deltas.bytes();
    let mut first = true;
    while digits.len() > 0 {
        let old_i = i;
        let mut weight: u32 = 1;
        let mut k = BASE;
        loop {
            let digit = digit_value(digits.next()?)?;
            i = i.checked_add(digit.checked_mul(weight)?)?;
            let t = if k <= bias {
                T_MIN
            } else if k >= bias + T_MAX {
                T_MAX
            } else {
                k - bias
            };
            if digit < t {
                break;
            }
            weight = weight.checked_mul(BASE - t)?;
            k = k.checked_add(BASE)?;
        }
        let len = u32::try_from(output.len()).ok()?.checked_add(1)?;
        bias = adapt(i - old_i, len, first);
        first = false;
        n = n.checked_add(i / len)?;
        i %= len;
        let ch = char::from_u32(n)?;
        output.insert(usize::try_from(i).ok()?, ch);
        i += 1;
    }
    Some(output.into_iter().collect())
}

const fn digit_value(byte: u8) -> Option<u32> {
    match byte {
        b'a'..=b'z' => Some((byte - b'a') as u32),
        b'A'..=b'Z' => Some((byte - b'A') as u32),
        b'0'..=b'9' => Some((byte - b'0') as u32 + 26),
        _ => None,
    }
}

const fn adapt(delta: u32, points: u32, first: bool) -> u32 {
    let mut delta = if first { delta / DAMP } else { delta / 2 };
    delta += delta / points;
    let mut k = 0;
    while delta > ((BASE - T_MIN) * T_MAX) / 2 {
        delta /= BASE - T_MIN;
        k += BASE;
    }
    k + (BASE - T_MIN + 1) * delta / (delta + SKEW)
}

#[cfg(test)]
mod tests {
    use super::decode;

    #[test]
    fn decodes_psl_test_labels() {
        assert_eq!(decode("85x722f").as_deref(), Some("食狮"));
        assert_eq!(decode("55qx5d").as_deref(), Some("公司"));
        assert_eq!(decode("fiqs8s").as_deref(), Some("中国"));
    }

    // Sample strings from RFC 3492 §7.1.
    #[test]
    fn rfc_3492_samples() {
        assert_eq!(
            decode("ihqwcrb4cv8a8dqg056pqjye").as_deref(),
            Some("他们为什么不说中文")
        );
        assert_eq!(
            decode("egbpdaj6bu4bxfgehfvwxn").as_deref(),
            Some(
                "\u{0644}\u{064A}\u{0647}\u{0645}\u{0627}\u{0628}\u{062A}\u{0643}\u{0644}\u{0645}\u{0648}\u{0634}\u{0639}\u{0631}\u{0628}\u{064A}\u{061F}"
            )
        );
        assert_eq!(
            decode("Hello-Another-Way--fc4qua05auwb3674vfr0b").as_deref(),
            Some("Hello-Another-Way-それぞれの場所")
        );
        assert_eq!(
            decode("MajiKoi5-783gue6qz075azm5e").as_deref(),
            Some("MajiでKoiする5秒前")
        );
        assert_eq!(decode("-> $1.00 <--").as_deref(), Some("-> $1.00 <-"));
    }

    #[test]
    fn rejects_malformed_input() {
        // Truncated integer, non-digit, non-ASCII, overflow.
        assert_eq!(decode("9"), None);
        assert_eq!(decode("a!"), None);
        assert_eq!(decode("ü"), None);
        assert_eq!(decode("99999999999999"), None);
        // Only basic code points, or nothing at all.
        assert_eq!(decode("a-"), Some("a".to_owned()));
        assert_eq!(decode(""), Some(String::new()));
    }
}
