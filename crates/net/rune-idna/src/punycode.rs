//! Punycode, the Bootstring encoding of Unicode for IDNA
//! ([RFC 3492](https://www.rfc-editor.org/rfc/rfc3492)).
//!
//! These functions work on a single label and do not add or strip the
//! `xn--` ACE prefix; [`to_ascii`](crate::to_ascii) and
//! [`to_unicode`](crate::to_unicode) handle whole domain names.
//!
//! ```
//! use rune_idna::punycode;
//!
//! assert_eq!(punycode::encode("bücher")?, "bcher-kva");
//! assert_eq!(punycode::decode("bcher-kva")?, "bücher");
//! # Ok::<(), rune_idna::Error>(())
//! ```
//!
//! Mixed-case annotations (RFC 3492 appendix A) are not produced; the
//! decoder accepts upper- and lowercase digits alike.

use crate::Error;

/// Longest Unicode text, in characters, that [`encode`] accepts and
/// [`decode`] produces.
///
/// A DNS label is at most 63 octets, so real labels are far below this.
/// The bound keeps the quadratic worst case of decoding small, and
/// everything [`encode`] accepts decodes again.
pub const MAX_LEN: usize = 4096;

const BASE: u32 = 36;
const T_MIN: u32 = 1;
const T_MAX: u32 = 26;
const SKEW: u32 = 38;
const DAMP: u32 = 700;
const INITIAL_BIAS: u32 = 72;
const INITIAL_N: u32 = 0x80;
const DELIMITER: char = '-';

/// Bias adaptation (RFC 3492 section 6.1).
const fn adapt(delta: u32, num_points: u32, first_time: bool) -> u32 {
    let mut delta = if first_time { delta / DAMP } else { delta / 2 };
    delta += delta / num_points;
    let mut k = 0;
    while delta > ((BASE - T_MIN) * T_MAX) / 2 {
        delta /= BASE - T_MIN;
        k += BASE;
    }
    k + (BASE - T_MIN + 1) * delta / (delta + SKEW)
}

/// The threshold `t` for digit position `k` (RFC 3492 section 6.2).
const fn threshold(k: u32, bias: u32) -> u32 {
    if k <= bias {
        T_MIN
    } else if k >= bias + T_MAX {
        T_MAX
    } else {
        k - bias
    }
}

/// Digit values 0..36 in order: `a`-`z` are 0-25, `0`-`9` are 26-35.
const DIGITS: &[u8; 36] = b"abcdefghijklmnopqrstuvwxyz0123456789";

/// Lowercase digit for `d`, which is below 36 by construction.
fn encode_digit(d: u32) -> char {
    char::from(DIGITS.get(d as usize).copied().unwrap_or(b'?'))
}

/// Value of a base-36 digit, either case.
const fn decode_digit(c: char) -> Option<u32> {
    match c {
        'a'..='z' => Some(c as u32 - 'a' as u32),
        'A'..='Z' => Some(c as u32 - 'A' as u32),
        '0'..='9' => Some(c as u32 - '0' as u32 + 26),
        _ => None,
    }
}

fn to_u32(n: usize) -> Result<u32, Error> {
    u32::try_from(n).map_err(|_| Error::PunycodeOverflow)
}

/// Encodes a Unicode string as Punycode.
///
/// The basic (ASCII) code points are copied first, followed by a `-` if
/// there were any, then the deltas for the rest. An all-ASCII input `s`
/// encodes to `s-`; the empty string encodes to itself.
///
/// # Errors
///
/// - [`Error::PunycodeTooLong`] if `input` has more than [`MAX_LEN`]
///   characters.
/// - [`Error::PunycodeOverflow`] if a delta does not fit in 32 bits.
#[allow(
    clippy::many_single_char_names,
    reason = "n, i, k, t, q, w and m are the variable names of RFC 3492"
)]
pub fn encode(input: &str) -> Result<String, Error> {
    let chars: Vec<u32> = input.chars().map(u32::from).collect();
    if chars.len() > MAX_LEN {
        return Err(Error::PunycodeTooLong {
            len: chars.len(),
            max: MAX_LEN,
        });
    }
    let mut output: String = input.chars().filter(char::is_ascii).collect();
    let basic = to_u32(output.len())?;
    let total = to_u32(chars.len())?;
    if basic > 0 {
        output.push(DELIMITER);
    }

    let mut n = INITIAL_N;
    let mut delta: u32 = 0;
    let mut bias = INITIAL_BIAS;
    let mut handled = basic;
    while handled < total {
        // The smallest code point not handled yet; one exists because
        // `handled < total`.
        let Some(m) = chars.iter().copied().filter(|&c| c >= n).min() else {
            break;
        };
        delta = (m - n)
            .checked_mul(handled + 1)
            .and_then(|d| delta.checked_add(d))
            .ok_or(Error::PunycodeOverflow)?;
        n = m;
        for &c in &chars {
            if c < n {
                delta = delta.checked_add(1).ok_or(Error::PunycodeOverflow)?;
            }
            if c == n {
                let mut q = delta;
                let mut k = BASE;
                loop {
                    let t = threshold(k, bias);
                    if q < t {
                        break;
                    }
                    output.push(encode_digit(t + (q - t) % (BASE - t)));
                    q = (q - t) / (BASE - t);
                    k += BASE;
                }
                output.push(encode_digit(q));
                bias = adapt(delta, handled + 1, handled == basic);
                delta = 0;
                handled += 1;
            }
        }
        delta = delta.checked_add(1).ok_or(Error::PunycodeOverflow)?;
        n = n.checked_add(1).ok_or(Error::PunycodeOverflow)?;
    }
    Ok(output)
}

/// Decodes Punycode to a Unicode string.
///
/// Everything before the last `-` is copied as basic code points; the
/// rest is a sequence of base-36 deltas, in either case. A `-` at the very
/// start is not a delimiter, so `-abc` is invalid.
///
/// # Errors
///
/// - [`Error::PunycodeTooLong`] if the decoded text would have more than
///   [`MAX_LEN`] characters.
/// - [`Error::PunycodeNonBasic`] if `input` contains a non-ASCII character.
/// - [`Error::PunycodeInvalidDigit`] if a character after the last `-` is
///   not a base-36 digit.
/// - [`Error::PunycodeTruncated`] if the input ends inside a delta.
/// - [`Error::PunycodeOverflow`] on arithmetic overflow.
/// - [`Error::PunycodeInvalidCodePoint`] if a delta decodes to a basic code
///   point or to a value that is not a Unicode scalar value.
#[allow(
    clippy::many_single_char_names,
    reason = "n, i, k, t, q, w and m are the variable names of RFC 3492"
)]
pub fn decode(input: &str) -> Result<String, Error> {
    if let Some(c) = input.chars().find(|c| !c.is_ascii()) {
        return Err(Error::PunycodeNonBasic(c));
    }
    // RFC 3492 section 6.2: copy what precedes the last delimiter, and
    // consume the delimiter only if something preceded it.
    let (basic, extended) = match input.rfind(DELIMITER) {
        Some(pos) if pos > 0 => (&input[..pos], &input[pos + 1..]),
        _ => ("", input),
    };
    // All ASCII, so bytes are characters.
    if basic.len() > MAX_LEN {
        return Err(Error::PunycodeTooLong {
            len: basic.len(),
            max: MAX_LEN,
        });
    }
    let mut output: Vec<char> = basic.chars().collect();

    let mut n = INITIAL_N;
    let mut i: u32 = 0;
    let mut bias = INITIAL_BIAS;
    let mut digits = extended.chars();
    while !digits.as_str().is_empty() {
        let old_i = i;
        let mut w: u32 = 1;
        let mut k = BASE;
        loop {
            let c = digits.next().ok_or(Error::PunycodeTruncated)?;
            let digit = decode_digit(c).ok_or(Error::PunycodeInvalidDigit(c))?;
            i = digit
                .checked_mul(w)
                .and_then(|d| i.checked_add(d))
                .ok_or(Error::PunycodeOverflow)?;
            let t = threshold(k, bias);
            if digit < t {
                break;
            }
            w = w.checked_mul(BASE - t).ok_or(Error::PunycodeOverflow)?;
            k += BASE;
        }
        if output.len() >= MAX_LEN {
            return Err(Error::PunycodeTooLong {
                len: output.len() + 1,
                max: MAX_LEN,
            });
        }
        let len = to_u32(output.len())? + 1;
        bias = adapt(i - old_i, len, old_i == 0);
        n = n.checked_add(i / len).ok_or(Error::PunycodeOverflow)?;
        i %= len;
        let c = char::from_u32(n)
            .filter(|c| !c.is_ascii())
            .ok_or(Error::PunycodeInvalidCodePoint(n))?;
        // `i < len == output.len() + 1`, so the index is in bounds.
        output.insert(i as usize, c);
        i += 1;
    }
    Ok(output.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 3492 section 7.1 sample strings, plus common IDN labels.
    const VECTORS: &[(&str, &str)] = &[
        ("ليهمابتكلموشعربي؟", "egbpdaj6bu4bxfgehfvwxn"),
        ("他们为什么不说中文", "ihqwcrb4cv8a8dqg056pqjye"),
        ("他們爲什麽不說中文", "ihqwctvzc91f659drss3x8bo0yb"),
        ("Pročprostěnemluvíčesky", "Proprostnemluvesky-uyb24dma41a"),
        ("למההםפשוטלאמדבריםעברית", "4dbcagdahymbxekheh6e0a7fei0b"),
        (
            "PorquénopuedensimplementehablarenEspañol",
            "PorqunopuedensimplementehablarenEspaol-fmd56a",
        ),
        (
            "TạisaohọkhôngthểchỉnóitiếngViệt",
            "TisaohkhngthchnitingVit-kjcr8268qyxafd2f1b9g",
        ),
        ("3年B組金八先生", "3B-ww4c5e180e575a65lsy2b"),
        (
            "安室奈美恵-with-SUPER-MONKEYS",
            "-with-SUPER-MONKEYS-pc58ag80a8qai00g7n9n",
        ),
        (
            "Hello-Another-Way-それぞれの場所",
            "Hello-Another-Way--fc4qua05auwb3674vfr0b",
        ),
        ("ひとつ屋根の下2", "2-u9tlzr9756bt3uc0v"),
        ("MajiでKoiする5秒前", "MajiKoi5-783gue6qz075azm5e"),
        ("パフィーdeルンバ", "de-jg4avhby1noc0d"),
        ("そのスピードで", "d9juau41awczczp"),
        ("-> $1.00 <-", "-> $1.00 <--"),
        ("bücher", "bcher-kva"),
        ("münchen", "mnchen-3ya"),
        ("例え", "r8jz45g"),
        ("", ""),
        ("abc", "abc-"),
    ];

    #[test]
    fn rfc3492_known_answers() {
        for &(unicode, puny) in VECTORS {
            assert_eq!(encode(unicode).unwrap(), puny, "encode {unicode:?}");
            assert_eq!(decode(puny).unwrap(), unicode, "decode {puny:?}");
        }
    }

    #[test]
    fn decode_accepts_uppercase_digits() {
        assert_eq!(decode("BCHER-KVA").unwrap(), "BüCHER");
    }

    #[test]
    fn decode_without_delimiter_is_all_extended() {
        assert_eq!(decode("d9juau41awczczp").unwrap(), "そのスピードで");
        // A delimiter with nothing before it is not consumed.
        assert_eq!(decode("-"), Err(Error::PunycodeInvalidDigit('-')));
        assert_eq!(decode("-abc"), Err(Error::PunycodeInvalidDigit('-')));
    }

    #[test]
    fn decode_errors() {
        assert_eq!(decode("bü-x"), Err(Error::PunycodeNonBasic('ü')));
        assert_eq!(decode("abc-!"), Err(Error::PunycodeInvalidDigit('!')));
        // 'z' = 25 is above every threshold, so another digit must follow.
        assert_eq!(decode("abc-z"), Err(Error::PunycodeTruncated));
        assert_eq!(decode("99999999999"), Err(Error::PunycodeOverflow));
    }

    #[test]
    fn decode_rejects_surrogates() {
        // 8 + 35·1 + 1225·35 + 12250·1 = 0xD800 − 0x80: one delta to U+D800.
        assert_eq!(decode("ib9b"), Err(Error::PunycodeInvalidCodePoint(0xD800)));
        assert_eq!(decode("hb9b").unwrap(), "\u{d7ff}");
    }

    #[test]
    fn length_limit() {
        let long = "a".repeat(MAX_LEN + 1);
        assert_eq!(
            encode(&long),
            Err(Error::PunycodeTooLong {
                len: MAX_LEN + 1,
                max: MAX_LEN
            })
        );
        assert!(matches!(
            decode(&format!("{long}-")),
            Err(Error::PunycodeTooLong { .. })
        ));
        // Whatever encodes decodes, though the encoding is longer than MAX_LEN.
        let max = "ü".repeat(MAX_LEN);
        let encoded = encode(&max).unwrap();
        assert!(encoded.len() > MAX_LEN);
        assert_eq!(decode(&encoded).unwrap(), max);
        // MAX_LEN basic code points, then one delta.
        let over = format!("{}-a", "a".repeat(MAX_LEN));
        assert_eq!(
            decode(&over),
            Err(Error::PunycodeTooLong {
                len: MAX_LEN + 1,
                max: MAX_LEN
            })
        );
    }
}
