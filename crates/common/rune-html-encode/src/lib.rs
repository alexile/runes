//! HTML entity encoding and decoding for strings.
//!
//! Encodes the five characters that must be escaped in HTML (`&`, `<`, `>`,
//! `"`, `'`) and decodes the most common named and numeric HTML entities.
//! Suitable for escaping user-supplied content before inserting it into HTML
//! documents, and for decoding HTML source text.
//!
//! # Features
//!
//! - [`encode`] — escape `& < > " '` to their named HTML entities.
//! - [`decode`] — decode named entities (`&amp;`, `&lt;`, …) and numeric
//!   entities (`&#60;`, `&#x3C;`).
//!
//! # Quick Start
//!
//! ```rust
//! use rune_html_encode::{encode, decode};
//!
//! let escaped = encode("<script>alert('xss')</script>");
//! assert_eq!(escaped, "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;");
//!
//! let back = decode("&lt;h1&gt;Hello &amp; World&lt;/h1&gt;");
//! assert_eq!(back, "<h1>Hello & World</h1>");
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-html-encode "<b>hello</b>"    # encode
//! rune-html-encode -d "&lt;b&gt;"   # decode
//! ```

#![cfg_attr(not(any(feature = "std", test)), no_std)]

extern crate alloc;

use alloc::string::String;

/// Escapes HTML special characters in a string.
///
/// The five characters `& < > " '` are replaced with their named entities.
/// All other characters are passed through unchanged.
///
/// # Examples
///
/// ```rust
/// use rune_html_encode::encode;
///
/// assert_eq!(encode("hello"), "hello");
/// assert_eq!(encode("<b>hi</b>"), "&lt;b&gt;hi&lt;/b&gt;");
/// assert_eq!(encode("a & b"), "a &amp; b");
/// assert_eq!(encode("\"quoted\""), "&quot;quoted&quot;");
/// assert_eq!(encode("it's"), "it&#x27;s");
/// ```
#[must_use]
pub fn encode(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&#x27;"),
            c => output.push(c),
        }
    }
    output
}

/// Decodes HTML entities in a string.
///
/// Handles the five named entities (`&amp;`, `&lt;`, `&gt;`, `&quot;`,
/// `&apos;`), decimal numeric entities (`&#60;`), and hex numeric entities
/// (`&#x3C;`). Unrecognised entities, numeric references that are not a
/// Unicode scalar value, and entities longer than 32 characters are passed
/// through unchanged. Decoding runs in linear time.
///
/// # Examples
///
/// ```rust
/// use rune_html_encode::decode;
///
/// assert_eq!(decode("&lt;b&gt;"), "<b>");
/// assert_eq!(decode("&amp;"), "&");
/// assert_eq!(decode("&#60;"), "<");
/// assert_eq!(decode("&#x3C;"), "<");
/// assert_eq!(decode("&unknown;"), "&unknown;");
/// assert_eq!(decode("no entities here"), "no entities here");
/// ```
#[must_use]
pub fn decode(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut rest = input;

    while let Some(amp) = rest.find('&') {
        output.push_str(&rest[..amp]);
        let after = &rest[amp + 1..];

        // Only look a bounded distance ahead for the `;`, so that input with
        // many `&` and no `;` decodes in linear time.
        let semicolon = after
            .bytes()
            .take(MAX_ENTITY_LEN + 1)
            .position(|byte| byte == b';');
        if let Some(end) = semicolon
            && let Some(decoded) = decode_entity(&after[..end])
        {
            output.push(decoded);
            rest = &after[end + 1..];
            continue;
        }

        output.push('&');
        rest = after;
    }

    output.push_str(rest);
    output
}

/// Longest entity body (between `&` and `;`) that [`decode`] recognises.
///
/// Named entities are at most six characters, and every Unicode scalar value
/// fits in far fewer digits; the margin admits zero-padded numeric entities.
const MAX_ENTITY_LEN: usize = 32;

fn decode_entity(entity: &str) -> Option<char> {
    match entity {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        "nbsp" => Some('\u{00A0}'),
        "copy" => Some('©'),
        "reg" => Some('®'),
        "trade" => Some('™'),
        "mdash" => Some('—'),
        "ndash" => Some('–'),
        "hellip" => Some('…'),
        _ => {
            let numeric = entity.strip_prefix('#')?;
            let (digits, radix) = numeric
                .strip_prefix('x')
                .or_else(|| numeric.strip_prefix('X'))
                .map_or((numeric, 10), |hex| (hex, 16));
            // `from_str_radix` accepts a leading `+`; HTML numeric character
            // references are digits only.
            if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
                return None;
            }
            u32::from_str_radix(digits, radix)
                .ok()
                .and_then(char::from_u32)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_no_special_chars() {
        assert_eq!(encode("hello world"), "hello world");
    }

    #[test]
    fn encode_ampersand() {
        assert_eq!(encode("a & b"), "a &amp; b");
    }

    #[test]
    fn encode_angle_brackets() {
        assert_eq!(encode("<b>text</b>"), "&lt;b&gt;text&lt;/b&gt;");
    }

    #[test]
    fn encode_double_quote() {
        assert_eq!(encode("say \"hi\""), "say &quot;hi&quot;");
    }

    #[test]
    fn encode_single_quote() {
        assert_eq!(encode("it's"), "it&#x27;s");
    }

    #[test]
    fn encode_xss_script() {
        let input = "<script>alert('xss')</script>";
        let encoded = encode(input);
        assert!(!encoded.contains('<'));
        assert!(!encoded.contains('>'));
        assert!(!encoded.contains('\''));
    }

    #[test]
    fn decode_named_entities() {
        assert_eq!(decode("&amp;"), "&");
        assert_eq!(decode("&lt;"), "<");
        assert_eq!(decode("&gt;"), ">");
        assert_eq!(decode("&quot;"), "\"");
        assert_eq!(decode("&apos;"), "'");
    }

    #[test]
    fn decode_decimal_numeric() {
        assert_eq!(decode("&#60;"), "<");
        assert_eq!(decode("&#62;"), ">");
        assert_eq!(decode("&#38;"), "&");
    }

    #[test]
    fn decode_hex_numeric() {
        assert_eq!(decode("&#x3C;"), "<");
        assert_eq!(decode("&#x3E;"), ">");
        assert_eq!(decode("&#x26;"), "&");
    }

    #[test]
    fn decode_unknown_entity_passthrough() {
        assert_eq!(decode("&unknown;"), "&unknown;");
    }

    #[test]
    fn roundtrip() {
        let original = "<b>Hello & 'world'</b>";
        assert_eq!(decode(&encode(original)), original);
    }

    #[test]
    fn decode_mixed_content() {
        assert_eq!(decode("Hello &lt;b&gt; &amp; world"), "Hello <b> & world");
    }

    // Regression: `u32::from_str_radix` accepts a leading `+`, so
    // `&#+60;` and `&#x+3C;` used to decode to `<`. They are not character
    // references and must pass through unchanged.
    #[test]
    fn decode_rejects_signed_numeric_entities() {
        assert_eq!(decode("&#+60;"), "&#+60;");
        assert_eq!(decode("&#x+3C;"), "&#x+3C;");
        assert_eq!(decode("&#-60;"), "&#-60;");
        assert_eq!(decode("&#x;"), "&#x;");
        assert_eq!(decode("&#;"), "&#;");
    }

    // Regression: every `&` used to scan the rest of the input for a
    // `;`, which is quadratic on input like `&&&&…`. The look-ahead is now
    // bounded; this input would take minutes with the old scan.
    #[test]
    fn decode_many_ampersands_is_linear() {
        let input = "&".repeat(1 << 20) + ";";
        assert_eq!(decode(&input), input);
    }

    #[test]
    fn decode_zero_padded_numeric_within_bound() {
        assert_eq!(decode("&#0000000060;"), "<");
        assert_eq!(decode("&#x00000003C;"), "<");
    }

    #[test]
    fn decode_multibyte_text_around_entities() {
        assert_eq!(decode("é&lt;ü&gt;😀&amp"), "é<ü>😀&amp");
        assert_eq!(decode("&é;&#x1F600;"), "&é;😀");
    }
}
