//! The built-in transform table.
//!
//! Codecs delegate to the rune crates; only the escapes and small byte
//! shuffles that have no rune of their own are written here.

// Step functions share one `fn(&[u8]) -> Result<..>` signature, so the
// infallible ones still return `Result`.
#![allow(
    clippy::unnecessary_wraps,
    reason = "every step shares the StepFn signature"
)]

use std::fmt::Write as _;
use std::str;
use std::sync::Arc;

use sha2::Digest as _;

use crate::compress::{CompressTransform, CompressionFormat};
use crate::transform::{Fault, FnTransform, StepFn};
use crate::{Category, Transform};

/// Build one table entry.
fn entry(
    id: &'static str,
    description: &'static str,
    category: Category,
    encode: StepFn,
    decode: Option<StepFn>,
) -> Arc<dyn Transform> {
    Arc::new(FnTransform {
        id,
        description,
        category,
        encode,
        decode,
    })
}

/// Every built-in transform, in listing order.
pub fn all() -> Vec<Arc<dyn Transform>> {
    let mut all = encodings();
    all.extend(escapes());
    all.extend(others());
    all
}

/// Base64, base32, hex, URL and HTML encodings.
fn encodings() -> Vec<Arc<dyn Transform>> {
    use Category::Encoding;
    vec![
        // Encodings.
        entry(
            "base64",
            "Standard base64 (padded)",
            Encoding,
            b64_encode,
            Some(b64_decode),
        ),
        entry(
            "base64url",
            "URL-safe base64 (padded)",
            Encoding,
            b64url_encode,
            Some(b64_decode),
        ),
        entry(
            "base64url_nopad",
            "URL-safe base64 without padding",
            Encoding,
            b64url_nopad_encode,
            Some(b64_decode),
        ),
        entry(
            "base32",
            "RFC 4648 base32 (padded)",
            Encoding,
            b32_encode,
            Some(b32_decode),
        ),
        entry(
            "hex",
            "Lowercase hexadecimal",
            Encoding,
            hex_encode,
            Some(hex_decode),
        ),
        entry(
            "hex_upper",
            "Uppercase hexadecimal",
            Encoding,
            hex_upper_encode,
            Some(hex_decode),
        ),
        entry(
            "hex_space",
            "Space-separated hexadecimal",
            Encoding,
            hex_space_encode,
            Some(hex_decode),
        ),
        entry(
            "hex_0x",
            "0x-prefixed hexadecimal",
            Encoding,
            hex_0x_encode,
            Some(hex_decode),
        ),
        entry(
            "url",
            "Percent-encode bytes outside the RFC 3986 unreserved set",
            Encoding,
            url_encode,
            Some(url_decode),
        ),
        entry(
            "url_encode_all",
            "Percent-encode every byte",
            Encoding,
            url_all_encode,
            Some(url_decode),
        ),
        entry(
            "double_url",
            "Percent-encode twice",
            Encoding,
            double_url_encode,
            Some(double_url_decode),
        ),
        entry(
            "html",
            "HTML entity encode (the five specials)",
            Encoding,
            html_encode,
            Some(html_decode),
        ),
        entry(
            "html_entity_decimal",
            "Decimal numeric HTML entities",
            Encoding,
            html_decimal_encode,
            Some(html_decode),
        ),
        entry(
            "html_entity_hex",
            "Hexadecimal numeric HTML entities",
            Encoding,
            html_hex_encode,
            Some(html_decode),
        ),
    ]
}

/// Escape sequences and numeric renderings.
fn escapes() -> Vec<Arc<dyn Transform>> {
    use Category::{Escape, Numeric};
    vec![
        // Escapes.
        entry(
            "js_hex_escape",
            "JavaScript \\xHH escapes",
            Escape,
            js_hex_encode,
            Some(js_hex_decode),
        ),
        entry(
            "js_unicode_escape",
            "JavaScript \\uHHHH escapes",
            Escape,
            js_unicode_encode,
            Some(js_unicode_decode),
        ),
        entry(
            "percent_u_escape",
            "IIS-style %uHHHH escapes",
            Escape,
            percent_u_encode,
            Some(percent_u_decode),
        ),
        entry(
            "octal_escape",
            "Backslash octal escapes",
            Escape,
            octal_encode,
            Some(octal_decode),
        ),
        entry(
            "decimal_escape",
            "Backslash decimal escapes",
            Escape,
            decimal_encode,
            Some(decimal_decode),
        ),
        // Numeric renderings.
        entry(
            "binary",
            "Concatenated 8-bit binary",
            Numeric,
            binary_encode,
            Some(binary_decode),
        ),
        entry(
            "binary_spaced",
            "Space-separated 8-bit binary",
            Numeric,
            binary_spaced_encode,
            Some(binary_decode),
        ),
        entry(
            "ascii_decimal",
            "Space-separated decimal byte values",
            Numeric,
            ascii_decimal_encode,
            Some(ascii_decimal_decode),
        ),
    ]
}

/// Compression, ciphers, digests, text rewrites and JWT decoding.
fn others() -> Vec<Arc<dyn Transform>> {
    use Category::{Cipher, Hash, Other, Text};
    vec![
        // Compression.
        Arc::new(CompressTransform::new(CompressionFormat::Gzip)),
        Arc::new(CompressTransform::new(CompressionFormat::Zlib)),
        Arc::new(CompressTransform::new(CompressionFormat::Deflate)),
        // Ciphers and self-inverse shuffles.
        entry("rot13", "ROT13 letter rotation", Cipher, rot13, Some(rot13)),
        entry("rot5", "ROT5 digit rotation", Cipher, rot5, Some(rot5)),
        entry(
            "rot47",
            "ROT47 printable-ASCII rotation",
            Cipher,
            rot47,
            Some(rot47),
        ),
        entry(
            "atbash",
            "Atbash alphabet mirror",
            Cipher,
            atbash,
            Some(atbash),
        ),
        entry(
            "reverse",
            "Reverse byte order",
            Cipher,
            reverse,
            Some(reverse),
        ),
        entry(
            "nibble_swap",
            "Swap the nibbles of each byte",
            Cipher,
            nibble_swap,
            Some(nibble_swap),
        ),
        entry(
            "bitwise_not",
            "Invert every bit",
            Cipher,
            bitwise_not,
            Some(bitwise_not),
        ),
        entry(
            "swap_case",
            "Swap the case of ASCII letters",
            Cipher,
            swap_case,
            Some(swap_case),
        ),
        // Digests (raw bytes; chain with `hex` to print).
        entry("md5", "MD5 digest", Hash, md5, None),
        entry("sha1", "SHA-1 digest", Hash, sha1, None),
        entry("sha224", "SHA-224 digest", Hash, sha224, None),
        entry("sha256", "SHA-256 digest", Hash, sha256, None),
        entry("sha384", "SHA-384 digest", Hash, sha384, None),
        entry("sha512", "SHA-512 digest", Hash, sha512, None),
        // Lossy text rewrites.
        entry(
            "upper_case",
            "Uppercase ASCII letters",
            Text,
            upper_case,
            None,
        ),
        entry(
            "lower_case",
            "Lowercase ASCII letters",
            Text,
            lower_case,
            None,
        ),
        entry(
            "leetspeak",
            "Leetspeak character substitution",
            Text,
            leetspeak,
            None,
        ),
        // Structured decoders.
        entry(
            "jwt_decode",
            "Decode a JWT into {header, payload} JSON (no signature check)",
            Other,
            jwt_decode,
            None,
        ),
    ]
}

// --- helpers -----------------------------------------------------------------

/// Input as UTF-8 text.
fn text(input: &[u8]) -> Result<&str, Fault> {
    Ok(str::from_utf8(input)?)
}

/// Input with ASCII whitespace removed, as text.
fn compact(input: &[u8]) -> Result<String, Fault> {
    let kept: Vec<u8> = input
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    String::from_utf8(kept).map_err(|_| Fault::NotUtf8)
}

// --- encodings ---------------------------------------------------------------

fn b64_encode(input: &[u8]) -> Result<Vec<u8>, Fault> {
    Ok(rune_base64::encode(input).into_bytes())
}

fn b64url_encode(input: &[u8]) -> Result<Vec<u8>, Fault> {
    Ok(rune_base64::encode_url(input).into_bytes())
}

fn b64url_nopad_encode(input: &[u8]) -> Result<Vec<u8>, Fault> {
    Ok(rune_base64::encode_url_no_pad(input).into_bytes())
}

/// Base64 decode; the alphabet (standard or URL-safe) and padding are
/// detected, whitespace is ignored.
fn b64_decode(input: &[u8]) -> Result<Vec<u8>, Fault> {
    rune_base64::decode(&compact(input)?).map_err(Fault::malformed)
}

fn b32_encode(input: &[u8]) -> Result<Vec<u8>, Fault> {
    Ok(rune_base32::encode(input).into_bytes())
}

fn b32_decode(input: &[u8]) -> Result<Vec<u8>, Fault> {
    rune_base32::decode(&compact(input)?).map_err(Fault::malformed)
}

fn hex_encode(input: &[u8]) -> Result<Vec<u8>, Fault> {
    Ok(rune_hex::encode(input).into_bytes())
}

fn hex_upper_encode(input: &[u8]) -> Result<Vec<u8>, Fault> {
    Ok(rune_hex::encode_upper(input).into_bytes())
}

fn hex_space_encode(input: &[u8]) -> Result<Vec<u8>, Fault> {
    let parts: Vec<String> = input
        .iter()
        .map(|byte| rune_hex::encode(std::slice::from_ref(byte)))
        .collect();
    Ok(parts.join(" ").into_bytes())
}

fn hex_0x_encode(input: &[u8]) -> Result<Vec<u8>, Fault> {
    Ok(format!("0x{}", rune_hex::encode(input)).into_bytes())
}

/// Hex decode: whitespace ignored, case-insensitive, optional `0x`.
fn hex_decode(input: &[u8]) -> Result<Vec<u8>, Fault> {
    rune_hex::decode(&compact(input)?).map_err(Fault::malformed)
}

fn url_encode(input: &[u8]) -> Result<Vec<u8>, Fault> {
    Ok(rune_url_encode::encode_bytes(input).into_bytes())
}

fn url_decode(input: &[u8]) -> Result<Vec<u8>, Fault> {
    rune_url_encode::decode_bytes(input).map_err(Fault::malformed)
}

fn url_all_encode(input: &[u8]) -> Result<Vec<u8>, Fault> {
    let mut out = String::with_capacity(input.len() * 3);
    for byte in input {
        let _ = write!(out, "%{byte:02X}");
    }
    Ok(out.into_bytes())
}

fn double_url_encode(input: &[u8]) -> Result<Vec<u8>, Fault> {
    url_encode(&url_encode(input)?)
}

fn double_url_decode(input: &[u8]) -> Result<Vec<u8>, Fault> {
    url_decode(&url_decode(input)?)
}

fn html_encode(input: &[u8]) -> Result<Vec<u8>, Fault> {
    Ok(rune_html_encode::encode(text(input)?).into_bytes())
}

/// HTML entity decode (named and numeric).
fn html_decode(input: &[u8]) -> Result<Vec<u8>, Fault> {
    Ok(rune_html_encode::decode(text(input)?).into_bytes())
}

fn html_decimal_encode(input: &[u8]) -> Result<Vec<u8>, Fault> {
    let mut out = String::new();
    for ch in text(input)?.chars() {
        let _ = write!(out, "&#{};", u32::from(ch));
    }
    Ok(out.into_bytes())
}

fn html_hex_encode(input: &[u8]) -> Result<Vec<u8>, Fault> {
    let mut out = String::new();
    for ch in text(input)?.chars() {
        let _ = write!(out, "&#x{:x};", u32::from(ch));
    }
    Ok(out.into_bytes())
}

// --- escapes -----------------------------------------------------------------

fn js_hex_encode(input: &[u8]) -> Result<Vec<u8>, Fault> {
    let mut out = String::with_capacity(input.len() * 4);
    for byte in input {
        let _ = write!(out, "\\x{byte:02x}");
    }
    Ok(out.into_bytes())
}

fn js_hex_decode(input: &[u8]) -> Result<Vec<u8>, Fault> {
    parse_byte_escapes(input, b"\\x", 2, 16)
}

fn js_unicode_encode(input: &[u8]) -> Result<Vec<u8>, Fault> {
    encode_u16_escapes(input, "\\u")
}

fn js_unicode_decode(input: &[u8]) -> Result<Vec<u8>, Fault> {
    parse_u16_escapes(input, b"\\u")
}

fn percent_u_encode(input: &[u8]) -> Result<Vec<u8>, Fault> {
    encode_u16_escapes(input, "%u")
}

fn percent_u_decode(input: &[u8]) -> Result<Vec<u8>, Fault> {
    parse_u16_escapes(input, b"%u")
}

fn octal_encode(input: &[u8]) -> Result<Vec<u8>, Fault> {
    let mut out = String::with_capacity(input.len() * 4);
    for byte in input {
        let _ = write!(out, "\\{byte:03o}");
    }
    Ok(out.into_bytes())
}

fn octal_decode(input: &[u8]) -> Result<Vec<u8>, Fault> {
    parse_byte_escapes(input, b"\\", 3, 8)
}

fn decimal_encode(input: &[u8]) -> Result<Vec<u8>, Fault> {
    let mut out = String::with_capacity(input.len() * 4);
    for byte in input {
        let _ = write!(out, "\\{byte:03}");
    }
    Ok(out.into_bytes())
}

fn decimal_decode(input: &[u8]) -> Result<Vec<u8>, Fault> {
    parse_byte_escapes(input, b"\\", 3, 10)
}

/// The `digits` bytes after `prefix` at the start of `rest`, as text.
fn escape_digits<'a>(rest: &'a [u8], prefix: &[u8], digits: usize) -> Result<&'a str, Fault> {
    let body = rest
        .strip_prefix(prefix)
        .ok_or_else(|| Fault::malformed("expected an escape sequence"))?;
    let digits = body
        .get(..digits)
        .ok_or_else(|| Fault::malformed("truncated escape sequence"))?;
    // `from_str_radix` accepts a leading sign; escapes never have one.
    if digits.iter().any(|byte| !byte.is_ascii_alphanumeric()) {
        return Err(Fault::malformed("invalid digit in escape sequence"));
    }
    text(digits)
}

/// Parse a run of fixed-width byte escapes such as `\x41` or `\101`.
fn parse_byte_escapes(
    input: &[u8],
    prefix: &[u8],
    digits: usize,
    radix: u32,
) -> Result<Vec<u8>, Fault> {
    let mut out = Vec::with_capacity(input.len() / (prefix.len() + digits));
    let mut rest = input;
    while !rest.is_empty() {
        let number = escape_digits(rest, prefix, digits)?;
        out.push(u8::from_str_radix(number, radix).map_err(Fault::malformed)?);
        rest = rest.get(prefix.len() + digits..).unwrap_or_default();
    }
    Ok(out)
}

/// Encode UTF-8 text as four-hex-digit UTF-16 escapes.
fn encode_u16_escapes(input: &[u8], prefix: &str) -> Result<Vec<u8>, Fault> {
    let mut out = String::new();
    for unit in text(input)?.encode_utf16() {
        let _ = write!(out, "{prefix}{unit:04x}");
    }
    Ok(out.into_bytes())
}

/// Parse four-hex-digit UTF-16 escapes back into UTF-8 text.
fn parse_u16_escapes(input: &[u8], prefix: &[u8]) -> Result<Vec<u8>, Fault> {
    let mut units = Vec::with_capacity(input.len() / (prefix.len() + 4));
    let mut rest = input;
    while !rest.is_empty() {
        let number = escape_digits(rest, prefix, 4)?;
        units.push(u16::from_str_radix(number, 16).map_err(Fault::malformed)?);
        rest = rest.get(prefix.len() + 4..).unwrap_or_default();
    }
    String::from_utf16(&units)
        .map(String::into_bytes)
        .map_err(Fault::malformed)
}

// --- numeric -----------------------------------------------------------------

fn binary_encode(input: &[u8]) -> Result<Vec<u8>, Fault> {
    Ok(rune_binary::encode_compact(input).into_bytes())
}

fn binary_spaced_encode(input: &[u8]) -> Result<Vec<u8>, Fault> {
    Ok(rune_binary::encode(input).into_bytes())
}

/// Binary decode; whitespace between groups is ignored.
fn binary_decode(input: &[u8]) -> Result<Vec<u8>, Fault> {
    rune_binary::decode(&compact(input)?).map_err(Fault::malformed)
}

fn ascii_decimal_encode(input: &[u8]) -> Result<Vec<u8>, Fault> {
    let parts: Vec<String> = input.iter().map(ToString::to_string).collect();
    Ok(parts.join(" ").into_bytes())
}

fn ascii_decimal_decode(input: &[u8]) -> Result<Vec<u8>, Fault> {
    text(input)?
        .split_ascii_whitespace()
        .map(|token| {
            if token.bytes().all(|byte| byte.is_ascii_digit()) {
                token.parse::<u8>().map_err(Fault::malformed)
            } else {
                Err(Fault::malformed(format!("not a decimal byte: {token:?}")))
            }
        })
        .collect()
}

// --- ciphers and shuffles ----------------------------------------------------

fn rot13(input: &[u8]) -> Result<Vec<u8>, Fault> {
    Ok(rune_rot13::rot13_bytes(input))
}

fn rot47(input: &[u8]) -> Result<Vec<u8>, Fault> {
    Ok(rune_rot47::rot47_bytes(input))
}

fn atbash(input: &[u8]) -> Result<Vec<u8>, Fault> {
    Ok(rune_atbash::atbash_bytes(input))
}

/// Rotate ASCII digits by five places.
fn rot5(input: &[u8]) -> Result<Vec<u8>, Fault> {
    Ok(input
        .iter()
        .map(|&byte| match byte {
            b'0'..=b'9' => (byte - b'0' + 5) % 10 + b'0',
            other => other,
        })
        .collect())
}

fn reverse(input: &[u8]) -> Result<Vec<u8>, Fault> {
    Ok(input.iter().rev().copied().collect())
}

fn nibble_swap(input: &[u8]) -> Result<Vec<u8>, Fault> {
    Ok(input.iter().map(|&byte| byte.rotate_left(4)).collect())
}

fn bitwise_not(input: &[u8]) -> Result<Vec<u8>, Fault> {
    Ok(input.iter().map(|&byte| !byte).collect())
}

fn swap_case(input: &[u8]) -> Result<Vec<u8>, Fault> {
    Ok(input
        .iter()
        .map(|&byte| {
            if byte.is_ascii_alphabetic() {
                byte ^ 0x20
            } else {
                byte
            }
        })
        .collect())
}

// --- digests -----------------------------------------------------------------

fn md5(input: &[u8]) -> Result<Vec<u8>, Fault> {
    Ok(rune_md5::hash_raw(input).to_vec())
}

fn sha1(input: &[u8]) -> Result<Vec<u8>, Fault> {
    Ok(rune_sha1::hash_raw(input).to_vec())
}

/// SHA-224 has no rune of its own; it comes from `sha2`, like `rune-sha256`.
fn sha224(input: &[u8]) -> Result<Vec<u8>, Fault> {
    Ok(sha2::Sha224::digest(input).to_vec())
}

fn sha256(input: &[u8]) -> Result<Vec<u8>, Fault> {
    Ok(rune_sha256::hash_raw(input).to_vec())
}

/// SHA-384 has no rune of its own; it comes from `sha2`, like `rune-sha512`.
fn sha384(input: &[u8]) -> Result<Vec<u8>, Fault> {
    Ok(sha2::Sha384::digest(input).to_vec())
}

fn sha512(input: &[u8]) -> Result<Vec<u8>, Fault> {
    Ok(rune_sha512::hash_raw(input).to_vec())
}

// --- lossy text --------------------------------------------------------------

fn upper_case(input: &[u8]) -> Result<Vec<u8>, Fault> {
    Ok(input.to_ascii_uppercase())
}

fn lower_case(input: &[u8]) -> Result<Vec<u8>, Fault> {
    Ok(input.to_ascii_lowercase())
}

fn leetspeak(input: &[u8]) -> Result<Vec<u8>, Fault> {
    Ok(input
        .iter()
        .map(|&byte| match byte.to_ascii_lowercase() {
            b'a' => b'4',
            b'b' => b'8',
            b'e' => b'3',
            b'g' => b'9',
            b'i' | b'l' => b'1',
            b'o' => b'0',
            b's' => b'5',
            b't' => b'7',
            b'z' => b'2',
            _ => byte,
        })
        .collect())
}

// --- structured --------------------------------------------------------------

/// Decode a JWT (`header.payload.signature`, or `header.payload`) into
/// pretty-printed `{"header": …, "payload": …}` JSON, via `rune-jwt`.
fn jwt_decode(input: &[u8]) -> Result<Vec<u8>, Fault> {
    let token = text(input)?.trim();
    let token = if token.matches('.').count() == 1 {
        format!("{token}.")
    } else {
        token.to_owned()
    };
    let decoded = rune_jwt::decode(&token).map_err(Fault::malformed)?;
    let combined = serde_json::json!({ "header": decoded.header, "payload": decoded.payload });
    serde_json::to_vec_pretty(&combined).map_err(Fault::malformed)
}
