//! ASCII table lookup and character conversion — decimal, hex, octal, binary, and char.
//!
//! Provides a complete reference for all 128 ASCII code points, including control
//! character names (NUL, SOH, STX…) and printable character descriptions. Useful
//! for security research, CTF challenges, and any tool that needs to inspect or
//! convert between ASCII representations. The library has zero dependencies.
//!
//! # Features
//!
//! - [`lookup`] — look up any code point 0–127 by its decimal value.
//! - [`from_char`] — look up a printable character (32–126) by its `char` value.
//! - [`table`] — retrieve all 128 entries at once.
//! - [`parse_input`] — smart parser that accepts decimal, `0x` hex, `0o` octal,
//!   `0b` binary, or a single printable character.
//! - [`AsciiEntry`] — structured result with every representation of a code point.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_ascii::{lookup, parse_input};
//!
//! let entry = lookup(65).unwrap();
//! assert_eq!(entry.character, 'A');
//! assert_eq!(entry.hex, "0x41");
//!
//! let entry = parse_input("0x41").unwrap();
//! assert_eq!(entry.code, 65);
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-ascii 65        # look up by decimal
//! rune-ascii 0x41      # look up by hex
//! rune-ascii A         # look up by character
//! rune-ascii --table   # print full ASCII table
//! ```

#![cfg_attr(not(any(feature = "std", test)), no_std)]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

static DESCRIPTIONS: [&str; 128] = [
    "NUL", "SOH", "STX", "ETX", "EOT", "ENQ", "ACK", "BEL", "BS", "HT", "LF", "VT", "FF", "CR",
    "SO", "SI", "DLE", "DC1", "DC2", "DC3", "DC4", "NAK", "SYN", "ETB", "CAN", "EM", "SUB", "ESC",
    "FS", "GS", "RS", "US", "SP", "!", "\"", "#", "$", "%", "&", "'", "(", ")", "*", "+", ",", "-",
    ".", "/", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", ":", ";", "<", "=", ">", "?", "@",
    "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S",
    "T", "U", "V", "W", "X", "Y", "Z", "[", "\\", "]", "^", "_", "`", "a", "b", "c", "d", "e", "f",
    "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y",
    "z", "{", "|", "}", "~", "DEL",
];

/// A single ASCII code point with all its representations.
///
/// Returned by [`lookup`], [`from_char`], and [`parse_input`]. Every field is
/// pre-formatted so callers can display or compare values without additional
/// formatting work.
///
/// The `character` field uses `'?'` for non-printable code points (0–31 and
/// 127); consult `description` for the canonical control-character name.
///
/// # Example
///
/// ```rust
/// use rune_ascii::lookup;
///
/// let entry = lookup(9).unwrap();
/// assert_eq!(entry.description, "HT");
/// assert_eq!(entry.binary, "00001001");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsciiEntry {
    /// Decimal code point (0–127).
    pub code: u8,
    /// Printable character, or `'?'` for control characters and DEL.
    pub character: char,
    /// Hex representation, e.g. `"0x41"`.
    pub hex: String,
    /// Octal representation, e.g. `"0o101"`.
    pub octal: String,
    /// 8-bit binary string, e.g. `"01000001"`.
    pub binary: String,
    /// Short name or glyph: control names like `"NUL"`, `"LF"`, or the
    /// printable character itself like `"A"`.
    pub description: &'static str,
}

/// Returns the [`AsciiEntry`] for a code point in the range 0–127.
///
/// Returns `None` for values 128–255, which are outside standard ASCII.
///
/// # Example
///
/// ```rust
/// use rune_ascii::lookup;
///
/// let entry = lookup(65).unwrap();
/// assert_eq!(entry.character, 'A');
/// assert_eq!(entry.hex, "0x41");
/// assert_eq!(entry.octal, "0o101");
/// assert_eq!(entry.binary, "01000001");
///
/// assert!(lookup(200).is_none());
/// ```
#[must_use]
pub fn lookup(code: u8) -> Option<AsciiEntry> {
    if code > 127 {
        return None;
    }
    Some(build_entry(code))
}

/// Returns the [`AsciiEntry`] for a printable ASCII character (code points 32–126).
///
/// Returns `None` for characters outside the printable ASCII range, including
/// control characters, DEL (127), and any non-ASCII Unicode character.
///
/// # Example
///
/// ```rust
/// use rune_ascii::from_char;
///
/// let entry = from_char('A').unwrap();
/// assert_eq!(entry.code, 65);
///
/// assert!(from_char('\n').is_none());
/// assert!(from_char('é').is_none());
/// ```
#[must_use]
pub fn from_char(ch: char) -> Option<AsciiEntry> {
    u8::try_from(ch)
        .ok()
        .filter(|code| (32..=126).contains(code))
        .map(build_entry)
}

/// Returns all 128 ASCII entries in code-point order (0–127).
///
/// # Example
///
/// ```rust
/// use rune_ascii::table;
///
/// let entries = table();
/// assert_eq!(entries.len(), 128);
/// assert_eq!(entries[65].character, 'A');
/// ```
pub fn table() -> Vec<AsciiEntry> {
    (0u8..=127).map(build_entry).collect()
}

/// Parses a flexible input string and returns the matching [`AsciiEntry`].
///
/// The following formats are accepted, tried in order:
///
/// - A single printable character, including a lone space — delegates to
///   [`from_char`]. Surrounding whitespace is otherwise trimmed.
/// - A string starting with `"0x"` or `"0X"` — parsed as hexadecimal.
/// - A string starting with `"0o"` or `"0O"` — parsed as octal.
/// - A string starting with `"0b"` or `"0B"` — parsed as binary.
/// - Any other string — parsed as a decimal integer.
///
/// Numbers are plain digits in the given radix; a sign is not accepted.
/// Returns `None` if the input cannot be parsed or the resulting code point
/// is outside 0–127.
///
/// # Example
///
/// ```rust
/// use rune_ascii::parse_input;
///
/// assert_eq!(parse_input("65").unwrap().character,  'A');
/// assert_eq!(parse_input("0x41").unwrap().character, 'A');
/// assert_eq!(parse_input("0o101").unwrap().character, 'A');
/// assert_eq!(parse_input("0b01000001").unwrap().character, 'A');
/// assert_eq!(parse_input("A").unwrap().code,  65);
///
/// assert!(parse_input("999").is_none());
/// assert!(parse_input("xyz").is_none());
/// ```
#[must_use]
pub fn parse_input(input: &str) -> Option<AsciiEntry> {
    // A lone space is the printable character SP, so check for a single
    // character before trimming whitespace away.
    if let Some(entry) = single_char(input).and_then(from_char) {
        return Some(entry);
    }

    let trimmed = input.trim();
    if let Some(entry) = single_char(trimmed).and_then(from_char) {
        return Some(entry);
    }

    let (digits, radix) = [('x', 16), ('o', 8), ('b', 2)]
        .into_iter()
        .find_map(|(letter, radix)| Some((strip_prefix_ci(trimmed, letter)?, radix)))
        .unwrap_or((trimmed, 10));

    // `from_str_radix` accepts a leading `+`; only plain digits are numbers.
    if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
        return None;
    }
    lookup(u8::from_str_radix(digits, radix).ok()?)
}

/// Returns the only character of `text`, or `None` if it has zero or several.
fn single_char(text: &str) -> Option<char> {
    let mut chars = text.chars();
    let first = chars.next()?;
    chars.next().is_none().then_some(first)
}

/// Strips a `0x`-style prefix whose letter is `lower` in either case.
fn strip_prefix_ci(text: &str, lower: char) -> Option<&str> {
    let rest = text.strip_prefix('0')?;
    rest.strip_prefix(lower)
        .or_else(|| rest.strip_prefix(lower.to_ascii_uppercase()))
}

fn build_entry(code: u8) -> AsciiEntry {
    let character = if (32..=126).contains(&code) {
        code as char
    } else {
        '?'
    };

    let hex = format!("{code:#04x}");
    let octal = format!("{code:#05o}");
    let binary = format!("{code:08b}");
    let description = DESCRIPTIONS[usize::from(code)];

    AsciiEntry {
        code,
        character,
        hex,
        octal,
        binary,
        description,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_letter_a() {
        let entry = lookup(65).unwrap();
        assert_eq!(entry.code, 65);
        assert_eq!(entry.character, 'A');
        assert_eq!(entry.hex, "0x41");
        assert_eq!(entry.octal, "0o101");
        assert_eq!(entry.binary, "01000001");
        assert_eq!(entry.description, "A");
    }

    #[test]
    fn lookup_out_of_range_returns_none() {
        assert!(lookup(200).is_none());
        assert!(lookup(128).is_none());
        assert!(lookup(255).is_none());
    }

    #[test]
    fn lookup_control_nul() {
        let entry = lookup(0).unwrap();
        assert_eq!(entry.code, 0);
        assert_eq!(entry.character, '?');
        assert_eq!(entry.description, "NUL");
    }

    #[test]
    fn lookup_del() {
        let entry = lookup(127).unwrap();
        assert_eq!(entry.description, "DEL");
        assert_eq!(entry.character, '?');
    }

    #[test]
    fn from_char_letter_a() {
        let entry = from_char('A').unwrap();
        assert_eq!(entry.code, 65);
    }

    #[test]
    fn from_char_control_returns_none() {
        assert!(from_char('\n').is_none());
        assert!(from_char('\x00').is_none());
    }

    #[test]
    fn from_char_non_ascii_returns_none() {
        assert!(from_char('é').is_none());
    }

    #[test]
    fn table_has_128_entries() {
        let entries = table();
        assert_eq!(entries.len(), 128);
    }

    #[test]
    fn table_entries_ordered_by_code() {
        let entries = table();
        for (index, entry) in entries.iter().enumerate() {
            assert_eq!(entry.code as usize, index);
        }
    }

    #[test]
    fn parse_input_decimal() {
        let entry = parse_input("65").unwrap();
        assert_eq!(entry.code, 65);
    }

    #[test]
    fn parse_input_hex() {
        let entry = parse_input("0x41").unwrap();
        assert_eq!(entry.code, 65);
    }

    #[test]
    fn parse_input_octal() {
        let entry = parse_input("0o101").unwrap();
        assert_eq!(entry.code, 65);
    }

    #[test]
    fn parse_input_binary() {
        let entry = parse_input("0b01000001").unwrap();
        assert_eq!(entry.code, 65);
    }

    #[test]
    fn parse_input_single_char() {
        let entry = parse_input("A").unwrap();
        assert_eq!(entry.code, 65);
    }

    #[test]
    fn parse_input_out_of_range_returns_none() {
        assert!(parse_input("999").is_none());
    }

    #[test]
    fn parse_input_invalid_returns_none() {
        assert!(parse_input("xyz").is_none());
    }

    // Regression: the input was trimmed before the single-character
    // check, so a lone space (SP, printable) was rejected.
    #[test]
    fn parse_input_lone_space() {
        assert_eq!(parse_input(" ").unwrap().code, 32);
        assert_eq!(parse_input(" A ").unwrap().code, 65);
    }

    // Regression: `from_str_radix` accepts a leading `+`, so `+65`,
    // `0x+41` and `0b+1000001` used to parse.
    #[test]
    fn parse_input_rejects_signs() {
        assert!(parse_input("+65").is_none());
        assert!(parse_input("0x+41").is_none());
        assert!(parse_input("0b+1000001").is_none());
        assert!(parse_input("0x").is_none());
        assert!(parse_input("").is_none());
    }

    #[test]
    fn control_descriptions_correct() {
        assert_eq!(lookup(7).unwrap().description, "BEL");
        assert_eq!(lookup(9).unwrap().description, "HT");
        assert_eq!(lookup(10).unwrap().description, "LF");
        assert_eq!(lookup(13).unwrap().description, "CR");
        assert_eq!(lookup(27).unwrap().description, "ESC");
        assert_eq!(lookup(32).unwrap().description, "SP");
    }
}
