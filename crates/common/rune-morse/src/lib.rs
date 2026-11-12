//! Morse code encoder and decoder — ASCII text to dots and dashes and back.
//!
//! Converts between ASCII text and International Morse Code. Letters are
//! separated by a single space; words are separated by ` / `. Both uppercase
//! and lowercase input are accepted during encoding. The library has zero
//! dependencies and works entirely in safe, pure Rust.
//!
//! # Features
//!
//! - [`encode`] — convert ASCII text to Morse code.
//! - [`decode`] — convert Morse code back to ASCII text.
//! - [`MorseError`] — error type for unknown characters or unrecognised sequences.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_morse::{encode, decode};
//!
//! let morse = encode("SOS").unwrap();
//! assert_eq!(morse, "... --- ...");
//!
//! let text = decode("... --- ...").unwrap();
//! assert_eq!(text, "SOS");
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-morse encode "Hello World"
//! rune-morse decode ".... . .-.. .-.. --- / .-- --- .-. .-.. -.."
//! ```

#![cfg_attr(not(any(feature = "std", test)), no_std)]

extern crate alloc;

use alloc::borrow::ToOwned;
use alloc::string::String;
use alloc::vec::Vec;

use core::fmt;

static MORSE_TABLE: &[(char, &str)] = &[
    ('A', ".-"),
    ('B', "-..."),
    ('C', "-.-."),
    ('D', "-.."),
    ('E', "."),
    ('F', "..-."),
    ('G', "--."),
    ('H', "...."),
    ('I', ".."),
    ('J', ".---"),
    ('K', "-.-"),
    ('L', ".-.."),
    ('M', "--"),
    ('N', "-."),
    ('O', "---"),
    ('P', ".--."),
    ('Q', "--.-"),
    ('R', ".-."),
    ('S', "..."),
    ('T', "-"),
    ('U', "..-"),
    ('V', "...-"),
    ('W', ".--"),
    ('X', "-..-"),
    ('Y', "-.--"),
    ('Z', "--.."),
    ('0', "-----"),
    ('1', ".----"),
    ('2', "..---"),
    ('3', "...--"),
    ('4', "....-"),
    ('5', "....."),
    ('6', "-...."),
    ('7', "--..."),
    ('8', "---.."),
    ('9', "----."),
];

/// Error returned when encoding or decoding encounters unexpected input.
#[derive(Debug, PartialEq, Eq)]
pub enum MorseError {
    /// A character in the source text has no Morse representation.
    UnknownChar(char),
    /// A dot-dash sequence does not match any known Morse code.
    UnknownCode(String),
}

impl fmt::Display for MorseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownChar(ch) => write!(f, "no Morse code for character: {ch:?}"),
            Self::UnknownCode(code) => write!(f, "unknown Morse sequence: {code:?}"),
        }
    }
}

impl core::error::Error for MorseError {}

/// Encodes ASCII `text` as Morse code.
///
/// Letters are converted to uppercase before lookup. Individual letter codes
/// are joined by a single space; words (separated by ASCII spaces in the
/// input) are separated by ` / ` in the output. An empty string returns an
/// empty string without error.
///
/// # Errors
///
/// Returns [`MorseError::UnknownChar`] for any character that has no Morse
/// representation (e.g. punctuation other than digits and letters).
///
/// # Examples
///
/// ```rust
/// use rune_morse::encode;
///
/// assert_eq!(encode("SOS").unwrap(), "... --- ...");
/// assert_eq!(encode("sos").unwrap(), "... --- ...");
/// assert_eq!(encode("HI MOM").unwrap(), ".... .. / -- --- --");
/// assert_eq!(encode("").unwrap(), "");
/// ```
pub fn encode(text: &str) -> Result<String, MorseError> {
    if text.is_empty() {
        return Ok(String::new());
    }

    let words: Result<Vec<String>, MorseError> = text.split(' ').map(encode_word).collect();

    Ok(words?.join(" / "))
}

/// Decodes Morse code back to uppercase ASCII text.
///
/// Letter codes must be separated by single spaces. Word boundaries must be
/// marked with ` / ` (space-slash-space). An empty string returns an empty
/// string without error, and an empty word between separators decodes to an
/// empty word, so `decode(&encode(text)?)` returns `text` upper-cased even
/// when it has leading, trailing or repeated spaces.
///
/// # Errors
///
/// Returns [`MorseError::UnknownCode`] for any dot-dash sequence that does
/// not appear in the standard International Morse table.
///
/// # Examples
///
/// ```rust
/// use rune_morse::decode;
///
/// assert_eq!(decode("... --- ...").unwrap(), "SOS");
/// assert_eq!(decode(".... .. / -- --- --").unwrap(), "HI MOM");
/// assert_eq!(decode("").unwrap(), "");
/// ```
pub fn decode(morse: &str) -> Result<String, MorseError> {
    if morse.is_empty() {
        return Ok(String::new());
    }

    morse
        .split(" / ")
        .map(decode_word)
        .collect::<Result<Vec<String>, MorseError>>()
        .map(|words| words.join(" "))
}

fn encode_word(word: &str) -> Result<String, MorseError> {
    let codes: Result<Vec<&str>, MorseError> = word
        .chars()
        .map(|ch| char_to_morse(ch.to_ascii_uppercase()))
        .collect();
    Ok(codes?.join(" "))
}

fn decode_word(word: &str) -> Result<String, MorseError> {
    // `encode` turns leading, trailing and repeated spaces into empty words;
    // decode them back to empty words so the round trip holds.
    if word.is_empty() {
        return Ok(String::new());
    }
    word.split(' ').map(morse_to_char).collect()
}

fn char_to_morse(ch: char) -> Result<&'static str, MorseError> {
    MORSE_TABLE
        .iter()
        .find(|(letter, _)| *letter == ch)
        .map(|(_, code)| *code)
        .ok_or(MorseError::UnknownChar(ch))
}

fn morse_to_char(code: &str) -> Result<char, MorseError> {
    MORSE_TABLE
        .iter()
        .find(|(_, morse)| *morse == code)
        .map(|(letter, _)| *letter)
        .ok_or_else(|| MorseError::UnknownCode(code.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_sos() {
        assert_eq!(encode("SOS").unwrap(), "... --- ...");
    }

    #[test]
    fn encode_lowercase_treated_as_uppercase() {
        assert_eq!(encode("sos").unwrap(), "... --- ...");
    }

    #[test]
    fn encode_hello_world() {
        assert_eq!(
            encode("HELLO WORLD").unwrap(),
            ".... . .-.. .-.. --- / .-- --- .-. .-.. -.."
        );
    }

    #[test]
    fn decode_sos() {
        assert_eq!(decode("... --- ...").unwrap(), "SOS");
    }

    #[test]
    fn decode_hello_world() {
        assert_eq!(
            decode(".... . .-.. .-.. --- / .-- --- .-. .-.. -..").unwrap(),
            "HELLO WORLD"
        );
    }

    #[test]
    fn roundtrip_letters_and_digits() {
        let original = "THE QUICK BROWN FOX 123";
        let encoded = encode(original).unwrap();
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn roundtrip_lowercase_normalised() {
        let encoded = encode("hello world").unwrap();
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, "HELLO WORLD");
    }

    #[test]
    fn encode_unknown_char_returns_error() {
        assert!(matches!(
            encode("HI!").unwrap_err(),
            MorseError::UnknownChar('!')
        ));
    }

    #[test]
    fn decode_unknown_code_returns_error() {
        assert!(matches!(
            decode("....----").unwrap_err(),
            MorseError::UnknownCode(ref code) if code == "....----"
        ));
    }

    #[test]
    fn encode_empty_string() {
        assert_eq!(encode("").unwrap(), "");
    }

    #[test]
    fn decode_empty_string() {
        assert_eq!(decode("").unwrap(), "");
    }

    #[test]
    fn encode_digits() {
        assert_eq!(encode("42").unwrap(), "....- ..---");
    }

    #[test]
    fn decode_digits() {
        assert_eq!(decode("....- ..---").unwrap(), "42");
    }
}
