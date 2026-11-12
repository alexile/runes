//! Extract printable ASCII strings from binary data, like the Unix `strings` utility.
//!
//! Scans byte slices for contiguous runs of printable ASCII characters (0x20–0x7E)
//! and returns each run that meets a configurable minimum length. Useful for quick
//! triage of binaries, firmware images, and captured network traffic.
//!
//! # Features
//!
//! - [`extract`] — configurable minimum length and offset tracking.
//! - [`extract_default`] — zero-config convenience that returns plain strings.
//! - [`StringsConfig`] — tune minimum run length and whether offsets are recorded.
//! - [`ExtractedString`] — pairs a byte offset with the string text.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_strings::extract_default;
//!
//! let data = b"\x00\x01hello\x00world\x02\x03hi\x00";
//! let strings = extract_default(data);
//! assert_eq!(strings, vec!["hello", "world"]);
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-strings firmware.bin
//! rune-strings firmware.bin -n 8
//! rune-strings firmware.bin -o
//! cat firmware.bin | rune-strings -
//! ```

#![cfg_attr(not(any(feature = "std", test)), no_std)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

/// Configuration that controls how printable-string extraction behaves.
///
/// Pass a value of this type to [`extract`] to tune minimum run length and
/// whether byte offsets are recorded in the returned [`ExtractedString`]s.
///
/// # Examples
///
/// ```rust
/// use rune_strings::StringsConfig;
///
/// let config = StringsConfig { min_length: 8, include_offset: true };
/// assert_eq!(config.min_length, 8);
/// assert!(config.include_offset);
/// ```
#[derive(Debug, Clone)]
pub struct StringsConfig {
    /// Minimum number of consecutive printable bytes required to emit a string.
    /// Runs shorter than this are silently discarded.
    pub min_length: usize,
    /// When `true`, the [`ExtractedString::offset`] field holds the byte position
    /// of the first character in the source slice.
    pub include_offset: bool,
}

impl Default for StringsConfig {
    fn default() -> Self {
        Self {
            min_length: 4,
            include_offset: false,
        }
    }
}

/// A printable-ASCII run found inside a byte slice.
///
/// Returned by [`extract`]. The `offset` field is the index of the first byte
/// of the run in the original slice; `text` contains the characters as a `String`.
///
/// # Examples
///
/// ```rust
/// use rune_strings::{extract, StringsConfig};
///
/// let config = StringsConfig { min_length: 4, include_offset: true };
/// let found = extract(b"\x00hello\x00", &config);
/// assert_eq!(found[0].offset, 1);
/// assert_eq!(found[0].text, "hello");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedString {
    /// Byte offset of the first character of this run within the scanned slice.
    pub offset: usize,
    /// The printable characters that form this run.
    pub text: String,
}

/// Extracts printable-ASCII strings from `data` according to `config`.
///
/// Scans `data` byte by byte, accumulating consecutive printable ASCII bytes
/// (codepoints 0x20 through 0x7E inclusive). Each time a non-printable byte
/// breaks the run, the accumulated text is emitted as an [`ExtractedString`]
/// if it meets or exceeds [`StringsConfig::min_length`]. The last run is
/// flushed at the end of `data`.
///
/// # Examples
///
/// ```rust
/// use rune_strings::{extract, StringsConfig};
///
/// let config = StringsConfig::default();
/// let found = extract(b"\x00\x01hello world\x00", &config);
/// assert_eq!(found.len(), 1);
/// assert_eq!(found[0].text, "hello world");
///
/// let config_long = StringsConfig { min_length: 20, include_offset: false };
/// let none_found = extract(b"short", &config_long);
/// assert!(none_found.is_empty());
/// ```
#[must_use]
pub fn extract(data: &[u8], config: &StringsConfig) -> Vec<ExtractedString> {
    let mut results = Vec::new();
    let mut run_start = 0usize;
    let mut run: Vec<u8> = Vec::new();

    for (index, &byte) in data.iter().enumerate() {
        if is_printable(byte) {
            if run.is_empty() {
                run_start = index;
            }
            run.push(byte);
        } else {
            flush_run(&mut run, run_start, config, &mut results);
        }
    }
    flush_run(&mut run, run_start, config, &mut results);

    results
}

/// Extracts printable-ASCII strings using default settings (minimum length 4).
///
/// A convenience wrapper around [`extract`] with a default [`StringsConfig`].
/// Returns plain `String` values without byte offsets.
///
/// # Examples
///
/// ```rust
/// use rune_strings::extract_default;
///
/// let strings = extract_default(b"\x00\x01AAAA\x00BB\x00CCCCCC\x00");
/// assert_eq!(strings, vec!["AAAA", "CCCCCC"]);
/// ```
#[must_use]
pub fn extract_default(data: &[u8]) -> Vec<String> {
    extract(data, &StringsConfig::default())
        .into_iter()
        .map(|extracted| extracted.text)
        .collect()
}

fn is_printable(byte: u8) -> bool {
    (0x20..=0x7e).contains(&byte)
}

fn flush_run(
    run: &mut Vec<u8>,
    run_start: usize,
    config: &StringsConfig,
    results: &mut Vec<ExtractedString>,
) {
    if run.len() >= config.min_length {
        results.push(ExtractedString {
            offset: run_start,
            // The run holds printable ASCII only, so the lossy decode is exact.
            text: String::from_utf8_lossy(run).into_owned(),
        });
    }
    run.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_returns_empty_vec() {
        assert_eq!(
            extract(b"", &StringsConfig::default()),
            [] as [ExtractedString; 0]
        );
    }

    #[test]
    fn known_strings_are_found() {
        let data = b"\x00\x01hello\x00world\x00";
        let strings = extract_default(data);
        assert_eq!(strings, vec!["hello", "world"]);
    }

    #[test]
    fn short_run_below_min_length_is_skipped() {
        let data = b"\x00\x01hi\x00";
        let strings = extract_default(data);
        assert_eq!(strings, [] as [String; 0]);
    }

    #[test]
    fn exact_min_length_is_included() {
        let data = b"\x00\x01abcd\x00";
        let config = StringsConfig {
            min_length: 4,
            include_offset: false,
        };
        let found = extract(data, &config);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].text, "abcd");
    }

    #[test]
    fn non_printable_bytes_separate_strings() {
        let data = b"hello\x00world";
        let strings = extract_default(data);
        assert_eq!(strings, vec!["hello", "world"]);
    }

    #[test]
    fn extract_default_returns_strings_without_offsets() {
        let data = b"\x00hello world\x00";
        let strings = extract_default(data);
        assert_eq!(strings, vec!["hello world"]);
    }

    #[test]
    fn offset_is_correct_byte_position() {
        let data = b"\x00\x00\x00hello\x00";
        let config = StringsConfig {
            min_length: 4,
            include_offset: true,
        };
        let found = extract(data, &config);
        assert_eq!(found[0].offset, 3);
    }

    #[test]
    fn min_length_default_is_4() {
        let config = StringsConfig::default();
        assert_eq!(config.min_length, 4);
    }

    #[test]
    fn run_at_end_of_data_is_flushed() {
        let data = b"\x00hello";
        let strings = extract_default(data);
        assert_eq!(strings, vec!["hello"]);
    }

    #[test]
    fn all_printable_input_is_one_string() {
        let data = b"hello world";
        let strings = extract_default(data);
        assert_eq!(strings, vec!["hello world"]);
    }

    #[test]
    fn custom_min_length_filters_correctly() {
        let data = b"\x00\x01abcd\x00abcdefgh\x00";
        let config = StringsConfig {
            min_length: 8,
            include_offset: false,
        };
        let found = extract(data, &config);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].text, "abcdefgh");
    }
}
