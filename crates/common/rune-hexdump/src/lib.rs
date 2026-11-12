//! Hex dump with sidebar — inspect binary files like xxd.
//!
//! Formats arbitrary byte slices as a human-readable hex dump. Each row shows
//! the byte offset, hex values grouped in blocks of eight, and an ASCII sidebar
//! where printable characters are shown as-is and non-printable bytes appear as
//! `.`. Output is compatible with the familiar `xxd` layout. The library has
//! zero dependencies.
//!
//! # Features
//!
//! - [`hexdump`] — format bytes with a fully configurable [`HexdumpConfig`].
//! - [`hexdump_default`] — convenience wrapper using the standard 16-byte-wide layout.
//! - [`HexdumpConfig`] — control column width, offset visibility, ASCII sidebar, and case.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_hexdump::hexdump_default;
//!
//! let output = hexdump_default(b"hello, world!\n");
//! assert!(output.starts_with("00000000"));
//! assert!(output.contains("|hello, world!.|"));
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-hexdump myfile.bin        # dump a file
//! cat myfile.bin | rune-hexdump -  # read from stdin
//! rune-hexdump myfile.bin --cols 8 --upper
//! ```

#![cfg_attr(not(any(feature = "std", test)), no_std)]

extern crate alloc;

use alloc::string::String;

use core::fmt::Write as _;

/// Configuration for [`hexdump`] output formatting.
///
/// Use [`HexdumpConfig::default`] to get the standard `xxd`-style layout, then
/// adjust individual fields as needed.
///
/// # Example
///
/// ```rust
/// use rune_hexdump::{hexdump, HexdumpConfig};
///
/// let config = HexdumpConfig { uppercase: true, ..HexdumpConfig::default() };
/// let output = hexdump(b"\xde\xad\xbe\xef", &config);
/// assert!(output.contains("DE AD BE EF"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HexdumpConfig {
    /// Number of bytes displayed per row. Defaults to 16.
    pub bytes_per_row: usize,
    /// Whether to prefix each row with its byte offset. Defaults to `true`.
    pub show_offset: bool,
    /// Whether to append the ASCII sidebar. Defaults to `true`.
    pub show_ascii: bool,
    /// Whether to use uppercase hex digits. Defaults to `false`.
    pub uppercase: bool,
}

impl Default for HexdumpConfig {
    fn default() -> Self {
        Self {
            bytes_per_row: 16,
            show_offset: true,
            show_ascii: true,
            uppercase: false,
        }
    }
}

/// Formats a byte slice as a hex dump using the given [`HexdumpConfig`].
///
/// Each row contains the byte offset (optional), hex values in groups of eight
/// separated by an extra space, and an ASCII sidebar (optional). Partial final
/// rows are padded so the sidebar aligns with full rows.
///
/// Returns an empty string for empty input.
///
/// # Example
///
/// ```rust
/// use rune_hexdump::{hexdump, HexdumpConfig};
///
/// let output = hexdump(b"hello, world!\n", &HexdumpConfig::default());
/// assert!(output.contains("68 65 6c 6c 6f"));
/// assert!(output.contains("|hello, world!.|"));
/// ```
#[must_use]
pub fn hexdump(data: &[u8], config: &HexdumpConfig) -> String {
    if data.is_empty() {
        return String::new();
    }

    let bytes_per_row = config.bytes_per_row.max(1);
    let mut output = String::new();

    for (row_index, row_bytes) in data.chunks(bytes_per_row).enumerate() {
        let offset = row_index * bytes_per_row;

        if config.show_offset {
            let _ = write!(output, "{offset:08x}  ");
        }

        output.push_str(&format_hex_section(
            row_bytes,
            bytes_per_row,
            config.uppercase,
        ));

        if config.show_ascii {
            output.push_str(&format_ascii_sidebar(row_bytes));
        }

        output.push('\n');
    }

    output
}

/// Formats a byte slice as a hex dump using the default 16-byte-wide layout.
///
/// Equivalent to calling `hexdump(data, &HexdumpConfig::default())`.
///
/// # Example
///
/// ```rust
/// use rune_hexdump::hexdump_default;
///
/// let output = hexdump_default(b"AB");
/// assert!(output.starts_with("00000000  41 42"));
/// ```
#[must_use]
pub fn hexdump_default(data: &[u8]) -> String {
    hexdump(data, &HexdumpConfig::default())
}

fn format_hex_section(row_bytes: &[u8], bytes_per_row: usize, uppercase: bool) -> String {
    let half = bytes_per_row / 2;
    let mut section = String::new();

    for (byte_index, byte) in row_bytes.iter().enumerate() {
        if uppercase {
            let _ = write!(section, "{byte:02X}");
        } else {
            let _ = write!(section, "{byte:02x}");
        }
        section.push(' ');

        if half > 0 && byte_index + 1 == half {
            section.push(' ');
        }
    }

    let filled_bytes = row_bytes.len();
    let missing_bytes = bytes_per_row - filled_bytes;

    for missing_index in 0..missing_bytes {
        let absolute_index = filled_bytes + missing_index;
        section.push_str("   ");
        if half > 0 && absolute_index + 1 == half {
            section.push(' ');
        }
    }

    section.push(' ');
    section
}

fn format_ascii_sidebar(row_bytes: &[u8]) -> String {
    let mut sidebar = String::from("|");
    for byte in row_bytes {
        let printable = if (32u8..=126).contains(byte) {
            *byte as char
        } else {
            '.'
        };
        sidebar.push(printable);
    }
    sidebar.push('|');
    sidebar
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_returns_empty_string() {
        assert_eq!(hexdump_default(b""), "");
    }

    #[test]
    fn known_output_hello_world() {
        let output = hexdump_default(b"hello, world!\n");
        assert_eq!(
            output,
            "00000000  68 65 6c 6c 6f 2c 20 77  6f 72 6c 64 21 0a        |hello, world!.|\n"
        );
    }

    #[test]
    fn partial_last_row_pads_correctly() {
        let output = hexdump_default(b"AB");
        assert_eq!(
            output,
            "00000000  41 42                                             |AB|\n"
        );
    }

    #[test]
    fn uppercase_config_works() {
        let config = HexdumpConfig {
            uppercase: true,
            ..HexdumpConfig::default()
        };
        let output = hexdump(b"\xde\xad", &config);
        assert!(output.contains("DE AD"));
        assert!(!output.contains("de ad"));
    }

    #[test]
    fn show_ascii_false_omits_sidebar() {
        let config = HexdumpConfig {
            show_ascii: false,
            ..HexdumpConfig::default()
        };
        let output = hexdump(b"hello", &config);
        assert!(!output.contains('|'));
    }

    #[test]
    fn show_offset_false_omits_offset() {
        let config = HexdumpConfig {
            show_offset: false,
            ..HexdumpConfig::default()
        };
        let output = hexdump(b"hello", &config);
        assert!(!output.starts_with("00000000"));
        assert!(output.starts_with("68"));
    }

    #[test]
    fn eight_bytes_per_row_works() {
        let config = HexdumpConfig {
            bytes_per_row: 8,
            ..HexdumpConfig::default()
        };
        let output = hexdump(b"hello, world!\n", &config);

        assert_eq!(output.lines().count(), 2);
    }

    #[test]
    fn non_printable_bytes_in_sidebar_show_as_dot() {
        let output = hexdump_default(b"\x00\x01\x02\x7f");
        assert!(output.contains("|....|"));
    }

    #[test]
    fn printable_boundary_characters_in_sidebar() {
        let output = hexdump_default(b" ~");
        assert!(output.contains("| ~|"));
    }

    #[test]
    fn full_row_then_partial_row_alignment() {
        let data: Vec<u8> = (0u8..20).collect();
        let output = hexdump_default(&data);
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 2);
        let second_line = lines[1];
        assert!(second_line.contains("00000010"));
        assert!(second_line.ends_with('|'));
    }
}
