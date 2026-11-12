//! JA4T, the TCP client fingerprint, from the client's SYN.
//!
//! Specification: the `FoxIO` JA4+ documentation and reference
//! implementation, <https://github.com/FoxIO-LLC/ja4>. JA4T is part of JA4+
//! (`FoxIO` License 1.1).

use std::fmt::Write as _;

use crate::Error;

/// TCP option kind: end of option list.
const EOL: u8 = 0;
/// TCP option kind: no-operation.
const NOP: u8 = 1;
/// TCP option kind: maximum segment size.
const MSS: u8 = 2;
/// TCP option kind: window scale.
const WINDOW_SCALE: u8 = 3;

/// The fields of a TCP SYN that JA4T reads.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct TcpSyn {
    /// The raw (unscaled) window size from the TCP header.
    pub window_size: u16,
    /// Option kinds in wire order, every `NOP` and trailing `EOL` byte
    /// included.
    pub option_kinds: Vec<u8>,
    /// The maximum segment size option, if present.
    pub mss: Option<u16>,
    /// The window scale shift option, if present.
    pub window_scale: Option<u8>,
}

impl TcpSyn {
    /// A SYN with the given window and no options.
    #[must_use]
    pub const fn new(window_size: u16) -> Self {
        Self {
            window_size,
            option_kinds: Vec::new(),
            mss: None,
            window_scale: None,
        }
    }

    /// Reads the options area of a TCP header (the bytes after the fixed
    /// 20-byte header, up to the data offset).
    ///
    /// `EOL` and `NOP` are one byte each; every byte after an `EOL` is read
    /// as another option kind too, so the padding shows in the fingerprint
    /// as captures show it (`…-4-0-0`).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidTcpOptions`] if an option's length byte is missing,
    /// below 2, or runs past the end, or an MSS or window scale option has
    /// the wrong length.
    ///
    /// ```
    /// use rune_ja::TcpSyn;
    ///
    /// let syn = TcpSyn::parse_options(64240, &[2, 4, 0x05, 0xb4, 1, 3, 3, 8, 1, 1, 4, 2])?;
    /// assert_eq!(syn.option_kinds, [2, 1, 3, 1, 1, 4]);
    /// assert_eq!(syn.mss, Some(1460));
    /// assert_eq!(syn.window_scale, Some(8));
    /// # Ok::<(), rune_ja::Error>(())
    /// ```
    pub fn parse_options(window_size: u16, options: &[u8]) -> Result<Self, Error> {
        let mut syn = Self::new(window_size);
        let mut offset = 0;
        while let Some(&kind) = options.get(offset) {
            syn.option_kinds.push(kind);
            if kind == EOL || kind == NOP {
                offset += 1;
                continue;
            }
            let invalid = |reason| Error::InvalidTcpOptions { offset, reason };
            let len = usize::from(
                *options
                    .get(offset + 1)
                    .ok_or_else(|| invalid("missing length byte"))?,
            );
            if len < 2 {
                return Err(invalid("length below 2"));
            }
            let body = options
                .get(offset + 2..offset + len)
                .ok_or_else(|| invalid("option runs past the end"))?;
            match (kind, body) {
                (MSS, &[hi, lo]) => syn.mss = Some(u16::from_be_bytes([hi, lo])),
                (WINDOW_SCALE, &[shift]) => syn.window_scale = Some(shift),
                (MSS | WINDOW_SCALE, _) => return Err(invalid("bad MSS or window scale length")),
                _ => {}
            }
            offset += len;
        }
        Ok(syn)
    }
}

/// The JA4T fingerprint of a SYN: `window_options_mss_scale`.
///
/// `options` is the option kinds joined with `-` (`00` if there are none),
/// `mss` is the MSS as at least two digits (`00` if absent) and `scale` is
/// the window scale shift (`00` if absent or zero). JA4T has no hashed
/// form.
///
/// ```
/// use rune_ja::{TcpSyn, ja4t};
///
/// let syn = TcpSyn::parse_options(64240, &[2, 4, 0x05, 0xb4, 1, 3, 3, 8, 1, 1, 4, 2])?;
/// assert_eq!(ja4t(&syn), "64240_2-1-3-1-1-4_1460_8");
/// assert_eq!(ja4t(&TcpSyn::new(8192)), "8192_00_00_00");
/// # Ok::<(), rune_ja::Error>(())
/// ```
#[must_use]
pub fn ja4t(syn: &TcpSyn) -> String {
    let mut out = String::new();
    // Writing to a String cannot fail.
    let _ = write!(out, "{}_", syn.window_size);
    if syn.option_kinds.is_empty() {
        out.push_str("00");
    }
    for (i, kind) in syn.option_kinds.iter().enumerate() {
        if i > 0 {
            out.push('-');
        }
        let _ = write!(out, "{kind}");
    }
    let _ = write!(out, "_{:02}_", syn.mss.unwrap_or(0));
    match syn.window_scale {
        None | Some(0) => out.push_str("00"),
        Some(shift) => {
            let _ = write!(out, "{shift}");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference_format_cases() {
        // The FoxIO reference implementation's JA4T formatting tests.
        let syn = TcpSyn {
            window_size: 5744,
            option_kinds: vec![2, 4, 8, 1, 3],
            mss: Some(1436),
            window_scale: Some(0),
        };
        assert_eq!(ja4t(&syn), "5744_2-4-8-1-3_1436_00");
        let syn = TcpSyn {
            window_size: 8192,
            option_kinds: vec![2],
            mss: Some(9),
            window_scale: None,
        };
        assert_eq!(ja4t(&syn), "8192_2_09_00");
    }

    #[test]
    fn eol_padding_is_kept() {
        // macOS SYN: MSS, NOP, WS, NOP, NOP, TS, SACK-permitted, EOL, EOL.
        let options = [
            2, 4, 0x05, 0xb4, 1, 3, 3, 6, 1, 1, 8, 10, 0x78, 0x03, 0x21, 0xb5, 0, 0, 0, 0, 4, 2, 0,
            0,
        ];
        let syn = TcpSyn::parse_options(65535, &options).unwrap();
        assert_eq!(ja4t(&syn), "65535_2-1-3-1-1-8-4-0-0_1460_6");
    }

    #[test]
    fn malformed_options() {
        for (bad, offset) in [
            (&[2][..], 0),
            (&[1, 8, 1], 1),
            (&[8, 10, 0], 0),
            (&[2, 3, 0], 0),
            (&[3, 4, 0, 0], 0),
        ] {
            assert!(
                matches!(
                    TcpSyn::parse_options(0, bad),
                    Err(Error::InvalidTcpOptions { offset: o, .. }) if o == offset
                ),
                "{bad:?}"
            );
        }
    }
}
