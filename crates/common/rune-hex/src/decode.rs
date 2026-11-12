//! Decoding: a block decoder for plain hex and a byte-at-a-time state
//! machine for tolerant input and streams.

#[cfg(feature = "alloc")]
use alloc::{vec, vec::Vec};

use crate::HexError;

const LANES: u64 = 0x0101_0101_0101_0101;
const HIGH: u64 = LANES * 0x80;
const NIBBLES: u64 = LANES * 0x0f;

/// Decodes eight hex digits into four bytes.
///
/// The second value is non-zero when any of the eight input bytes is not a
/// hex digit; the first is then meaningless. Uses only arithmetic, so the
/// running time does not depend on the input.
#[inline]
#[allow(clippy::many_single_char_names)] // bit-twiddling reads best with short names
const fn decode_block(src: [u8; 8]) -> (u32, u64) {
    let c = u64::from_be_bytes(src);
    // Range checks on the low seven bits of each lane. Bit 7 of a lane in
    // `x + k` tells whether `x + k >= 0x80`; no lane can carry into the next.
    let x = c & !HIGH;
    let digit = (x + LANES * 0x50) & !(x + LANES * 0x46); // '0'..='9'
    let l = x | (LANES * 0x20); // fold 'A'..='F' onto 'a'..='f'
    let alpha = (l + LANES * 0x1f) & !(l + LANES * 0x19); // 'a'..='f'
    let bad = ((digit | alpha) & !c & HIGH) ^ HIGH;

    let v = (x & NIBBLES) + ((alpha & HIGH) >> 7) * 9;
    // Pair up nibbles, then squeeze the four bytes together.
    let y = ((v >> 4) | v) & 0x00ff_00ff_00ff_00ff;
    let y = (y | (y >> 8)) & 0x0000_ffff_0000_ffff;
    let y = (y | (y >> 16)) & 0xffff_ffff;
    #[allow(clippy::cast_possible_truncation)] // masked to 32 bits above
    (y as u32, bad)
}

/// Decodes up to eight digits (an even number), padding with `'0'`.
#[inline]
fn decode_short(src: &[u8], out: &mut [u8]) -> u64 {
    let mut block = [b'0'; 8];
    block[..src.len()].copy_from_slice(src);
    let (bytes, bad) = decode_block(block);
    out.copy_from_slice(&bytes.to_be_bytes()[..out.len()]);
    bad
}

/// Decodes `src` into `out` (exactly half as long) without data-dependent
/// branches. Returns `false` if any input byte is not a hex digit.
pub fn decode_ct(src: &[u8], out: &mut [u8]) -> bool {
    debug_assert_eq!(src.len(), out.len() * 2);
    let mut bad = 0;
    let (blocks, tail) = src.as_chunks::<8>();
    let (out_blocks, out_tail) = out.as_chunks_mut::<4>();
    for (s, o) in blocks.iter().zip(out_blocks) {
        let (bytes, b) = decode_block(*s);
        *o = bytes.to_be_bytes();
        bad |= b;
    }
    bad |= decode_short(tail, out_tail);
    bad == 0
}

/// Decodes `src` into `out` (exactly half as long). On failure returns the
/// index of the first byte that is not a hex digit.
///
/// Checking once at the end is faster than bailing out early, and errors are
/// the rare case.
pub fn decode_fast(src: &[u8], out: &mut [u8]) -> Result<(), usize> {
    if decode_ct(src, out) {
        Ok(())
    } else {
        Err(src
            .iter()
            .position(|b| !b.is_ascii_hexdigit())
            .unwrap_or_default())
    }
}

/// Options for decoding less tidy hex.
///
/// [`DecodeOptions::new`] is strict: digits only, no prefix, no whitespace.
/// Each relaxation is opt-in. Whitespace and separators are skipped only
/// between bytes; one that splits the two digits of a byte is an error, so
/// `"de ad"` decodes but `"d ead"` does not.
///
/// [`decode`](crate::decode) is the same as
/// `DecodeOptions::new().allow_prefix(true).decode(..)`.
///
/// # Examples
///
/// ```rust
/// use rune_hex::DecodeOptions;
///
/// // A certificate fingerprint as printed by many tools.
/// let opts = DecodeOptions::new().separator(b':');
/// assert_eq!(opts.decode("DE:AD:BE:EF")?, [0xde, 0xad, 0xbe, 0xef]);
///
/// // Wrapped output from `xxd -p` or a hex dump pasted into a config file.
/// let opts = DecodeOptions::new().skip_whitespace(true);
/// assert_eq!(opts.decode("dead\nbeef\n")?, [0xde, 0xad, 0xbe, 0xef]);
///
/// // Everything at once.
/// assert_eq!(DecodeOptions::lenient().decode(" 0xde-ad:be ef ")?, [0xde, 0xad, 0xbe, 0xef]);
/// # Ok::<(), rune_hex::HexError>(())
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[must_use]
pub struct DecodeOptions {
    prefix: bool,
    whitespace: bool,
    /// Bit `b` is set when ASCII byte `b` is a separator.
    separators: u128,
}

impl DecodeOptions {
    /// Strict decoding: an even number of hex digits and nothing else.
    pub const fn new() -> Self {
        Self {
            prefix: false,
            whitespace: false,
            separators: 0,
        }
    }

    /// Accepts the `0x` prefix, ASCII whitespace, and `:` and `-` between
    /// bytes.
    pub const fn lenient() -> Self {
        Self::new()
            .allow_prefix(true)
            .skip_whitespace(true)
            .separator(b':')
            .separator(b'-')
    }

    /// Accepts one leading `0x` or `0X`. With whitespace or separators
    /// enabled, those may come before the prefix.
    pub const fn allow_prefix(mut self, allow: bool) -> Self {
        self.prefix = allow;
        self
    }

    /// Skips ASCII whitespace (space, tab, line feed, form feed, carriage
    /// return) between bytes.
    pub const fn skip_whitespace(mut self, skip: bool) -> Self {
        self.whitespace = skip;
        self
    }

    /// Skips `byte` between bytes. Can be called several times.
    ///
    /// Only ASCII bytes can be separators; hex digits always decode as
    /// digits, and non-ASCII bytes are ignored here.
    pub const fn separator(mut self, byte: u8) -> Self {
        if byte.is_ascii() {
            self.separators |= 1 << byte;
        }
        self
    }

    /// Whether `0x` is accepted.
    #[must_use]
    pub const fn allows_prefix(&self) -> bool {
        self.prefix
    }

    /// Whether `byte` is skipped between bytes.
    #[must_use]
    pub const fn skips(&self, byte: u8) -> bool {
        (self.whitespace && byte.is_ascii_whitespace())
            || (byte.is_ascii() && (self.separators >> byte) & 1 == 1)
    }

    const fn skips_anything(&self) -> bool {
        self.whitespace || self.separators != 0
    }

    /// Splits off the prefix, returning the body and its offset.
    const fn strip<'a>(&self, hex: &'a [u8]) -> (&'a [u8], usize) {
        match hex {
            [b'0', b'x' | b'X', body @ ..] if self.prefix => (body, 2),
            _ => (hex, 0),
        }
    }

    /// Strips the prefix and checks the length for the plain fast path.
    const fn plain_body<'a>(&self, hex: &'a [u8]) -> Result<(&'a [u8], usize), HexError> {
        let (body, skip) = self.strip(hex);
        if body.len() % 2 == 1 {
            return Err(HexError::OddLength);
        }
        Ok((body, skip))
    }

    /// Decodes `hex` to a byte vector.
    ///
    /// # Errors
    ///
    /// [`HexError::OddLength`] or [`HexError::InvalidByte`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_hex::{DecodeOptions, HexError};
    ///
    /// let opts = DecodeOptions::new().skip_whitespace(true);
    /// assert_eq!(opts.decode("01 02")?, [1, 2]);
    /// assert_eq!(opts.decode("0 102"), Err(HexError::InvalidByte { byte: b' ', offset: 1 }));
    /// # Ok::<(), HexError>(())
    /// ```
    #[cfg(feature = "alloc")]
    pub fn decode(&self, hex: impl AsRef<[u8]>) -> Result<Vec<u8>, HexError> {
        let hex = hex.as_ref();
        if self.skips_anything() {
            let mut out = Vec::with_capacity(hex.len() / 2);
            let mut machine = Machine::new(*self);
            machine.feed(hex, |b| out.push(b))?;
            machine.finish()?;
            return Ok(out);
        }
        let (body, skip) = self.plain_body(hex)?;
        let mut out = vec![0; body.len() / 2];
        decode_fast(body, &mut out).map_err(|i| invalid(body, i, skip))?;
        Ok(out)
    }

    /// Decodes `hex` into `out` and returns the written part.
    ///
    /// # Errors
    ///
    /// [`HexError::OddLength`], [`HexError::InvalidByte`], or
    /// [`HexError::BufferTooSmall`] with the full decoded size. The contents
    /// of `out` are unspecified after an error.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_hex::DecodeOptions;
    ///
    /// let mut buf = [0u8; 16];
    /// let bytes = DecodeOptions::lenient().decode_to_slice("0a-0b", &mut buf)?;
    /// assert_eq!(bytes, [0x0a, 0x0b]);
    /// # Ok::<(), rune_hex::HexError>(())
    /// ```
    pub fn decode_to_slice<'o>(
        &self,
        hex: impl AsRef<[u8]>,
        out: &'o mut [u8],
    ) -> Result<&'o mut [u8], HexError> {
        let hex = hex.as_ref();
        let available = out.len();
        if self.skips_anything() {
            let mut written = 0;
            let mut machine = Machine::new(*self);
            machine.feed(hex, |b| {
                if let Some(slot) = out.get_mut(written) {
                    *slot = b;
                }
                written += 1;
            })?;
            machine.finish()?;
            let needed = written;
            return out
                .get_mut(..written)
                .ok_or(HexError::BufferTooSmall { needed, available });
        }
        let (body, skip) = self.plain_body(hex)?;
        let needed = body.len() / 2;
        let out = out
            .get_mut(..needed)
            .ok_or(HexError::BufferTooSmall { needed, available })?;
        decode_fast(body, out).map_err(|i| invalid(body, i, skip))?;
        Ok(out)
    }

    /// Decodes `hex` into an array of exactly `N` bytes.
    ///
    /// # Errors
    ///
    /// [`HexError::OddLength`], [`HexError::InvalidByte`], or
    /// [`HexError::WrongLength`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_hex::DecodeOptions;
    ///
    /// let mac: [u8; 6] = DecodeOptions::lenient().decode_array("00:1a:2b:3c:4d:5e")?;
    /// assert_eq!(mac, [0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]);
    /// # Ok::<(), rune_hex::HexError>(())
    /// ```
    pub fn decode_array<const N: usize>(&self, hex: impl AsRef<[u8]>) -> Result<[u8; N], HexError> {
        let mut out = [0u8; N];
        match self.decode_to_slice(hex, &mut out) {
            Ok(bytes) if bytes.len() == N => Ok(out),
            Ok(bytes) => Err(HexError::WrongLength {
                expected: N,
                actual: bytes.len(),
            }),
            Err(HexError::BufferTooSmall { needed, .. }) => Err(HexError::WrongLength {
                expected: N,
                actual: needed,
            }),
            Err(err) => Err(err),
        }
    }
}

fn invalid(body: &[u8], index: usize, skip: usize) -> HexError {
    HexError::InvalidByte {
        byte: body.get(index).copied().unwrap_or_default(),
        offset: index + skip,
    }
}

/// Value of one hex digit.
const fn nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Prefix {
    /// Nothing but skipped bytes seen yet; a prefix may follow.
    Pending,
    /// Saw a leading `0`; an `x` now makes it a prefix.
    Zero,
    /// Past the point where a prefix could appear.
    Done,
}

/// Incremental decoder shared by the tolerant decoder and the stream
/// adapters. Offsets keep counting across calls to [`Machine::feed`].
#[derive(Debug, Clone)]
pub struct Machine {
    opts: DecodeOptions,
    high: Option<u8>,
    prefix: Prefix,
    offset: usize,
}

impl Machine {
    pub const fn new(opts: DecodeOptions) -> Self {
        Self {
            opts,
            high: None,
            prefix: if opts.prefix {
                Prefix::Pending
            } else {
                Prefix::Done
            },
            offset: 0,
        }
    }

    /// Decodes `input`, passing each finished byte to `emit`.
    pub fn feed(&mut self, input: &[u8], mut emit: impl FnMut(u8)) -> Result<(), HexError> {
        for &b in input {
            let offset = self.offset;
            self.offset += 1;
            if let Some(v) = nibble(b) {
                if let Some(h) = self.high.take() {
                    emit((h << 4) | v);
                    self.prefix = Prefix::Done;
                } else {
                    self.high = Some(v);
                    self.prefix = if self.prefix == Prefix::Pending && b == b'0' {
                        Prefix::Zero
                    } else {
                        Prefix::Done
                    };
                }
            } else if self.prefix == Prefix::Zero && b | 0x20 == b'x' {
                self.high = None;
                self.prefix = Prefix::Done;
            } else if self.high.is_none() && self.opts.skips(b) {
                // Between bytes; nothing to do.
            } else {
                return Err(HexError::InvalidByte { byte: b, offset });
            }
        }
        Ok(())
    }

    /// Checks that no half byte is left over.
    pub const fn finish(&self) -> Result<(), HexError> {
        if self.high.is_some() {
            Err(HexError::OddLength)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn via_machine(opts: DecodeOptions, hex: &[u8]) -> Result<Vec<u8>, HexError> {
        let mut out = Vec::new();
        let mut m = Machine::new(opts);
        m.feed(hex, |b| out.push(b))?;
        m.finish()?;
        Ok(out)
    }

    #[test]
    fn block_decoder_matches_reference_for_every_byte() {
        for c in 0..=255u8 {
            let mut block = [b'0'; 8];
            for pos in 0..8 {
                block[pos] = c;
                let (bytes, bad) = decode_block(block);
                assert_eq!(bad != 0, nibble(c).is_none(), "byte {c:#04x}");
                if let Some(v) = nibble(c) {
                    let mut expect = [0u8; 4];
                    expect[pos / 2] = if pos % 2 == 0 { v << 4 } else { v };
                    assert_eq!(bytes.to_be_bytes(), expect);
                }
                block[pos] = b'0';
            }
        }
    }

    #[test]
    fn fast_and_ct_find_errors_everywhere() {
        let good = b"00112233445566778899aabbccddeeffAABBCCDDEEFF0123";
        for len in (0..=good.len()).step_by(2) {
            let mut out = vec![0u8; len / 2];
            assert_eq!(decode_fast(&good[..len], &mut out), Ok(()));
            assert!(decode_ct(&good[..len], &mut out));
            assert_eq!(
                out,
                via_machine(DecodeOptions::new(), &good[..len]).unwrap_or_default()
            );
            for bad_at in 0..len {
                let mut text = good[..len].to_vec();
                text[bad_at] = b'g';
                assert_eq!(decode_fast(&text, &mut out), Err(bad_at));
                assert!(!decode_ct(&text, &mut out));
            }
        }
    }

    #[test]
    fn plain_and_tolerant_paths_agree() {
        let opts = DecodeOptions::new().allow_prefix(true);
        for text in [
            "", "0x", "0X00", "0x0x", "00x0", "x0", "0", "0xa", "abz0", "ffFF",
        ] {
            assert_eq!(
                opts.decode(text),
                via_machine(opts, text.as_bytes()),
                "{text:?}"
            );
        }
    }

    #[test]
    fn prefix_rules() {
        let opts = DecodeOptions::lenient();
        assert_eq!(opts.decode("  0x01"), Ok(vec![1]));
        assert_eq!(opts.decode("0x 01"), Ok(vec![1]));
        assert_eq!(
            opts.decode("01 0x02").unwrap_err(),
            HexError::InvalidByte {
                byte: b'x',
                offset: 4
            }
        );
        assert_eq!(
            DecodeOptions::new().decode("0x01").unwrap_err(),
            HexError::InvalidByte {
                byte: b'x',
                offset: 1
            }
        );
        assert_eq!(opts.decode("0"), Err(HexError::OddLength));
        assert_eq!(opts.decode("0x"), Ok(vec![]));
    }

    #[test]
    fn separators() {
        let opts = DecodeOptions::new()
            .separator(b':')
            .separator(b'a')
            .separator(0xff);
        assert!(opts.skips(b':'));
        assert!(!opts.skips(b'-'));
        assert!(!opts.skips(0xff));
        assert_eq!(opts.decode("aa:bb"), Ok(vec![0xaa, 0xbb]));
        assert_eq!(opts.decode("::aa::"), Ok(vec![0xaa]));
        assert_eq!(
            opts.decode("a:a"),
            Err(HexError::InvalidByte {
                byte: b':',
                offset: 1
            })
        );
        assert_eq!(
            opts.decode("aa "),
            Err(HexError::InvalidByte {
                byte: b' ',
                offset: 2
            })
        );
    }

    #[test]
    fn slices_and_arrays() {
        let mut buf = [0u8; 2];
        assert_eq!(
            DecodeOptions::lenient().decode_to_slice("01 02 03", &mut buf),
            Err(HexError::BufferTooSmall {
                needed: 3,
                available: 2
            })
        );
        assert_eq!(
            DecodeOptions::new().decode_to_slice("010203", &mut buf),
            Err(HexError::BufferTooSmall {
                needed: 3,
                available: 2
            })
        );
        assert_eq!(
            DecodeOptions::lenient().decode_array::<2>("01 02 03"),
            Err(HexError::WrongLength {
                expected: 2,
                actual: 3
            })
        );
        assert_eq!(
            DecodeOptions::new().decode_array::<4>("010203"),
            Err(HexError::WrongLength {
                expected: 4,
                actual: 3
            })
        );
        assert_eq!(DecodeOptions::lenient().decode_array("01 02"), Ok([1, 2]));
    }
}
