//! Streaming adapters for [`std::io::Read`] and [`std::io::Write`].
//!
//! Each adapter works through a fixed 4 KiB stack buffer, so memory use
//! stays flat no matter how much data passes through.
//!
//! | Adapter | Wraps | You give it | It produces |
//! |---|---|---|---|
//! | [`EncodeWriter`] | a writer | bytes | hex text, written to the inner writer |
//! | [`DecodeWriter`] | a writer | hex text | bytes, written to the inner writer |
//! | [`EncodeReader`] | a reader of bytes | — | hex text |
//! | [`DecodeReader`] | a reader of hex text | — | bytes |
//!
//! Decoding errors surface as [`std::io::Error`]s of kind
//! [`InvalidData`](std::io::ErrorKind::InvalidData) wrapping a
//! [`HexError`](crate::HexError), with offsets counted from the start of the stream.
//!
//! # Examples
//!
//! ```rust
//! use std::io::{Read, Write};
//! use rune_hex::io::{DecodeReader, EncodeWriter};
//!
//! let mut enc = EncodeWriter::new(Vec::new());
//! enc.write_all(b"streamed")?;
//! let text = enc.into_inner();
//! assert_eq!(text, b"73747265616d6564");
//!
//! let mut bytes = Vec::new();
//! DecodeReader::new(&text[..]).read_to_end(&mut bytes)?;
//! assert_eq!(bytes, b"streamed");
//! # Ok::<(), std::io::Error>(())
//! ```

use std::io::{self, Read, Write};

use crate::{
    DecodeOptions,
    decode::Machine,
    encode::{LOWER, UPPER, encode_into},
};

/// Size of the stack buffer each adapter uses.
const BUF: usize = 4096;

/// A writer that hex-encodes everything written to it.
///
/// # Examples
///
/// ```rust
/// use std::io::Write;
/// use rune_hex::io::EncodeWriter;
///
/// let mut w = EncodeWriter::new(Vec::new()).uppercase(true);
/// w.write_all(&[0xab, 0xcd])?;
/// assert_eq!(w.into_inner(), b"ABCD");
/// # Ok::<(), std::io::Error>(())
/// ```
#[derive(Debug)]
pub struct EncodeWriter<W> {
    inner: W,
    case: u8,
}

impl<W: Write> EncodeWriter<W> {
    /// Wraps `inner`, writing lowercase hex.
    pub const fn new(inner: W) -> Self {
        Self { inner, case: LOWER }
    }

    /// Switches between uppercase and lowercase output.
    #[must_use]
    pub const fn uppercase(mut self, upper: bool) -> Self {
        self.case = if upper { UPPER } else { LOWER };
        self
    }

    /// The wrapped writer.
    pub const fn get_ref(&self) -> &W {
        &self.inner
    }

    /// The wrapped writer, mutably. Writing to it directly mixes raw bytes
    /// into the hex output.
    pub const fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    /// Unwraps the inner writer. No data is buffered, so nothing is lost.
    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: Write> Write for EncodeWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = buf.len().min(BUF / 2);
        let mut out = [0u8; BUF];
        let out = &mut out[..n * 2];
        encode_into(&buf[..n], out, self.case);
        self.inner.write_all(out)?;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// A writer that decodes the hex text written to it and passes the bytes on.
///
/// Call [`finish`](Self::finish) at the end to catch a dangling half byte;
/// dropping the writer skips that check.
///
/// # Examples
///
/// ```rust
/// use std::io::Write;
/// use rune_hex::{DecodeOptions, io::DecodeWriter};
///
/// let mut w = DecodeWriter::with_options(Vec::new(), DecodeOptions::lenient());
/// w.write_all(b"68 65 6c\n")?;
/// w.write_all(b"6c 6f\n")?;
/// assert_eq!(w.finish()?, b"hello");
/// # Ok::<(), std::io::Error>(())
/// ```
#[derive(Debug)]
pub struct DecodeWriter<W> {
    inner: W,
    machine: Machine,
}

impl<W: Write> DecodeWriter<W> {
    /// Wraps `inner`, accepting the same input as [`decode`](crate::decode).
    pub const fn new(inner: W) -> Self {
        Self::with_options(inner, DecodeOptions::new().allow_prefix(true))
    }

    /// Wraps `inner` with explicit decoding options.
    pub const fn with_options(inner: W, options: DecodeOptions) -> Self {
        Self {
            inner,
            machine: Machine::new(options),
        }
    }

    /// The wrapped writer.
    pub const fn get_ref(&self) -> &W {
        &self.inner
    }

    /// The wrapped writer, mutably.
    pub const fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    /// Checks that the input ended on a byte boundary and returns the inner
    /// writer.
    ///
    /// # Errors
    ///
    /// An [`InvalidData`](io::ErrorKind::InvalidData) error wrapping
    /// [`HexError::OddLength`](crate::HexError::OddLength) if half a byte is left over.
    pub fn finish(self) -> io::Result<W> {
        self.machine.finish()?;
        Ok(self.inner)
    }
}

impl<W: Write> Write for DecodeWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // At most BUF * 2 digits plus one held-over nibble: never more than
        // BUF bytes out.
        let n = buf.len().min(BUF * 2);
        let mut out = [0u8; BUF];
        let mut len = 0;
        self.machine.feed(&buf[..n], |b| {
            if let Some(slot) = out.get_mut(len) {
                *slot = b;
                len += 1;
            }
        })?;
        self.inner.write_all(&out[..len])?;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// A reader that yields the hex encoding of another reader's bytes.
///
/// # Examples
///
/// ```rust
/// use std::io::Read;
/// use rune_hex::io::EncodeReader;
///
/// let mut text = String::new();
/// EncodeReader::new(&b"\x00\xff"[..]).read_to_string(&mut text)?;
/// assert_eq!(text, "00ff");
/// # Ok::<(), std::io::Error>(())
/// ```
#[derive(Debug)]
pub struct EncodeReader<R> {
    inner: R,
    case: u8,
    /// Second digit of a byte when the caller's buffer had room for one.
    pending: Option<u8>,
}

impl<R: Read> EncodeReader<R> {
    /// Wraps `inner`, producing lowercase hex.
    pub const fn new(inner: R) -> Self {
        Self {
            inner,
            case: LOWER,
            pending: None,
        }
    }

    /// Switches between uppercase and lowercase output.
    #[must_use]
    pub const fn uppercase(mut self, upper: bool) -> Self {
        self.case = if upper { UPPER } else { LOWER };
        self
    }

    /// The wrapped reader.
    pub const fn get_ref(&self) -> &R {
        &self.inner
    }

    /// Unwraps the inner reader. A digit held back for a one-byte read is
    /// dropped.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Read for EncodeReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let Some(first) = out.first_mut() else {
            return Ok(0);
        };
        if let Some(digit) = self.pending.take() {
            *first = digit;
            return Ok(1);
        }
        if out.len() == 1 {
            let mut byte = [0u8; 1];
            if self.inner.read(&mut byte)? == 0 {
                return Ok(0);
            }
            let mut pair = [0u8; 2];
            encode_into(&byte, &mut pair, self.case);
            out[0] = pair[0];
            self.pending = Some(pair[1]);
            return Ok(1);
        }
        let mut buf = [0u8; BUF / 2];
        let want = (out.len() / 2).min(buf.len());
        let got = self.inner.read(&mut buf[..want])?;
        encode_into(&buf[..got], &mut out[..got * 2], self.case);
        Ok(got * 2)
    }
}

/// A reader that decodes the hex text of another reader.
///
/// Reaching the end of the inner reader with half a byte left over is an
/// [`InvalidData`](io::ErrorKind::InvalidData) error.
///
/// # Examples
///
/// ```rust
/// use std::io::Read;
/// use rune_hex::{DecodeOptions, io::DecodeReader};
///
/// let text = "de:ad:be:ef\n";
/// let mut bytes = Vec::new();
/// DecodeReader::with_options(text.as_bytes(), DecodeOptions::lenient())
///     .read_to_end(&mut bytes)?;
/// assert_eq!(bytes, [0xde, 0xad, 0xbe, 0xef]);
/// # Ok::<(), std::io::Error>(())
/// ```
#[derive(Debug)]
pub struct DecodeReader<R> {
    inner: R,
    machine: Machine,
}

impl<R: Read> DecodeReader<R> {
    /// Wraps `inner`, accepting the same input as [`decode`](crate::decode).
    pub const fn new(inner: R) -> Self {
        Self::with_options(inner, DecodeOptions::new().allow_prefix(true))
    }

    /// Wraps `inner` with explicit decoding options.
    pub const fn with_options(inner: R, options: DecodeOptions) -> Self {
        Self {
            inner,
            machine: Machine::new(options),
        }
    }

    /// The wrapped reader.
    pub const fn get_ref(&self) -> &R {
        &self.inner
    }

    /// Unwraps the inner reader. A held-over half byte is dropped.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Read for DecodeReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        let mut buf = [0u8; BUF];
        loop {
            // 2 * out.len() digits plus a held-over nibble fit in `out`.
            let want = out.len().saturating_mul(2).min(buf.len());
            let got = self.inner.read(&mut buf[..want])?;
            if got == 0 {
                self.machine.finish()?;
                return Ok(0);
            }
            let mut len = 0;
            self.machine.feed(&buf[..got], |b| {
                if let Some(slot) = out.get_mut(len) {
                    *slot = b;
                    len += 1;
                }
            })?;
            if len > 0 {
                return Ok(len);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A reader that hands out at most `step` bytes per call.
    struct Trickle<'a> {
        data: &'a [u8],
        step: usize,
    }

    impl Read for Trickle<'_> {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            let n = self.data.len().min(self.step).min(out.len());
            out[..n].copy_from_slice(&self.data[..n]);
            self.data = &self.data[n..];
            Ok(n)
        }
    }

    fn sample(len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| u8::try_from(i * 31 % 251).unwrap_or(0))
            .collect()
    }

    #[test]
    fn writers_round_trip_large_input() -> io::Result<()> {
        let data = sample(3 * BUF + 7);
        let mut enc = EncodeWriter::new(Vec::new());
        for piece in data.chunks(999) {
            enc.write_all(piece)?;
        }
        enc.flush()?;
        let text = enc.into_inner();
        assert_eq!(text, crate::encode(&data).into_bytes());

        let mut dec = DecodeWriter::new(Vec::new());
        for piece in text.chunks(777) {
            dec.write_all(piece)?;
        }
        assert_eq!(dec.finish()?, data);
        Ok(())
    }

    #[test]
    fn readers_round_trip_with_awkward_sizes() -> io::Result<()> {
        let data = sample(2 * BUF + 3);
        for step in [1, 2, 3, 4097] {
            for out_len in [1, 2, 3, 64, 10_000] {
                let mut enc = EncodeReader::new(Trickle { data: &data, step }).uppercase(true);
                let mut text = Vec::new();
                let mut chunk = vec![0u8; out_len];
                loop {
                    let n = enc.read(&mut chunk)?;
                    if n == 0 {
                        break;
                    }
                    text.extend_from_slice(&chunk[..n]);
                }
                assert_eq!(text, crate::encode_upper(&data).into_bytes());

                let mut dec = DecodeReader::new(Trickle { data: &text, step });
                let mut bytes = Vec::new();
                loop {
                    let n = dec.read(&mut chunk)?;
                    if n == 0 {
                        break;
                    }
                    bytes.extend_from_slice(&chunk[..n]);
                }
                assert_eq!(bytes, data);
            }
        }
        Ok(())
    }

    #[test]
    fn errors_report_stream_offsets() {
        let mut dec = DecodeWriter::new(Vec::new());
        assert!(dec.write_all(b"0011").is_ok());
        let err = dec.write_all(b"22?3").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(err.to_string(), "invalid hex character '?' at offset 6");

        let mut dec = DecodeWriter::new(Vec::new());
        assert!(dec.write_all(b"001").is_ok());
        let err = dec.finish().unwrap_err();
        assert_eq!(err.to_string(), "odd number of hex digits");

        let mut out = Vec::new();
        let err = DecodeReader::new(&b"abc"[..])
            .read_to_end(&mut out)
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn decode_reader_skips_long_runs_of_whitespace() -> io::Result<()> {
        let mut text = vec![b' '; 3 * BUF];
        text.extend_from_slice(b"0x41\n");
        let mut out = Vec::new();
        DecodeReader::with_options(&text[..], DecodeOptions::lenient()).read_to_end(&mut out)?;
        assert_eq!(out, b"A");
        Ok(())
    }
}
