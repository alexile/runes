//! Streaming encoders over an in-memory buffer, and one-shot [`compress`].

use std::io;
#[cfg(any(
    feature = "gzip",
    feature = "deflate",
    feature = "br",
    feature = "zstd"
))]
use std::io::Write;

use crate::Encoding;

/// The crate's error type.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The coding was not compiled in (see the crate's cargo features), or
    /// it is not a compressing coding.
    #[error("content coding `{0}` is not enabled in this build")]
    Unsupported(Encoding),
    /// The encoder failed.
    #[error("compression failed: {0}")]
    Io(#[from] io::Error),
}

/// Compression level, mapped onto each coding's own scale.
///
/// | Level | gzip / deflate | br | zstd |
/// |-------|----------------|----|------|
/// | [`Fastest`](Level::Fastest) | 1 | 0 | 1 |
/// | [`Default`](Level::Default) | 6 | 4 | 3 |
/// | [`Best`](Level::Best) | 9 | 11 | 19 |
/// | [`Precise(n)`](Level::Precise) | `n`, clamped to 0..=9 | 0..=11 | 1..=22 |
///
/// The default favours latency: on-the-fly compression runs on every
/// response, so the slow, high-ratio settings are opt-in.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Level {
    /// Fastest compression.
    Fastest,
    /// A balanced level suited to dynamic responses.
    #[default]
    Default,
    /// Smallest output, slowest.
    Best,
    /// An explicit coding-specific level, clamped to the coding's range.
    Precise(u32),
}

impl Level {
    #[cfg(any(feature = "gzip", feature = "deflate"))]
    fn flate2(self) -> flate2::Compression {
        flate2::Compression::new(match self {
            Self::Fastest => 1,
            Self::Default => 6,
            Self::Best => 9,
            Self::Precise(n) => n.min(9),
        })
    }

    #[cfg(feature = "br")]
    const fn brotli(self) -> u32 {
        match self {
            Self::Fastest => 0,
            Self::Default => 4,
            Self::Best => 11,
            Self::Precise(n) => {
                if n > 11 {
                    11
                } else {
                    n
                }
            }
        }
    }

    #[cfg(feature = "zstd")]
    fn zstd(self) -> i32 {
        match self {
            Self::Fastest => 1,
            Self::Default => 3,
            Self::Best => 19,
            Self::Precise(n) => i32::try_from(n.clamp(1, 22)).unwrap_or(3),
        }
    }
}

/// Brotli window size (log2): 4 MiB, brotli's own default.
#[cfg(feature = "br")]
const BROTLI_LGWIN: u32 = 22;
/// Brotli internal buffer size.
#[cfg(feature = "br")]
const BROTLI_BUFFER: usize = 4096;

/// A streaming encoder that writes into a `Vec<u8>` the caller drains.
pub enum Encoder {
    #[cfg(feature = "gzip")]
    Gzip(flate2::write::GzEncoder<Vec<u8>>),
    #[cfg(feature = "deflate")]
    Deflate(flate2::write::ZlibEncoder<Vec<u8>>),
    #[cfg(feature = "br")]
    Brotli(Box<brotli::CompressorWriter<Vec<u8>>>),
    #[cfg(feature = "zstd")]
    Zstd(zstd::stream::write::Encoder<'static, Vec<u8>>),
}

#[cfg_attr(
    not(any(
        feature = "gzip",
        feature = "deflate",
        feature = "br",
        feature = "zstd"
    )),
    allow(
        clippy::uninhabited_references,
        clippy::missing_const_for_fn,
        clippy::needless_pass_by_ref_mut,
        reason = "with no coding compiled in, `Encoder` is uninhabited"
    )
)]
impl Encoder {
    /// Creates an encoder for a compressing coding.
    #[allow(
        clippy::needless_pass_by_value,
        unused_variables,
        reason = "`level` is unused when no coding is enabled"
    )]
    pub fn new(encoding: Encoding, level: Level) -> Result<Self, Error> {
        match encoding {
            #[cfg(feature = "gzip")]
            Encoding::Gzip => Ok(Self::Gzip(flate2::write::GzEncoder::new(
                Vec::new(),
                level.flate2(),
            ))),
            #[cfg(feature = "deflate")]
            Encoding::Deflate => Ok(Self::Deflate(flate2::write::ZlibEncoder::new(
                Vec::new(),
                level.flate2(),
            ))),
            #[cfg(feature = "br")]
            Encoding::Brotli => Ok(Self::Brotli(Box::new(brotli::CompressorWriter::new(
                Vec::new(),
                BROTLI_BUFFER,
                level.brotli(),
                BROTLI_LGWIN,
            )))),
            #[cfg(feature = "zstd")]
            Encoding::Zstd => Ok(Self::Zstd(zstd::stream::write::Encoder::new(
                Vec::new(),
                level.zstd(),
            )?)),
            other => Err(Error::Unsupported(other)),
        }
    }

    /// Feeds input to the encoder.
    pub fn write(&mut self, input: &[u8]) -> io::Result<()> {
        #[cfg(not(any(
            feature = "gzip",
            feature = "deflate",
            feature = "br",
            feature = "zstd"
        )))]
        let _ = input;
        match *self {
            #[cfg(feature = "gzip")]
            Self::Gzip(ref mut e) => e.write_all(input),
            #[cfg(feature = "deflate")]
            Self::Deflate(ref mut e) => e.write_all(input),
            #[cfg(feature = "br")]
            Self::Brotli(ref mut e) => e.write_all(input),
            #[cfg(feature = "zstd")]
            Self::Zstd(ref mut e) => e.write_all(input),
        }
    }

    /// Takes the compressed bytes produced so far.
    pub fn take(&mut self) -> Vec<u8> {
        match *self {
            #[cfg(feature = "gzip")]
            Self::Gzip(ref mut e) => std::mem::take(e.get_mut()),
            #[cfg(feature = "deflate")]
            Self::Deflate(ref mut e) => std::mem::take(e.get_mut()),
            #[cfg(feature = "br")]
            Self::Brotli(ref mut e) => std::mem::take(e.get_mut()),
            #[cfg(feature = "zstd")]
            Self::Zstd(ref mut e) => std::mem::take(e.get_mut()),
        }
    }

    /// Ends the stream and returns the remaining compressed bytes.
    pub fn finish(self) -> io::Result<Vec<u8>> {
        match self {
            #[cfg(feature = "gzip")]
            Self::Gzip(e) => e.finish(),
            #[cfg(feature = "deflate")]
            Self::Deflate(e) => e.finish(),
            #[cfg(feature = "br")]
            Self::Brotli(e) => Ok(e.into_inner()),
            #[cfg(feature = "zstd")]
            Self::Zstd(e) => e.finish(),
        }
    }
}

/// Compresses `input` in one shot with `encoding` at `level`.
///
/// [`Encoding::Identity`] returns the input unchanged. The output is exactly
/// what the middleware sends for a single-chunk body.
///
/// # Errors
///
/// [`Error::Unsupported`] when the coding is not compiled in, or
/// [`Error::Io`] if the encoder fails.
///
/// # Examples
///
/// ```rust
/// use rune_axum_compression::{compress, Encoding, Level};
///
/// let text = "hello hello hello hello hello hello".repeat(20);
/// let gz = compress(Encoding::Gzip, Level::Default, text.as_bytes())?;
/// assert!(gz.len() < text.len());
/// assert_eq!(&gz[..2], &[0x1f, 0x8b]); // gzip magic
/// # Ok::<(), rune_axum_compression::Error>(())
/// ```
pub fn compress(encoding: Encoding, level: Level, input: &[u8]) -> Result<Vec<u8>, Error> {
    if encoding == Encoding::Identity {
        return Ok(input.to_vec());
    }
    let mut encoder = Encoder::new(encoding, level)?;
    encoder.write(input)?;
    let mut out = encoder.take();
    out.extend(encoder.finish()?);
    Ok(out)
}

#[cfg(test)]
#[cfg_attr(
    not(any(
        feature = "gzip",
        feature = "deflate",
        feature = "br",
        feature = "zstd"
    )),
    allow(unused_imports, dead_code, reason = "round-trip tests need a coding")
)]
mod tests {
    use super::*;
    use std::io::Read;

    fn sample() -> Vec<u8> {
        b"The quick brown fox jumps over the lazy dog. ".repeat(100)
    }

    #[test]
    fn identity_is_a_copy() {
        assert_eq!(
            compress(Encoding::Identity, Level::Best, b"abc").unwrap(),
            b"abc"
        );
    }

    #[cfg(feature = "gzip")]
    #[test]
    fn gzip_round_trip_all_levels() {
        let data = sample();
        for level in [
            Level::Fastest,
            Level::Default,
            Level::Best,
            Level::Precise(0),
            Level::Precise(99),
        ] {
            let gz = compress(Encoding::Gzip, level, &data).unwrap();
            let mut out = Vec::new();
            flate2::read::GzDecoder::new(&gz[..])
                .read_to_end(&mut out)
                .unwrap();
            assert_eq!(out, data, "{level:?}");
        }
    }

    #[cfg(feature = "deflate")]
    #[test]
    fn deflate_is_zlib_wrapped() {
        let data = sample();
        let z = compress(Encoding::Deflate, Level::Default, &data).unwrap();
        assert_eq!(z[0] & 0x0f, 8, "CM=8 (deflate) zlib header");
        let mut out = Vec::new();
        flate2::read::ZlibDecoder::new(&z[..])
            .read_to_end(&mut out)
            .unwrap();
        assert_eq!(out, data);
    }

    #[cfg(feature = "br")]
    #[test]
    fn brotli_round_trip() {
        let data = sample();
        let br = compress(Encoding::Brotli, Level::Precise(50), &data).unwrap();
        let mut out = Vec::new();
        brotli::Decompressor::new(&br[..], 4096)
            .read_to_end(&mut out)
            .unwrap();
        assert_eq!(out, data);
    }

    #[cfg(feature = "zstd")]
    #[test]
    fn zstd_round_trip() {
        let data = sample();
        let z = compress(Encoding::Zstd, Level::Precise(0), &data).unwrap();
        assert_eq!(zstd::decode_all(&z[..]).unwrap(), data);
    }

    #[cfg(not(feature = "zstd"))]
    #[test]
    fn disabled_coding_is_an_error() {
        let err = compress(Encoding::Zstd, Level::Default, b"x").unwrap_err();
        assert!(matches!(err, Error::Unsupported(Encoding::Zstd)));
        assert_eq!(
            err.to_string(),
            "content coding `zstd` is not enabled in this build"
        );
    }
}
