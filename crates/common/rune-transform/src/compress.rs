//! gzip, zlib and raw deflate, with bounded decompression.

use std::io::{Read, Write};

use flate2::Compression;

use crate::{Category, Error, Transform};

/// Default cap on decompressed output: 64 MiB.
///
/// Decompressing untrusted input without a cap invites "zip bombs"; the
/// built-in compression transforms stop at this size.
pub const DEFAULT_MAX_OUTPUT: usize = 64 * 1024 * 1024;

/// A compression container format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CompressionFormat {
    /// gzip ([RFC 1952](https://www.rfc-editor.org/rfc/rfc1952)).
    Gzip,
    /// zlib ([RFC 1950](https://www.rfc-editor.org/rfc/rfc1950)).
    Zlib,
    /// Raw deflate ([RFC 1951](https://www.rfc-editor.org/rfc/rfc1951)).
    Deflate,
}

impl CompressionFormat {
    /// The registry id of the format: `"gzip"`, `"zlib"` or `"deflate"`.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Gzip => "gzip",
            Self::Zlib => "zlib",
            Self::Deflate => "deflate",
        }
    }
}

/// Compress on encode, decompress on decode.
///
/// Decoding fails with [`Error::OutputTooLarge`] once the output would pass
/// [`max_output`](Self::with_max_output) bytes, and with
/// [`Error::Malformed`] on a corrupt or truncated stream.
///
/// ```
/// use rune_transform::{CompressTransform, CompressionFormat, Transform};
///
/// let gzip = CompressTransform::new(CompressionFormat::Gzip).with_max_output(16);
/// let packed = gzip.encode(&[b'a'; 17])?;
/// assert_eq!(gzip.decode(&gzip.encode(b"short")?)?, b"short");
/// assert!(gzip.decode(&packed).is_err());
/// # Ok::<(), rune_transform::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompressTransform {
    /// Container format.
    format: CompressionFormat,
    /// Largest decompressed output accepted, in bytes.
    max_output: usize,
    /// Compression level, 0–9.
    level: u32,
}

impl CompressTransform {
    /// A transform for `format` with the default level and
    /// [`DEFAULT_MAX_OUTPUT`].
    #[must_use]
    pub const fn new(format: CompressionFormat) -> Self {
        Self {
            format,
            max_output: DEFAULT_MAX_OUTPUT,
            level: 6,
        }
    }

    /// Set the largest decompressed output accepted, in bytes.
    #[must_use]
    pub const fn with_max_output(mut self, max_output: usize) -> Self {
        self.max_output = max_output;
        self
    }

    /// Set the compression level, from 0 (store) to 9 (smallest); larger
    /// values are clamped to 9.
    #[must_use]
    pub const fn with_level(mut self, level: u32) -> Self {
        self.level = if level > 9 { 9 } else { level };
        self
    }

    /// The container format.
    #[must_use]
    pub const fn format(&self) -> CompressionFormat {
        self.format
    }

    /// The decompression cap, in bytes.
    #[must_use]
    pub const fn max_output(&self) -> usize {
        self.max_output
    }

    /// Read all of `reader`, failing past the cap.
    fn read_capped(&self, reader: impl Read) -> Result<Vec<u8>, Error> {
        let cap = u64::try_from(self.max_output)
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        let mut out = Vec::new();
        reader
            .take(cap)
            .read_to_end(&mut out)
            .map_err(|error| Error::malformed(self.id(), error))?;
        if out.len() > self.max_output {
            return Err(Error::OutputTooLarge {
                transform: self.id().to_owned(),
                limit: self.max_output,
            });
        }
        Ok(out)
    }
}

impl Transform for CompressTransform {
    fn id(&self) -> &str {
        self.format.id()
    }

    fn description(&self) -> &str {
        match self.format {
            CompressionFormat::Gzip => "Gzip compression",
            CompressionFormat::Zlib => "Zlib compression",
            CompressionFormat::Deflate => "Raw deflate compression",
        }
    }

    fn category(&self) -> Category {
        Category::Compression
    }

    fn is_reversible(&self) -> bool {
        true
    }

    fn encode(&self, input: &[u8]) -> Result<Vec<u8>, Error> {
        let level = Compression::new(self.level);
        let result = match self.format {
            CompressionFormat::Gzip => {
                let mut encoder = flate2::write::GzEncoder::new(Vec::new(), level);
                encoder.write_all(input).and_then(|()| encoder.finish())
            }
            CompressionFormat::Zlib => {
                let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), level);
                encoder.write_all(input).and_then(|()| encoder.finish())
            }
            CompressionFormat::Deflate => {
                let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), level);
                encoder.write_all(input).and_then(|()| encoder.finish())
            }
        };
        result.map_err(|error| Error::malformed(self.id(), error))
    }

    fn decode(&self, input: &[u8]) -> Result<Vec<u8>, Error> {
        match self.format {
            CompressionFormat::Gzip => self.read_capped(flate2::read::GzDecoder::new(input)),
            CompressionFormat::Zlib => self.read_capped(flate2::read::ZlibDecoder::new(input)),
            CompressionFormat::Deflate => {
                self.read_capped(flate2::read::DeflateDecoder::new(input))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FORMATS: [CompressionFormat; 3] = [
        CompressionFormat::Gzip,
        CompressionFormat::Zlib,
        CompressionFormat::Deflate,
    ];

    #[test]
    fn round_trips_every_format_and_level() {
        let data = b"hello hello hello hello, compressed world".repeat(10);
        for format in FORMATS {
            for level in [0, 1, 6, 9, 42] {
                let codec = CompressTransform::new(format).with_level(level);
                let packed = codec.encode(&data).ok();
                let unpacked = packed.and_then(|p| codec.decode(&p).ok());
                assert_eq!(unpacked.as_deref(), Some(data.as_slice()), "{format:?}");
            }
        }
    }

    #[test]
    fn gzip_magic_and_known_stream() {
        let gzip = CompressTransform::new(CompressionFormat::Gzip);
        let packed = gzip.encode(b"x").ok().unwrap_or_default();
        assert_eq!(packed.get(..2), Some(&[0x1f, 0x8b][..]));
        // `printf 'hi' | gzip -n | xxd -i`
        let known = [
            0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xcb, 0xc8, 0x04, 0x00,
            0xac, 0x2a, 0x93, 0xd8, 0x02, 0x00, 0x00, 0x00,
        ];
        assert_eq!(gzip.decode(&known).ok(), Some(b"hi".to_vec()));
    }

    #[test]
    fn cap_and_corruption() {
        for format in FORMATS {
            let codec = CompressTransform::new(format).with_max_output(1000);
            assert_eq!(codec.max_output(), 1000);
            assert_eq!(codec.format(), format);
            let exact = codec.encode(&[0; 1000]).ok().unwrap_or_default();
            assert_eq!(codec.decode(&exact).map(|v| v.len()).ok(), Some(1000));
            let bomb = codec.encode(&[0; 1001]).ok().unwrap_or_default();
            assert_eq!(
                codec.decode(&bomb).err().map(|e| e.code()),
                Some("transform.output_too_large")
            );
            assert_eq!(
                codec.decode(b"\xffnot compressed").err().map(|e| e.code()),
                Some("transform.malformed"),
                "{format:?}"
            );
        }
    }
}
