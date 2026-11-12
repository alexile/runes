//! Bounded file and stream access shared by every loader.

use std::fs::{self, File};
use std::io::{BufRead, Read};
use std::path::{Path, PathBuf};

use crate::error::LoadError;
use crate::jail::Jail;

/// Open `path` for reading, refusing anything but a regular file and, with a
/// jail, anything outside it. Returns the opened file and the path used.
///
/// The type is checked before `open` (so a FIFO is never opened, which would
/// block) and again on the open handle.
pub fn open_regular(path: &Path, jail: Option<&Jail>) -> Result<(File, PathBuf), LoadError> {
    let resolved = match jail {
        Some(jail) => jail.resolve(path)?,
        None => path.to_path_buf(),
    };
    let meta = fs::metadata(&resolved).map_err(LoadError::io(path))?;
    if !meta.is_file() {
        return Err(LoadError::NotRegularFile {
            path: path.to_path_buf(),
        });
    }
    let file = File::open(&resolved).map_err(LoadError::io(path))?;
    let meta = file.metadata().map_err(LoadError::io(path))?;
    if !meta.is_file() {
        return Err(LoadError::NotRegularFile {
            path: path.to_path_buf(),
        });
    }
    Ok((file, resolved))
}

/// Read at most `limit` bytes; more is [`LoadError::TooLarge`].
pub fn read_limited(
    reader: impl Read,
    limit: u64,
    path: Option<&Path>,
) -> Result<Vec<u8>, LoadError> {
    let mut buf = Vec::new();
    reader
        .take(limit.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|source| LoadError::Io {
            path: path.map(Path::to_path_buf),
            source,
        })?;
    if buf.len() as u64 > limit {
        return Err(LoadError::TooLarge {
            path: path.map(Path::to_path_buf),
            limit,
        });
    }
    Ok(buf)
}

/// Open and fully read a regular file under the size limit.
pub fn read_file(path: &Path, jail: Option<&Jail>, limit: u64) -> Result<Vec<u8>, LoadError> {
    let (file, _) = open_regular(path, jail)?;
    let len = file.metadata().map_err(LoadError::io(path))?.len();
    if len > limit {
        return Err(LoadError::TooLarge {
            path: Some(path.to_path_buf()),
            limit,
        });
    }
    read_limited(file, limit, Some(path))
}

/// Decode UTF-8, dropping a leading byte-order mark.
pub fn utf8(bytes: Vec<u8>, path: Option<&Path>) -> Result<String, LoadError> {
    let mut text = String::from_utf8(bytes).map_err(|_| LoadError::InvalidUtf8 {
        path: path.map(Path::to_path_buf),
        line: None,
    })?;
    if text.starts_with('\u{feff}') {
        text.drain(..'\u{feff}'.len_utf8());
    }
    Ok(text)
}

/// One line read by [`LineReader`].
pub struct Line {
    /// 1-based line number.
    pub number: u64,
    /// Offset of the first byte.
    pub start: u64,
    /// The line's bytes without `\n` / `\r\n`, or `None` if it exceeded the limit.
    pub bytes: Option<Vec<u8>>,
}

/// Reads `\n`-terminated lines with a per-line byte cap. An over-long line is
/// consumed (not buffered) and reported with `bytes: None`, so the reader
/// stays in sync and memory stays bounded.
pub struct LineReader<R> {
    inner: R,
    max: usize,
    offset: u64,
    number: u64,
}

impl<R> std::fmt::Debug for LineReader<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LineReader")
            .field("max", &self.max)
            .field("offset", &self.offset)
            .finish_non_exhaustive()
    }
}

impl<R> LineReader<R> {
    /// The per-line byte cap.
    pub const fn max(&self) -> usize {
        self.max
    }
}

impl<R: BufRead> LineReader<R> {
    pub const fn new(inner: R, max: usize) -> Self {
        Self {
            inner,
            max,
            offset: 0,
            number: 0,
        }
    }

    pub fn next_line(&mut self) -> Result<Option<Line>, LoadError> {
        let start = self.offset;
        let mut buf = Vec::new();
        let mut overflow = false;
        let mut saw_any = false;
        loop {
            let chunk = self
                .inner
                .fill_buf()
                .map_err(|source| LoadError::Io { path: None, source })?;
            if chunk.is_empty() {
                if !saw_any {
                    return Ok(None);
                }
                break;
            }
            saw_any = true;
            let (take, done) = chunk
                .iter()
                .position(|&b| b == b'\n')
                .map_or((chunk.len(), false), |i| (i + 1, true));
            let data = &chunk[..if done { take - 1 } else { take }];
            if !overflow {
                if buf.len().saturating_add(data.len()) > self.max {
                    overflow = true;
                    buf = Vec::new();
                } else {
                    buf.extend_from_slice(data);
                }
            }
            self.inner.consume(take);
            self.offset += take as u64;
            if done {
                break;
            }
        }
        self.number += 1;
        if buf.last() == Some(&b'\r') {
            buf.pop();
        }
        Ok(Some(Line {
            number: self.number,
            start,
            bytes: (!overflow).then_some(buf),
        }))
    }
}
