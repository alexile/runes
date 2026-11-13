//! Bounded, checked reading of config files.

use std::fs::File;
use std::io::{self, Read as _};
use std::path::Path;

/// The default size limit for every file this crate reads: 1 MiB.
pub const DEFAULT_MAX_FILE_SIZE: u64 = 1024 * 1024;

/// Why a file could not be read as text.
#[derive(Debug)]
pub enum ReadError {
    Io(io::Error),
    TooLarge(u64),
    NotUtf8,
    WorldWritable,
}

impl ReadError {
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::Io(error) if error.kind() == io::ErrorKind::NotFound)
    }
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "cannot read file: {error}"),
            Self::TooLarge(limit) => write!(f, "file is larger than the {limit}-byte limit"),
            Self::NotUtf8 => f.write_str("file is not valid UTF-8"),
            Self::WorldWritable => {
                f.write_str("file is writable by every user; refusing to read it")
            }
        }
    }
}

/// Reads `path` as UTF-8, refusing files over `max` bytes and, when
/// `reject_world_writable` is set (Unix only), files any user may modify.
///
/// The limit is checked against the metadata and again while reading, so a
/// file that grows in between is still cut off.
pub fn read_text(path: &Path, max: u64, reject_world_writable: bool) -> Result<String, ReadError> {
    let file = File::open(path).map_err(ReadError::Io)?;
    let meta = file.metadata().map_err(ReadError::Io)?;
    if reject_world_writable && is_world_writable(&meta) {
        return Err(ReadError::WorldWritable);
    }
    if meta.len() > max {
        return Err(ReadError::TooLarge(max));
    }
    let mut buf = Vec::new();
    file.take(max.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(ReadError::Io)?;
    if buf.len() as u64 > max {
        return Err(ReadError::TooLarge(max));
    }
    String::from_utf8(buf).map_err(|_| ReadError::NotUtf8)
}

#[cfg(unix)]
fn is_world_writable(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    meta.permissions().mode() & 0o002 != 0
}

#[cfg(not(unix))]
const fn is_world_writable(_meta: &std::fs::Metadata) -> bool {
    false
}
