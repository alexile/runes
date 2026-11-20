use std::fmt;
use std::io;
use std::path::PathBuf;
use std::time::Duration;

/// Everything that can go wrong while loading documents.
///
/// The enum is `#[non_exhaustive]`: new limits or formats may add variants in
/// a minor release, so match with a wildcard arm.
///
/// `LoadError` converts into [`io::Error`] (with a matching
/// [`io::ErrorKind`]) for callers that only deal in I/O errors.
#[derive(Debug)]
#[non_exhaustive]
pub enum LoadError {
    /// An I/O operation failed.
    Io {
        /// The path involved, if any (`None` for readers such as stdin).
        path: Option<PathBuf>,
        /// The underlying error.
        source: io::Error,
    },
    /// A file or input stream is larger than [`Limits::max_file_bytes`](crate::Limits::max_file_bytes).
    TooLarge {
        /// The path involved, if any.
        path: Option<PathBuf>,
        /// The limit that was exceeded, in bytes.
        limit: u64,
    },
    /// A single record (JSON line, CSV row) is larger than
    /// [`Limits::max_record_bytes`](crate::Limits::max_record_bytes).
    RecordTooLarge {
        /// 1-based line on which the record starts.
        line: u64,
        /// The limit that was exceeded, in bytes.
        limit: usize,
    },
    /// An input produced more than [`Limits::max_records`](crate::Limits::max_records) documents.
    TooManyRecords {
        /// The limit that was exceeded.
        limit: usize,
    },
    /// The documents produced from one input hold more than
    /// [`Limits::max_total_bytes`](crate::Limits::max_total_bytes) bytes of content.
    OutputTooLarge {
        /// The limit that was exceeded, in bytes.
        limit: usize,
    },
    /// A directory walk matched more than [`Limits::max_files`](crate::Limits::max_files) files.
    TooManyFiles {
        /// The limit that was exceeded.
        limit: usize,
    },
    /// A path resolves (after following symlinks) outside the [`Jail`](crate::Jail) root.
    OutsideRoot {
        /// The path as given by the caller.
        path: PathBuf,
    },
    /// The path is not a regular file (a directory, FIFO, socket or device).
    NotRegularFile {
        /// The offending path.
        path: PathBuf,
    },
    /// The content is not valid UTF-8.
    InvalidUtf8 {
        /// The path involved, if any.
        path: Option<PathBuf>,
        /// 1-based line, for record-oriented formats.
        line: Option<u64>,
    },
    /// A JSON or CSV record could not be parsed.
    Parse {
        /// 1-based line (or record number for JSON documents) of the failure.
        line: u64,
        /// What went wrong.
        message: String,
    },
    /// A record lacks the selected content field, or it is not a string.
    MissingField {
        /// 1-based line (or record number) of the record.
        line: u64,
        /// The field selector that did not match.
        field: String,
    },
    /// A glob or field selector is malformed.
    InvalidPattern {
        /// The pattern as given.
        pattern: String,
        /// Why it was rejected.
        reason: &'static str,
    },
    /// A PDF or EPUB is encrypted (password protected or DRM).
    Encrypted {
        /// The path involved, if any.
        path: Option<PathBuf>,
    },
    /// A PDF or EPUB is broken beyond what the loader can recover from.
    Malformed {
        /// The path involved, if any.
        path: Option<PathBuf>,
        /// What went wrong.
        message: String,
    },
    /// A PDF has more than [`Limits::max_pages`](crate::Limits::max_pages)
    /// pages, or an EPUB more spine chapters.
    TooManyPages {
        /// The limit that was exceeded.
        limit: usize,
    },
    /// An EPUB archive has more than
    /// [`Limits::max_archive_entries`](crate::Limits::max_archive_entries) entries.
    TooManyEntries {
        /// The limit that was exceeded.
        limit: usize,
    },
    /// A PDF or EPUB decompresses to more than
    /// [`Limits::max_decompressed_bytes`](crate::Limits::max_decompressed_bytes).
    DecompressedTooLarge {
        /// The limit that was exceeded, in bytes.
        limit: u64,
    },
    /// An archive entry compresses better than
    /// [`Limits::max_compression_ratio`](crate::Limits::max_compression_ratio),
    /// the mark of a zip bomb.
    CompressionRatio {
        /// The entry's name inside the archive.
        entry: String,
        /// The ratio that was exceeded.
        limit: u64,
    },
    /// Loading took longer than [`Limits::max_duration`](crate::Limits::max_duration).
    TimedOut {
        /// The budget that was exceeded.
        limit: Duration,
    },
}

impl LoadError {
    pub(crate) fn io(path: impl Into<PathBuf>) -> impl FnOnce(io::Error) -> Self {
        let path = path.into();
        move |source| Self::Io {
            path: Some(path),
            source,
        }
    }

    /// `true` for errors confined to the content of one file (too large, not
    /// UTF-8, not a regular file, a broken or encrypted PDF or EPUB) that a
    /// bulk loader may skip and carry on.
    #[must_use]
    pub const fn is_per_file(&self) -> bool {
        matches!(
            self,
            Self::TooLarge { .. }
                | Self::InvalidUtf8 { .. }
                | Self::NotRegularFile { .. }
                | Self::OutputTooLarge { .. }
                | Self::Encrypted { .. }
                | Self::Malformed { .. }
                | Self::TooManyPages { .. }
                | Self::TooManyEntries { .. }
                | Self::DecompressedTooLarge { .. }
                | Self::CompressionRatio { .. }
                | Self::TimedOut { .. }
        )
    }

    /// Fill in the path of a path-less error from a bytes loader.
    pub(crate) fn with_path(mut self, given: &std::path::Path) -> Self {
        match &mut self {
            Self::Io { path, .. }
            | Self::TooLarge { path, .. }
            | Self::InvalidUtf8 { path, .. }
            | Self::Encrypted { path }
            | Self::Malformed { path, .. }
                if path.is_none() =>
            {
                *path = Some(given.to_path_buf());
            }
            _ => {}
        }
        self
    }
}

fn path_suffix(path: Option<&PathBuf>) -> String {
    path.map_or_else(String::new, |p| format!(" ({})", p.display()))
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(f, "I/O error{}: {source}", path_suffix(path.as_ref()))
            }
            Self::TooLarge { path, limit } => write!(
                f,
                "input exceeds {limit} bytes{}",
                path_suffix(path.as_ref())
            ),
            Self::RecordTooLarge { line, limit } => {
                write!(f, "record at line {line} exceeds {limit} bytes")
            }
            Self::TooManyRecords { limit } => write!(f, "more than {limit} records"),
            Self::OutputTooLarge { limit } => {
                write!(f, "documents exceed {limit} bytes of content in total")
            }
            Self::TooManyFiles { limit } => {
                write!(f, "directory walk matched more than {limit} files")
            }
            Self::OutsideRoot { path } => {
                write!(f, "path escapes the loader root: {}", path.display())
            }
            Self::NotRegularFile { path } => write!(f, "not a regular file: {}", path.display()),
            Self::InvalidUtf8 { path, line } => {
                write!(f, "invalid UTF-8{}", path_suffix(path.as_ref()))?;
                if let Some(line) = line {
                    write!(f, " at line {line}")?;
                }
                Ok(())
            }
            Self::Parse { line, message } => write!(f, "parse error at line {line}: {message}"),
            Self::MissingField { line, field } => {
                write!(f, "record at line {line} has no string field `{field}`")
            }
            Self::InvalidPattern { pattern, reason } => {
                write!(f, "invalid pattern `{pattern}`: {reason}")
            }
            Self::Encrypted { path } => {
                write!(f, "document is encrypted{}", path_suffix(path.as_ref()))
            }
            Self::Malformed { path, message } => {
                write!(
                    f,
                    "malformed document{}: {message}",
                    path_suffix(path.as_ref())
                )
            }
            Self::TooManyPages { limit } => write!(f, "more than {limit} pages or chapters"),
            Self::TooManyEntries { limit } => write!(f, "archive has more than {limit} entries"),
            Self::DecompressedTooLarge { limit } => {
                write!(f, "decompressed content exceeds {limit} bytes")
            }
            Self::CompressionRatio { entry, limit } => {
                write!(f, "archive entry `{entry}` compresses more than {limit}:1")
            }
            Self::TimedOut { limit } => write!(f, "loading took longer than {limit:?}"),
        }
    }
}

impl std::error::Error for LoadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<LoadError> for io::Error {
    fn from(err: LoadError) -> Self {
        let kind = match &err {
            LoadError::Io { source, .. } => source.kind(),
            LoadError::TooLarge { .. }
            | LoadError::RecordTooLarge { .. }
            | LoadError::TooManyRecords { .. }
            | LoadError::OutputTooLarge { .. }
            | LoadError::TooManyFiles { .. }
            | LoadError::TooManyPages { .. }
            | LoadError::TooManyEntries { .. }
            | LoadError::DecompressedTooLarge { .. }
            | LoadError::CompressionRatio { .. } => io::ErrorKind::FileTooLarge,
            LoadError::TimedOut { .. } => io::ErrorKind::TimedOut,
            LoadError::OutsideRoot { .. } | LoadError::Encrypted { .. } => {
                io::ErrorKind::PermissionDenied
            }
            LoadError::NotRegularFile { .. } | LoadError::InvalidPattern { .. } => {
                io::ErrorKind::InvalidInput
            }
            LoadError::InvalidUtf8 { .. }
            | LoadError::Parse { .. }
            | LoadError::MissingField { .. }
            | LoadError::Malformed { .. } => io::ErrorKind::InvalidData,
        };
        match err {
            LoadError::Io { source, .. } => source,
            other => Self::new(kind, other),
        }
    }
}
