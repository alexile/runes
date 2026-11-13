use std::fmt;
use std::io;
use std::path::PathBuf;

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
    /// UTF-8, not a regular file) that a bulk loader may skip and carry on.
    #[must_use]
    pub const fn is_per_file(&self) -> bool {
        matches!(
            self,
            Self::TooLarge { .. } | Self::InvalidUtf8 { .. } | Self::NotRegularFile { .. }
        )
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
            | LoadError::TooManyFiles { .. } => io::ErrorKind::FileTooLarge,
            LoadError::OutsideRoot { .. } => io::ErrorKind::PermissionDenied,
            LoadError::NotRegularFile { .. } | LoadError::InvalidPattern { .. } => {
                io::ErrorKind::InvalidInput
            }
            LoadError::InvalidUtf8 { .. }
            | LoadError::Parse { .. }
            | LoadError::MissingField { .. } => io::ErrorKind::InvalidData,
        };
        match err {
            LoadError::Io { source, .. } => source,
            other => Self::new(kind, other),
        }
    }
}
