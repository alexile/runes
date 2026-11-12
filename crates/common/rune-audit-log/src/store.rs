//! Where records live: the [`Store`] trait, an in-memory store and a
//! JSON-lines file store.

use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::{Error, Record};

/// A boxed, streaming iterator over stored records.
pub type Records<'a> = Box<dyn Iterator<Item = Result<Record, Error>> + 'a>;

/// Append-only storage for records.
///
/// Implement it to keep the log elsewhere (SQLite, an object store, a
/// remote collector); wrap backend errors in [`Error::Storage`].
pub trait Store {
    /// Stores `record` after every record already stored.
    fn append(&mut self, record: &Record) -> Result<(), Error>;

    /// The newest record, if any. Used to resume the chain on open.
    fn last(&self) -> Result<Option<Record>, Error>;

    /// Every record, oldest first, read lazily so that verifying or
    /// exporting a long log needs constant memory.
    fn records(&self) -> Result<Records<'_>, Error>;
}

/// Records in a `Vec`; for tests and short-lived processes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MemoryStore {
    records: Vec<Record>,
}

impl MemoryStore {
    /// An empty store.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    /// The stored records.
    #[must_use]
    pub fn as_slice(&self) -> &[Record] {
        &self.records
    }

    /// Mutable access to the stored records, to simulate tampering in
    /// tests.
    pub const fn records_mut(&mut self) -> &mut Vec<Record> {
        &mut self.records
    }
}

impl Store for MemoryStore {
    fn append(&mut self, record: &Record) -> Result<(), Error> {
        self.records.push(record.clone());
        Ok(())
    }

    fn last(&self) -> Result<Option<Record>, Error> {
        Ok(self.records.last().cloned())
    }

    fn records(&self) -> Result<Records<'_>, Error> {
        Ok(Box::new(self.records.iter().cloned().map(Ok)))
    }
}

/// The default bound on one stored line: 1 MiB.
pub const DEFAULT_MAX_LINE_LEN: usize = 1024 * 1024;

/// Records as JSON lines in one file, opened for appending.
///
/// Each [`append`](Store::append) is a single `write` of a complete line
/// on a file opened in append mode. On Unix a newly created file gets
/// mode `0600`. Reading is bounded: a line longer than
/// [`max_line_len`](Self::with_max_line_len) is reported as corrupt
/// rather than buffered.
#[derive(Debug)]
pub struct FileStore {
    path: PathBuf,
    file: File,
    sync: bool,
    max_line_len: usize,
}

impl FileStore {
    /// Opens (creating if needed) the log file at `path`.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] when the file cannot be opened.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref().to_path_buf();
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let file = options.open(&path).map_err(|source| Error::Io {
            path: Some(path.clone()),
            source,
        })?;
        Ok(Self {
            path,
            file,
            sync: false,
            max_line_len: DEFAULT_MAX_LINE_LEN,
        })
    }

    /// Whether to `fsync` after every append. Default `false`: durable
    /// against crashes of the process, not of the machine.
    #[must_use]
    pub const fn with_sync(mut self, sync: bool) -> Self {
        self.sync = sync;
        self
    }

    /// The largest line accepted on append or read, in bytes (without
    /// the newline). Default [`DEFAULT_MAX_LINE_LEN`].
    #[must_use]
    pub const fn with_max_line_len(mut self, max: usize) -> Self {
        self.max_line_len = max;
        self
    }

    /// The file's path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn io(&self, source: io::Error) -> Error {
        Error::Io {
            path: Some(self.path.clone()),
            source,
        }
    }
}

impl Store for FileStore {
    fn append(&mut self, record: &Record) -> Result<(), Error> {
        let mut line = record.to_json()?;
        if line.len() > self.max_line_len {
            return Err(Error::TooLarge {
                len: line.len(),
                max: self.max_line_len,
            });
        }
        line.push('\n');
        self.file
            .write_all(line.as_bytes())
            .map_err(|err| self.io(err))?;
        if self.sync {
            self.file.sync_data().map_err(|err| self.io(err))?;
        }
        Ok(())
    }

    fn last(&self) -> Result<Option<Record>, Error> {
        // Read only the tail: at most one full line plus its newline and
        // the newline before it.
        let mut file = File::open(&self.path).map_err(|err| self.io(err))?;
        let len = file.metadata().map_err(|err| self.io(err))?.len();
        let window = u64::try_from(self.max_line_len)
            .unwrap_or(u64::MAX)
            .saturating_add(2)
            .min(len);
        file.seek(SeekFrom::Start(len - window))
            .map_err(|err| self.io(err))?;
        let mut tail = Vec::new();
        file.take(window)
            .read_to_end(&mut tail)
            .map_err(|err| self.io(err))?;
        if tail.is_empty() {
            return Ok(None);
        }
        let Some(body) = tail.strip_suffix(b"\n") else {
            return Err(Error::Corrupt {
                line: None,
                reason: "the last record is not terminated by a newline (torn write?)".into(),
            });
        };
        let line = match body.iter().rposition(|&b| b == b'\n') {
            Some(newline) => &body[newline + 1..],
            None if window == len => body,
            None => {
                return Err(Error::TooLarge {
                    len: body.len(),
                    max: self.max_line_len,
                });
            }
        };
        parse_line(line, None).map(Some)
    }

    fn records(&self) -> Result<Records<'_>, Error> {
        let file = File::open(&self.path).map_err(|err| self.io(err))?;
        Ok(Box::new(
            JsonlReader::new(BufReader::new(file)).with_max_line_len(self.max_line_len),
        ))
    }
}

/// Reads records from JSON lines, one at a time, with a bound on line
/// length: verify an exported log with [`Verifier`](crate::Verifier)
/// without loading it.
///
/// Empty lines are skipped. A final line without a newline is accepted.
///
/// ```
/// use rune_audit_log::{AuditLog, Entry, JsonlReader, MemoryStore, Verifier};
///
/// let mut log = AuditLog::open(MemoryStore::new())?;
/// log.append_at(Entry::new("ci", "deploy"), 1)?;
/// let mut exported = Vec::new();
/// log.export_jsonl(&mut exported)?;
///
/// let mut verifier = Verifier::new();
/// for record in JsonlReader::new(exported.as_slice()) {
///     verifier.push(&record?)?;
/// }
/// assert_eq!(verifier.finish().count, 1);
/// # Ok::<(), rune_audit_log::Error>(())
/// ```
#[derive(Debug)]
pub struct JsonlReader<R> {
    reader: R,
    max_line_len: usize,
    line: u64,
    done: bool,
}

impl<R: BufRead> JsonlReader<R> {
    /// A reader with the default bound, [`DEFAULT_MAX_LINE_LEN`].
    pub const fn new(reader: R) -> Self {
        Self {
            reader,
            max_line_len: DEFAULT_MAX_LINE_LEN,
            line: 0,
            done: false,
        }
    }

    /// Sets the largest line accepted, in bytes.
    #[must_use]
    pub const fn with_max_line_len(mut self, max: usize) -> Self {
        self.max_line_len = max;
        self
    }

    fn next_line(&mut self) -> Result<Option<Vec<u8>>, Error> {
        let limit = u64::try_from(self.max_line_len)
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        let mut buf = Vec::new();
        (&mut self.reader)
            .take(limit)
            .read_until(b'\n', &mut buf)
            .map_err(|source| Error::Io { path: None, source })?;
        if buf.is_empty() {
            return Ok(None);
        }
        self.line += 1;
        if buf.last() == Some(&b'\n') {
            buf.pop();
            if buf.last() == Some(&b'\r') {
                buf.pop();
            }
        } else if buf.len() > self.max_line_len {
            return Err(Error::TooLarge {
                len: buf.len(),
                max: self.max_line_len,
            });
        }
        Ok(Some(buf))
    }
}

impl<R: BufRead> Iterator for JsonlReader<R> {
    type Item = Result<Record, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        while !self.done {
            match self.next_line() {
                Ok(None) => self.done = true,
                Ok(Some(line)) if line.iter().all(u8::is_ascii_whitespace) => {}
                Ok(Some(line)) => return Some(parse_line(&line, Some(self.line))),
                Err(err) => {
                    self.done = true;
                    return Some(Err(err));
                }
            }
        }
        None
    }
}

fn parse_line(line: &[u8], number: Option<u64>) -> Result<Record, Error> {
    serde_json::from_slice(line).map_err(|err| Error::Corrupt {
        line: number,
        reason: err.to_string(),
    })
}
