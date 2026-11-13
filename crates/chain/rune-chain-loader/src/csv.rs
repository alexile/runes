//! CSV: one [`Document`] per row, parsed lazily by a small RFC 4180 reader.
//!
//! Quoted fields may contain delimiters, `""` escapes and newlines. Outside
//! quotes, `\r` is ignored so both `\n` and `\r\n` endings work. Parsing is
//! lenient about stray quotes inside unquoted fields (kept literally) but an
//! unterminated quoted field at end of input is a [`LoadError::Parse`].
//! Each row is capped at [`Limits::max_record_bytes`], so a missing closing
//! quote cannot swallow unbounded memory, and the content of all rows
//! together is capped at [`Limits::max_total_bytes`], so a long header row
//! repeated into many short rows cannot blow up either.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use crate::document::Document;
use crate::error::LoadError;
use crate::io::open_regular;
use crate::jail::Jail;
use crate::limits::Limits;
use crate::meta;

/// Loads CSV rows as documents.
///
/// The content of each document is, by default, one `column: value` line per
/// column. Select columns with [`content_columns`](Self::content_columns); a
/// single selected column yields its raw value. Columns named in
/// [`metadata_columns`](Self::metadata_columns) are copied into metadata.
///
/// Each document gets [`meta::ROW`] (1-based, header excluded),
/// [`meta::LINE`], [`meta::BYTE_START`], [`meta::BYTE_END`],
/// [`meta::CONTENT_SHA256`] and, for files, [`meta::SOURCE`].
///
/// Without a header row (or for extra cells beyond it) columns are named
/// `column_1`, `column_2`, …; missing cells are empty.
///
/// # Example
///
/// ```rust
/// use rune_chain_loader::csv::CsvLoader;
///
/// let input = "title,body,lang\nHello,\"Hi, there\",en\nBye,\"See\n you\",fr\n";
/// let docs = CsvLoader::new()
///     .content_columns(&["body"])
///     .metadata_columns(&["title", "lang"])
///     .load_str(input)
///     .unwrap();
/// assert_eq!(docs.len(), 2);
/// assert_eq!(docs[0].content, "Hi, there");
/// assert_eq!(docs[1].content, "See\n you");
/// assert_eq!(docs[1].metadata["lang"], "fr");
/// assert_eq!(docs[1].metadata["row"], "2");
/// assert_eq!(docs[1].metadata["line"], "3");
///
/// let all = CsvLoader::new().load_str("a,b\n1,2\n").unwrap();
/// assert_eq!(all[0].content, "a: 1\nb: 2");
/// ```
#[derive(Debug, Clone)]
pub struct CsvLoader {
    delimiter: u8,
    has_headers: bool,
    content_columns: Option<Vec<String>>,
    metadata_columns: Vec<String>,
    limits: Limits,
    jail: Option<Jail>,
}

impl Default for CsvLoader {
    fn default() -> Self {
        Self {
            delimiter: b',',
            has_headers: true,
            content_columns: None,
            metadata_columns: Vec::new(),
            limits: Limits::DEFAULT,
            jail: None,
        }
    }
}

impl CsvLoader {
    /// Comma-delimited, with a header row, all columns as content.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Field delimiter byte (default `b','`; use `b'\t'` for TSV).
    #[must_use]
    pub const fn delimiter(mut self, delimiter: u8) -> Self {
        self.delimiter = delimiter;
        self
    }

    /// Whether the first row names the columns (default `true`).
    #[must_use]
    pub const fn has_headers(mut self, has_headers: bool) -> Self {
        self.has_headers = has_headers;
        self
    }

    /// Columns that form the content. With a header row, every name must
    /// exist in it ([`LoadError::MissingField`] otherwise).
    #[must_use]
    pub fn content_columns(mut self, columns: &[&str]) -> Self {
        self.content_columns = Some(columns.iter().map(ToString::to_string).collect());
        self
    }

    /// Columns copied into metadata under their own names.
    #[must_use]
    pub fn metadata_columns(mut self, columns: &[&str]) -> Self {
        self.metadata_columns = columns.iter().map(ToString::to_string).collect();
        self
    }

    /// Replace the limits (`max_record_bytes`, `max_records` and
    /// `max_total_bytes` apply).
    #[must_use]
    pub const fn limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Confine file paths to a [`Jail`].
    #[must_use]
    pub fn jail(mut self, jail: Jail) -> Self {
        self.jail = Some(jail);
        self
    }

    /// Lazily read rows from any buffered reader.
    pub fn iter<R: BufRead>(&self, reader: R) -> CsvIter<R> {
        CsvIter {
            reader: RecordReader {
                inner: reader,
                max: self.limits.max_record_bytes,
                offset: 0,
                lines: 0,
            },
            config: self.clone(),
            headers: None,
            source: None,
            rows: 0,
            produced: 0,
            done: false,
        }
    }

    /// Lazily read rows from a file (streamed: `max_file_bytes` does not
    /// apply, the record limits do).
    pub fn iter_file(&self, path: impl AsRef<Path>) -> Result<CsvIter<BufReader<File>>, LoadError> {
        let path = path.as_ref();
        let (file, _) = open_regular(path, self.jail.as_ref())?;
        let mut iter = self.iter(BufReader::new(file));
        iter.source = Some(path.display().to_string());
        Ok(iter)
    }

    /// Load every row of a string.
    pub fn load_str(&self, input: &str) -> Result<Vec<Document>, LoadError> {
        self.iter(input.as_bytes()).collect()
    }

    /// Load every row of a file.
    pub fn load_file(&self, path: impl AsRef<Path>) -> Result<Vec<Document>, LoadError> {
        self.iter_file(path)?.collect()
    }
}

struct RawRecord {
    fields: Vec<Vec<u8>>,
    start: u64,
    end: u64,
    line: u64,
    blank: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    FieldStart,
    Unquoted,
    Quoted,
    QuoteInQuoted,
}

struct RecordReader<R> {
    inner: R,
    max: usize,
    offset: u64,
    lines: u64,
}

impl<R: BufRead> RecordReader<R> {
    fn next_record(&mut self, delimiter: u8) -> Result<Option<RawRecord>, LoadError> {
        let start = self.offset;
        let line = self.lines + 1;
        let mut fields = Vec::new();
        let mut field = Vec::new();
        let mut state = State::FieldStart;
        let mut quoted_any = false;
        let mut size = 0usize;
        let mut end = start;
        let mut any = false;
        loop {
            let chunk = self
                .inner
                .fill_buf()
                .map_err(|source| LoadError::Io { path: None, source })?;
            if chunk.is_empty() {
                break;
            }
            let mut used = 0;
            let mut finished = false;
            for &b in chunk {
                used += 1;
                any = true;
                size += 1;
                if size > self.max {
                    return Err(LoadError::RecordTooLarge {
                        line,
                        limit: self.max,
                    });
                }
                if b == b'\n' {
                    self.lines += 1;
                }
                match (state, b) {
                    (State::Quoted, b'"') => state = State::QuoteInQuoted,
                    (State::Quoted, _) => field.push(b),
                    (State::QuoteInQuoted, b'"') => {
                        field.push(b'"');
                        state = State::Quoted;
                    }
                    (State::FieldStart, b'"') => {
                        state = State::Quoted;
                        quoted_any = true;
                    }
                    (_, b) if b == delimiter => {
                        fields.push(std::mem::take(&mut field));
                        state = State::FieldStart;
                    }
                    (_, b'\n') => {
                        finished = true;
                        break;
                    }
                    (_, b'\r') => continue,
                    (_, b) => {
                        field.push(b);
                        state = State::Unquoted;
                    }
                }
                end = self.offset + used as u64;
            }
            self.inner.consume(used);
            self.offset += used as u64;
            if finished {
                break;
            }
        }
        if !any {
            return Ok(None);
        }
        if state == State::Quoted {
            return Err(LoadError::Parse {
                line,
                message: "unterminated quoted field".to_string(),
            });
        }
        fields.push(field);
        let blank = !quoted_any && fields.len() == 1 && fields[0].is_empty();
        Ok(Some(RawRecord {
            fields,
            start,
            end,
            line,
            blank,
        }))
    }
}

/// Lazy CSV iterator returned by [`CsvLoader::iter`].
pub struct CsvIter<R> {
    reader: RecordReader<R>,
    config: CsvLoader,
    headers: Option<Vec<String>>,
    source: Option<String>,
    rows: u64,
    produced: usize,
    done: bool,
}

impl<R> std::fmt::Debug for CsvIter<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CsvIter")
            .field("headers", &self.headers)
            .field("rows", &self.rows)
            .finish_non_exhaustive()
    }
}

fn column_name(headers: Option<&[String]>, index: usize) -> String {
    headers
        .and_then(|h| h.get(index))
        .cloned()
        .unwrap_or_else(|| format!("column_{}", index + 1))
}

impl<R: BufRead> CsvIter<R> {
    fn set_headers(&mut self, headers: Vec<String>, line: u64) -> Result<(), LoadError> {
        if let Some(columns) = &self.config.content_columns
            && let Some(missing) = columns.iter().find(|c| !headers.contains(c))
        {
            return Err(LoadError::MissingField {
                line,
                field: missing.clone(),
            });
        }
        self.headers = Some(headers);
        Ok(())
    }

    fn build(&self, values: &[String]) -> Document {
        let headers = self.headers.as_deref();
        let width = values.len().max(headers.map_or(0, <[String]>::len));
        let names: Vec<String> = (0..width).map(|i| column_name(headers, i)).collect();
        let value_of = |name: &str| {
            names
                .iter()
                .position(|n| n == name)
                .and_then(|i| values.get(i))
                .map_or("", String::as_str)
        };
        let content = match &self.config.content_columns {
            Some(columns) if columns.len() == 1 => value_of(&columns[0]).to_string(),
            Some(columns) => columns
                .iter()
                .map(|c| format!("{c}: {}", value_of(c)))
                .collect::<Vec<_>>()
                .join("\n"),
            None => names
                .iter()
                .enumerate()
                .map(|(i, n)| format!("{n}: {}", values.get(i).map_or("", String::as_str)))
                .collect::<Vec<_>>()
                .join("\n"),
        };
        let mut doc = Document::new(content);
        for column in &self.config.metadata_columns {
            if names.contains(column) {
                doc.metadata
                    .insert(column.clone(), value_of(column).to_string());
            }
        }
        doc
    }
}

impl<R: BufRead> Iterator for CsvIter<R> {
    type Item = Result<Document, LoadError>;

    fn next(&mut self) -> Option<Self::Item> {
        while !self.done {
            let record = match self.reader.next_record(self.config.delimiter) {
                Ok(Some(record)) => record,
                Ok(None) => return None,
                Err(err) => {
                    self.done = true;
                    return Some(Err(err));
                }
            };
            if record.blank {
                continue;
            }
            let values: Result<Vec<String>, _> =
                record.fields.into_iter().map(String::from_utf8).collect();
            let Ok(values) = values else {
                return Some(Err(LoadError::InvalidUtf8 {
                    path: None,
                    line: Some(record.line),
                }));
            };
            if self.config.has_headers && self.headers.is_none() {
                if let Err(err) = self.set_headers(values, record.line) {
                    self.done = true;
                    return Some(Err(err));
                }
                continue;
            }
            if self.rows >= self.config.limits.max_records as u64 {
                self.done = true;
                return Some(Err(LoadError::TooManyRecords {
                    limit: self.config.limits.max_records,
                }));
            }
            self.rows += 1;
            let mut doc = self.build(&values);
            self.produced = self.produced.saturating_add(doc.content.len());
            if self.produced > self.config.limits.max_total_bytes {
                self.done = true;
                return Some(Err(LoadError::OutputTooLarge {
                    limit: self.config.limits.max_total_bytes,
                }));
            }
            meta::default_source(&mut doc, self.source.as_deref());
            meta::stamp_position(
                &mut doc,
                &[
                    (meta::ROW, self.rows),
                    (meta::LINE, record.line),
                    (meta::BYTE_START, record.start),
                    (meta::BYTE_END, record.end),
                ],
            );
            meta::stamp_hash(&mut doc);
            return Some(Ok(doc));
        }
        None
    }
}
