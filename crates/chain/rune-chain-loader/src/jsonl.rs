//! JSON Lines: one record per line, read lazily with a per-line size cap.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use serde_json::Value;

use crate::document::Document;
use crate::error::LoadError;
use crate::io::{LineReader, open_regular};
use crate::jail::Jail;
use crate::json::Fields;
use crate::limits::Limits;
use crate::meta;

/// Loads JSON Lines, one [`Document`] per non-blank line.
///
/// Each document gets [`meta::LINE`], [`meta::BYTE_START`],
/// [`meta::BYTE_END`] (the line within the input, terminator excluded),
/// [`meta::CONTENT_SHA256`] and, for files, [`meta::SOURCE`] unless the
/// record has its own `source`.
///
/// By default the loader is **lenient**: lines that are not JSON, lack the
/// content field, or exceed [`Limits::max_record_bytes`] are skipped.
/// [`strict`](Self::strict) yields them as errors instead. I/O errors and
/// [`LoadError::TooManyRecords`] are always yielded and end the stream.
///
/// # Example
///
/// ```rust
/// use rune_chain_loader::jsonl::JsonlLoader;
/// use rune_chain_loader::json::Fields;
///
/// let input = "{\"text\":\"a\",\"lang\":\"en\"}\n{\"text\":\"b\",\"lang\":\"fr\"}\n";
/// let loader = JsonlLoader::new()
///     .fields(Fields::new().content("text").unwrap().metadata_only(&["lang"]).unwrap());
/// let docs: Vec<_> = loader.iter(input.as_bytes()).collect::<Result<_, _>>().unwrap();
/// assert_eq!(docs[1].content, "b");
/// assert_eq!(docs[1].metadata["lang"], "fr");
/// assert_eq!(docs[1].metadata["line"], "2");
/// assert_eq!(docs[1].metadata["byte_start"], "25");
/// ```
#[derive(Debug, Clone, Default)]
pub struct JsonlLoader {
    fields: Fields,
    limits: Limits,
    jail: Option<Jail>,
    strict: bool,
}

impl JsonlLoader {
    /// `content` field, default [`Limits`], lenient.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the content / metadata field mapping.
    #[must_use]
    pub fn fields(mut self, fields: Fields) -> Self {
        self.fields = fields;
        self
    }

    /// Replace the limits (`max_record_bytes` and `max_records` apply).
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

    /// Yield bad lines as errors instead of skipping them (default `false`).
    #[must_use]
    pub const fn strict(mut self, strict: bool) -> Self {
        self.strict = strict;
        self
    }

    /// Lazily read records from any buffered reader.
    pub fn iter<R: BufRead>(&self, reader: R) -> JsonlIter<R> {
        JsonlIter {
            lines: LineReader::new(reader, self.limits.max_record_bytes),
            fields: self.fields.clone(),
            max_records: self.limits.max_records,
            strict: self.strict,
            source: None,
            produced: 0,
            done: false,
        }
    }

    /// Lazily read records from a file. The file is streamed, so
    /// [`Limits::max_file_bytes`] does not apply; the record limits do.
    pub fn iter_file(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<JsonlIter<BufReader<File>>, LoadError> {
        let path = path.as_ref();
        let (file, _) = open_regular(path, self.jail.as_ref())?;
        let mut iter = self.iter(BufReader::new(file));
        iter.source = Some(path.display().to_string());
        Ok(iter)
    }

    /// Load every record from a string.
    pub fn load_str(&self, input: &str) -> Result<Vec<Document>, LoadError> {
        self.iter(input.as_bytes()).collect()
    }

    /// Load every record from a file.
    pub fn load_file(&self, path: impl AsRef<Path>) -> Result<Vec<Document>, LoadError> {
        self.iter_file(path)?.collect()
    }
}

/// Lazy JSON Lines iterator returned by [`JsonlLoader::iter`].
#[derive(Debug)]
pub struct JsonlIter<R> {
    lines: LineReader<R>,
    fields: Fields,
    max_records: usize,
    strict: bool,
    source: Option<String>,
    produced: usize,
    done: bool,
}

impl<R: BufRead> JsonlIter<R> {
    fn parse(&self, number: u64, bytes: &[u8]) -> Result<Option<Document>, LoadError> {
        let text = std::str::from_utf8(bytes).map_err(|_| LoadError::InvalidUtf8 {
            path: None,
            line: Some(number),
        })?;
        if text.trim().is_empty() {
            return Ok(None);
        }
        let value: Value = serde_json::from_str(text).map_err(|e| LoadError::Parse {
            line: number,
            message: e.to_string(),
        })?;
        if !value.is_object() {
            return Err(LoadError::Parse {
                line: number,
                message: "not a JSON object".to_string(),
            });
        }
        self.fields.to_document(&value, number).map(Some)
    }
}

impl<R: BufRead> Iterator for JsonlIter<R> {
    type Item = Result<Document, LoadError>;

    fn next(&mut self) -> Option<Self::Item> {
        while !self.done {
            let line = match self.lines.next_line() {
                Ok(Some(line)) => line,
                Ok(None) => return None,
                Err(err) => {
                    self.done = true;
                    return Some(Err(err));
                }
            };
            let result = match &line.bytes {
                None => Err(LoadError::RecordTooLarge {
                    line: line.number,
                    limit: self.lines_max(),
                }),
                Some(bytes) => self.parse(line.number, bytes),
            };
            let mut doc = match result {
                Ok(Some(doc)) => doc,
                Err(err) if self.strict => return Some(Err(err)),
                Ok(None) | Err(_) => continue,
            };
            if self.produced >= self.max_records {
                self.done = true;
                return Some(Err(LoadError::TooManyRecords {
                    limit: self.max_records,
                }));
            }
            self.produced += 1;
            let len = line.bytes.as_ref().map_or(0, Vec::len) as u64;
            meta::default_source(&mut doc, self.source.as_deref());
            meta::stamp_position(
                &mut doc,
                &[
                    (meta::LINE, line.number),
                    (meta::BYTE_START, line.start),
                    (meta::BYTE_END, line.start + len),
                ],
            );
            meta::stamp_hash(&mut doc);
            return Some(Ok(doc));
        }
        None
    }
}

impl<R> JsonlIter<R> {
    const fn lines_max(&self) -> usize {
        self.lines.max()
    }
}

/// Parse JSON Lines leniently with default [`Limits`], one [`Document`] per
/// valid line.
///
/// Each line must be a JSON object with a string `content` field, which
/// becomes the document text; all other fields become string metadata.
/// Invalid lines are skipped, as is everything after
/// [`Limits::max_records`] documents.
///
/// # Example
///
/// ```rust
/// use rune_chain_loader::jsonl::load_jsonl_str;
///
/// let input = r#"{"content":"hello","source":"a.txt"}
/// {"content":"world","source":"b.txt"}"#;
///
/// let docs = load_jsonl_str(input);
/// assert_eq!(docs.len(), 2);
/// assert_eq!(docs[0].content, "hello");
/// assert_eq!(docs[0].metadata["source"], "a.txt");
/// assert_eq!(docs[1].metadata["line"], "2");
/// ```
#[must_use]
pub fn load_jsonl_str(input: &str) -> Vec<Document> {
    JsonlLoader::new()
        .iter(input.as_bytes())
        .map_while(Result::ok)
        .collect()
}

/// Load a `.jsonl` file leniently with default [`Limits`]; `source` defaults
/// to the path.
///
/// # Example
///
/// ```rust,no_run
/// use rune_chain_loader::jsonl::load_jsonl_file;
///
/// let docs = load_jsonl_file("data.jsonl").unwrap();
/// println!("loaded {} documents", docs.len());
/// ```
pub fn load_jsonl_file(path: impl AsRef<Path>) -> Result<Vec<Document>, LoadError> {
    JsonlLoader::new().load_file(path)
}
