//! PDF text extraction (feature `pdf`): one [`Document`] per page.
//!
//! Built on [`lopdf`], a pure-Rust PDF parser. Text comes from the page
//! content streams (`Tj`, `TJ`, `'` and `"` operators) decoded through each
//! font's encoding or `ToUnicode` map. There is no layout analysis or OCR, so
//! scanned pages come out empty and are skipped.
//!
//! # Metadata
//!
//! Every page gets [`meta::SOURCE`], [`meta::PAGE`] (1-based),
//! [`meta::PAGE_COUNT`] and [`meta::CONTENT_SHA256`], plus [`meta::TITLE`] and
//! [`meta::AUTHOR`] when the document info dictionary has them.
//!
//! # Hardening
//!
//! - the input is capped at [`Limits::max_file_bytes`] and the page count at
//!   [`Limits::max_pages`];
//! - every stream the loader decompresses (page content, font maps) is
//!   charged to one budget of [`Limits::max_decompressed_bytes`]. Object and
//!   cross-reference streams, which `lopdf` inflates while parsing, are each
//!   capped at a share of that budget sized from the number of streams in the
//!   file (at least 1 MiB);
//! - extracted text is capped at [`Limits::max_total_bytes`] and the whole
//!   load at [`Limits::max_duration`], checked between pages and every few
//!   thousand operators;
//! - encrypted PDFs are refused with [`LoadError::Encrypted`], even those that
//!   open with an empty password;
//! - parser panics become [`LoadError::Malformed`]. `lopdf` 0.42+ also bounds
//!   object nesting, so deep nesting cannot overflow the stack.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::io::Read;
use std::path::Path;

use lopdf::content::Content;
use lopdf::{DecompressError, Dictionary, Encoding, LoadOptions, Object};

use crate::Document;
use crate::error::LoadError;
use crate::guard::{self, Budget, Deadline};
use crate::html::normalise;
use crate::io::{read_file, read_limited};
use crate::jail::Jail;
use crate::limits::Limits;
use crate::meta;

/// Smallest per-stream cap used while `lopdf` parses the file.
const MIN_LOAD_STREAM: u64 = 1024 * 1024;
/// Longest title or author kept, in bytes.
const MAX_INFO: usize = 1024;
/// Deepest `TJ` array nesting followed.
const MAX_ARRAY_DEPTH: usize = 8;
/// Operators processed between deadline checks.
const CHECK_EVERY: usize = 4096;

/// Loads PDF files and bytes, one [`Document`] per page with text.
///
/// # Example
///
/// ```rust,no_run
/// use rune_chain_loader::{Limits, pdf::PdfLoader};
///
/// let pages = PdfLoader::new()
///     .limits(Limits::default().with_max_pages(500))
///     .load_file("paper.pdf")
///     .unwrap();
/// for page in &pages {
///     println!("page {} of {}", page.metadata["page"], page.metadata["page_count"]);
/// }
/// ```
#[derive(Debug, Clone, Default)]
pub struct PdfLoader {
    limits: Limits,
    jail: Option<Jail>,
}

impl PdfLoader {
    /// A loader with default [`Limits`] and no jail.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the limits.
    #[must_use]
    pub const fn limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Confine file paths to a [`Jail`]; relative paths resolve from its root.
    #[must_use]
    pub fn jail(mut self, jail: Jail) -> Self {
        self.jail = Some(jail);
        self
    }

    /// Load one regular file; `source` is set to the path.
    pub fn load_file(&self, path: impl AsRef<Path>) -> Result<Vec<Document>, LoadError> {
        let path = path.as_ref();
        let bytes = read_file(path, self.jail.as_ref(), self.limits.max_file_bytes)?;
        extract(&bytes, &path.display().to_string(), &self.limits).map_err(|e| e.with_path(path))
    }

    /// Load a PDF held in memory; `source` names it in the metadata.
    pub fn load_bytes(&self, bytes: &[u8], source: &str) -> Result<Vec<Document>, LoadError> {
        if bytes.len() as u64 > self.limits.max_file_bytes {
            return Err(LoadError::TooLarge {
                path: None,
                limit: self.limits.max_file_bytes,
            });
        }
        extract(bytes, source, &self.limits)
    }

    /// Read a PDF from `reader` (up to the size limit) and load it.
    pub fn load_reader(&self, reader: impl Read, source: &str) -> Result<Vec<Document>, LoadError> {
        let bytes = read_limited(reader, self.limits.max_file_bytes, None)?;
        extract(&bytes, source, &self.limits)
    }
}

/// Load a PDF file with default [`Limits`], one [`Document`] per page.
pub fn load_file(path: impl AsRef<Path>) -> Result<Vec<Document>, LoadError> {
    PdfLoader::new().load_file(path)
}

/// Load a PDF from memory with default [`Limits`]; `source` names it.
pub fn load_bytes(bytes: &[u8], source: &str) -> Result<Vec<Document>, LoadError> {
    PdfLoader::new().load_bytes(bytes, source)
}

pub(crate) fn extract(
    bytes: &[u8],
    source: &str,
    limits: &Limits,
) -> Result<Vec<Document>, LoadError> {
    guard::catch(|| extract_inner(bytes, source, limits))
}

/// Count `stream` keywords (not `endstream`): an upper bound on the streams
/// `lopdf` may inflate while parsing.
fn count_streams(bytes: &[u8]) -> u64 {
    let mut count = 0u64;
    let mut i = 0;
    while let Some(pos) = bytes
        .get(i..)
        .and_then(|rest| rest.windows(6).position(|w| w == b"stream"))
    {
        let at = i + pos;
        if !bytes[..at].ends_with(b"end") {
            count += 1;
        }
        i = at + 6;
    }
    count
}

fn load_stream_limit(bytes: &[u8], budget: u64) -> usize {
    let share = budget / count_streams(bytes).max(1);
    let limit = share.max(MIN_LOAD_STREAM).min(budget);
    usize::try_from(limit).unwrap_or(usize::MAX)
}

fn map_lopdf(err: lopdf::Error, budget: &Budget) -> LoadError {
    match err {
        lopdf::Error::Decompress(DecompressError::MemoryLimitExceeded { .. }) => budget.exceeded(),
        lopdf::Error::InvalidPassword
        | lopdf::Error::Decryption(_)
        | lopdf::Error::AlreadyEncrypted => LoadError::Encrypted { path: None },
        other => guard::malformed(other),
    }
}

fn info_string(doc: &lopdf::Document, key: &[u8]) -> Option<String> {
    let info = doc.trailer.get_deref(b"Info", doc).ok()?.as_dict().ok()?;
    let value = lopdf::decode_text_string(info.get_deref(key, doc).ok()?).ok()?;
    let mut value = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if value.len() > MAX_INFO {
        let mut end = MAX_INFO;
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        value.truncate(end);
    }
    (!value.is_empty()).then_some(value)
}

fn extract_inner(bytes: &[u8], source: &str, limits: &Limits) -> Result<Vec<Document>, LoadError> {
    let deadline = Deadline::start(limits.max_duration);
    let budget = Budget::new(limits);
    let options = LoadOptions {
        max_decompressed_size: Some(load_stream_limit(bytes, budget.limit())),
        ..LoadOptions::default()
    };
    let doc = lopdf::Document::load_mem_with_options(bytes, options)
        .map_err(|e| map_lopdf(e, &budget))?;
    if doc.is_encrypted() || doc.was_encrypted() {
        return Err(LoadError::Encrypted { path: None });
    }
    deadline.check()?;

    let pages: Vec<_> = doc
        .page_iter()
        .take(limits.max_pages.saturating_add(1))
        .collect();
    if pages.len() > limits.max_pages {
        return Err(LoadError::TooManyPages {
            limit: limits.max_pages,
        });
    }
    let page_count = pages.len().to_string();
    let title = info_string(&doc, b"Title");
    let author = info_string(&doc, b"Author");

    let mut pass = Pass {
        doc: &doc,
        encodings: Encodings::default(),
        budget,
        deadline,
        limits,
    };
    let mut total = 0usize;
    let mut docs = Vec::new();
    for (index, page_id) in pages.into_iter().enumerate() {
        deadline.check()?;
        let raw = pass.page_text(page_id, total)?;
        let text = normalise(&raw);
        if text.is_empty() {
            continue;
        }
        guard::charge_output(&mut total, text.len(), limits)?;
        let mut page = Document::new(text)
            .with_metadata(meta::SOURCE, source)
            .with_metadata(meta::PAGE, (index + 1).to_string())
            .with_metadata(meta::PAGE_COUNT, page_count.as_str());
        if let Some(title) = &title {
            page.metadata.insert(meta::TITLE.to_string(), title.clone());
        }
        if let Some(author) = &author {
            page.metadata
                .insert(meta::AUTHOR.to_string(), author.clone());
        }
        meta::stamp_hash(&mut page);
        docs.push(page);
    }
    Ok(docs)
}

/// Font encodings, resolved once per font dictionary and shared by pages.
#[derive(Default)]
struct Encodings<'a> {
    by_font: HashMap<*const Dictionary, Option<Encoding<'a>>>,
}

impl<'a> Encodings<'a> {
    fn get(
        &mut self,
        doc: &'a lopdf::Document,
        font: &'a Dictionary,
        budget: &mut Budget,
    ) -> Result<Option<&Encoding<'a>>, LoadError> {
        let entry = match self.by_font.entry(std::ptr::from_ref(font)) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                // Measure and charge the font's streams, then let lopdf inflate
                // them again under the budget as it stood before the charge.
                let before = budget.remaining_usize();
                charge_font_streams(doc, font, budget)?;
                let encoding = match font.get_font_encoding_with_limit(doc, before) {
                    Ok(encoding) => Some(encoding),
                    Err(lopdf::Error::Decompress(DecompressError::MemoryLimitExceeded {
                        ..
                    })) => return Err(budget.exceeded()),
                    Err(_) => None,
                };
                entry.insert(encoding)
            }
        };
        Ok(entry.as_ref())
    }
}

/// Charge the streams `get_font_encoding` will inflate to the budget.
fn charge_font_streams(
    doc: &lopdf::Document,
    font: &Dictionary,
    budget: &mut Budget,
) -> Result<(), LoadError> {
    for key in [b"ToUnicode".as_slice(), b"Encoding"] {
        let Ok(stream) = font.get_deref(key, doc).and_then(Object::as_stream) else {
            continue;
        };
        let len = match stream.decompressed_content_with_limit(budget.remaining_usize()) {
            Ok(data) => data.len(),
            Err(lopdf::Error::Decompress(DecompressError::MemoryLimitExceeded { .. })) => {
                return Err(budget.exceeded());
            }
            Err(_) => stream.content.len(),
        };
        budget.charge(len)?;
    }
    Ok(())
}

fn newline(text: &mut String) {
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
}

fn show(text: &mut String, encoding: Option<&Encoding<'_>>, operands: &[Object], depth: usize) {
    let Some(encoding) = encoding else {
        return;
    };
    for operand in operands {
        match operand {
            Object::String(bytes, _) => {
                // Undecodable bytes are dropped rather than failing the page.
                let _ = encoding.write_to_string(bytes, text);
            }
            Object::Array(items) if depth < MAX_ARRAY_DEPTH => {
                show(text, Some(encoding), items, depth + 1);
                text.push(' ');
            }
            Object::Integer(i) if *i < -100 => text.push(' '),
            Object::Real(r) if *r < -100.0 => text.push(' '),
            _ => {}
        }
    }
}

/// State for extracting the pages of one document.
struct Pass<'a, 'l> {
    doc: &'a lopdf::Document,
    encodings: Encodings<'a>,
    budget: Budget,
    deadline: Deadline,
    limits: &'l Limits,
}

impl<'a> Pass<'a, '_> {
    fn encoding(
        &mut self,
        font: Option<&'a Dictionary>,
    ) -> Result<Option<&Encoding<'a>>, LoadError> {
        match font {
            Some(font) => self.encodings.get(self.doc, font, &mut self.budget),
            None => Ok(None),
        }
    }

    /// Raw text of one page; `total` is the text already produced.
    fn page_text(&mut self, page_id: lopdf::ObjectId, total: usize) -> Result<String, LoadError> {
        let doc = self.doc;
        let content = doc
            .get_page_content_with_limit(page_id, self.budget.remaining_usize())
            .map_err(|e| map_lopdf(e, &self.budget))?;
        self.budget.charge(content.len())?;
        // A page whose content does not parse contributes no text.
        let operations = Content::decode(&content).map_or_else(|_| Vec::new(), |c| c.operations);
        drop(content);
        let fonts = doc.get_page_fonts(page_id).unwrap_or_default();

        let mut text = String::new();
        let mut font: Option<&'a Dictionary> = None;
        for (i, op) in operations.iter().enumerate() {
            if i % CHECK_EVERY == CHECK_EVERY - 1 {
                self.deadline.check()?;
            }
            match op.operator.as_str() {
                "Tf" => {
                    font = op
                        .operands
                        .first()
                        .and_then(|o| o.as_name().ok())
                        .and_then(|name| fonts.get(name).copied());
                }
                "Tj" | "TJ" => show(&mut text, self.encoding(font)?, &op.operands, 0),
                "'" | "\"" => {
                    newline(&mut text);
                    let operands = if op.operator == "'" {
                        op.operands.get(..1)
                    } else {
                        op.operands.get(2..3)
                    };
                    show(
                        &mut text,
                        self.encoding(font)?,
                        operands.unwrap_or_default(),
                        0,
                    );
                }
                "T*" | "ET" => newline(&mut text),
                "Td" | "TD" => {
                    let dy = op.operands.get(1).and_then(|o| o.as_float().ok());
                    if dy.is_some_and(|dy| dy != 0.0) {
                        newline(&mut text);
                    } else if !text.is_empty() && !text.ends_with([' ', '\n']) {
                        text.push(' ');
                    }
                }
                _ => {}
            }
            // Raw text still has the whitespace `normalise` drops, so allow
            // it twice the room here; the exact cap is checked afterwards.
            if total.saturating_add(text.len()) / 2 > self.limits.max_total_bytes {
                return Err(LoadError::OutputTooLarge {
                    limit: self.limits.max_total_bytes,
                });
            }
        }
        Ok(text)
    }
}
