//! Metadata keys set by the loaders.
//!
//! Every document gets [`SOURCE`] (when the input has a name) and
//! [`CONTENT_SHA256`]. Record-oriented loaders add the position of the record
//! in its input so a retrieved chunk can be traced back to its origin.

use crate::Document;

/// Where the document came from: a file path, `"stdin"`, or a caller-given
/// name. For JSON/JSONL records a `source` field in the record wins.
pub const SOURCE: &str = "source";
/// Path relative to the directory-walk root, `/`-separated.
pub const RELATIVE_PATH: &str = "relative_path";
/// Lower-case hex SHA-256 of the document's `content` (UTF-8 bytes).
pub const CONTENT_SHA256: &str = "content_sha256";
/// 1-based line on which a JSONL record or CSV row starts.
pub const LINE: &str = "line";
/// 1-based data row of a CSV record (the header row is not counted).
pub const ROW: &str = "row";
/// 1-based index of a record within a JSON document.
pub const RECORD: &str = "record";
/// Byte offset of the record's first byte within its input.
pub const BYTE_START: &str = "byte_start";
/// Byte offset one past the record's last byte (line terminator excluded).
pub const BYTE_END: &str = "byte_end";
/// The `<title>` of an HTML document, or the title of a PDF or EPUB.
pub const TITLE: &str = "title";
/// The author of a PDF (`/Author`) or EPUB (`dc:creator`, joined with `, `).
pub const AUTHOR: &str = "author";
/// 1-based page number of a PDF page.
pub const PAGE: &str = "page";
/// Number of pages in the PDF a page came from.
pub const PAGE_COUNT: &str = "page_count";
/// 1-based position of an EPUB chapter in the spine.
pub const CHAPTER: &str = "chapter";
/// Number of items in the EPUB spine a chapter came from.
pub const CHAPTER_COUNT: &str = "chapter_count";
/// The `<title>` of an EPUB chapter's XHTML file, when it has one.
pub const CHAPTER_TITLE: &str = "chapter_title";
/// Path of an EPUB chapter inside the archive.
pub const ENTRY: &str = "entry";

/// Set [`CONTENT_SHA256`] from the current content (always overwrites, so a
/// record cannot spoof it).
pub(crate) fn stamp_hash(doc: &mut Document) {
    doc.metadata.insert(
        CONTENT_SHA256.to_string(),
        rune_sha256::hash_bytes(doc.content.as_bytes()),
    );
}

/// Set loader-owned position keys (always overwrite).
pub(crate) fn stamp_position(doc: &mut Document, entries: &[(&str, u64)]) {
    for (key, value) in entries {
        doc.metadata.insert((*key).to_string(), value.to_string());
    }
}

/// Set `source` unless the record already carries one.
pub(crate) fn default_source(doc: &mut Document, source: Option<&str>) {
    if let Some(source) = source {
        doc.metadata
            .entry(SOURCE.to_string())
            .or_insert_with(|| source.to_string());
    }
}
