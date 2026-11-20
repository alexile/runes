//! EPUB loading (feature `epub`): one [`Document`] per spine chapter.
//!
//! The container (`META-INF/container.xml`) points at the package file,
//! whose spine gives the reading order. Each XHTML chapter is turned into
//! text with [`html::html_to_text`](crate::html::html_to_text); chapters
//! without text (cover images, blank pages) are skipped.
//!
//! # Metadata
//!
//! Every chapter gets [`meta::SOURCE`], [`meta::CHAPTER`] (1-based spine
//! position), [`meta::CHAPTER_COUNT`], [`meta::ENTRY`] (its path in the
//! archive) and [`meta::CONTENT_SHA256`], plus [`meta::TITLE`] and
//! [`meta::AUTHOR`] from the package metadata and [`meta::CHAPTER_TITLE`]
//! from the chapter's `<title>`, when present.
//!
//! # Hardening
//!
//! - the archive is capped at [`Limits::max_file_bytes`] and
//!   [`Limits::max_archive_entries`], the spine at [`Limits::max_pages`];
//! - every entry read is charged to [`Limits::max_decompressed_bytes`] (its
//!   declared size is checked before it is inflated, its real size while it
//!   is), and an entry over 1 MiB that compresses better than
//!   [`Limits::max_compression_ratio`] is refused as a zip bomb;
//! - entry names are never written to disk. Names that are absolute, contain
//!   `..`, backslashes or NUL are ignored, duplicate names are an error, and
//!   a manifest link that climbs out of the archive is
//!   [`LoadError::OutsideRoot`];
//! - zip-encrypted entries and chapters listed in `META-INF/encryption.xml`
//!   (DRM) are [`LoadError::Encrypted`]; obfuscated fonts are ignored;
//! - XML is parsed without DTDs or custom entities, so there is no entity
//!   expansion; text is capped at [`Limits::max_total_bytes`] and the load
//!   at [`Limits::max_duration`].

use std::collections::{HashMap, HashSet};
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

use quick_xml::XmlVersion;
use quick_xml::events::Event;
use quick_xml::reader::Reader;

use crate::Document;
use crate::error::LoadError;
use crate::guard::{self, Budget, Deadline};
use crate::html;
use crate::io::{read_file, read_limited, utf8};
use crate::jail::Jail;
use crate::limits::Limits;
use crate::meta;

/// Entries at or below this size are exempt from the ratio check.
const RATIO_FLOOR: u64 = 1024 * 1024;
/// Longest title or author kept, in bytes.
const MAX_INFO: usize = 1024;

/// Loads EPUB files and bytes, one [`Document`] per chapter with text.
///
/// # Example
///
/// ```rust,no_run
/// use rune_chain_loader::epub::EpubLoader;
///
/// let chapters = EpubLoader::new().load_file("book.epub").unwrap();
/// for chapter in &chapters {
///     println!("{} #{}", chapter.metadata["title"], chapter.metadata["chapter"]);
/// }
/// ```
#[derive(Debug, Clone, Default)]
pub struct EpubLoader {
    limits: Limits,
    jail: Option<Jail>,
}

impl EpubLoader {
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

    /// Load an EPUB held in memory; `source` names it in the metadata.
    pub fn load_bytes(&self, bytes: &[u8], source: &str) -> Result<Vec<Document>, LoadError> {
        if bytes.len() as u64 > self.limits.max_file_bytes {
            return Err(LoadError::TooLarge {
                path: None,
                limit: self.limits.max_file_bytes,
            });
        }
        extract(bytes, source, &self.limits)
    }

    /// Read an EPUB from `reader` (up to the size limit) and load it.
    pub fn load_reader(&self, reader: impl Read, source: &str) -> Result<Vec<Document>, LoadError> {
        let bytes = read_limited(reader, self.limits.max_file_bytes, None)?;
        extract(&bytes, source, &self.limits)
    }
}

/// Load an EPUB file with default [`Limits`], one [`Document`] per chapter.
pub fn load_file(path: impl AsRef<Path>) -> Result<Vec<Document>, LoadError> {
    EpubLoader::new().load_file(path)
}

/// Load an EPUB from memory with default [`Limits`]; `source` names it.
pub fn load_bytes(bytes: &[u8], source: &str) -> Result<Vec<Document>, LoadError> {
    EpubLoader::new().load_bytes(bytes, source)
}

pub(crate) fn extract(
    bytes: &[u8],
    source: &str,
    limits: &Limits,
) -> Result<Vec<Document>, LoadError> {
    guard::catch(|| extract_inner(bytes, source, limits))
}

/// A cleaned entry name: `/`-separated, relative, without `.` or `..`
/// segments. `None` for names that could escape a directory.
fn safe_entry_name(name: &str) -> Option<String> {
    if name.is_empty()
        || name.starts_with('/')
        || name.contains(['\\', '\0'])
        || name.as_bytes().get(1) == Some(&b':')
    {
        return None;
    }
    let mut parts = Vec::new();
    for part in name.split('/') {
        match part {
            "" | "." => {}
            ".." => return None,
            part => parts.push(part),
        }
    }
    (!parts.is_empty()).then(|| parts.join("/"))
}

fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = std::str::from_utf8(bytes.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Resolve a manifest `href` against the directory `base` (`""` for the
/// archive root). Climbing above the root is [`LoadError::OutsideRoot`];
/// external URLs give `Ok(None)`.
fn resolve_href(base: &str, href: &str) -> Result<Option<String>, LoadError> {
    let outside = || LoadError::OutsideRoot {
        path: PathBuf::from(href),
    };
    let href_path = href.split(['#', '?']).next().unwrap_or_default();
    if href_path
        .split('/')
        .next()
        .is_some_and(|first| first.contains(':'))
    {
        return Ok(None);
    }
    let decoded =
        percent_decode(href_path).ok_or_else(|| guard::malformed(format!("bad link `{href}`")))?;
    if decoded.starts_with('/') || decoded.contains(['\\', '\0']) {
        return Err(outside());
    }
    let mut parts: Vec<&str> = base.split('/').filter(|p| !p.is_empty()).collect();
    for part in decoded.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop().ok_or_else(outside)?;
            }
            part => parts.push(part),
        }
    }
    Ok((!parts.is_empty()).then(|| parts.join("/")))
}

fn parent_dir(path: &str) -> &str {
    path.rfind('/').map_or("", |i| &path[..i])
}

struct Archive<'a> {
    zip: zip::ZipArchive<Cursor<&'a [u8]>>,
    index: HashMap<String, usize>,
    budget: Budget,
    ratio: u64,
}

fn zip_error(err: zip::result::ZipError) -> LoadError {
    guard::malformed(err)
}

impl<'a> Archive<'a> {
    fn open(bytes: &'a [u8], limits: &Limits) -> Result<Self, LoadError> {
        let zip = zip::ZipArchive::new(Cursor::new(bytes)).map_err(zip_error)?;
        if zip.len() > limits.max_archive_entries {
            return Err(LoadError::TooManyEntries {
                limit: limits.max_archive_entries,
            });
        }
        let mut index = HashMap::with_capacity(zip.len());
        for i in 0..zip.len() {
            let Some(Ok(name)) = zip.name_for_index(i) else {
                continue;
            };
            if name.ends_with('/') {
                continue;
            }
            if let Some(clean) = safe_entry_name(&name)
                && index.insert(clean, i).is_some()
            {
                return Err(guard::malformed(format!("duplicate entry `{name}`")));
            }
        }
        Ok(Self {
            zip,
            index,
            budget: Budget::new(limits),
            ratio: limits.max_compression_ratio,
        })
    }

    /// Read an entry by its cleaned name; `Ok(None)` if there is none.
    fn read(&mut self, name: &str) -> Result<Option<Vec<u8>>, LoadError> {
        let Some(&i) = self.index.get(name) else {
            return Ok(None);
        };
        if self.zip.by_index_raw(i).map_err(zip_error)?.encrypted() {
            return Err(LoadError::Encrypted { path: None });
        }
        let file = self.zip.by_index(i).map_err(zip_error)?;
        let packed = file.compressed_size();
        let bomb =
            |size: u64| size > RATIO_FLOOR && size / packed.max(1) >= self.ratio && size > packed;
        if bomb(file.size()) {
            return Err(LoadError::CompressionRatio {
                entry: name.to_string(),
                limit: self.ratio,
            });
        }
        let cap = self.budget.remaining();
        if file.size() > cap {
            return Err(self.budget.exceeded());
        }
        let mut data = Vec::with_capacity(usize::try_from(file.size()).unwrap_or(0));
        file.take(cap.saturating_add(1))
            .read_to_end(&mut data)
            .map_err(guard::malformed)?;
        if bomb(data.len() as u64) {
            return Err(LoadError::CompressionRatio {
                entry: name.to_string(),
                limit: self.ratio,
            });
        }
        self.budget.charge(data.len())?;
        Ok(Some(data))
    }

    fn read_text(&mut self, name: &str) -> Result<Option<String>, LoadError> {
        self.read(name)?.map(|data| utf8(data, None)).transpose()
    }
}

/// Text of `ref` entities and character references, the only ones XML
/// without a DTD can contain.
fn push_ref(out: &mut String, reference: &quick_xml::events::BytesRef<'_>) {
    if let Ok(Some(c)) = reference.resolve_char_ref() {
        out.push(c);
    } else if let Some(text) =
        quick_xml::escape::resolve_predefined_entity(&reference.xml10_content())
    {
        out.push_str(text);
    }
}

fn attr(e: &quick_xml::events::BytesStart<'_>, name: &str) -> Option<String> {
    e.attributes()
        .flatten()
        .find(|a| a.key.local_name().as_ref() == name)
        .and_then(|a| a.normalized_value(XmlVersion::Implicit1_0).ok())
        .map(std::borrow::Cow::into_owned)
}

fn xml_error(err: impl std::fmt::Display) -> LoadError {
    guard::malformed(format!("bad XML: {err}"))
}

/// The package file path from `META-INF/container.xml`.
fn rootfile(container: &str) -> Result<String, LoadError> {
    let mut reader = Reader::from_str(container);
    loop {
        match reader.read_event().map_err(xml_error)? {
            Event::Start(e) | Event::Empty(e) if e.local_name().as_ref() == "rootfile" => {
                if let Some(path) = attr(&e, "full-path") {
                    return Ok(path);
                }
            }
            Event::Eof => return Err(guard::malformed("container.xml names no package file")),
            _ => {}
        }
    }
}

struct Item {
    href: String,
    media_type: String,
}

#[derive(Default)]
struct Package {
    title: Option<String>,
    authors: Vec<String>,
    manifest: HashMap<String, Item>,
    spine: Vec<String>,
}

fn clean_info(text: &str) -> Option<String> {
    let mut value = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if value.len() > MAX_INFO {
        let mut end = MAX_INFO;
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        value.truncate(end);
    }
    (!value.is_empty()).then_some(value)
}

fn parse_package(opf: &str) -> Result<Package, LoadError> {
    #[derive(PartialEq)]
    enum Field {
        None,
        Title,
        Creator,
    }
    let mut package = Package::default();
    let mut reader = Reader::from_str(opf);
    let mut field = Field::None;
    let mut text = String::new();
    loop {
        match reader.read_event().map_err(xml_error)? {
            Event::Start(e) => match e.local_name().as_ref() {
                "title" if package.title.is_none() => field = Field::Title,
                "creator" => field = Field::Creator,
                "item" => add_item(&mut package, &e),
                "itemref" => add_itemref(&mut package, &e),
                _ => {}
            },
            Event::Empty(e) => match e.local_name().as_ref() {
                "item" => add_item(&mut package, &e),
                "itemref" => add_itemref(&mut package, &e),
                _ => {}
            },
            Event::Text(t) if field != Field::None => text.push_str(&t.xml10_content()),
            Event::CData(t) if field != Field::None => text.push_str(&t.xml10_content()),
            Event::GeneralRef(r) if field != Field::None => push_ref(&mut text, &r),
            Event::End(_) if field != Field::None => {
                let value = clean_info(&text);
                match (field, value) {
                    (Field::Title, Some(v)) => package.title = Some(v),
                    (Field::Creator, Some(v)) if package.authors.len() < 16 => {
                        package.authors.push(v);
                    }
                    _ => {}
                }
                field = Field::None;
                text.clear();
            }
            Event::Eof => return Ok(package),
            _ => {}
        }
    }
}

fn add_item(package: &mut Package, e: &quick_xml::events::BytesStart<'_>) {
    if let (Some(id), Some(href)) = (attr(e, "id"), attr(e, "href")) {
        let media_type = attr(e, "media-type").unwrap_or_default();
        package.manifest.insert(id, Item { href, media_type });
    }
}

fn add_itemref(package: &mut Package, e: &quick_xml::events::BytesStart<'_>) {
    if let Some(idref) = attr(e, "idref") {
        package.spine.push(idref);
    }
}

/// Entries listed as encrypted in `META-INF/encryption.xml`.
fn encrypted_entries(xml: &str) -> Result<HashSet<String>, LoadError> {
    let mut entries = HashSet::new();
    let mut reader = Reader::from_str(xml);
    let mut font_obfuscation = false;
    loop {
        match reader.read_event().map_err(xml_error)? {
            Event::Start(e) | Event::Empty(e) => match e.local_name().as_ref() {
                "EncryptionMethod" => {
                    // IDPF and Adobe font obfuscation only scramble fonts.
                    font_obfuscation = attr(&e, "Algorithm").is_some_and(|a| {
                        a == "http://www.idpf.org/2008/embedding"
                            || a == "http://ns.adobe.com/pdf/enc#RC"
                    });
                }
                "CipherReference" if !font_obfuscation => {
                    if let Some(uri) = attr(&e, "URI")
                        && let Ok(Some(name)) = resolve_href("", &uri)
                    {
                        entries.insert(name);
                    }
                }
                _ => {}
            },
            Event::End(e) if e.local_name().as_ref() == "EncryptedData" => {
                font_obfuscation = false;
            }
            Event::Eof => return Ok(entries),
            _ => {}
        }
    }
}

fn is_html(media_type: &str, href: &str) -> bool {
    let media_type = media_type.trim().to_ascii_lowercase();
    if media_type.is_empty() {
        let href = href.to_ascii_lowercase();
        return [".xhtml", ".html", ".htm"]
            .iter()
            .any(|e| href.ends_with(e));
    }
    media_type == "application/xhtml+xml" || media_type == "text/html"
}

fn extract_inner(bytes: &[u8], source: &str, limits: &Limits) -> Result<Vec<Document>, LoadError> {
    let deadline = Deadline::start(limits.max_duration);
    let mut archive = Archive::open(bytes, limits)?;
    let container = archive
        .read_text("META-INF/container.xml")?
        .ok_or_else(|| guard::malformed("no META-INF/container.xml"))?;
    let opf_path = resolve_href("", &rootfile(&container)?)?
        .ok_or_else(|| guard::malformed("bad package path"))?;
    let opf = archive
        .read_text(&opf_path)?
        .ok_or_else(|| guard::malformed(format!("missing package file `{opf_path}`")))?;
    let package = parse_package(&opf)?;
    drop(opf);
    let encrypted = match archive.read_text("META-INF/encryption.xml")? {
        Some(xml) => encrypted_entries(&xml)?,
        None => HashSet::new(),
    };
    if package.spine.len() > limits.max_pages {
        return Err(LoadError::TooManyPages {
            limit: limits.max_pages,
        });
    }
    deadline.check()?;

    let base = parent_dir(&opf_path);
    let chapter_count = package.spine.len().to_string();
    let author = (!package.authors.is_empty()).then(|| package.authors.join(", "));
    let mut total = 0usize;
    let mut docs = Vec::new();
    for (index, idref) in package.spine.iter().enumerate() {
        deadline.check()?;
        let Some(item) = package.manifest.get(idref) else {
            continue;
        };
        if !is_html(&item.media_type, &item.href) {
            continue;
        }
        let Some(entry) = resolve_href(base, &item.href)? else {
            continue;
        };
        if encrypted.contains(&entry) {
            return Err(LoadError::Encrypted { path: None });
        }
        let Some(xhtml) = archive.read_text(&entry)? else {
            continue;
        };
        let (text, chapter_title) = html::convert(&xhtml);
        drop(xhtml);
        if text.is_empty() {
            continue;
        }
        guard::charge_output(&mut total, text.len(), limits)?;
        let mut chapter = Document::new(text)
            .with_metadata(meta::SOURCE, source)
            .with_metadata(meta::CHAPTER, (index + 1).to_string())
            .with_metadata(meta::CHAPTER_COUNT, chapter_count.as_str())
            .with_metadata(meta::ENTRY, entry);
        if let Some(title) = &package.title {
            chapter
                .metadata
                .insert(meta::TITLE.to_string(), title.clone());
        }
        if let Some(author) = &author {
            chapter
                .metadata
                .insert(meta::AUTHOR.to_string(), author.clone());
        }
        if let Some(chapter_title) = chapter_title.as_deref().and_then(clean_info) {
            chapter
                .metadata
                .insert(meta::CHAPTER_TITLE.to_string(), chapter_title);
        }
        meta::stamp_hash(&mut chapter);
        docs.push(chapter);
    }
    Ok(docs)
}
