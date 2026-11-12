//! sitemap.xml and sitemap index parsing ([sitemaps.org protocol](https://www.sitemaps.org/protocol.html)).

use std::borrow::Cow;

use quick_xml::Reader;
use quick_xml::escape::resolve_predefined_entity;
use quick_xml::events::Event;

use crate::Error;

/// Default cap on the (decompressed) size of a sitemap: 50 MiB, the limit
/// of the sitemaps.org protocol.
pub const MAX_SITEMAP_LEN: usize = 50 * 1024 * 1024;

/// Default cap on the number of entries in one sitemap or index: 50 000,
/// the limit of the sitemaps.org protocol.
pub const MAX_SITEMAP_ENTRIES: usize = 50_000;

/// Limits applied by [`Sitemap::parse_with`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Options {
    /// Largest accepted body, after gzip decompression.
    pub max_len: usize,
    /// Most entries accepted.
    pub max_entries: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            max_len: MAX_SITEMAP_LEN,
            max_entries: MAX_SITEMAP_ENTRIES,
        }
    }
}

impl Options {
    /// Sets [`Options::max_len`].
    #[must_use]
    pub const fn with_max_len(mut self, max_len: usize) -> Self {
        self.max_len = max_len;
        self
    }

    /// Sets [`Options::max_entries`].
    #[must_use]
    pub const fn with_max_entries(mut self, max_entries: usize) -> Self {
        self.max_entries = max_entries;
        self
    }
}

/// How often a page is likely to change (`<changefreq>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ChangeFreq {
    /// Changes on every access.
    Always,
    /// Hourly.
    Hourly,
    /// Daily.
    Daily,
    /// Weekly.
    Weekly,
    /// Monthly.
    Monthly,
    /// Yearly.
    Yearly,
    /// Archived; never changes.
    Never,
}

impl ChangeFreq {
    /// Parses a `<changefreq>` value (case-insensitive).
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        [
            Self::Always,
            Self::Hourly,
            Self::Daily,
            Self::Weekly,
            Self::Monthly,
            Self::Yearly,
            Self::Never,
        ]
        .into_iter()
        .find(|freq| freq.as_str().eq_ignore_ascii_case(value.trim()))
    }

    /// The protocol keyword.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Always => "always",
            Self::Hourly => "hourly",
            Self::Daily => "daily",
            Self::Weekly => "weekly",
            Self::Monthly => "monthly",
            Self::Yearly => "yearly",
            Self::Never => "never",
        }
    }
}

/// One `<url>` of a `<urlset>`.
#[derive(Debug, Clone, Default, PartialEq)]
#[non_exhaustive]
pub struct UrlEntry {
    /// `<loc>`: the page URL.
    pub loc: String,
    /// `<lastmod>`, as written (a W3C datetime).
    pub lastmod: Option<String>,
    /// `<changefreq>`, when it is a known keyword.
    pub changefreq: Option<ChangeFreq>,
    /// `<priority>`, when it is a number in `0.0..=1.0`.
    pub priority: Option<f32>,
}

impl UrlEntry {
    /// An entry with only a `<loc>`.
    #[must_use]
    pub fn new(loc: impl Into<String>) -> Self {
        Self {
            loc: loc.into(),
            ..Self::default()
        }
    }
}

/// One `<sitemap>` of a `<sitemapindex>`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct SitemapRef {
    /// `<loc>`: the child sitemap URL.
    pub loc: String,
    /// `<lastmod>`, as written (a W3C datetime).
    pub lastmod: Option<String>,
}

/// A parsed sitemap: page URLs or references to further sitemaps.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Sitemap {
    /// A `<urlset>`, or a plain-text sitemap (one URL per line).
    UrlSet(Vec<UrlEntry>),
    /// A `<sitemapindex>`.
    Index(Vec<SitemapRef>),
}

impl Sitemap {
    /// Parses a sitemap body with the default [`Options`].
    pub fn parse(body: &[u8]) -> Result<Self, Error> {
        Self::parse_with(body, &Options::default())
    }

    /// Parses a sitemap body.
    ///
    /// The body may be gzipped (detected by its magic bytes; needs the
    /// `gzip` feature), an XML `<urlset>` or `<sitemapindex>`, or plain text
    /// with one URL per line. Elements from other namespaces (image, video,
    /// news extensions) are skipped, and entries without a `<loc>` are
    /// dropped.
    pub fn parse_with(body: &[u8], options: &Options) -> Result<Self, Error> {
        let body = decompress(body, options.max_len)?;
        if body.len() > options.max_len {
            return Err(Error::TooLarge {
                limit: options.max_len,
            });
        }
        let body = body.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(&body);
        let text = std::str::from_utf8(body).map_err(|err| Error::NotUtf8 {
            offset: err.valid_up_to(),
        })?;
        if text.trim_start().starts_with('<') {
            parse_xml(text, options.max_entries)
        } else {
            parse_text(text, options.max_entries)
        }
    }

    /// Whether this is a sitemap index.
    #[must_use]
    pub const fn is_index(&self) -> bool {
        matches!(self, Self::Index(_))
    }

    /// Number of entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        match self {
            Self::UrlSet(entries) => entries.len(),
            Self::Index(entries) => entries.len(),
        }
    }

    /// Whether there are no entries.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The `<loc>` of every entry: page URLs for a URL set, sitemap URLs
    /// for an index.
    pub fn locations(&self) -> Box<dyn Iterator<Item = &str> + '_> {
        match self {
            Self::UrlSet(entries) => Box::new(entries.iter().map(|e| e.loc.as_str())),
            Self::Index(entries) => Box::new(entries.iter().map(|e| e.loc.as_str())),
        }
    }
}

const GZIP_MAGIC: &[u8] = &[0x1F, 0x8B];

#[cfg(feature = "gzip")]
fn decompress(body: &[u8], max_len: usize) -> Result<Cow<'_, [u8]>, Error> {
    use std::io::Read;

    if !body.starts_with(GZIP_MAGIC) {
        return Ok(Cow::Borrowed(body));
    }
    let mut out = Vec::new();
    let limit = u64::try_from(max_len).unwrap_or(u64::MAX).saturating_add(1);
    flate2::read::MultiGzDecoder::new(body)
        .take(limit)
        .read_to_end(&mut out)
        .map_err(|err| Error::Gzip {
            message: err.to_string(),
        })?;
    Ok(Cow::Owned(out))
}

#[cfg(not(feature = "gzip"))]
fn decompress(body: &[u8], _max_len: usize) -> Result<Cow<'_, [u8]>, Error> {
    if body.starts_with(GZIP_MAGIC) {
        return Err(Error::Gzip {
            message: "gzip support is disabled (enable the `gzip` feature)".to_owned(),
        });
    }
    Ok(Cow::Borrowed(body))
}

fn parse_text(text: &str, max_entries: usize) -> Result<Sitemap, Error> {
    let mut entries = Vec::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if entries.len() == max_entries {
            return Err(Error::TooManyEntries { limit: max_entries });
        }
        entries.push(UrlEntry::new(line));
    }
    Ok(Sitemap::UrlSet(entries))
}

/// The child element of an entry whose text is being collected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    Loc,
    LastMod,
    ChangeFreq,
    Priority,
}

impl Field {
    const fn from_name(name: &[u8]) -> Option<Self> {
        match name {
            b"loc" => Some(Self::Loc),
            b"lastmod" => Some(Self::LastMod),
            b"changefreq" => Some(Self::ChangeFreq),
            b"priority" => Some(Self::Priority),
            _ => None,
        }
    }
}

/// Event-walking state.
#[derive(Default)]
struct Walker {
    /// Root kind once seen: `Some(true)` for an index.
    index: Option<bool>,
    depth: usize,
    /// Open entry (`<url>` / `<sitemap>` at depth 2).
    entry: Option<UrlEntry>,
    /// Field being collected (depth 3), with its text so far.
    field: Option<(Field, String)>,
    urls: Vec<UrlEntry>,
    refs: Vec<SitemapRef>,
}

impl Walker {
    fn open(&mut self, name: &[u8], prefixed: bool) -> Result<(), Error> {
        self.depth += 1;
        let entry_name: &[u8] = if self.index == Some(true) {
            b"sitemap"
        } else {
            b"url"
        };
        match self.depth {
            1 => {
                self.index = Some(match name {
                    b"urlset" => false,
                    b"sitemapindex" => true,
                    _ => {
                        return Err(Error::NotSitemap {
                            root: String::from_utf8_lossy(name).into_owned(),
                        });
                    }
                });
            }
            2 if !prefixed && name == entry_name => {
                self.entry = Some(UrlEntry::default());
            }
            3 if !prefixed && self.entry.is_some() => {
                self.field = Field::from_name(name).map(|field| (field, String::new()));
            }
            _ => {}
        }
        Ok(())
    }

    fn text(&mut self, text: &str) {
        if let Some((_, buffer)) = self.field.as_mut() {
            buffer.push_str(text);
        }
    }

    fn close(&mut self, max_entries: usize) -> Result<(), Error> {
        match self.depth {
            3 => {
                if let (Some((field, value)), Some(entry)) =
                    (self.field.take(), self.entry.as_mut())
                {
                    let value = value.trim();
                    match field {
                        Field::Loc => value.clone_into(&mut entry.loc),
                        Field::LastMod => {
                            entry.lastmod = (!value.is_empty()).then(|| value.to_owned());
                        }
                        Field::ChangeFreq => entry.changefreq = ChangeFreq::parse(value),
                        Field::Priority => {
                            entry.priority = value
                                .parse::<f32>()
                                .ok()
                                .filter(|p| (0.0..=1.0).contains(p));
                        }
                    }
                }
            }
            2 => {
                if let Some(entry) = self.entry.take().filter(|e| !e.loc.is_empty()) {
                    if self.urls.len() + self.refs.len() == max_entries {
                        return Err(Error::TooManyEntries { limit: max_entries });
                    }
                    if self.index == Some(true) {
                        self.refs.push(SitemapRef {
                            loc: entry.loc,
                            lastmod: entry.lastmod,
                        });
                    } else {
                        self.urls.push(entry);
                    }
                }
            }
            _ => {}
        }
        self.depth = self.depth.saturating_sub(1);
        Ok(())
    }
}

fn parse_xml(text: &str, max_entries: usize) -> Result<Sitemap, Error> {
    let mut reader = Reader::from_str(text);
    let mut walker = Walker::default();
    let xml_error = |reader: &Reader<&[u8]>, message: String| Error::Xml {
        position: reader.error_position(),
        message,
    };
    loop {
        match reader.read_event() {
            Ok(Event::Start(element)) => {
                let (name, prefixed) = local_name(&element);
                walker.open(&name, prefixed)?;
            }
            Ok(Event::Empty(element)) => {
                let (name, prefixed) = local_name(&element);
                walker.open(&name, prefixed)?;
                walker.close(max_entries)?;
            }
            Ok(Event::End(_)) => walker.close(max_entries)?,
            Ok(Event::Text(text)) => walker.text(&text.xml10_content()),
            Ok(Event::CData(data)) => walker.text(&data.xml10_content()),
            Ok(Event::GeneralRef(reference)) => {
                if let Ok(Some(ch)) = reference.resolve_char_ref() {
                    walker.text(ch.encode_utf8(&mut [0; 4]));
                } else {
                    let name: &str = &reference;
                    match resolve_predefined_entity(name) {
                        Some(resolved) => walker.text(resolved),
                        None => {
                            return Err(xml_error(&reader, format!("unknown entity `&{name};`")));
                        }
                    }
                }
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(err) => return Err(xml_error(&reader, err.to_string())),
        }
    }
    if walker.depth != 0 {
        return Err(xml_error(&reader, "unexpected end of document".to_owned()));
    }
    match walker.index {
        None => Err(Error::NotSitemap {
            root: String::new(),
        }),
        Some(true) => Ok(Sitemap::Index(walker.refs)),
        Some(false) => Ok(Sitemap::UrlSet(walker.urls)),
    }
}

/// The local name of an element, and whether it carries a namespace
/// prefix. Sitemap elements are unprefixed or use the default namespace;
/// prefixed children (`image:loc`) belong to extensions.
fn local_name(element: &quick_xml::events::BytesStart<'_>) -> (Vec<u8>, bool) {
    let name = element.name();
    (
        element.local_name().as_ref().as_bytes().to_vec(),
        name.prefix().is_some(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn changefreq_keywords() {
        assert_eq!(ChangeFreq::parse(" Daily "), Some(ChangeFreq::Daily));
        assert_eq!(ChangeFreq::parse("fortnightly"), None);
        assert_eq!(
            ChangeFreq::parse("never").map(ChangeFreq::as_str),
            Some("never")
        );
    }

    #[test]
    fn rejects_non_sitemaps() {
        assert!(matches!(
            Sitemap::parse(b"<html><body/></html>"),
            Err(Error::NotSitemap { root }) if root == "html"
        ));
        assert!(matches!(
            Sitemap::parse(b"<?xml version=\"1.0\"?>"),
            Err(Error::NotSitemap { .. })
        ));
        assert!(matches!(
            Sitemap::parse(b"<urlset><url><loc>x</loc>"),
            Err(Error::Xml { .. })
        ));
        assert!(matches!(
            Sitemap::parse(b"<urlset><url><loc>&bogus;</loc></url></urlset>"),
            Err(Error::Xml { .. })
        ));
        assert_eq!(Sitemap::parse(b"\xFF"), Err(Error::NotUtf8 { offset: 0 }));
    }
}
