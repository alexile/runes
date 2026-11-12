//! HTML to plain text, without a DOM or any dependency.
//!
//! [`html_to_text`] is a single linear scan: no recursion, no backtracking,
//! never panics, and its output is never longer than its input plus one
//! newline per tag. It drops `<script>`, `<style>`, `<noscript>`,
//! `<template>`, `<svg>`, `<iframe>`, `<object>`, comments and processing
//! instructions; turns block elements into line breaks (source newlines are
//! plain whitespace, as in a browser); decodes the common named entities and
//! all numeric ones; and collapses whitespace and empty lines.
//!
//! It is meant for feeding text to an embedder, not for rendering: it does
//! not build a tree, so badly nested markup degrades gracefully into text.

use std::path::Path;

use crate::Document;
use crate::error::LoadError;
use crate::io::{read_file, utf8};
use crate::jail::Jail;
use crate::limits::Limits;
use crate::meta;

/// Elements whose content is dropped entirely.
const SKIPPED: &[&str] = &[
    "script", "style", "noscript", "template", "svg", "iframe", "object", "title",
];

/// Elements that start or end a line.
const BLOCK: &[&str] = &[
    "address",
    "article",
    "aside",
    "blockquote",
    "br",
    "dd",
    "details",
    "div",
    "dl",
    "dt",
    "figcaption",
    "figure",
    "footer",
    "form",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "header",
    "hr",
    "li",
    "main",
    "nav",
    "ol",
    "p",
    "pre",
    "section",
    "summary",
    "table",
    "tr",
    "ul",
];

/// Convert HTML to readable plain text.
///
/// # Example
///
/// ```rust
/// use rune_chain_loader::html::html_to_text;
///
/// let html = "<html><head><style>p{color:red}</style><script>alert(1)</script></head>\
///             <body><h1>Title</h1><p>Fish &amp; chips&nbsp;&#x2014; tasty</p></body></html>";
/// assert_eq!(html_to_text(html), "Title\nFish & chips \u{2014} tasty");
/// ```
#[must_use]
pub fn html_to_text(html: &str) -> String {
    convert(html).0
}

/// The text of the first `<title>` element, entity-decoded and trimmed.
///
/// ```rust
/// use rune_chain_loader::html::html_title;
///
/// assert_eq!(html_title("<title> A &amp; B </title><p>x"), Some("A & B".to_string()));
/// assert_eq!(html_title("<p>no title</p>"), None);
/// ```
#[must_use]
pub fn html_title(html: &str) -> Option<String> {
    convert(html).1
}

/// Build a [`Document`] from HTML: text content, plus [`meta::TITLE`] and
/// [`meta::CONTENT_SHA256`] metadata.
#[must_use]
pub fn load_str(html: &str) -> Document {
    let (text, title) = convert(html);
    let mut doc = Document::new(text);
    if let Some(title) = title {
        doc.metadata.insert(meta::TITLE.to_string(), title);
    }
    meta::stamp_hash(&mut doc);
    doc
}

/// Load an HTML file as one text [`Document`] with default [`Limits`] and no
/// jail. `source` is set to the path.
pub fn load_file(path: impl AsRef<Path>) -> Result<Document, LoadError> {
    load_file_with(path, Limits::DEFAULT, None)
}

/// [`load_file`] with explicit limits and an optional [`Jail`].
pub fn load_file_with(
    path: impl AsRef<Path>,
    limits: Limits,
    jail: Option<&Jail>,
) -> Result<Document, LoadError> {
    let path = path.as_ref();
    let html = utf8(read_file(path, jail, limits.max_file_bytes)?, Some(path))?;
    let mut doc = load_str(&html);
    doc.metadata
        .insert(meta::SOURCE.to_string(), path.display().to_string());
    Ok(doc)
}

fn find_from(haystack: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    haystack
        .get(from..)?
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

/// Find `</name` (ASCII case-insensitive) followed by a non-name byte.
fn find_close(bytes: &[u8], from: usize, name: &str) -> Option<usize> {
    let name = name.as_bytes();
    let mut i = from;
    while let Some(lt) = find_from(bytes, i, b"</") {
        let start = lt + 2;
        let end = start + name.len();
        if bytes
            .get(start..end)
            .is_some_and(|s| s.eq_ignore_ascii_case(name))
            && !bytes.get(end).is_some_and(u8::is_ascii_alphanumeric)
        {
            return Some(lt);
        }
        i = start;
    }
    None
}

/// Index just past the `>` closing a tag that starts at `from`, honouring
/// quoted attribute values; `None` if the tag never closes.
fn tag_end(bytes: &[u8], from: usize) -> Option<usize> {
    let mut quote = None;
    for (offset, &b) in bytes.get(from..)?.iter().enumerate() {
        match (quote, b) {
            (None, b'"' | b'\'') => quote = Some(b),
            (Some(q), _) if b == q => quote = None,
            (None, b'>') => return Some(from + offset + 1),
            _ => {}
        }
    }
    None
}

/// Decode the entity starting at `&` (index `at`). Returns the replacement
/// and the index after `;`, or `None` to emit `&` literally.
fn entity(text: &str, at: usize) -> Option<(char, usize)> {
    let rest = text.get(at + 1..)?;
    let semi = rest.bytes().take(32).position(|b| b == b';')?;
    let name = &rest[..semi];
    let c = if let Some(num) = name.strip_prefix('#') {
        let code = match num.strip_prefix(['x', 'X']) {
            Some(hex) => u32::from_str_radix(hex, 16).ok()?,
            None => num.parse::<u32>().ok()?,
        };
        match char::from_u32(code) {
            Some('\0') | None => '\u{fffd}',
            Some(c) => c,
        }
    } else {
        named_entity(name)?
    };
    Some((c, at + 1 + semi + 1))
}

fn named_entity(name: &str) -> Option<char> {
    Some(match name {
        "amp" => '&',
        "lt" => '<',
        "gt" => '>',
        "quot" => '"',
        "apos" => '\'',
        "nbsp" => ' ',
        "copy" => '\u{a9}',
        "reg" => '\u{ae}',
        "trade" => '\u{2122}',
        "hellip" => '\u{2026}',
        "mdash" => '\u{2014}',
        "ndash" => '\u{2013}',
        "lsquo" => '\u{2018}',
        "rsquo" => '\u{2019}',
        "ldquo" => '\u{201c}',
        "rdquo" => '\u{201d}',
        "laquo" => '\u{ab}',
        "raquo" => '\u{bb}',
        "euro" => '\u{20ac}',
        "pound" => '\u{a3}',
        "deg" => '\u{b0}',
        "times" => '\u{d7}',
        "middot" => '\u{b7}',
        "bull" => '\u{2022}',
        _ => return None,
    })
}

/// Append source text; line breaks in HTML source are just whitespace.
fn push_text(out: &mut String, text: &str) {
    out.extend(
        text.chars()
            .map(|c| if c == '\n' || c == '\r' { ' ' } else { c }),
    );
}

/// Append `text[from..to]` with entities decoded.
fn push_decoded(out: &mut String, text: &str, from: usize, to: usize) {
    let mut i = from;
    while i < to {
        let rest = &text[i..to];
        match rest.find('&') {
            None => {
                push_text(out, rest);
                return;
            }
            Some(amp) => {
                push_text(out, &rest[..amp]);
                let at = i + amp;
                if let Some((c, next)) = entity(&text[..to], at) {
                    out.push(c);
                    i = next;
                } else {
                    out.push('&');
                    i = at + 1;
                }
            }
        }
    }
}

fn convert(html: &str) -> (String, Option<String>) {
    let bytes = html.as_bytes();
    let mut raw = String::with_capacity(html.len());
    let mut title = None;
    let mut i = 0;
    while i < bytes.len() {
        let Some(lt) = find_from(bytes, i, b"<") else {
            push_decoded(&mut raw, html, i, bytes.len());
            break;
        };
        push_decoded(&mut raw, html, i, lt);
        i = handle_markup(html, lt, &mut raw, &mut title);
    }
    (normalise(&raw), title)
}

/// Handle markup starting at `<` (index `lt`); returns where to resume.
fn handle_markup(html: &str, lt: usize, out: &mut String, title: &mut Option<String>) -> usize {
    let bytes = html.as_bytes();
    if bytes[lt..].starts_with(b"<!--") {
        return find_from(bytes, lt + 4, b"-->").map_or(bytes.len(), |p| p + 3);
    }
    if matches!(bytes.get(lt + 1), Some(b'!' | b'?')) {
        return tag_end(bytes, lt + 2).unwrap_or(bytes.len());
    }
    let closing = bytes.get(lt + 1) == Some(&b'/');
    let name_start = lt + 1 + usize::from(closing);
    let name_len = bytes
        .get(name_start..)
        .unwrap_or_default()
        .iter()
        .take_while(|b| b.is_ascii_alphanumeric())
        .count();
    if name_len == 0 || !bytes[name_start].is_ascii_alphabetic() {
        out.push('<');
        return lt + 1;
    }
    let name = html[name_start..name_start + name_len].to_ascii_lowercase();
    let Some(end) = tag_end(bytes, name_start + name_len) else {
        return bytes.len();
    };
    let self_closing = end >= 2 && bytes[end - 2] == b'/';
    if !closing && !self_closing && SKIPPED.contains(&name.as_str()) {
        let close = find_close(bytes, end, &name);
        if name == "title" && title.is_none() {
            let mut t = String::new();
            push_decoded(&mut t, html, end, close.unwrap_or(bytes.len()));
            let t = t.split_whitespace().collect::<Vec<_>>().join(" ");
            if !t.is_empty() {
                *title = Some(t);
            }
        }
        return close.map_or(bytes.len(), |c| tag_end(bytes, c).unwrap_or(bytes.len()));
    }
    if BLOCK.contains(&name.as_str()) {
        out.push('\n');
    } else if matches!(name.as_str(), "td" | "th") && !closing {
        out.push(' ');
    }
    end
}

/// Collapse runs of whitespace within lines, trim lines, and drop empty
/// lines.
fn normalise(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for line in raw.split('\n') {
        let mut words = line.split_whitespace().peekable();
        if words.peek().is_none() {
            continue;
        }
        if !out.is_empty() {
            out.push('\n');
        }
        let mut first = true;
        for word in words {
            if !first {
                out.push(' ');
            }
            out.push_str(word);
            first = false;
        }
    }
    out
}
