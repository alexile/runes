//! Tag stripping driven by a cut-down HTML tokenizer.
//!
//! The scanner follows the states of the WHATWG tokenizer that decide where
//! markup starts and ends: tag open, tag name, the attribute states (so a `>`
//! inside a quoted attribute value does not end the tag), comments, bogus
//! comments and the raw-text elements whose content is code, not text.
//!
//! It is not a full parser, and in a few pathological cases (escaped script
//! data, for example) the text it keeps differs from what a browser would
//! render. What it guarantees is narrower and checkable: the output never
//! contains a `<` directly followed by an ASCII letter, `/`, `!` or `?`, so
//! nothing in it can open a tag, comment or processing instruction. A final
//! pass enforces that, which is what defeats reassembly tricks like
//! `<<b>b>`.

use std::borrow::Cow;

/// Elements whose content the browser treats as code or raw text rather
/// than as markup with text in it. Their content is dropped along with the
/// tags.
const RAW_TEXT_ELEMENTS: &[&str] = &[
    "script", "style", "iframe", "noembed", "noframes", "noscript", "xmp",
];

/// Removes HTML markup from `input`, keeping only text content.
///
/// Tags (including their attributes, even when a quoted value contains `>`),
/// comments, `<!...>` declarations and `<?...>` instructions are removed. The
/// content of `script`, `style`, `iframe`, `noembed`, `noframes`, `noscript`
/// and `xmp` is removed too, since it is code rather than text. Markup left
/// unclosed at the end of the input is dropped, as a browser would.
///
/// A `<` that does not start markup (as in `a < b`) is kept, unless removing
/// markup next to it would make it start a tag, in which case it is dropped.
/// The result never contains `<` followed by an ASCII letter, `/`, `!` or
/// `?`. Entities are left alone: `&lt;b&gt;` stays as written.
///
/// Stripping is idempotent, and valid UTF-8 in is valid UTF-8 out.
///
/// # Examples
///
/// ```rust
/// use rune_axum_sanitize::strip_html;
///
/// assert_eq!(strip_html("<b>hello</b> world"), "hello world");
/// assert_eq!(strip_html("<script>alert(1)</script>safe"), "safe");
/// assert_eq!(strip_html("<img alt='>' src=x onerror=alert(1)>hi"), "hi");
/// assert_eq!(strip_html("<<b>b>alert(1)"), "b>alert(1)");
/// assert_eq!(strip_html("1 < 2 && 3 > 2"), "1 < 2 && 3 > 2");
/// ```
#[must_use]
pub fn strip_html(input: &str) -> String {
    strip_html_cow(input).into_owned()
}

/// [`strip_html`] without allocating when there is nothing to strip.
pub fn strip_html_cow(input: &str) -> Cow<'_, str> {
    if !input.contains('<') {
        return Cow::Borrowed(input);
    }
    let mut text = String::with_capacity(input.len());
    tokenize(input, &mut text);
    let cleaned = neutralise(&text);
    if cleaned == input {
        Cow::Borrowed(input)
    } else {
        Cow::Owned(cleaned)
    }
}

/// Whether `byte` after a `<` makes the tokenizer leave the data state.
const fn starts_markup(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || matches!(byte, b'/' | b'!' | b'?')
}

const fn is_html_whitespace(byte: u8) -> bool {
    matches!(byte, b'\t' | b'\n' | b'\x0C' | b'\r' | b' ')
}

/// Copies the text runs of `input` into `out`, skipping markup.
fn tokenize(input: &str, out: &mut String) {
    let bytes = input.as_bytes();
    let mut index = 0;
    let mut text_start = 0;

    while let Some(offset) = bytes[index..].iter().position(|&byte| byte == b'<') {
        let open = index + offset;
        let Some(end) = markup_end(input, open) else {
            index = open + 1;
            continue;
        };
        out.push_str(&input[text_start..open]);
        index = end;
        text_start = end;
    }
    out.push_str(&input[text_start..]);
}

/// If the `<` at `open` starts markup, returns the index just past it (or the
/// input length if it never closes).
fn markup_end(input: &str, open: usize) -> Option<usize> {
    let bytes = input.as_bytes();
    let len = bytes.len();
    let next = bytes.get(open + 1).copied()?;

    let end = if next.is_ascii_alphabetic() {
        let (name_end, tag_end) = scan_tag(bytes, open + 1);
        tag_end.map_or(len, |tag_end| {
            let name = &input[open + 1..name_end];
            RAW_TEXT_ELEMENTS
                .iter()
                .find(|element| name.eq_ignore_ascii_case(element))
                .map_or(tag_end, |element| skip_raw_text(input, tag_end, element))
        })
    } else {
        match next {
            b'/' => match bytes.get(open + 2) {
                Some(byte) if byte.is_ascii_alphabetic() => {
                    scan_tag(bytes, open + 2).1.unwrap_or(len)
                }
                Some(b'>') => open + 3,
                Some(_) => bogus_comment_end(bytes, open + 2),
                None => len,
            },
            b'!' if bytes[open + 2..].starts_with(b"--") => comment_end(bytes, open + 4),
            b'!' => bogus_comment_end(bytes, open + 2),
            b'?' => bogus_comment_end(bytes, open + 1),
            _ => return None,
        }
    };
    Some(end)
}

/// Scans a start or end tag whose name begins at `name_start`.
///
/// Returns the end of the tag name and the index just past the closing `>`,
/// or `None` for the latter when the tag is unterminated.
#[expect(
    clippy::match_same_arms,
    reason = "arms follow the tokenizer states one to one"
)]
fn scan_tag(bytes: &[u8], name_start: usize) -> (usize, Option<usize>) {
    #[derive(Clone, Copy)]
    enum State {
        BeforeName,
        Name,
        AfterName,
        BeforeValue,
        Quoted(u8),
        Unquoted,
    }

    let name_end = bytes[name_start..]
        .iter()
        .position(|&byte| is_html_whitespace(byte) || byte == b'/' || byte == b'>')
        .map_or(bytes.len(), |offset| name_start + offset);

    let mut state = State::BeforeName;
    for (index, &byte) in bytes.iter().enumerate().skip(name_end) {
        state = match (state, byte) {
            (State::Quoted(quote), _) if byte == quote => State::BeforeName,
            (State::Quoted(quote), _) => State::Quoted(quote),
            (_, b'>') => return (name_end, Some(index + 1)),
            (State::BeforeName, _) if is_html_whitespace(byte) || byte == b'/' => State::BeforeName,
            (State::BeforeName, _) => State::Name,
            (State::Name | State::AfterName, b'=') => State::BeforeValue,
            (State::Name | State::AfterName, b'/') => State::BeforeName,
            (State::Name | State::AfterName, _) if is_html_whitespace(byte) => State::AfterName,
            (State::Name | State::AfterName, _) => State::Name,
            (State::BeforeValue, b'"' | b'\'') => State::Quoted(byte),
            (State::BeforeValue, _) if is_html_whitespace(byte) => State::BeforeValue,
            (State::BeforeValue | State::Unquoted, _) if is_html_whitespace(byte) => {
                State::BeforeName
            }
            (State::BeforeValue | State::Unquoted, _) => State::Unquoted,
        };
    }
    (name_end, None)
}

/// Skips the content of a raw-text element up to and including its end tag.
fn skip_raw_text(input: &str, from: usize, element: &str) -> usize {
    let bytes = input.as_bytes();
    let mut search = from;
    while let Some(offset) = input[search..].find("</") {
        let name_start = search + offset + 2;
        let name_end = name_start + element.len();
        let matches_name = bytes
            .get(name_start..name_end)
            .is_some_and(|name| name.eq_ignore_ascii_case(element.as_bytes()));
        let terminated = bytes
            .get(name_end)
            .is_some_and(|&byte| is_html_whitespace(byte) || byte == b'/' || byte == b'>');
        if matches_name && terminated {
            return scan_tag(bytes, name_start).1.unwrap_or(bytes.len());
        }
        search = name_start;
    }
    bytes.len()
}

/// End of a `<!-- ... -->` comment whose body starts at `from`.
fn comment_end(bytes: &[u8], from: usize) -> usize {
    // `<!-->` and `<!--->` close immediately.
    let body = &bytes[from.min(bytes.len())..];
    if body.starts_with(b">") {
        return from + 1;
    }
    if body.starts_with(b"->") {
        return from + 2;
    }
    let mut index = from;
    while index < bytes.len() {
        let rest = &bytes[index..];
        if rest.starts_with(b"-->") {
            return index + 3;
        }
        if rest.starts_with(b"--!>") {
            return index + 4;
        }
        index += 1;
    }
    bytes.len()
}

/// End of a bogus comment (`<!x...>`, `<?...>`, `</1...>`) starting at `from`.
fn bogus_comment_end(bytes: &[u8], from: usize) -> usize {
    bytes
        .get(from..)
        .and_then(|rest| rest.iter().position(|&byte| byte == b'>'))
        .map_or(bytes.len(), |offset| from + offset + 1)
}

/// Drops every `<` that is followed by a byte that would start markup.
///
/// Runs of `<` are held back until the next character is known, so `<<a`
/// loses both brackets. Linear time.
fn neutralise(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut pending = 0usize;
    for character in text.chars() {
        if character == '<' {
            pending += 1;
            continue;
        }
        let dangerous = u8::try_from(character).is_ok_and(starts_markup);
        if !dangerous {
            out.extend(std::iter::repeat_n('<', pending));
        }
        pending = 0;
        out.push(character);
    }
    out.extend(std::iter::repeat_n('<', pending));
    out
}

#[cfg(test)]
mod tests {
    use super::strip_html;

    #[test]
    fn strips_simple_tags() {
        assert_eq!(strip_html("<b>bold</b> text"), "bold text");
        assert_eq!(strip_html("<a href='url'>link</a>"), "link");
    }

    #[test]
    fn drops_script_and_style_content() {
        assert_eq!(strip_html("<script>alert(1)</script>ok"), "ok");
        assert_eq!(strip_html("<STYLE>body{}</style >ok"), "ok");
        assert_eq!(strip_html("<script>if (a</b) x()</script>ok"), "ok");
        assert_eq!(strip_html("<script>never closed"), "");
    }

    #[test]
    fn quoted_gt_does_not_end_tag() {
        assert_eq!(strip_html(r#"<img alt=">" onerror="alert(1)">x"#), "x");
        assert_eq!(strip_html("<a title='a>b'>x</a>"), "x");
    }

    #[test]
    fn unclosed_markup_is_dropped() {
        assert_eq!(strip_html("before<img src=x onerror=alert(1)"), "before");
        assert_eq!(strip_html("a<!-- no end"), "a");
    }

    #[test]
    fn comments_and_declarations() {
        assert_eq!(strip_html("a<!-- <script> -->b"), "ab");
        assert_eq!(strip_html("a<!-->b"), "ab");
        assert_eq!(strip_html("a<!--->b"), "ab");
        assert_eq!(strip_html("a<!-- x --!>b"), "ab");
        assert_eq!(strip_html("<!DOCTYPE html>a"), "a");
        assert_eq!(strip_html("<?xml version='1'?>a"), "a");
        assert_eq!(strip_html("a</>b"), "ab");
        assert_eq!(strip_html("a</ 1>b"), "ab");
    }

    #[test]
    fn literal_angle_brackets_survive() {
        assert_eq!(strip_html("1 < 2"), "1 < 2");
        assert_eq!(strip_html("a <3 b"), "a <3 b");
        assert_eq!(strip_html("<<<"), "<<<");
    }

    #[test]
    fn reassembly_is_neutralised() {
        assert_eq!(strip_html("<<script>script>"), "<");
        assert_eq!(strip_html("<<b>b>x"), "b>x");
        assert_eq!(strip_html("<<b>a"), "a");
        assert_eq!(strip_html("<scr<script>ipt>alert(1)"), "ipt>alert(1)");
    }

    #[test]
    fn multibyte_text_is_kept() {
        assert_eq!(strip_html("<p>héllo 世界 👋</p>"), "héllo 世界 👋");
    }
}
