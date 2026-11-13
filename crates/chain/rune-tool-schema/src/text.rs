//! Text hygiene for model-facing strings: invisible and bidirectional
//! characters, line endings and length caps.
//!
//! Tool names, titles and descriptions go straight into a model's context,
//! so they are a prompt-injection surface. Characters that render as
//! nothing (zero-width spaces, Unicode tag characters, variation selectors)
//! or that reorder text on screen (bidi overrides and isolates) let a tool
//! definition say one thing to the human reviewing it and another to the
//! model. [`strip_hidden`] removes them; [`find_hidden`] reports the first
//! one so a validator can refuse the text instead.

use std::borrow::Cow;

/// Default cap on a tool description, in characters, applied by
/// [`ToolDescriptor::export`](crate::ToolDescriptor::export) and
/// [`ToolDescriptor::check_hygiene`](crate::ToolDescriptor::check_hygiene).
///
/// This is a guardrail of this crate, not a documented provider limit:
/// long descriptions cost context on every request and give injected text
/// room to hide. Raise it with
/// [`ExportOptions::max_description_chars`](crate::ExportOptions::max_description_chars)
/// when a tool really needs more.
pub const MAX_DESCRIPTION_CHARS: usize = 4096;

/// Whether `c` is invisible or changes the display order of text.
///
/// Covers C0 and C1 control characters other than tab and newline, the
/// format characters that render as nothing (soft hyphen, zero-width space,
/// joiners, word joiner, invisible math operators, byte-order mark,
/// interlinear annotation marks), bidirectional marks, embeddings,
/// overrides and isolates, Hangul fillers, variation selectors and the
/// Unicode tag block, which can spell out a whole hidden ASCII message.
///
/// ```
/// use rune_tool_schema::is_hidden_char;
///
/// assert!(is_hidden_char('\u{202e}')); // right-to-left override
/// assert!(is_hidden_char('\u{e0041}')); // tag letter A
/// assert!(!is_hidden_char('\n'));
/// assert!(!is_hidden_char('é'));
/// ```
#[must_use]
pub const fn is_hidden_char(c: char) -> bool {
    matches!(c,
        '\u{0}'..='\u{8}'
        | '\u{b}'..='\u{1f}'
        | '\u{7f}'..='\u{9f}'
        | '\u{ad}'
        | '\u{34f}'
        | '\u{61c}'
        | '\u{115f}'..='\u{1160}'
        | '\u{17b4}'..='\u{17b5}'
        | '\u{180b}'..='\u{180f}'
        | '\u{200b}'..='\u{200f}'
        | '\u{202a}'..='\u{202e}'
        | '\u{2060}'..='\u{2064}'
        | '\u{2066}'..='\u{206f}'
        | '\u{3164}'
        | '\u{fe00}'..='\u{fe0f}'
        | '\u{feff}'
        | '\u{ffa0}'
        | '\u{fff9}'..='\u{fffb}'
        | '\u{1d173}'..='\u{1d17a}'
        | '\u{e0000}'..='\u{e007f}'
        | '\u{e0100}'..='\u{e01ef}'
    )
}

/// The byte offset and value of the first hidden character in `text`
/// (see [`is_hidden_char`]); `\r` and the Unicode line and paragraph
/// separators count as hidden too.
///
/// ```
/// use rune_tool_schema::find_hidden;
///
/// assert_eq!(find_hidden("ok"), None);
/// assert_eq!(find_hidden("a\u{200b}b"), Some((1, '\u{200b}')));
/// ```
#[must_use]
pub fn find_hidden(text: &str) -> Option<(usize, char)> {
    text.char_indices()
        .find(|&(_, c)| is_hidden_char(c) || is_odd_line_break(c))
}

/// `\r`, U+2028 and U+2029: line breaks [`strip_hidden`] turns into `\n`.
const fn is_odd_line_break(c: char) -> bool {
    matches!(c, '\r' | '\u{2028}' | '\u{2029}')
}

/// Remove [hidden characters](is_hidden_char) and turn `\r\n`, `\r`,
/// U+2028 and U+2029 into `\n`. Borrows when there is nothing to change.
///
/// Variation selectors and the zero-width joiner are removed too, which
/// can split a composed emoji into its parts; that is the price of closing
/// the channel they open.
///
/// ```
/// use rune_tool_schema::strip_hidden;
///
/// assert_eq!(strip_hidden("read\u{200b}\u{e0041}me\r\n"), "readme\n");
/// assert!(matches!(strip_hidden("clean"), std::borrow::Cow::Borrowed(_)));
/// ```
#[must_use]
pub fn strip_hidden(text: &str) -> Cow<'_, str> {
    if find_hidden(text).is_none() {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                out.push('\n');
            }
            '\u{2028}' | '\u{2029}' => out.push('\n'),
            c if is_hidden_char(c) => {}
            c => out.push(c),
        }
    }
    Cow::Owned(out)
}

/// Cut `text` to at most `max_chars` characters, ending with `…` when
/// anything was cut (the ellipsis counts towards the cap).
///
/// ```
/// use rune_tool_schema::truncate_chars;
///
/// assert_eq!(truncate_chars("héllo", 3), "hé…");
/// assert_eq!(truncate_chars("hi", 3), "hi");
/// ```
#[must_use]
pub fn truncate_chars(text: &str, max_chars: usize) -> Cow<'_, str> {
    if max_chars == 0 {
        return Cow::Borrowed("");
    }
    if text.char_indices().nth(max_chars).is_none() {
        Cow::Borrowed(text)
    } else {
        let keep = max_chars - 1;
        let end = text.char_indices().nth(keep).map_or(text.len(), |(i, _)| i);
        let mut out = String::with_capacity(end + '…'.len_utf8());
        out.push_str(&text[..end]);
        out.push('…');
        Cow::Owned(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_known_smuggling_channels() {
        let poisoned =
            "Adds numbers.\u{202e}\u{e0049}\u{e0047}\u{2066}x\u{2069}\u{7}\tok\u{fe0f}\u{e0100}";
        assert_eq!(strip_hidden(poisoned), "Adds numbers.x\tok");
        assert_eq!(strip_hidden("a\r\nb\rc\u{2028}d"), "a\nb\nc\nd");
        assert_eq!(strip_hidden("\u{3164}\u{115f}x\u{ad}"), "x");
    }

    #[test]
    fn visible_text_is_untouched() {
        for text in [
            "plain",
            "naïve café",
            "日本語",
            "emoji 🙂",
            "tab\tand\nnewline",
        ] {
            assert!(matches!(strip_hidden(text), Cow::Borrowed(_)), "{text}");
            assert_eq!(find_hidden(text), None);
        }
    }

    #[test]
    fn truncation_counts_characters() {
        assert_eq!(truncate_chars("ééé", 2), "é…");
        assert_eq!(truncate_chars("ééé", 3), "ééé");
        assert_eq!(truncate_chars("abc", 1), "…");
        assert_eq!(truncate_chars("abc", 0), "");
    }
}
