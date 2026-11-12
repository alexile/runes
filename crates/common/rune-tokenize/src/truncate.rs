//! Budget-aware truncation with head / tail / middle strategies.

use alloc::borrow::Cow;
use alloc::string::String;
use alloc::vec::Vec;

use crate::counter::TokenCounter;
use crate::grapheme;

/// Default marker [`truncate_with`] puts where [`Truncation::Middle`] removed text.
pub const DEFAULT_ELLIPSIS: &str = " … ";

/// Which part of the text survives truncation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum Truncation {
    /// Keep the beginning, drop the end (what [`truncate`](crate::truncate) does).
    #[default]
    KeepStart,
    /// Keep the end, drop the beginning (recent log lines, chat history).
    KeepEnd,
    /// Keep the beginning and the end, replacing the middle with
    /// [`DEFAULT_ELLIPSIS`] (long tool output, stack traces).
    Middle,
}

/// Truncate `text` to at most `max_tokens` tokens as measured by `counter`.
///
/// Cuts land on word boundaries when a whole word fits, otherwise on a
/// grapheme boundary, so the result never splits a character, a combining
/// sequence or an emoji. Returns `text` borrowed when it already fits; only
/// [`Truncation::Middle`] allocates. Never panics.
///
/// The result is re-measured with `counter`, so it fits for any counter that
/// is monotone in the length of a prefix / suffix.
///
/// # Example
///
/// ```rust
/// use rune_tokenize::{truncate_with, Truncation, TokenCounter, TokenizerProfile};
///
/// let log = "boot ok; disk ok; net ok; ERROR: database unreachable";
/// let p = TokenizerProfile::Cl100k;
///
/// let tail = truncate_with(log, 6, &p, Truncation::KeepEnd);
/// assert!(tail.ends_with("unreachable"));
/// assert!(p.count_tokens(&tail) <= 6);
///
/// let mid = truncate_with(log, 10, &p, Truncation::Middle);
/// assert!(mid.starts_with("boot") && mid.contains('…'));
/// assert!(p.count_tokens(&mid) <= 10);
/// ```
#[must_use]
pub fn truncate_with<'a, C: TokenCounter + ?Sized>(
    text: &'a str,
    max_tokens: usize,
    counter: &C,
    strategy: Truncation,
) -> Cow<'a, str> {
    match strategy {
        Truncation::KeepStart => Cow::Borrowed(keep_start(text, max_tokens, counter)),
        Truncation::KeepEnd => Cow::Borrowed(keep_end(text, max_tokens, counter)),
        Truncation::Middle => truncate_middle(text, max_tokens, counter, DEFAULT_ELLIPSIS),
    }
}

/// [`Truncation::Middle`] with a custom `ellipsis` marker.
///
/// If the marker alone does not fit in `max_tokens`, falls back to keeping
/// the start without a marker.
///
/// ```rust
/// use rune_tokenize::{truncate_middle, TokenizerProfile};
///
/// let s = truncate_middle("alpha beta gamma delta epsilon zeta", 4, &TokenizerProfile::Simple, "..");
/// assert_eq!(s, "alpha..zeta");
/// ```
#[must_use]
pub fn truncate_middle<'a, C: TokenCounter + ?Sized>(
    text: &'a str,
    max_tokens: usize,
    counter: &C,
    ellipsis: &str,
) -> Cow<'a, str> {
    if counter.count_tokens(text) <= max_tokens {
        return Cow::Borrowed(text);
    }
    let marker = counter.count_tokens(ellipsis);
    if marker >= max_tokens {
        return Cow::Borrowed(keep_start(text, max_tokens, counter));
    }
    let mut room = max_tokens - marker;
    loop {
        let head = keep_start(text, room.div_ceil(2), counter);
        let rest = &text[head.len()..];
        let tail_room = room.saturating_sub(counter.count_tokens(head));
        let tail = keep_end(rest, tail_room, counter);
        let head = head.trim_end();
        let tail = tail.trim_start();
        let mut out = String::with_capacity(head.len() + ellipsis.len() + tail.len());
        out.push_str(head);
        out.push_str(ellipsis);
        out.push_str(tail);
        let used = counter.count_tokens(&out);
        if used <= max_tokens || room == 0 {
            return Cow::Owned(out);
        }
        room = room.saturating_sub(used - max_tokens);
    }
}

/// Longest prefix of `text` ending on a word (else grapheme) boundary whose
/// count is `<= max_tokens`.
pub fn keep_start<'a, C: TokenCounter + ?Sized>(
    text: &'a str,
    max_tokens: usize,
    counter: &C,
) -> &'a str {
    if counter.count_tokens(text) <= max_tokens {
        return text;
    }
    // Word ends: the start of every whitespace run that follows a non-space.
    let word_ends: Vec<usize> = text
        .char_indices()
        .zip(text.chars().skip(1))
        .filter(|&((_, c), next)| !c.is_whitespace() && next.is_whitespace())
        .map(|((i, c), _)| i + c.len_utf8())
        .collect();
    let fits = |end: usize| counter.count_tokens(&text[..end]) <= max_tokens;
    if let Some(end) = last_fitting(&word_ends, fits) {
        return &text[..end];
    }
    let cuts = grapheme::boundaries(text);
    last_fitting(&cuts, fits).map_or("", |end| &text[..end])
}

/// Longest suffix of `text` starting on a word (else grapheme) boundary whose
/// count is `<= max_tokens`.
pub fn keep_end<'a, C: TokenCounter + ?Sized>(
    text: &'a str,
    max_tokens: usize,
    counter: &C,
) -> &'a str {
    if counter.count_tokens(text) <= max_tokens {
        return text;
    }
    // Word starts, latest first: suffixes get longer as the start moves left.
    let mut word_starts: Vec<usize> = text
        .char_indices()
        .zip(text.chars().skip(1))
        .filter(|&((_, c), next)| c.is_whitespace() && !next.is_whitespace())
        .map(|((i, c), _)| i + c.len_utf8())
        .collect();
    word_starts.reverse();
    let fits = |start: usize| counter.count_tokens(&text[start..]) <= max_tokens;
    if let Some(start) = last_fitting(&word_starts, fits) {
        return &text[start..];
    }
    let mut cuts: Vec<usize> = core::iter::once(0)
        .chain(grapheme::boundaries(text))
        .filter(|&i| i < text.len())
        .collect();
    cuts.reverse();
    last_fitting(&cuts, fits).map_or("", |start| &text[start..])
}

/// Binary search for the last candidate satisfying `fits`, assuming `fits`
/// holds for a (possibly empty) prefix of `candidates`.
fn last_fitting(candidates: &[usize], fits: impl Fn(usize) -> bool) -> Option<usize> {
    let n = candidates.partition_point(|&c| fits(c));
    n.checked_sub(1).map(|i| candidates[i])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TokenizerProfile;

    const P: TokenizerProfile = TokenizerProfile::Simple;

    #[test]
    fn keep_start_snaps_to_words() {
        assert_eq!(keep_start("aaaa bbbb cccc", 2, &P), "aaaa");
        assert_eq!(keep_start("aaaa bbbb cccc", 100, &P), "aaaa bbbb cccc");
        assert_eq!(keep_start("aaaa bbbb", 0, &P), "");
    }

    #[test]
    fn keep_start_falls_back_to_graphemes() {
        let s = "e\u{301}e\u{301}e\u{301}e\u{301}e\u{301}"; // 10 chars, 5 graphemes
        let out = keep_start(s, 1, &P);
        assert_eq!(out, "e\u{301}e\u{301}");
    }

    #[test]
    fn keep_end_snaps_to_words() {
        assert_eq!(keep_end("aaaa bbbb cccc", 2, &P), "cccc");
        assert_eq!(keep_end("aaaa bbbb cccc", 3, &P), "bbbb cccc");
    }

    #[test]
    fn middle_keeps_both_ends() {
        let s = truncate_with(
            "alpha beta gamma delta epsilon zeta",
            6,
            &P,
            Truncation::Middle,
        );
        assert!(s.starts_with("alpha"), "{s}");
        assert!(s.ends_with("zeta"), "{s}");
        assert!(crate::estimate(&s) <= 6);
    }

    #[test]
    fn middle_with_huge_marker_falls_back() {
        let s = truncate_middle("alpha beta gamma", 1, &P, "[...snip...]");
        assert_eq!(s, "alph"); // no whole word fits: grapheme cut
        let s = truncate_middle("alpha beta gamma", 2, &P, "[...snip...]");
        assert_eq!(s, "alpha");
    }

    #[test]
    fn fitting_text_is_borrowed() {
        assert!(matches!(
            truncate_with("hi", 5, &P, Truncation::Middle),
            Cow::Borrowed("hi")
        ));
    }
}
