//! Structure-aware chunking: paragraphs, then sentences, then words, then
//! grapheme clusters, packed greedily up to a token budget with overlap.

use alloc::vec::Vec;
use core::fmt;

use crate::counter::TokenCounter;
use crate::grapheme;

/// Why a chunking configuration was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ChunkError {
    /// The chunk size was 0 tokens.
    ZeroChunkSize,
    /// The overlap was not smaller than the chunk size, so chunking would
    /// never advance.
    OverlapTooLarge {
        /// Requested chunk size.
        chunk_tokens: usize,
        /// Requested overlap.
        overlap_tokens: usize,
    },
}

impl fmt::Display for ChunkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroChunkSize => f.write_str("chunk size must be greater than zero tokens"),
            Self::OverlapTooLarge {
                chunk_tokens,
                overlap_tokens,
            } => write!(
                f,
                "overlap ({overlap_tokens} tokens) must be smaller than the chunk size ({chunk_tokens} tokens)"
            ),
        }
    }
}

impl core::error::Error for ChunkError {}

/// The coarsest structure [`chunk_with`] tries to keep intact.
///
/// Units that are too large on their own are split at the next finer level
/// (paragraph → sentence → word → grapheme cluster), so chunking always
/// succeeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum Boundary {
    /// Cut anywhere between grapheme clusters.
    Grapheme,
    /// Cut between whitespace-separated words.
    Word,
    /// Cut after `.`, `!`, `?`, `…` (followed by whitespace) or `。！？`.
    Sentence,
    /// Cut at blank lines.
    #[default]
    Paragraph,
}

impl Boundary {
    const fn finer(self) -> Option<Self> {
        match self {
            Self::Grapheme => None,
            Self::Word => Some(Self::Grapheme),
            Self::Sentence => Some(Self::Word),
            Self::Paragraph => Some(Self::Sentence),
        }
    }
}

/// Settings for [`chunk_with`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChunkConfig {
    /// Maximum tokens per chunk (must be > 0).
    pub max_tokens: usize,
    /// Tokens of trailing context repeated at the start of the next chunk
    /// (must be < `max_tokens`). Overlap is made of whole units.
    pub overlap_tokens: usize,
    /// Preferred cut points.
    pub boundary: Boundary,
}

impl ChunkConfig {
    /// `max_tokens` per chunk, no overlap, paragraph boundaries.
    #[must_use]
    pub const fn new(max_tokens: usize) -> Self {
        Self {
            max_tokens,
            overlap_tokens: 0,
            boundary: Boundary::Paragraph,
        }
    }

    /// Set the overlap.
    #[must_use]
    pub const fn overlap(mut self, overlap_tokens: usize) -> Self {
        self.overlap_tokens = overlap_tokens;
        self
    }

    /// Set the preferred boundary.
    #[must_use]
    pub const fn boundary(mut self, boundary: Boundary) -> Self {
        self.boundary = boundary;
        self
    }

    /// Check the size / overlap invariants.
    pub const fn validate(&self) -> Result<(), ChunkError> {
        if self.max_tokens == 0 {
            return Err(ChunkError::ZeroChunkSize);
        }
        if self.overlap_tokens >= self.max_tokens {
            return Err(ChunkError::OverlapTooLarge {
                chunk_tokens: self.max_tokens,
                overlap_tokens: self.overlap_tokens,
            });
        }
        Ok(())
    }
}

/// One chunk: a borrowed slice of the input plus where it sits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Chunk<'a> {
    /// The chunk text, `&input[start..end]`, original whitespace preserved.
    pub text: &'a str,
    /// Byte offset of the chunk in the input.
    pub start: usize,
    /// Byte offset one past the chunk's end.
    pub end: usize,
    /// Tokens in `text` according to the counter.
    pub tokens: usize,
}

/// Split `text` into chunks of at most `config.max_tokens` tokens, cutting at
/// the coarsest [`Boundary`] that fits, with `config.overlap_tokens` of
/// repeated context between consecutive chunks.
///
/// Chunks borrow from `text` (no copying, formatting preserved) and are
/// trimmed of surrounding whitespace. Every non-whitespace character of `text`
/// lands in at least one chunk, in order. Each chunk fits the budget, except a
/// single grapheme cluster that alone exceeds it (e.g. an emoji with
/// `max_tokens = 1`), which becomes its own chunk. Never panics and always
/// terminates.
///
/// Every chunk is measured as a whole with `counter` (galloping search, so the
/// number of counter calls grows logarithmically with the chunk size), so the
/// budget holds for exact, non-additive tokenizers too.
///
/// # Errors
///
/// [`ChunkError`] if `max_tokens` is 0 or `overlap_tokens >= max_tokens`.
///
/// # Example
///
/// ```rust
/// use rune_tokenize::{chunk_with, Boundary, ChunkConfig, TokenCounter, TokenizerProfile};
///
/// let doc = "First paragraph. It has two sentences.\n\nSecond paragraph here.";
/// let p = TokenizerProfile::Cl100k;
/// let config = ChunkConfig::new(8).overlap(2).boundary(Boundary::Sentence);
///
/// let chunks = chunk_with(doc, &config, &p)?;
/// assert_eq!(chunks[0].text, "First paragraph.");
/// for c in &chunks {
///     assert!(c.tokens <= 8);
///     assert_eq!(&doc[c.start..c.end], c.text);
/// }
///
/// assert!(chunk_with(doc, &ChunkConfig::new(4).overlap(4), &p).is_err());
/// # Ok::<(), rune_tokenize::ChunkError>(())
/// ```
pub fn chunk_with<'a, C: TokenCounter + ?Sized>(
    text: &'a str,
    config: &ChunkConfig,
    counter: &C,
) -> Result<Vec<Chunk<'a>>, ChunkError> {
    config.validate()?;
    let max = config.max_tokens;

    let mut units: Vec<Unit> = Vec::new();
    let trimmed_start = text.len() - text.trim_start().len();
    let trimmed_end = text.trim_end().len();
    if trimmed_start >= trimmed_end {
        return Ok(Vec::new());
    }
    let top = if config.boundary == Boundary::Grapheme {
        alloc::vec![(trimmed_start, trimmed_end)]
    } else {
        segment(text, trimmed_start, trimmed_end, config.boundary)
    };
    for (s, e) in top {
        refine(text, (s, e), config.boundary, max, counter, &mut units);
    }

    let n = units.len();
    // Tokens of units[a..b] measured as one string (b > a).
    let span = |a: usize, b: usize| counter.count_tokens(&text[units[a].start..units[b - 1].end]);
    let overlap = config.overlap_tokens;
    let mut chunks = Vec::new();
    let mut i = 0;
    while i < n {
        // Largest j > i with units[i..j] within budget (at least one unit).
        let j = gallop(i + 1, n, |j| span(i, j) <= max);
        let (start, end) = (units[i].start, units[j - 1].end);
        chunks.push(Chunk {
            text: &text[start..end],
            start,
            end,
            tokens: span(i, j),
        });
        if j >= n {
            break;
        }
        // Start the next chunk d units back for overlap, keeping room for
        // unit j and always advancing past i.
        let d = gallop(0, j - i - 1, |d| {
            d == 0 || (span(j - d, j) <= overlap && span(j - d, j + 1) <= max)
        });
        i = j - d;
    }
    Ok(chunks)
}

#[derive(Clone, Copy)]
struct Unit {
    start: usize,
    end: usize,
}

/// Largest `x` in `[lo, hi]` with `ok(x)`, assuming `ok(lo)` and that `ok` is
/// monotone (true then false). Exponential then binary search, so the cost is
/// proportional to the answer, not to `hi`.
fn gallop(lo: usize, hi: usize, ok: impl Fn(usize) -> bool) -> usize {
    let mut good = lo;
    let mut step = 1usize;
    while good < hi && ok(good.saturating_add(step).min(hi)) {
        good = good.saturating_add(step).min(hi);
        step = step.saturating_mul(2);
    }
    let mut bad = good.saturating_add(step).min(hi.saturating_add(1));
    while bad - good > 1 {
        let mid = good + (bad - good) / 2;
        if ok(mid) {
            good = mid;
        } else {
            bad = mid;
        }
    }
    good
}

fn refine<C: TokenCounter + ?Sized>(
    text: &str,
    (s, e): (usize, usize),
    level: Boundary,
    max: usize,
    counter: &C,
    out: &mut Vec<Unit>,
) {
    if counter.count_tokens(&text[s..e]) <= max {
        out.push(Unit { start: s, end: e });
        return;
    }
    match level.finer() {
        Some(finer) if finer != Boundary::Grapheme => {
            for (a, b) in segment(text, s, e, finer) {
                refine(text, (a, b), finer, max, counter, out);
            }
        }
        _ => hard_split(text, s, e, max, counter, out),
    }
}

/// Split `text[s..e]` at grapheme boundaries into maximal pieces that fit,
/// each trimmed of surrounding whitespace (whitespace-only pieces are dropped).
fn hard_split<C: TokenCounter + ?Sized>(
    text: &str,
    s: usize,
    e: usize,
    max: usize,
    counter: &C,
    out: &mut Vec<Unit>,
) {
    let sub = &text[s..e];
    let cuts = grapheme::boundaries(sub);
    let mut from = 0usize; // byte offset in `sub`
    let mut idx = 0usize; // first cut > from
    loop {
        let rest = &sub[from..];
        from += rest.len() - rest.trim_start().len();
        while idx < cuts.len() && cuts[idx] <= from {
            idx += 1;
        }
        if idx >= cuts.len() {
            break;
        }
        // Largest cut that fits; a lone oversized grapheme still advances.
        let last = gallop(idx, cuts.len() - 1, |t| {
            t == idx || counter.count_tokens(&sub[from..cuts[t]]) <= max
        });
        let to = cuts[last];
        // Starts on non-whitespace, so this is never empty.
        let end = from + sub[from..to].trim_end().len();
        out.push(Unit {
            start: s + from,
            end: s + end,
        });
        from = to;
        idx = last + 1;
    }
}

/// Spans (absolute byte ranges, trimmed, non-empty) of `text[s..e]` at `level`.
fn segment(text: &str, s: usize, e: usize, level: Boundary) -> Vec<(usize, usize)> {
    let slice = &text[s..e];
    let mut pieces = words(slice);
    if level == Boundary::Sentence {
        pieces = split_cjk_sentences(slice, &pieces);
    }
    let mut spans: Vec<(usize, usize)> = Vec::new();
    for (a, b) in pieces {
        if let Some(last) = spans.last_mut() {
            let gap = &slice[last.1..a];
            let paragraph_break = gap.matches('\n').count() >= 2;
            let merge = match level {
                Boundary::Paragraph => !paragraph_break,
                Boundary::Sentence => !paragraph_break && !ends_sentence(&slice[last.0..last.1]),
                Boundary::Word | Boundary::Grapheme => false,
            };
            if merge {
                last.1 = b;
                continue;
            }
        }
        spans.push((a, b));
    }
    spans.into_iter().map(|(a, b)| (s + a, s + b)).collect()
}

/// Maximal non-whitespace runs of `slice`.
fn words(slice: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut start: Option<usize> = None;
    for (i, c) in slice.char_indices() {
        match (c.is_whitespace(), start) {
            (true, Some(st)) => {
                out.push((st, i));
                start = None;
            }
            (false, None) => start = Some(i),
            _ => {}
        }
    }
    if let Some(st) = start {
        out.push((st, slice.len()));
    }
    out
}

const fn is_closer(c: char) -> bool {
    matches!(
        c,
        '"' | '\'' | ')' | ']' | '}' | '”' | '’' | '»' | '」' | '』' | '）'
    )
}

const fn is_cjk_terminator(c: char) -> bool {
    matches!(c, '。' | '！' | '？' | '｡')
}

fn ends_sentence(span: &str) -> bool {
    let core = span.trim_end_matches(is_closer);
    core.ends_with(['.', '!', '?', '…']) || core.ends_with(is_cjk_terminator)
}

/// Split pieces after inner CJK terminators (which need no following space).
fn split_cjk_sentences(slice: &str, pieces: &[(usize, usize)]) -> Vec<(usize, usize)> {
    let mut out = Vec::with_capacity(pieces.len());
    for &(a, b) in pieces {
        let mut from = a;
        let mut iter = slice[a..b].char_indices().peekable();
        while let Some((i, c)) = iter.next() {
            if !is_cjk_terminator(c) {
                continue;
            }
            let mut cut = a + i + c.len_utf8();
            while let Some(&(j, n)) = iter.peek() {
                if !(is_closer(n) || is_cjk_terminator(n)) {
                    break;
                }
                cut = a + j + n.len_utf8();
                iter.next();
            }
            if cut < b && grapheme::is_boundary(slice, cut) {
                out.push((from, cut));
                from = cut;
            }
        }
        out.push((from, b));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TokenizerProfile;
    use alloc::vec;

    const P: TokenizerProfile = TokenizerProfile::Simple;

    fn texts<'a>(chunks: &[Chunk<'a>]) -> Vec<&'a str> {
        chunks.iter().map(|c| c.text).collect()
    }

    #[test]
    fn rejects_bad_configs() {
        assert_eq!(
            chunk_with("x", &ChunkConfig::new(0), &P),
            Err(ChunkError::ZeroChunkSize)
        );
        assert_eq!(
            chunk_with("x", &ChunkConfig::new(3).overlap(3), &P),
            Err(ChunkError::OverlapTooLarge {
                chunk_tokens: 3,
                overlap_tokens: 3
            })
        );
    }

    #[test]
    fn empty_and_blank_inputs() {
        let c = ChunkConfig::new(4);
        assert_eq!(chunk_with("", &c, &P), Ok(vec![]));
        assert_eq!(chunk_with(" \n\t ", &c, &P), Ok(vec![]));
    }

    #[test]
    fn paragraphs_are_kept_whole() {
        let doc = "aaaa bbbb\ncccc\n\ndddd eeee\n\nffff";
        let chunks = chunk_with(doc, &ChunkConfig::new(4), &P).unwrap_or_default();
        assert_eq!(texts(&chunks), ["aaaa bbbb\ncccc", "dddd eeee\n\nffff"]);
    }

    #[test]
    fn sentences_split_when_paragraph_is_too_big() {
        let doc = "One two. Three four! Five six?";
        let chunks = chunk_with(doc, &ChunkConfig::new(3), &P).unwrap_or_default();
        assert_eq!(texts(&chunks), ["One two.", "Three four!", "Five six?"]);
    }

    #[test]
    fn cjk_sentences_split_without_spaces() {
        let doc = "今日は晴れ。明日は雨。";
        let cfg = ChunkConfig::new(2).boundary(Boundary::Sentence);
        let chunks = chunk_with(doc, &cfg, &P).unwrap_or_default();
        assert_eq!(texts(&chunks), ["今日は晴れ。", "明日は雨。"]);
    }

    #[test]
    fn long_word_is_hard_split_on_graphemes() {
        let doc = "e\u{301}e\u{301}e\u{301}e\u{301}e\u{301}e\u{301}";
        let cfg = ChunkConfig::new(1).boundary(Boundary::Word);
        let chunks = chunk_with(doc, &cfg, &P).unwrap_or_default();
        assert_eq!(chunks.len(), 3);
        assert!(chunks.iter().all(|c| c.text == "e\u{301}e\u{301}"));
    }

    #[test]
    fn overlap_repeats_trailing_units() {
        let doc = "aaaa bbbb cccc dddd eeee";
        let cfg = ChunkConfig::new(3).overlap(1).boundary(Boundary::Word);
        let chunks = chunk_with(doc, &cfg, &P).unwrap_or_default();
        assert_eq!(
            texts(&chunks),
            ["aaaa bbbb", "bbbb cccc", "cccc dddd", "dddd eeee"]
        );
    }

    #[test]
    fn offsets_round_trip() {
        let doc = "  lead\n\n\nmid text here\n\ntail  ";
        let chunks = chunk_with(doc, &ChunkConfig::new(2), &P).unwrap_or_default();
        for c in chunks {
            assert_eq!(&doc[c.start..c.end], c.text);
        }
    }

    #[test]
    fn grapheme_chunks_are_trimmed() {
        let config = ChunkConfig::new(1).boundary(Boundary::Grapheme);
        let texts: Vec<Vec<&str>> = ["abcd    efgh", "abc defg", "abcd efgh"]
            .iter()
            .map(|doc| {
                let chunks = chunk_with(doc, &config, &P).unwrap();
                for c in &chunks {
                    assert_eq!(&doc[c.start..c.end], c.text);
                }
                chunks.iter().map(|c| c.text).collect()
            })
            .collect();
        assert_eq!(texts[0], ["abcd", "efgh"]);
        for t in texts.iter().flatten() {
            assert!(!t.is_empty() && *t == t.trim(), "{t:?}");
        }
    }
}
