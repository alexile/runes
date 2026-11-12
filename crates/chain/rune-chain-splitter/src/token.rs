use std::ops::Range;

use crate::chunk::{Chunk, char_len, chunks_from_ranges};
use crate::error::{SplitError, check_sizes};
use crate::splitter::TextSplitter;

const DEFAULT_CHUNK_TOKENS: usize = 256;
const DEFAULT_OVERLAP_TOKENS: usize = 32;
/// The `OpenAI` rule of thumb used by `rune-tokenize`: 4 chars ≈ 1 token.
const CHARS_PER_TOKEN: usize = 4;

/// Split text into token-budget windows of whole words.
///
/// Uses the `OpenAI` approximation of **4 characters ≈ 1 token** (the same
/// estimate as `rune-tokenize`) to keep each chunk within `chunk_tokens`.
/// Windows hold whole words (a word longer than the budget becomes its own
/// chunk) and consecutive windows share about `overlap_tokens` of words.
///
/// Each word keeps its trailing whitespace (the first also any leading
/// whitespace), so with `overlap_tokens(0)` the chunks concatenate back to
/// the input exactly.
///
/// # Examples
///
/// ```rust
/// use rune_chain_splitter::{TextSplitter, TokenSplitter};
///
/// let text = "one two three four five six seven eight nine ten";
/// let splitter = TokenSplitter::new().chunk_tokens(4).overlap_tokens(1);
/// let chunks = splitter.split(text);
/// assert!(chunks.len() > 1);
/// ```
#[derive(Debug, Clone)]
pub struct TokenSplitter {
    chunk_tokens: usize,
    overlap_tokens: usize,
}

impl Default for TokenSplitter {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenSplitter {
    /// Create a splitter with default settings.
    ///
    /// Defaults: `chunk_tokens = 256`, `overlap_tokens = 32`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_splitter::TokenSplitter;
    ///
    /// let splitter = TokenSplitter::new();
    /// ```
    #[must_use]
    pub const fn new() -> Self {
        Self {
            chunk_tokens: DEFAULT_CHUNK_TOKENS,
            overlap_tokens: DEFAULT_OVERLAP_TOKENS,
        }
    }

    /// Set the maximum token count per chunk (must be > 0).
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_splitter::TokenSplitter;
    ///
    /// let splitter = TokenSplitter::new().chunk_tokens(128);
    /// ```
    #[must_use]
    pub const fn chunk_tokens(mut self, tokens: usize) -> Self {
        self.chunk_tokens = tokens;
        self
    }

    /// Set how many tokens of the previous chunk appear at the start of the next.
    ///
    /// Should be less than `chunk_tokens`; [`split`](TextSplitter::split)
    /// clamps larger values to `chunk_tokens - 1` (and treats a zero
    /// `chunk_tokens` as 1), while [`try_chunks`](TextSplitter::try_chunks)
    /// rejects them.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_splitter::TokenSplitter;
    ///
    /// let splitter = TokenSplitter::new().overlap_tokens(16);
    /// ```
    #[must_use]
    pub const fn overlap_tokens(mut self, tokens: usize) -> Self {
        self.overlap_tokens = tokens;
        self
    }
}

impl TextSplitter for TokenSplitter {
    fn split(&self, text: &str) -> Vec<String> {
        self.chunks(text).into_iter().map(|c| c.text).collect()
    }

    fn chunks(&self, text: &str) -> Vec<Chunk> {
        if text.is_empty() {
            return Vec::new();
        }
        let chunk_tokens = self.chunk_tokens.max(1);
        let overlap = self.overlap_tokens.min(chunk_tokens - 1);
        let budget = chunk_tokens.saturating_mul(CHARS_PER_TOKEN);
        let step = (chunk_tokens - overlap).saturating_mul(CHARS_PER_TOKEN);

        let words = word_pieces(text);
        let sizes: Vec<usize> = words.iter().map(|w| char_len(&text[w.clone()])).collect();
        let mut ranges = Vec::new();
        let mut start = 0;
        while start < words.len() {
            // Fill the window with whole words (at least one).
            let mut chars = 0;
            let mut end = start;
            for (i, &size) in sizes.iter().enumerate().skip(start) {
                if chars + size > budget && i > start {
                    break;
                }
                chars += size;
                end = i + 1;
            }
            ranges.push(words[start].start..words[end - 1].end);
            if end >= words.len() {
                break;
            }
            // Advance by `step` chars of whole words; always at least one word.
            let mut advanced = 0;
            let mut next = start;
            while next < end && advanced < step {
                advanced += sizes[next];
                next += 1;
            }
            start = next;
        }
        chunks_from_ranges(text, &ranges)
    }

    fn validate(&self) -> Result<(), SplitError> {
        check_sizes(self.chunk_tokens, self.overlap_tokens)
    }
}

/// Words with their trailing whitespace; the first also takes any leading
/// whitespace, so the pieces tile `text`.
fn word_pieces(text: &str) -> Vec<Range<usize>> {
    let mut pieces = Vec::new();
    let mut start = 0;
    let mut prev_ws = false;
    let mut seen_word = false;
    for (i, c) in text.char_indices() {
        let ws = c.is_whitespace();
        if !ws && prev_ws && seen_word {
            pieces.push(start..i);
            start = i;
        }
        seen_word |= !ws;
        prev_ws = ws;
    }
    pieces.push(start..text.len());
    pieces
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_settings_are_clamped_instead_of_panicking() {
        let text = "one two three four five six seven eight nine ten";
        for (chunk_tokens, overlap) in [(0, 0), (4, 4), (4, 100), (1, 1)] {
            let s = TokenSplitter::new()
                .chunk_tokens(chunk_tokens)
                .overlap_tokens(overlap);
            assert!(!s.split(text).is_empty(), "{chunk_tokens}/{overlap}");
            assert!(s.try_chunks(text).is_err(), "{chunk_tokens}/{overlap}");
        }
    }

    #[test]
    fn short_text_fits_in_one_chunk() {
        let splitter = TokenSplitter::new().chunk_tokens(256).overlap_tokens(0);
        assert_eq!(splitter.split("hello world"), ["hello world"]);
    }

    #[test]
    fn long_text_splits_into_multiple_chunks() {
        let text = (0..80)
            .map(|i| format!("word{i}"))
            .collect::<Vec<_>>()
            .join(" ");
        let splitter = TokenSplitter::new().chunk_tokens(4).overlap_tokens(1);
        assert!(splitter.split(&text).len() > 1);
    }

    #[test]
    fn empty_input_returns_empty() {
        assert_eq!(TokenSplitter::new().split(""), [] as [String; 0]);
    }

    #[test]
    fn chunks_respect_token_budget() {
        let text = (0..100)
            .map(|i| format!("word{i:02}"))
            .collect::<Vec<_>>()
            .join(" ");
        let splitter = TokenSplitter::new().chunk_tokens(20).overlap_tokens(4);
        let chunks = splitter.split(&text);
        assert!(chunks.len() > 1);
        for chunk in &chunks {
            assert!(chunk.chars().count() <= 80, "chunk too large: {chunk:?}");
        }
    }

    #[test]
    fn whitespace_is_preserved_without_overlap() {
        // Regression: words were re-joined with single spaces, so chunks were
        // not slices of the input and offsets could not be cited.
        let text = "  alpha\tbeta\n\ngamma   delta ";
        let chunks = TokenSplitter::new()
            .chunk_tokens(3)
            .overlap_tokens(0)
            .chunks(text);
        assert!(chunks.len() > 1);
        assert_eq!(
            chunks.iter().map(|c| c.text.as_str()).collect::<String>(),
            text
        );
    }

    #[test]
    fn overlap_repeats_whole_words() {
        let text = "aaa bbb ccc ddd eee fff";
        let chunks = TokenSplitter::new()
            .chunk_tokens(3)
            .overlap_tokens(1)
            .split(text);
        assert_eq!(chunks[0], "aaa bbb ccc ");
        assert!(
            chunks[1].starts_with("ccc ") || chunks[1].starts_with("bbb "),
            "{chunks:?}"
        );
    }
}
