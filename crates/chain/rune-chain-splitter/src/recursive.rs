use std::ops::Range;

use crate::chunk::{Chunk, char_len, chunks_from_ranges};
use crate::error::{SplitError, check_sizes};
use crate::splitter::{TextSplitter, merge_spans, split_keeping_separator};

const DEFAULT_CHUNK_SIZE: usize = 1000;
const DEFAULT_CHUNK_OVERLAP: usize = 200;

/// Split text recursively using progressively finer separators.
///
/// Tries each separator in order — `"\n\n"`, `"\n"`, `". "`, `" "`, `""` —
/// and recurses on any piece that still exceeds `chunk_size` characters.
/// Small pieces are merged with overlap using the same strategy as
/// [`CharacterSplitter`](crate::CharacterSplitter).
///
/// Sizes are counted in `char`s, never bytes. Separators are kept (at the end
/// of the piece they terminate), so with `chunk_overlap(0)` the chunks
/// concatenate back to the input exactly, and every chunk holds at most
/// `chunk_size` characters (a zero size is treated as 1).
///
/// This mirrors `LangChain`'s `RecursiveCharacterTextSplitter` and is the
/// recommended default when the document structure is unknown.
///
/// # Examples
///
/// ```rust
/// use rune_chain_splitter::{TextSplitter, RecursiveSplitter};
///
/// let text = "First paragraph.\n\nSecond paragraph. With two sentences.\n\nThird.";
/// let splitter = RecursiveSplitter::new().chunk_size(40).chunk_overlap(0);
/// let chunks = splitter.split(text);
/// assert!(chunks.len() > 1);
/// ```
#[derive(Debug, Clone)]
pub struct RecursiveSplitter {
    chunk_size: usize,
    chunk_overlap: usize,
    separators: Vec<String>,
}

impl Default for RecursiveSplitter {
    fn default() -> Self {
        Self::new()
    }
}

impl RecursiveSplitter {
    /// Create a splitter with default settings.
    ///
    /// Defaults: `chunk_size = 1000`, `chunk_overlap = 200`.
    /// Separators (in order): `"\n\n"`, `"\n"`, `". "`, `" "`, `""`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_splitter::RecursiveSplitter;
    ///
    /// let splitter = RecursiveSplitter::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            chunk_size: DEFAULT_CHUNK_SIZE,
            chunk_overlap: DEFAULT_CHUNK_OVERLAP,
            separators: Self::default_separators(),
        }
    }

    pub(crate) fn default_separators() -> Vec<String> {
        ["\n\n", "\n", ". ", " ", ""].map(String::from).to_vec()
    }

    /// Set the maximum character count per chunk.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_splitter::RecursiveSplitter;
    ///
    /// let splitter = RecursiveSplitter::new().chunk_size(500);
    /// ```
    #[must_use]
    pub const fn chunk_size(mut self, size: usize) -> Self {
        self.chunk_size = size;
        self
    }

    /// Set how many characters of the previous chunk are repeated at the start
    /// of the next.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_splitter::RecursiveSplitter;
    ///
    /// let splitter = RecursiveSplitter::new().chunk_overlap(50);
    /// ```
    #[must_use]
    pub const fn chunk_overlap(mut self, overlap: usize) -> Self {
        self.chunk_overlap = overlap;
        self
    }

    /// Override the separator list.
    ///
    /// Separators are tried in order; the first one that splits the text is
    /// used. Recursion continues with the remaining separators.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_splitter::RecursiveSplitter;
    ///
    /// let splitter = RecursiveSplitter::new()
    ///     .separators(vec!["---", "\n\n", "\n"]);
    /// ```
    #[must_use]
    pub fn separators(mut self, seps: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.separators = seps.into_iter().map(Into::into).collect();
        self
    }
}

impl TextSplitter for RecursiveSplitter {
    fn split(&self, text: &str) -> Vec<String> {
        self.chunks(text).into_iter().map(|c| c.text).collect()
    }

    fn chunks(&self, text: &str) -> Vec<Chunk> {
        if text.is_empty() {
            return Vec::new();
        }
        let mut ranges = Vec::new();
        split_recursive(
            text,
            0..text.len(),
            &self.separators,
            self.chunk_size.max(1),
            self.chunk_overlap,
            &mut ranges,
        );
        chunks_from_ranges(text, &ranges)
    }

    fn validate(&self) -> Result<(), SplitError> {
        check_sizes(self.chunk_size, self.chunk_overlap)
    }
}

/// Recursively split `text[range]` into chunk spans of at most `chunk_size`
/// (>= 1) chars, appending them to `out` in order.
pub fn split_recursive(
    text: &str,
    range: Range<usize>,
    separators: &[String],
    chunk_size: usize,
    overlap: usize,
    out: &mut Vec<Range<usize>>,
) {
    let slice = &text[range.clone()];
    if slice.is_empty() {
        return;
    }
    if char_len(slice) <= chunk_size {
        out.push(range);
        return;
    }

    // Find the first separator that actually splits this text.
    let (separator, remaining_seps) = find_separator(slice, separators);

    // Every piece keeps its trailing separator, so pieces tile `range` exactly.
    let pieces = split_keeping_separator(slice, separator, range.start);
    if separator.is_empty() {
        // Single characters cannot be split further.
        out.extend(merge_spans(text, &pieces, chunk_size, overlap));
        return;
    }

    let mut small: Vec<Range<usize>> = Vec::new();
    for piece in pieces {
        if char_len(&text[piece.clone()]) <= chunk_size {
            small.push(piece);
            continue;
        }
        // Flush the small pieces before this one to preserve order, then
        // recurse on the oversized piece with the finer separators.
        out.extend(merge_spans(text, &small, chunk_size, overlap));
        small.clear();
        split_recursive(text, piece, remaining_seps, chunk_size, overlap, out);
    }
    out.extend(merge_spans(text, &small, chunk_size, overlap));
}

fn find_separator<'a>(text: &str, separators: &'a [String]) -> (&'a str, &'a [String]) {
    for (i, sep) in separators.iter().enumerate() {
        if sep.is_empty() || text.contains(sep.as_str()) {
            return (sep, &separators[i + 1..]);
        }
    }
    // No configured separator occurs: fall back to a character split.
    ("", &[])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_chunk_size_does_not_panic() {
        // Regression: the character-level fallback called `chunks(0)`.
        let chunks = RecursiveSplitter::new().chunk_size(0).split("abc");
        assert_eq!(chunks.concat(), "abc");
    }

    #[test]
    fn short_text_returns_single_chunk() {
        let splitter = RecursiveSplitter::new();
        let chunks = splitter.split("hello world");
        assert_eq!(chunks, vec!["hello world"]);
    }

    #[test]
    fn long_text_splits_into_multiple_chunks() {
        let text = "First paragraph.\n\nSecond paragraph.\n\nThird paragraph.\n\nFourth paragraph.";
        let splitter = RecursiveSplitter::new().chunk_size(30).chunk_overlap(0);
        let chunks = splitter.split(text);
        assert!(chunks.len() > 1);
    }

    #[test]
    fn no_paragraph_breaks_falls_back_to_newlines() {
        let text = "line one\nline two\nline three\nline four\nline five";
        let splitter = RecursiveSplitter::new().chunk_size(20).chunk_overlap(0);
        let chunks = splitter.split(text);
        assert!(chunks.len() > 1);
    }

    #[test]
    fn empty_input_returns_empty() {
        assert_eq!(RecursiveSplitter::new().split(""), [] as [String; 0]);
    }

    #[test]
    fn chunks_do_not_exceed_chunk_size() {
        let text = "word ".repeat(200);
        let splitter = RecursiveSplitter::new().chunk_size(50).chunk_overlap(10);
        for chunk in splitter.split(&text) {
            assert!(chunk.len() <= 60, "chunk too large: {}", chunk.len());
        }
    }

    #[test]
    fn chunk_size_counts_chars_not_bytes() {
        // Regression: sizes were measured in bytes, so 4 CJK chars (12 bytes)
        // overflowed a 4-char chunk and were split.
        let s = RecursiveSplitter::new().chunk_size(4).chunk_overlap(0);
        assert_eq!(s.split("日本語だ"), ["日本語だ"]);
        // A 6-char word (12 bytes) is cut into 3-char chunks, not 1-char ones.
        let s = RecursiveSplitter::new().chunk_size(3).chunk_overlap(0);
        assert_eq!(s.split("éééééé"), ["ééé", "ééé"]);
    }

    #[test]
    fn separators_are_kept() {
        // Regression: separators between merged pieces were dropped, and a
        // finer separator's pieces were re-joined with the coarser one.
        let text = "one two. three four.\n\nfive six";
        let s = RecursiveSplitter::new().chunk_size(12).chunk_overlap(0);
        let chunks = s.split(text);
        assert_eq!(chunks.concat(), text);
        assert!(chunks.iter().all(|c| c.chars().count() <= 12), "{chunks:?}");
        assert_eq!(chunks, ["one two. ", "three four.\n", "\n", "five six"]);
    }

    #[test]
    fn overlap_is_counted_in_chars_and_bounded_by_chunk_size() {
        let text = "ab cd ef gh ij";
        let s = RecursiveSplitter::new().chunk_size(6).chunk_overlap(3);
        let chunks = s.split(text);
        assert!(chunks.iter().all(|c| c.chars().count() <= 6), "{chunks:?}");
        assert_eq!(chunks.first().map(String::as_str), Some("ab cd "));
        assert!(chunks.iter().any(|c| c.starts_with("cd ")), "{chunks:?}");
    }

    #[test]
    fn chunks_carry_byte_and_char_offsets() {
        let text = "héllo wörld. ünïcode text";
        let chunks = RecursiveSplitter::new()
            .chunk_size(8)
            .chunk_overlap(0)
            .chunks(text);
        let mut chars = 0;
        for (i, c) in chunks.iter().enumerate() {
            assert_eq!(c.index, i);
            assert_eq!(&text[c.byte_range.clone()], c.text);
            assert_eq!(c.char_range.start, chars);
            chars += c.text.chars().count();
            assert_eq!(c.char_range.end, chars);
        }
    }

    #[test]
    fn try_chunks_rejects_zero_size() {
        let s = RecursiveSplitter::new().chunk_size(0).chunk_overlap(0);
        assert!(matches!(
            s.try_chunks("abc"),
            Err(SplitError::ZeroChunkSize)
        ));
    }

    #[test]
    fn custom_separators() {
        let splitter = RecursiveSplitter::new()
            .separators(vec!["---", "\n"])
            .chunk_size(20)
            .chunk_overlap(0);
        let chunks = splitter.split("block one---block two---block three");
        assert!(chunks.len() > 1);
    }
}
