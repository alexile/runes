use std::ops::Range;

use crate::chunk::{Chunk, char_len, locate_chunks};
use crate::error::SplitError;

/// Split text into chunks for LLM context windows.
///
/// Only [`split`](TextSplitter::split) is required. The built-in splitters
/// also override [`chunks`](TextSplitter::chunks) to return exact byte and
/// `char` offsets, and [`validate`](TextSplitter::validate) to reject
/// settings that cannot make progress.
///
/// The built-in splitters guarantee:
///
/// - they never panic and never split inside a UTF-8 character;
/// - every chunk is the verbatim slice `&text[chunk.byte_range]`;
/// - with no overlap, the chunks concatenate back to the input exactly.
pub trait TextSplitter {
    /// Split `text` into chunks according to this splitter's strategy.
    ///
    /// Returns an empty `Vec` when `text` is empty. Invalid settings (a zero
    /// size, an overlap not below the size) are clamped; use
    /// [`try_chunks`](TextSplitter::try_chunks) to reject them instead.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_splitter::{TextSplitter, CharacterSplitter};
    ///
    /// let splitter = CharacterSplitter::new().chunk_size(50).chunk_overlap(0);
    /// let chunks = splitter.split("hello world");
    /// assert_eq!(chunks, vec!["hello world"]);
    /// ```
    fn split(&self, text: &str) -> Vec<String>;

    /// Split `text` into [`Chunk`]s carrying byte/`char` offsets and metadata.
    ///
    /// The default implementation locates each [`split`](TextSplitter::split)
    /// result in `text`; a result that is not a verbatim slice gets an empty
    /// range. Implementors that know their offsets should override it.
    ///
    /// ```rust
    /// use rune_chain_splitter::{TextSplitter, RecursiveSplitter};
    ///
    /// let text = "Alpha beta. Gamma delta.";
    /// let chunks = RecursiveSplitter::new().chunk_size(12).chunk_overlap(0).chunks(text);
    /// for c in &chunks {
    ///     assert_eq!(&text[c.byte_range.clone()], c.text);
    /// }
    /// ```
    fn chunks(&self, text: &str) -> Vec<Chunk> {
        locate_chunks(text, self.split(text))
    }

    /// Check the settings: a zero size or an overlap that is not below the
    /// size is an error. The default accepts everything.
    ///
    /// # Errors
    ///
    /// [`SplitError::ZeroChunkSize`] or [`SplitError::OverlapTooLarge`] for
    /// the built-in splitters.
    fn validate(&self) -> Result<(), SplitError> {
        Ok(())
    }

    /// [`validate`](TextSplitter::validate), then [`chunks`](TextSplitter::chunks).
    ///
    /// # Errors
    ///
    /// Whatever [`validate`](TextSplitter::validate) reports.
    ///
    /// ```rust
    /// use rune_chain_splitter::{SplitError, TextSplitter, RecursiveSplitter};
    ///
    /// let bad = RecursiveSplitter::new().chunk_size(10).chunk_overlap(10);
    /// assert!(matches!(bad.try_chunks("x"), Err(SplitError::OverlapTooLarge { .. })));
    /// ```
    fn try_chunks(&self, text: &str) -> Result<Vec<Chunk>, SplitError> {
        self.validate()?;
        Ok(self.chunks(text))
    }
}

/// Merge non-empty, ordered byte spans of `text` into chunk spans of at most
/// `chunk_size` chars (unless a single piece is larger).
///
/// A chunk spans from its first piece's start to its last piece's end, so
/// any text between pieces stays inside the chunk. Up to `overlap` chars of
/// each chunk's tail start the next chunk, shortened so the tail plus the
/// next piece still fits. A zero `chunk_size` is treated as 1 and `overlap`
/// is clamped below it.
pub fn merge_spans(
    text: &str,
    pieces: &[Range<usize>],
    chunk_size: usize,
    overlap: usize,
) -> Vec<Range<usize>> {
    let chunk_size = chunk_size.max(1);
    let overlap = overlap.min(chunk_size - 1);
    let mut out = Vec::new();
    // (start, end, chars) of the chunk being built.
    let mut cur: Option<(usize, usize, usize)> = None;

    for piece in pieces {
        let piece_chars = char_len(&text[piece.clone()]);
        if let Some((start, end, chars)) = cur {
            let gap = char_len(&text[end..piece.start]);
            if chars + gap + piece_chars > chunk_size {
                out.push(start..end);
                let keep = overlap
                    .min(chars)
                    .min(chunk_size.saturating_sub(gap + piece_chars));
                cur = (keep > 0).then(|| (tail_start(text, start..end, chars, keep), end, keep));
            }
        }
        cur = Some(match cur {
            Some((start, end, chars)) => (
                start,
                piece.end,
                chars + char_len(&text[end..piece.start]) + piece_chars,
            ),
            None => (piece.start, piece.end, piece_chars),
        });
    }
    if let Some((start, end, _)) = cur {
        out.push(start..end);
    }
    out
}

/// Byte position where the last `keep` chars of `text[range]` (`len` chars) begin.
fn tail_start(text: &str, range: Range<usize>, len: usize, keep: usize) -> usize {
    let start = range.start;
    text[range]
        .char_indices()
        .nth(len.saturating_sub(keep))
        .map_or(start, |(i, _)| start + i)
}

/// Split `text` after every occurrence of `separator`, keeping it at the end
/// of its piece, as byte spans offset by `base`. An empty separator splits
/// into single characters.
pub fn split_keeping_separator(text: &str, separator: &str, base: usize) -> Vec<Range<usize>> {
    if separator.is_empty() {
        return text
            .char_indices()
            .map(|(i, c)| base + i..base + i + c.len_utf8())
            .collect();
    }
    let mut pieces = Vec::new();
    let mut start = 0;
    for (i, sep) in text.match_indices(separator) {
        let end = i + sep.len();
        pieces.push(base + start..base + end);
        start = end;
    }
    if start < text.len() {
        pieces.push(base + start..base + text.len());
    }
    pieces
}
