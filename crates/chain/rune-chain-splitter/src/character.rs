use crate::chunk::{Chunk, chunks_from_ranges};
use crate::error::{SplitError, check_sizes};
use crate::splitter::{TextSplitter, merge_spans, split_keeping_separator};

const DEFAULT_SEPARATOR: &str = "\n\n";
const DEFAULT_CHUNK_SIZE: usize = 1000;
const DEFAULT_CHUNK_OVERLAP: usize = 200;

/// Split text on a fixed separator, then merge pieces into size-bounded chunks
/// with optional overlap.
///
/// The text is cut after each `separator` (default `"\n\n"`, kept at the end
/// of its piece), then pieces are packed into chunks of at most `chunk_size`
/// characters, carrying up to `chunk_overlap` characters of context from one
/// chunk into the next. A single piece longer than `chunk_size` becomes its
/// own oversized chunk; use [`RecursiveSplitter`](crate::RecursiveSplitter)
/// for a hard bound.
///
/// Sizes are counted in `char`s. With `chunk_overlap(0)` the chunks
/// concatenate back to the input.
///
/// # Examples
///
/// ```rust
/// use rune_chain_splitter::{TextSplitter, CharacterSplitter};
///
/// let text = "First paragraph.\n\nSecond paragraph.\n\nThird paragraph.";
/// let splitter = CharacterSplitter::new().chunk_size(40).chunk_overlap(0);
/// let chunks = splitter.split(text);
/// assert!(chunks.len() >= 2);
/// assert_eq!(chunks.concat(), text);
/// ```
#[derive(Debug, Clone)]
pub struct CharacterSplitter {
    separator: String,
    chunk_size: usize,
    chunk_overlap: usize,
}

impl Default for CharacterSplitter {
    fn default() -> Self {
        Self::new()
    }
}

impl CharacterSplitter {
    /// Create a splitter with default settings.
    ///
    /// Defaults: separator = `"\n\n"`, `chunk_size = 1000`, `chunk_overlap = 200`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_splitter::CharacterSplitter;
    ///
    /// let splitter = CharacterSplitter::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            separator: DEFAULT_SEPARATOR.to_string(),
            chunk_size: DEFAULT_CHUNK_SIZE,
            chunk_overlap: DEFAULT_CHUNK_OVERLAP,
        }
    }

    /// Set the separator used to split the text before merging.
    ///
    /// An empty separator splits into single characters.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_splitter::CharacterSplitter;
    ///
    /// let splitter = CharacterSplitter::new().separator("\n");
    /// ```
    #[must_use]
    pub fn separator(mut self, separator: impl Into<String>) -> Self {
        self.separator = separator.into();
        self
    }

    /// Set the maximum character count per chunk.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_splitter::CharacterSplitter;
    ///
    /// let splitter = CharacterSplitter::new().chunk_size(500);
    /// ```
    #[must_use]
    pub const fn chunk_size(mut self, size: usize) -> Self {
        self.chunk_size = size;
        self
    }

    /// Set how many characters of the previous chunk are repeated at the start
    /// of the next chunk.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_splitter::CharacterSplitter;
    ///
    /// let splitter = CharacterSplitter::new().chunk_overlap(100);
    /// ```
    #[must_use]
    pub const fn chunk_overlap(mut self, overlap: usize) -> Self {
        self.chunk_overlap = overlap;
        self
    }
}

impl TextSplitter for CharacterSplitter {
    fn split(&self, text: &str) -> Vec<String> {
        self.chunks(text).into_iter().map(|c| c.text).collect()
    }

    fn chunks(&self, text: &str) -> Vec<Chunk> {
        if text.is_empty() {
            return Vec::new();
        }
        let pieces = split_keeping_separator(text, &self.separator, 0);
        let ranges = merge_spans(text, &pieces, self.chunk_size, self.chunk_overlap);
        chunks_from_ranges(text, &ranges)
    }

    fn validate(&self) -> Result<(), SplitError> {
        check_sizes(self.chunk_size, self.chunk_overlap)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_paragraph_returns_one_chunk() {
        let splitter = CharacterSplitter::new().chunk_size(500).chunk_overlap(0);
        let chunks = splitter.split("Hello world.");
        assert_eq!(chunks, vec!["Hello world."]);
    }

    #[test]
    fn two_short_paragraphs_merge_into_one() {
        let splitter = CharacterSplitter::new().chunk_size(200).chunk_overlap(0);
        let text = "Para one.\n\nPara two.";
        let chunks = splitter.split(text);
        assert_eq!(chunks, [text]);
    }

    #[test]
    fn oversized_text_splits_into_multiple_chunks() {
        let para = "x".repeat(300);
        let text = format!("{para}\n\n{para}\n\n{para}\n\n{para}");
        let splitter = CharacterSplitter::new().chunk_size(400).chunk_overlap(0);
        let chunks = splitter.split(&text);
        assert!(chunks.len() > 1);
        assert_eq!(chunks.concat(), text);
    }

    #[test]
    fn empty_input_returns_empty() {
        let splitter = CharacterSplitter::new();
        assert_eq!(splitter.split(""), [] as [String; 0]);
    }

    #[test]
    fn custom_separator() {
        let splitter = CharacterSplitter::new()
            .separator("|")
            .chunk_size(2)
            .chunk_overlap(0);
        assert_eq!(splitter.split("a|b|c"), ["a|", "b|", "c"]);
    }

    #[test]
    fn repeated_separators_are_not_lost() {
        // Regression: empty pieces were dropped and pieces re-joined with a
        // single separator, so chunks were not slices of the input.
        let text = "a\n\n\n\nb";
        let chunks = CharacterSplitter::new()
            .chunk_size(3)
            .chunk_overlap(0)
            .chunks(text);
        assert_eq!(
            chunks.iter().map(|c| c.text.as_str()).collect::<String>(),
            text
        );
        for c in &chunks {
            assert_eq!(&text[c.byte_range.clone()], c.text);
        }
    }

    #[test]
    fn validate_rejects_degenerate_settings() {
        assert!(matches!(
            CharacterSplitter::new().chunk_size(0).validate(),
            Err(SplitError::ZeroChunkSize)
        ));
        assert!(matches!(
            CharacterSplitter::new()
                .chunk_size(5)
                .chunk_overlap(5)
                .validate(),
            Err(SplitError::OverlapTooLarge {
                overlap: 5,
                chunk_size: 5
            })
        ));
        assert!(CharacterSplitter::new().validate().is_ok());
    }
}
