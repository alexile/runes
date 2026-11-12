use std::collections::BTreeMap;
use std::ops::Range;

/// A chunk of a source document, with its position for citation.
///
/// `text` is always `&source[byte_range]` for chunks produced by this crate's
/// splitters, so a chunk can be cited, highlighted or re-embedded in place
/// (for example by late chunking, which pools token embeddings of the whole
/// document over each chunk's span). `char_range` gives the same span in
/// Unicode scalar values, for consumers that index by `char` (JavaScript
/// front-ends, Python strings).
///
/// `metadata` carries splitter-specific facts, such as the Markdown header
/// path (`"header_path"`, `"h1"`…`"h6"`) or the sentence span of a semantic
/// chunk (`"sentence_start"`, `"sentence_end"`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct Chunk {
    /// The chunk's text.
    pub text: String,
    /// Position of the chunk in the splitter's output (0-based).
    pub index: usize,
    /// Byte span of the chunk in the source text.
    pub byte_range: Range<usize>,
    /// `char` span of the chunk in the source text.
    pub char_range: Range<usize>,
    /// Splitter-specific metadata.
    pub metadata: BTreeMap<String, String>,
}

impl Chunk {
    /// Build the chunk for `source[byte_range]`, computing its `char` span.
    ///
    /// Returns `None` when `byte_range` is out of bounds, reversed, or not on
    /// `char` boundaries. Costs `O(byte_range.end)`; the built-in splitters
    /// compute offsets incrementally instead.
    ///
    /// ```rust
    /// use rune_chain_splitter::Chunk;
    ///
    /// let c = Chunk::from_range("héllo wörld", 3, 7..13).unwrap();
    /// assert_eq!(c.text, "wörld");
    /// assert_eq!(c.char_range, 6..11);
    /// assert!(Chunk::from_range("é", 0, 1..2).is_none());
    /// ```
    #[must_use]
    pub fn from_range(source: &str, index: usize, byte_range: Range<usize>) -> Option<Self> {
        let text = source.get(byte_range.clone())?;
        let char_start = source.get(..byte_range.start)?.chars().count();
        Some(Self {
            text: text.to_owned(),
            index,
            char_range: char_start..char_start + text.chars().count(),
            byte_range,
            metadata: BTreeMap::new(),
        })
    }

    /// Add a metadata entry (builder style).
    ///
    /// ```rust
    /// use rune_chain_splitter::Chunk;
    ///
    /// let c = Chunk::from_range("abc", 0, 0..3).unwrap().with_metadata("source", "a.txt");
    /// assert_eq!(c.metadata["source"], "a.txt");
    /// ```
    #[must_use]
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Byte length of the chunk.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.text.len()
    }

    /// `true` if the chunk holds no text.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.text.is_empty()
    }
}

/// Converts byte positions to `char` positions for a sequence of
/// non-decreasing positions, in amortised `O(n)` overall.
struct CharCursor {
    byte: usize,
    chars: usize,
}

impl CharCursor {
    const fn new() -> Self {
        Self { byte: 0, chars: 0 }
    }

    fn advance_to(&mut self, text: &str, pos: usize) -> usize {
        if pos < self.byte {
            // Not monotonic: restart (only reachable through misuse).
            *self = Self::new();
        }
        self.chars += text.get(self.byte..pos).map_or(0, |s| s.chars().count());
        self.byte = pos;
        self.chars
    }
}

/// Build chunks from byte ranges whose starts and ends are each non-decreasing.
pub fn chunks_from_ranges(text: &str, ranges: &[Range<usize>]) -> Vec<Chunk> {
    let mut starts = CharCursor::new();
    let mut ends = CharCursor::new();
    ranges
        .iter()
        .enumerate()
        .map(|(index, r)| Chunk {
            text: text.get(r.clone()).unwrap_or_default().to_owned(),
            index,
            char_range: starts.advance_to(text, r.start)..ends.advance_to(text, r.end),
            byte_range: r.clone(),
            metadata: BTreeMap::new(),
        })
        .collect()
}

/// Find each piece in `text` in order, for splitters that only return strings.
///
/// Each piece is searched from just after the previous piece's start. A piece
/// that is not a verbatim slice of `text` gets an empty range at the search
/// position.
pub fn locate_chunks(text: &str, pieces: Vec<String>) -> Vec<Chunk> {
    let mut from = 0usize;
    let mut ranges = Vec::with_capacity(pieces.len());
    for piece in &pieces {
        let range = text
            .get(from..)
            .and_then(|rest| rest.find(piece.as_str()))
            .map_or(from..from, |i| from + i..from + i + piece.len());
        // The next chunk starts strictly after this one (unless this was empty).
        from = range.start
            + text
                .get(range.start..)
                .and_then(|s| s.chars().next())
                .filter(|_| !piece.is_empty())
                .map_or(0, char::len_utf8);
        ranges.push(range);
    }
    let mut chunks = chunks_from_ranges(text, &ranges);
    for (chunk, piece) in chunks.iter_mut().zip(pieces) {
        chunk.text = piece;
    }
    chunks
}

pub fn char_len(s: &str) -> usize {
    s.chars().count()
}
