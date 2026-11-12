//! Text splitters for RAG: structural, token-budget, and embedding-based
//! semantic chunking, with byte/char offsets for citation.
//!
//! All structural splitters implement [`TextSplitter`]. Besides plain
//! strings ([`TextSplitter::split`]) they return [`Chunk`]s
//! ([`TextSplitter::chunks`]) that carry the chunk's byte and `char` span in
//! the source plus metadata, so answers can cite and highlight their sources.
//!
//! # Guarantees
//!
//! For every built-in splitter and any input and settings:
//!
//! - no panic, no infinite loop, and no cut inside a UTF-8 character;
//! - each chunk is the verbatim slice `&text[chunk.byte_range]`;
//! - with no overlap, the chunks concatenate back to the input exactly;
//! - degenerate settings (zero size, overlap ≥ size) are clamped by
//!   [`split`](TextSplitter::split)/[`chunks`](TextSplitter::chunks) and
//!   rejected with a [`SplitError`] by [`try_chunks`](TextSplitter::try_chunks).
//!
//! # Splitters
//!
//! - [`RecursiveSplitter`] — try `"\n\n"` → `"\n"` → `". "` → `" "` → chars; best default
//! - [`MarkdownSplitter`] — split at headings, keeping the header path (`"header_path"`, `"h1"`…) as metadata
//! - [`TokenSplitter`] — whole-word token-budget windows (4 chars ≈ 1 token)
//! - [`CharacterSplitter`] — split on one separator, merge with overlap
//! - [`SemanticChunker`] — break where the cosine distance between adjacent
//!   sentence embeddings spikes (percentile, std-dev, IQR, gradient or a
//!   target chunk count), like `LangChain`'s `SemanticChunker`; works with any
//!   [`rune_chain_embed::Embedder`] (feature `embed`, on by default) or with
//!   precomputed / late-chunking embeddings
//!
//! # Quick Start
//!
//! ```rust
//! use rune_chain_splitter::{TextSplitter, RecursiveSplitter};
//!
//! let document = "First paragraph.\n\nSecond paragraph.\n\nThird paragraph.";
//! let splitter = RecursiveSplitter::new().chunk_size(30).chunk_overlap(0);
//! let chunks = splitter.chunks(document);
//! assert!(chunks.len() > 1);
//! for chunk in &chunks {
//!     assert_eq!(&document[chunk.byte_range.clone()], chunk.text);
//! }
//! ```
//!
//! # Choosing a Splitter
//!
//! | Use case | Recommended splitter |
//! |----------|---------------------|
//! | Unknown document structure | [`RecursiveSplitter`] |
//! | Markdown / documentation | [`MarkdownSplitter`] |
//! | Token-budget RAG pipeline | [`TokenSplitter`] |
//! | Fixed-format text (CSV rows, logs) | [`CharacterSplitter`] with custom separator |
//! | Topic-coherent chunks, embedder available | [`SemanticChunker`] |
//!
//! For code-aware or exact-tokenizer splitting, the `text-splitter` crate is
//! a good complement; this crate focuses on citation offsets, header metadata
//! and semantic chunking over the `rune-chain` embedder trait.

mod character;
mod chunk;
mod error;
mod markdown;
mod recursive;
mod semantic;
mod splitter;
mod token;

pub use character::CharacterSplitter;
pub use chunk::Chunk;
pub use error::SplitError;
pub use markdown::{HEADER_PATH_KEY, MarkdownSplitter};
pub use recursive::RecursiveSplitter;
pub use semantic::{
    BreakpointThreshold, SemanticChunker, cosine_distances, pool_spans, sentence_spans,
};
pub use splitter::TextSplitter;
pub use token::TokenSplitter;
