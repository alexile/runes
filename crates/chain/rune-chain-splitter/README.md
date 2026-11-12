# rune-chain-splitter

> Text splitters for RAG: semantic (embedding-based), recursive, markdown and token chunking with citation offsets.

[![crates.io](https://img.shields.io/crates/v/rune-chain-splitter)](https://crates.io/crates/rune-chain-splitter)
[![docs.rs](https://img.shields.io/docsrs/rune-chain-splitter)](https://docs.rs/rune-chain-splitter)
[![license](https://img.shields.io/crates/l/rune-chain-splitter)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Splits documents into chunks for embedding and retrieval in `rune-chain` pipelines:

- **Semantic chunking**: breaks text where the cosine distance between adjacent
  sentence embeddings spikes, like LangChain's `SemanticChunker`. It runs over any
  `rune_chain_embed::Embedder`, or over embeddings you computed yourself (including
  late-chunking token embeddings).
- **Structural splitters**: `RecursiveSplitter`, `MarkdownSplitter` (records the header path
  as metadata), `TokenSplitter` and `CharacterSplitter`, all behind one `TextSplitter` trait.
- **Citation offsets**: every `Chunk` carries its byte range and `char` range in the source,
  plus metadata, so answers can quote and highlight their sources.

Guarantees, enforced by property tests: no panics and no cuts inside a UTF-8 character;
every chunk is the verbatim slice `&text[chunk.byte_range]`; with no overlap the chunks
concatenate back to the input; zero sizes and an overlap ≥ the size are clamped by `split`/`chunks`
and rejected with a `SplitError` by `try_chunks`.

## Installation

```toml
[dependencies]
rune-chain-splitter = "0.2"
```

The default `embed` feature pulls in `rune-chain-embed` for `SemanticChunker::chunk`. If you
don't need it, use `default-features = false`; `chunk_with_embeddings` still works.

## Usage

```rust
use rune_chain_splitter::{TextSplitter, RecursiveSplitter};

let document = "First paragraph.\n\nSecond paragraph.\n\nThird paragraph.";
let splitter = RecursiveSplitter::new().chunk_size(30).chunk_overlap(0);
for chunk in splitter.chunks(document) {
    println!("{:?} {:?}: {}", chunk.byte_range, chunk.char_range, chunk.text);
}
```

### Semantic chunking

```rust,ignore
use rune_chain_splitter::{BreakpointThreshold, SemanticChunker};

let chunker = SemanticChunker::new()
    .threshold(BreakpointThreshold::Percentile(95.0)) // or StandardDeviation(3.0), Interquartile(1.5), Gradient(95.0), ChunkCount(n)
    .buffer_size(1)                // embed each sentence with one neighbour on each side
    .min_chunk_chars(200)          // skip breakpoints that would leave tiny chunks
    .max_chunk_chars(Some(2_000)); // re-split oversized chunks recursively
let chunks = chunker.chunk(&document, &embedder).await?; // any rune_chain_embed::Embedder
for c in &chunks {
    println!("sentences {}..{}: {}", c.metadata["sentence_start"], c.metadata["sentence_end"], c.text);
}
```

The work is split into synchronous steps you can call yourself: `sentence_spans`,
`SemanticChunker::embedding_inputs`, `cosine_distances`, `SemanticChunker::breakpoints` and
`SemanticChunker::chunk_with_embeddings`.

**Late chunking:** embed the whole document once with a long-context model. Then mean-pool its
token vectors over each sentence span with `pool_spans`, and pass the result to
`chunk_with_embeddings`. To get context-aware chunk embeddings, pool the same token vectors
over each returned chunk's `byte_range`.

### Markdown with header paths

```rust
use rune_chain_splitter::{TextSplitter, MarkdownSplitter};

let md = "# Guide\n\nIntro.\n\n## Install\n\nRun it.";
let chunks = MarkdownSplitter::new().max_chunk_size(1000).chunks(md);
assert_eq!(chunks[1].metadata["header_path"], "Guide > Install");
assert_eq!(chunks[1].metadata["h2"], "Install");
```

The splitter only treats real ATX headings as section breaks. `#` lines inside code fences
and `#hashtags` are not headings. A heading directly followed by another heading stays with
its body, and sections longer than `max_chunk_size` are re-split recursively.

## Splitters

| Splitter | Best for |
|----------|----------|
| `RecursiveSplitter` | Unknown document structure (recommended default) |
| `MarkdownSplitter` | Markdown / documentation, with header-path metadata |
| `TokenSplitter` | Token-budget windows of whole words (4 chars ≈ 1 token) |
| `CharacterSplitter` | Fixed-format text (CSV rows, logs) |
| `SemanticChunker` | Topic-coherent chunks when an embedder is available |

For code-aware splitting or exact tokenizer counts, the
[`text-splitter`](https://crates.io/crates/text-splitter) crate is a good complement.

## Migrating from 0.1

- Uses `rune-chain-embed` 0.2, whose types changed; see its migration notes.
- No behaviour change.

## License

MIT
