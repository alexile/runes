# rune-chain-knowledge-graph

> LLM-powered knowledge graph — extract entity-relation triples from text and query them as a graph.

[![crates.io](https://img.shields.io/crates/v/rune-chain-knowledge-graph)](https://crates.io/crates/rune-chain-knowledge-graph)
[![docs.rs](https://img.shields.io/docsrs/rune-chain-knowledge-graph)](https://docs.rs/rune-chain-knowledge-graph)
[![license](https://img.shields.io/crates/l/rune-chain-knowledge-graph)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

`rune-chain-knowledge-graph` bridges two tracks of the `rune-*` ecosystem: the LLM orchestration
layer (`rune-chain-*`) and the graph primitive (`rune-graph`). Feed it any text and an LLM extracts
structured `(subject, relation, object)` triples; those triples are stored as a directed property
graph where entities are nodes and relations are labelled edges. The graph grows with every `extract`
call and can be queried with traversal, shortest-path, and neighbourhood expansion.

## Installation

```toml
[dependencies]
rune-chain-knowledge-graph = "0.3"
rune-chain-core            = "0.1"
# plus any rune-chain-* LLM provider
```

## Usage

```rust,no_run
use rune_chain_knowledge_graph::KnowledgeGraph;
// Plug in any rune-chain-* LLM (OpenAI, Anthropic, Ollama…)
// let kg = KnowledgeGraph::new(openai_llm);

// Extract facts from text
// kg.extract("Alice knows Bob. Bob works at Acme Corp.").await.unwrap();

// Query relations
// let rels = kg.relations_of("Alice").await;

// Find how two entities are connected
// let path = kg.path_between("Alice", "Acme Corp").await.unwrap();
```

## API

### `KnowledgeGraph::new(llm)`

Create a new knowledge graph backed by any `rune-chain-core::Llm` implementation.

### `extract(text)`

Ask the LLM to identify all entity-relation-entity triples in `text`. Each unique entity name
maps to a graph node (created once, reused on subsequent calls). Duplicate triples are silently
ignored.

### `extract_batch(chunks)`

Extract from multiple text chunks in a single call — useful when the document has been pre-split
with `rune-chain-splitter`.

### `relations_of(entity)`

Return all `Triple` values where `entity` is the subject or object.

### `path_between(from, to)`

Find the shortest path between two named entities. Returns `None` if they are not connected.

### `subgraph_around(entity, depth)`

Return all entities reachable within `depth` hops from `entity`, as a `GraphView`.

### `graph()`

Direct access to the underlying `rune-graph::Graph` for advanced queries (PageRank, BFS, etc.).

### `Chain` impl

`KnowledgeGraph` implements `rune-chain-core::Chain`. Use it as a step in a sequential pipeline:

```text
input key  → "input"  (text to extract from)
output      → formatted triple list, e.g. "Alice --[knows]--> Bob"
```

## Output

```
Alice --[knows]--> Bob
Bob --[works_at]--> Acme Corp
Alice --[founded]--> Acme Corp
```

## Chunking large documents

```rust,no_run
use rune_chain_splitter::{TextSplitter, RecursiveSplitter};
// let splitter = RecursiveSplitter::new().chunk_size(500).chunk_overlap(50);
// let chunks: Vec<String> = splitter.split(document);
// kg.extract_batch(&chunks.iter().map(String::as_str).collect::<Vec<_>>()).await.unwrap();
```

## Migrating from 0.2

- Uses `rune-chain-core` 0.2, whose `LlmError`, `GenerateResult`, `TokenUsage` and `Message` changed; see its [migration notes](https://crates.io/crates/rune-chain-core).
- No behaviour change.

## License

MIT
