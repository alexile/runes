# rune-vectorstore

> Vector-store trait with in-memory flat and HNSW indexes for RAG pipelines

[![crates.io](https://img.shields.io/crates/v/rune-vectorstore)](https://crates.io/crates/rune-vectorstore)
[![docs.rs](https://img.shields.io/docsrs/rune-vectorstore)](https://docs.rs/rune-vectorstore)
[![license](https://img.shields.io/crates/l/rune-vectorstore)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

`VectorStore` is an async upsert / query / delete / get trait: retrieval
pipelines program against it, and external databases (Qdrant, pgvector, …)
implement it. `InMemoryVectorStore` is the default backend, built on a
synchronous, sans-I/O `VectorIndex` core with two implementations:

| Index       | Search      | Recall | Use when                               |
| ----------- | ----------- | ------ | -------------------------------------- |
| `FlatIndex` | exact scan  | 100 %  | default; up to tens of thousands of records |
| `HnswIndex` | HNSW graph  | ~95 %+ | larger sets where scan latency matters |

Metrics: cosine (default), dot product and Euclidean. Scores are always
"higher is more similar". Queries support metadata-equality filters and a
minimum score; filtered HNSW queries fall back to an exact scan when the
graph walk cannot fill `top_k`, so filters never drop matches.

## Installation

```toml
[dependencies]
rune-vectorstore = "0.1"
```

## Usage

```rust
use rune_vectorstore::{InMemoryVectorStore, Options, Query, Record, StoreError, VectorStore};

async fn demo() -> Result<(), StoreError> {
    let store = InMemoryVectorStore::new(Options::default());
    store.upsert(vec![
        Record::new("fr", vec![1.0, 0.0]).with_content("Paris").with_meta("lang", "fr"),
        Record::new("de", vec![0.0, 1.0]).with_content("Berlin").with_meta("lang", "de"),
    ]).await?;

    let hits = store.query(&Query::new(vec![0.9, 0.2], 1)).await?;
    assert_eq!(hits[0].record.content, "Paris");
    Ok(())
}
```

Synchronous use without a runtime:

```rust
use rune_vectorstore::{HnswIndex, HnswParams, Metric, Query, Record, StoreError, VectorIndex};

fn demo() -> Result<(), StoreError> {
    let mut index = HnswIndex::new(Metric::Cosine, HnswParams::default().with_ef_search(128));
    index.upsert(vec![Record::new("a", vec![0.3, 0.7])])?;
    let hits = index.query(&Query::new(vec![0.3, 0.7], 1))?;
    assert_eq!(hits[0].record.id, "a");
    Ok(())
}
```

`rune-chain-retrieval` can run its `RetrievalQaChain` on any `VectorStore`
through its `VectorStoreBackend` adapter.

## License

MIT
