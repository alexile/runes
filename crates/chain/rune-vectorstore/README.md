# rune-vectorstore

> Vector stores for RAG: async trait, exact and HNSW in-memory indexes, JSON metadata filters, MMR and checksummed snapshots

[![crates.io](https://img.shields.io/crates/v/rune-vectorstore)](https://crates.io/crates/rune-vectorstore)
[![docs.rs](https://img.shields.io/docsrs/rune-vectorstore)](https://docs.rs/rune-vectorstore)
[![license](https://img.shields.io/crates/l/rune-vectorstore)](LICENSE)

`VectorStore` is an async upsert / query / delete / get trait with batch
queries and MMR: retrieval pipelines program against it, and external
databases (Qdrant, pgvector, …) implement it. `InMemoryVectorStore` is the
default backend, built on a synchronous, sans-I/O `VectorIndex` core with two
implementations:

| Index       | Search            | Recall                    | Use when                                   |
| ----------- | ----------------- | ------------------------- | ------------------------------------------ |
| `FlatIndex` | exact brute force | 100 %                     | default and reference; up to tens of thousands of records |
| `HnswIndex` | HNSW graph        | ≥ 95 % @10 at defaults    | larger sets where scan latency matters     |

HNSW parameters: `m` (links per node, default 16), `ef_construction`
(default 200) and `ef_search` (default 64, overridable per query). Level
assignment is seeded, so builds are reproducible. The test suite checks
recall@10 against the exact index on seeded random data for all three
metrics, with and without filters.

## Features

- **Metrics**: cosine (default), dot product and Euclidean (L2). Scores are
  always "higher is more similar" (L2 is negated distance).
- **Validation, not panics**: wrong dimensions, empty vectors, NaN or
  infinite components, zero vectors under cosine, a NaN `min_score` and
  malformed filters all return a `StoreError`. Upsert batches are atomic.
- **JSON metadata filters**: `Filter::eq`, `is_in`, `gt` / `gte` / `lt` /
  `lte` / `between`, `exists`, combined with `and`, `or` and `!`. Numbers
  compare by value, strings byte-wise (so ISO dates work), and array fields
  match when any element does.
- **Filtered ANN that never drops matches**: HNSW evaluates the filter on
  every live record first (no vector math). Few matches (at most
  `ef * 2m`, or under 5 % of the index) are scanned exactly; otherwise the
  graph walk routes through all nodes but only admits matching ones, and
  falls back to an exact scan if it still comes up short.
- **Upsert and delete**: by id, plus `delete_where(filter)`. HNSW deletes
  leave tombstones that keep the graph connected; it rebuilds itself once
  they outnumber live records.
- **Batch and MMR**: `query_batch` takes the read lock once; `query_mmr` and
  the `mmr` function diversify results using the stored vectors, with no
  re-embedding.
- **Snapshots**: `save` / `load` (and `to_bytes` / `from_bytes`) use a
  versioned binary format with a CRC-32 checksum. Saving writes a temp file,
  fsyncs it and renames it into place. Loading enforces `LoadLimits` (file
  size, record count, dimension, field size) before allocating, so a hostile
  file cannot exhaust memory. HNSW graphs are rebuilt from the records on
  load rather than trusted from the file.
- **Concurrency**: the store is `Send + Sync`; reads share an `RwLock`,
  writes take it exclusively, and no lock is ever held across an `.await`.

## Installation

```toml
[dependencies]
rune-vectorstore = "0.2"
```

## Usage

```rust
use rune_vectorstore::{
    Filter, HnswParams, IndexKind, InMemoryVectorStore, LoadLimits, Metric, Options, Query,
    Record, StoreError, VectorStore,
};

async fn demo() -> Result<(), StoreError> {
    let store = InMemoryVectorStore::new(
        Options::default().with_index(IndexKind::Hnsw(HnswParams::default())),
    );
    store.upsert(vec![
        Record::new("fr", vec![1.0, 0.0]).with_content("Paris").with_meta("lang", "fr").with_meta("pop", 2.1),
        Record::new("de", vec![0.0, 1.0]).with_content("Berlin").with_meta("lang", "de").with_meta("pop", 3.6),
    ]).await?;

    let hits = store.query(&Query::new(vec![0.9, 0.2], 1)).await?;
    assert_eq!(hits[0].record.content, "Paris");

    let big = Query::new(vec![0.9, 0.2], 1).with_filter(Filter::gt("pop", 3));
    assert_eq!(store.query(&big).await?[0].record.content, "Berlin");

    let diverse = store.query_mmr(&Query::new(vec![0.9, 0.2], 2), 20, 0.5, Metric::Cosine).await?;
    assert_eq!(diverse.len(), 2);

    store.save("store.bin")?;
    let restored = InMemoryVectorStore::load("store.bin", &LoadLimits::default())?;
    assert_eq!(restored.len().await?, 2);
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

A runnable version with filters, MMR and a snapshot round trip:
`cargo run -p rune-vectorstore --example quickstart`.

`rune-chain-retrieval` can run its `RetrievalQaChain` on any `VectorStore`
through its `VectorStoreBackend` adapter.

## Migrating from 0.1

- `Record::metadata` is now `BTreeMap<String, serde_json::Value>` (re-exported
  as `Value`). `with_meta` accepts anything convertible to a JSON value, so
  `with_meta("k", "v")` still works; code that reads metadata as `String`
  needs `.as_str()`.
- `Filter` is now an enum of conditions. `Filter::default().must_equal(k, v)`
  still works; prefer `Filter::eq(k, v)` and the new range / `in` / `exists`
  builders. `Filter::matches` takes a `&Record` as before.
- `Query` gained `ef_search` and `include_vectors` fields (default `None` and
  `true`).
- `VectorIndex` gained the required `records` method and the provided
  `delete_where` and `kind` methods; custom indexes must implement
  `records`.
- `VectorStore` gained provided `query_batch` and `query_mmr` methods.
- `StoreError` has new variants: `InvalidQuery`, `InvalidFilter`, `Io`,
  `InvalidSnapshot` and `LimitExceeded`. A NaN `min_score` used to return no
  hits; it is now `InvalidQuery`.
- Filtered HNSW queries with few matches are now answered by an exact scan
  of the matches instead of a graph walk, so they can be slightly slower on
  tiny indexes but never miss.

## License

MIT
