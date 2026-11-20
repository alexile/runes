# rune-vectorstore-sqlite

> Embedded single-file SQLite vector store for rune-vectorstore: exact search with a bounded top-k scan, WAL, bound JSON metadata filters

[![crates.io](https://img.shields.io/crates/v/rune-vectorstore-sqlite)](https://crates.io/crates/rune-vectorstore-sqlite)
[![docs.rs](https://img.shields.io/docsrs/rune-vectorstore-sqlite)](https://docs.rs/rune-vectorstore-sqlite)
[![license](https://img.shields.io/crates/l/rune-vectorstore-sqlite)](LICENSE)

`SqliteVectorStore` implements `rune-vectorstore`'s async `VectorStore` trait
on one SQLite file. Use it when you want vectors to survive restarts without
running a database server: desktop apps, CLIs, tests, small RAG services.

## What it does

- **Exact search, bounded memory**: vectors are stored as little-endian `f32`
  BLOBs and scored in Rust. Each query scans the table in keyset-paginated
  chunks inside one read transaction and keeps the best `top_k` in a heap, so
  memory is `O(top_k + dimension)` whatever the table size. Only rows that
  would enter the heap copy their id.
- **Same answers as the in-memory store**: scores, ordering (ties by id),
  validation errors and filter semantics match `InMemoryVectorStore` with a
  flat index. The test suite checks that on seeded random data for all three
  metrics, hundreds of random filters, `delete_where`, batches and MMR.
- **Filters pushed down safely**: `Filter`s compile to `json_each` /
  `json_type` conditions over bound JSON paths (`$."key"`), so metadata keys
  and values never become SQL text. The SQL is a pre-filter; candidates are
  re-checked exactly in Rust, which keeps float comparisons, odd keys and huge
  filters correct.
- **Durable**: WAL mode, `synchronous = NORMAL`, atomic upsert batches
  (`BEGIN IMMEDIATE`), `trusted_schema = OFF`. The metric and dimension of
  each collection are recorded in the file and checked on open. Several
  collections can share a file.
- **Parallel reads**: file databases get a few read-only connections, so
  queries run alongside each other and alongside writes. With the default
  `tokio` feature, blocking calls go to tokio's blocking pool when a runtime
  is present; without one they run inline.
- **Validated input**: NaN or infinite components, empty vectors, zero
  vectors under cosine, dimension mismatches, empty or duplicate ids and
  malformed filters are errors, never panics. Table names must be plain
  identifiers.

## Scale

Search is a linear scan over every row. Measured on one core in a release
build, 100 000 vectors of 384 dimensions take about 80 ms per query, and
cost grows with the row count and the dimension. A metadata filter skips the
scoring but not the read, so it barely helps. That is comfortable up to a
few hundred thousand records at modest query rates. Past that, or for many queries per second, use an approximate index:
`rune-vectorstore-pgvector`, or the in-memory HNSW in `rune-vectorstore`.

There is no `sqlite-vec` integration: its releases still need `unsafe` to
register, it has no inner-product distance, and its KNN tables cannot apply
JSON metadata filters before the `k` cut. The portable scan gives exact,
filter-correct answers without native extensions.

## Installation

```toml
[dependencies]
rune-vectorstore = "0.2"
rune-vectorstore-sqlite = "0.1"
```

SQLite is compiled in (`rusqlite` with `bundled`).

## Usage

```rust
use rune_vectorstore::{Filter, Metric, Query, Record, StoreError, VectorStore};
use rune_vectorstore_sqlite::{SqliteConfig, SqliteVectorStore};

async fn demo() -> Result<(), StoreError> {
    let store = SqliteVectorStore::open(
        "vectors.db",
        SqliteConfig::new("docs").with_metric(Metric::Cosine),
    )?;
    store.upsert(vec![
        Record::new("fr", vec![1.0, 0.0]).with_content("Paris").with_meta("lang", "fr"),
        Record::new("de", vec![0.0, 1.0]).with_content("Berlin").with_meta("lang", "de"),
    ]).await?;

    let q = Query::new(vec![0.9, 0.2], 5).with_filter(Filter::eq("lang", "de"));
    assert_eq!(store.query(&q).await?[0].record.content, "Berlin");

    store.delete_where(&Filter::eq("lang", "fr")).await?;
    assert_eq!(store.len().await?, 1);
    Ok(())
}
```

`SqliteVectorStore::open_in_memory` gives a private in-memory database for
tests. `SqliteConfig::with_options` takes the metric and dimension from
`rune_vectorstore::Options`.

## License

MIT
