# rune-vectorstore-pgvector

> PostgreSQL + pgvector backend for rune-vectorstore: HNSW or IVFFlat indexes, batched upserts, metadata filters as bound jsonb conditions

[![crates.io](https://img.shields.io/crates/v/rune-vectorstore-pgvector)](https://crates.io/crates/rune-vectorstore-pgvector)
[![docs.rs](https://img.shields.io/docsrs/rune-vectorstore-pgvector)](https://docs.rs/rune-vectorstore-pgvector)
[![license](https://img.shields.io/crates/l/rune-vectorstore-pgvector)](LICENSE)

`PgVectorStore` implements `rune-vectorstore`'s async `VectorStore` trait on
a Postgres table with a [pgvector](https://github.com/pgvector/pgvector)
column, so retrieval pipelines written against the trait run unchanged on
Postgres.

## What it does

- **Schema setup**: `ensure_schema` (run by `connect`) creates the extension
  (optional), the table (`id text PRIMARY KEY`, `embedding vector(n)`,
  `content text`, `metadata jsonb`) and the index, all idempotent and
  serialized with an advisory lock. An existing table with another dimension
  is a `DimensionMismatch` error.
- **Indexes**: `PgIndex::Hnsw { m, ef_construction }` (default),
  `PgIndex::IvfFlat { lists }` or `PgIndex::None` for exact scans. The
  operator class follows the metric: `vector_cosine_ops`, `vector_ip_ops` or
  `vector_l2_ops`, and queries order by the matching operator (`<=>`, `<#>`,
  `<->`) so the index serves them.
- **Per-query tuning**: `hnsw.ef_search` (from the query or the config, at
  least `top_k`, at most 1000), `ivfflat.probes`, and pgvector 0.8 iterative
  scans for filtered queries, so a selective filter still returns `top_k`
  rows. Settings are applied with `set_config(.., true)` inside the query's
  transaction and never leak to other pool users.
- **Safe SQL**: schema, table and index names must be plain identifiers and
  are quoted. Ids, vectors, contents, metadata keys and values, limits and
  settings are always bound parameters. Tests check that hostile keys and
  values produce byte-identical SQL text to harmless ones.
- **Filters**: `Filter`s compile to exact `jsonb` conditions with the
  in-memory semantics: array fields match any element, ranges compare
  numbers with numbers and strings with strings byte-wise (`COLLATE "C"`,
  whatever the database collation), `exists` means present and not null, and
  `NOT` of a missing key matches. One difference: Postgres compares JSON
  numbers as exact decimals, while the in-memory store goes through `f64`
  when either side is a float.
- **Batched upserts**: one transaction, a prepared `INSERT ... ON CONFLICT
  DO UPDATE` over array parameters (`upsert_batch_rows` rows per statement,
  default 500).
- **Validated input**: NaN or infinite components, empty vectors, zero
  vectors under cosine, wrong dimensions, empty or duplicate ids and NUL
  characters (which Postgres text cannot hold) are rejected before any I/O,
  with the same errors as the in-memory store.
- **Quiet errors**: messages carry the Postgres error code and text; the
  connection string and password are never included, and `Debug` shows no
  credentials.

Built on `tokio-postgres` and `deadpool-postgres`. They link no native
library, so the crate sits in the same build as any `rusqlite` or `sqlx`
version.

## Installation

```toml
[dependencies]
rune-vectorstore = "0.2"
rune-vectorstore-pgvector = { version = "0.1", features = ["rustls"] }
```

| Feature | What it adds |
|---|---|
| `rustls` | TLS for `connect` (rustls with ring and the webpki roots), used as the URL's `sslmode` asks |

Without `rustls`, `connect` uses plain connections. To bring your own TLS
connector or pool settings, build a `deadpool_postgres::Pool` and pass it to
`PgVectorStore::new`.

## Usage

```rust
use rune_vectorstore::{Filter, Metric, Query, Record, StoreError, VectorStore};
use rune_vectorstore_pgvector::{PgIndex, PgVectorConfig, PgVectorStore};

async fn demo(url: &str) -> Result<(), StoreError> {
    let config = PgVectorConfig::new("docs", 3)
        .with_metric(Metric::Cosine)
        .with_index(PgIndex::Hnsw { m: 16, ef_construction: 64 })
        .with_ef_search(100);
    let store = PgVectorStore::connect(url, config).await?;

    store.upsert(vec![
        Record::new("a", vec![1.0, 0.0, 0.0]).with_content("Rust").with_meta("year", 2015),
        Record::new("b", vec![0.0, 1.0, 0.0]).with_content("Go").with_meta("year", 2012),
    ]).await?;

    let q = Query::new(vec![0.9, 0.1, 0.0], 5).with_filter(Filter::lt("year", 2014));
    assert_eq!(store.query(&q).await?[0].record.content, "Go");

    store.delete_where(&Filter::exists("year")).await?;
    Ok(())
}
```

## Testing

Unit tests cover SQL and filter generation offline. The integration tests
(parity with `InMemoryVectorStore` on random data and filters, HNSW and
IVFFlat recall under a 2 % filter, injection attempts) run when
`DATABASE_URL` points at a Postgres with pgvector available, and are skipped
otherwise:

```sh
docker run -d -e POSTGRES_PASSWORD=pw -p 5432:5432 pgvector/pgvector:pg17
DATABASE_URL=postgres://postgres:pw@127.0.0.1:5432/postgres cargo test -p rune-vectorstore-pgvector
```

## License

MIT
