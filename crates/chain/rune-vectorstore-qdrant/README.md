# rune-vectorstore-qdrant

> Qdrant backend for rune-vectorstore over the REST API: collections, batched upserts, filtered search, delete by id or filter, bounded responses

[![crates.io](https://img.shields.io/crates/v/rune-vectorstore-qdrant)](https://crates.io/crates/rune-vectorstore-qdrant)
[![docs.rs](https://img.shields.io/docsrs/rune-vectorstore-qdrant)](https://docs.rs/rune-vectorstore-qdrant)
[![license](https://img.shields.io/crates/l/rune-vectorstore-qdrant)](LICENSE)

`QdrantStore` implements `rune-vectorstore`'s `VectorStore` trait on a
Qdrant collection. It talks to Qdrant's REST API with `reqwest`, so there is
no gRPC or protobuf stack to build. Anything that takes a `VectorStore`
works with it: `EmbeddingIndex` and `AgentBuilder::dynamic_context` in
`rune-chain`, and `VectorStoreExt::add_documents` for `#[derive(Embed)]`
documents.

```rust,no_run
use rune_vectorstore::{Filter, Query, Record, VectorStore};
use rune_vectorstore_qdrant::{QdrantConfig, QdrantStore};

# async fn run() -> Result<(), rune_vectorstore::StoreError> {
// QDRANT_URL (default http://localhost:6333) and QDRANT_API_KEY.
let store = QdrantStore::new(QdrantConfig::from_env("articles"))?;

store.upsert(vec![
    Record::new("rust", vec![0.9, 0.1, 0.0]).with_content("Rust").with_meta("year", 2015),
    Record::new("go", vec![0.8, 0.3, 0.1]).with_content("Go").with_meta("year", 2012),
]).await?;

let q = Query::new(vec![1.0, 0.0, 0.0], 5)
    .with_filter(Filter::lt("year", 2014))
    .with_min_score(0.5);
for hit in store.query(&q).await? {
    println!("{} {:.3}", hit.record.content, hit.score);
}

store.delete(&["go"]).await?;
store.delete_where(&Filter::gte("year", 2015)).await?;
# Ok(()) }
```

With `rune-chain` (feature `qdrant`):

```rust,ignore
use rune_chain::{openai, prelude::*, qdrant::{QdrantConfig, QdrantStore}};

let client = openai::Client::from_env()?;
let store = QdrantStore::new(QdrantConfig::from_env("docs"))?;
let index = EmbeddingIndex::new(client.embedding_model("text-embedding-3-small"), store);
let agent = client.agent("gpt-4o-mini").dynamic_context(4, index).build();
```

## Features

- **Collections**: created on first use with the configured metric
  (cosine → `Cosine`, dot product → `Dot`, Euclidean → `Euclid`), vector
  size (configured, or taken from the first upsert), on-disk payload and
  on-disk vectors. An existing collection is checked: a different metric or
  size is an error, not a silent mismatch. Named vectors are supported.
- **Ids**: canonical decimal `u64` ids and lowercase UUIDs pass through;
  any other id becomes `uuid5(ID_NAMESPACE, id)`, reproducible from any
  language. The original id is stored in the payload and comes back on
  every hit.
- **Payload layout**: `{"page_content", "metadata", "doc_id"}` by default,
  the same content and metadata keys LangChain uses, so existing collections
  read fine. The keys are configurable.
- **Upserts**: validated up front (empty or duplicate ids, wrong
  dimension, NaN/inf, zero vectors under cosine), then streamed in batches
  bounded by point count (256) and body size (8 MiB), each acknowledged with
  `wait=true`. A single point above the size cap is refused.
- **Search**: `score_threshold`, `with_payload`, optional vectors,
  per-query `hnsw_ef`, native batch queries, and MMR through the trait.
  Scores keep `rune-vectorstore`'s "higher is better" rule, so Euclidean
  scores are negated distances and `min_score` is converted accordingly.
- **Filters**: every `Filter` maps to Qdrant's `must` / `should` /
  `must_not` with `match`, `range`, `is_null` and `is_empty`. Number
  equality uses a range so `1` finds `1.0`, as in memory; string ranges
  must be ISO-8601 dates and become datetime ranges. What Qdrant cannot
  express (equality with an array, ranges without bounds, keys with `.`)
  is an `InvalidFilter` error, never dropped.
- **Delete and count**: `delete` by id returns how many existed;
  `delete_where(filter)` and `count(filter)` use exact counts.
- **Transport**: the API key goes in the `api-key` header, never in a URL,
  never in `Debug` output, scrubbed from error text, and never over plain
  HTTP to a remote host unless you opt in. No redirects are followed.
  Requests have a timeout (30 s), responses a size cap (32 MiB), and rate
  limits, 502/503/504 and connection failures are retried with backoff.
- **Errors**: Qdrant's dimension errors become `DimensionMismatch`,
  oversized responses `LimitExceeded`, everything else a `Backend` error
  naming the HTTP status and Qdrant's message. Reading a collection that
  does not exist yet behaves like an empty store.

## Notes

- Qdrant normalises vectors in cosine collections, so vectors read back
  are unit length.
- An upsert split into several batches is not atomic: a failure leaves
  earlier batches written. `delete` and `delete_where` count first and
  delete second.
- `Exists` maps to "not `is_empty`", so an empty array counts as missing.

## Testing

Unit and mock-server tests run offline. The tests in `tests/live.rs` run
against a real server when `QDRANT_URL` is set and are skipped otherwise:

```sh
docker run -p 6333:6333 qdrant/qdrant
QDRANT_URL=http://localhost:6333 cargo test -p rune-vectorstore-qdrant
```

## License

MIT
