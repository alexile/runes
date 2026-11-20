# rune-chain-embed

> Provider-agnostic text embeddings for `rune-chain`: the `Embedder` trait,
> hardened OpenAI-compatible / Cohere / Voyage / Jina providers, batching,
> caching and vector helpers.

[![crates.io](https://img.shields.io/crates/v/rune-chain-embed)](https://crates.io/crates/rune-chain-embed)
[![docs.rs](https://img.shields.io/docsrs/rune-chain-embed)](https://docs.rs/rune-chain-embed)
[![license](https://img.shields.io/crates/l/rune-chain-embed)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Defines the `Embedder` trait so any embedding provider can plug into the
`rune-chain-*` ecosystem (`rune-chain-retrieval`, `rune-chain-splitter`,
`rune-chain-ollama`, …), and ships:

| Type | What |
|------|------|
| `OpenAiEmbedder` | `OpenAI` `/v1/embeddings`, and any compatible server (vLLM, LM Studio, LocalAI, …) via `base_url`; `dimensions`, `encoding_format` (float / base64) |
| `CohereEmbedder` | Cohere `/v2/embed` with `input_type` (`search_query` / `search_document` / …) |
| `VoyageEmbedder` | Voyage AI with `input_type` `query` / `document` |
| `JinaEmbedder` | Jina AI with `task` `retrieval.query` / `retrieval.passage` |
| `BatchingEmbedder` | Splits large batches for any embedder: max batch size, max concurrent requests, order preserved |
| `CacheBackedEmbedder` | Caches vectors by model id + SHA-256 of the text in a pluggable `EmbeddingStore`; batches embed only the misses |
| `LruStore` | Bounded, thread-safe in-memory LRU `EmbeddingStore` |
| `cosine_similarity`, `try_cosine_similarity`, `dot`, `l2_norm`, `normalize`, `check_dimensions` | Vector helpers |

Every HTTP provider:

- enforces HTTPS (plain HTTP only to `localhost` / loopback, or a host you
  allow with `.allow_http_host(..)`), and never follows redirects;
- times out each attempt (default 60 s; 10 s connect) and caps the response
  size (default 64 MiB);
- retries 429, 5xx, timeouts and connection failures (default 2 retries),
  honouring `Retry-After` / `retry-after-ms` up to 60 s, otherwise
  exponential backoff with jitter;
- keeps the API key out of `Debug` output and error messages, and truncates
  provider error bodies to 512 characters;
- splits large inputs into requests of at most `max_batch_size` inputs, up to
  `max_concurrency` (default 4) in flight, results in input order;
- checks the reply: one vector per input, each index exactly once, every
  vector of the configured `dimensions` (or of one length) — a mismatch is
  `EmbedError::DimensionMismatch`, never a panic.

## Installation

```toml
[dependencies]
rune-chain-embed = "0.3"
```

## Usage

### Queries and documents

```rust
use rune_chain_embed::{Embedder, OpenAiEmbedder};

let embedder = OpenAiEmbedder::from_env()?; // OPENAI_API_KEY (+ OPENAI_BASE_URL)
let query = embedder.embed_query("what is rust?").await?;
let docs = embedder.embed_documents(&["Rust", "Python", "Go"]).await?;
```

`embed_query` / `embed_documents` default to `embed` / `embed_batch`.
Providers whose models embed queries and documents differently (Cohere,
Voyage, Jina) treat `embed` as a query and `embed_batch` as documents.

### OpenAI-compatible servers, dimensions, base64

```rust
use rune_chain_embed::{EncodingFormat, OpenAiEmbedder};

let embedder = OpenAiEmbedder::new("sk-...")
    .model("text-embedding-3-large")
    .dimensions(256)                          // truncated vectors, checked on return
    .encoding_format(EncodingFormat::Base64); // ~4x smaller responses

let local = OpenAiEmbedder::new("")           // empty key: no Authorization header
    .base_url("http://localhost:8000/v1")
    .model("BAAI/bge-small-en-v1.5");
```

### Cohere, Voyage, Jina

```rust
use rune_chain_embed::{CohereEmbedder, JinaEmbedder, VoyageEmbedder};

let cohere = CohereEmbedder::from_env()?.dimensions(512); // COHERE_API_KEY
let voyage = VoyageEmbedder::from_env()?.model("voyage-3-large"); // VOYAGE_API_KEY
let jina = JinaEmbedder::from_env()?.task("text-matching"); // JINA_API_KEY
```

### Caching

```rust
use rune_chain_embed::{CacheBackedEmbedder, Embedder, LruStore, OpenAiEmbedder};

let cached = CacheBackedEmbedder::new(OpenAiEmbedder::from_env()?, LruStore::new(50_000))?;
cached.embed_documents(&["a", "b"]).await?;      // two misses, one request
cached.embed_documents(&["b", "c"]).await?;      // embeds only "c"
```

The namespace defaults to the embedder's `model_id()` (model plus options
that change the vectors, e.g. `text-embedding-3-small/256`); use
`CacheBackedEmbedder::with_namespace` for embedders without one. Implement
`EmbeddingStore` (`get_many` / `put_many`) for Redis, a database, etc.
Queries are cached only with `.cache_queries(true)`.

### Batching any embedder

```rust
use rune_chain_embed::BatchingEmbedder;

let batched = BatchingEmbedder::new(my_local_model, 32).max_concurrency(2);
```

### Transport settings

```rust
use std::time::Duration;
use rune_chain_embed::OpenAiEmbedder;

let embedder = OpenAiEmbedder::new("sk-...")
    .timeout(Duration::from_secs(30))
    .max_retries(5)
    .max_response_bytes(16 << 20)
    .max_batch_size(256)
    .max_concurrency(8)
    .base_url("http://gpu-box:8000/v1")
    .allow_http_host("gpu-box");
```

### Vector helpers

```rust
use rune_chain_embed::{cosine_similarity, dot, normalize, try_cosine_similarity};

let score = cosine_similarity(&a, &b);         // common prefix on length mismatch (0.1 behaviour)
let score = try_cosine_similarity(&a, &b)?;    // DimensionMismatch on length mismatch
normalize(&mut a);                             // unit length; then dot == cosine
let d = dot(&a, &b)?;
```

### Custom embedder

```rust
use rune_chain_embed::{EmbedError, Embedder};
use async_trait::async_trait;

struct LocalEmbedder;

#[async_trait]
impl Embedder for LocalEmbedder {
    async fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbedError> {
        Ok(texts.iter().map(|_| vec![0.0f32; 384]).collect())
    }
    fn model_id(&self) -> Option<String> {
        Some("local-384".into()) // optional: enables CacheBackedEmbedder::new
    }
}
```

`Embedder` is also implemented for `Arc<E>`, `Box<E>` and `&E`.

### Documents and vector stores

`Embed` says which texts of a value to embed. With the `derive` feature,
`#[derive(Embed)]` writes it; with the `vectorstore` feature,
`add_documents` embeds a batch in one call and upserts one
`rune-vectorstore` record per text (id from `#[embed_id]` or a content hash,
the struct's fields as metadata).

```toml
rune-chain-embed = { version = "0.3", features = ["derive", "vectorstore"] }
```

```rust
use rune_chain_embed::{Embed, VectorStoreExt};

#[derive(Embed, serde::Serialize)]
struct Article {
    #[embed_id]
    slug: String,
    #[embed]
    title: String,
    #[embed]
    paragraphs: Vec<String>,
    year: u16,
}

let added = store.add_documents(&embedder, &articles).await?;
```

## Migrating from 0.2

0.3 only moves to `rune-chain-core` 0.2: `From<EmbedError>` now converts into
`rune_chain_core` 0.2's `ChainError`. Use it together with the 0.2 line of the
other `rune-chain-*` crates; nothing else changed.

## Migrating from 0.1

The `Embedder` trait is source compatible: only defaulted methods were added
(`embed_query`, `embed_documents`, `model_id`), so existing implementations
compile unchanged. What changed:

- `EmbedError` is `#[non_exhaustive]` and gained `DimensionMismatch` and
  `InvalidConfig`. Add a wildcard arm to exhaustive matches. A missing
  `OPENAI_API_KEY` is now `InvalidConfig` (was `Other`).
- `OpenAiEmbedder` behaviour:
  - requests time out after 60 s and responses over 64 MiB are rejected
    (`.timeout(..)`, `.max_response_bytes(..)`); a custom `.http_client(..)`'s
    own timeout is overridden by `.timeout`;
  - 429 / 5xx / timeouts are retried twice (`.max_retries(0)` restores the old
    behaviour);
  - plain `http://` base URLs to non-loopback hosts are refused with
    `InvalidConfig` unless allowed with `.allow_http_host(..)`;
  - batches over 512 inputs are split into several requests
    (`.max_batch_size(..)`);
  - error messages carry the HTTP status (`"… (HTTP 401)"`,
    `"HTTP 502: …"`), are truncated to 512 characters and have the API key
    redacted;
  - replies with duplicate/missing indices are `InvalidResponse`, and vectors
    of the wrong length are `DimensionMismatch`;
  - `from_env` also reads `OPENAI_BASE_URL`;
  - `OpenAiEmbedder` now implements `Debug` (key redacted) and `Clone`.
- The default HTTP client no longer follows redirects.

## License

MIT
