# rune-chain-retrieval

> RAG for `rune-chain` — retrieve with BM25, vectors or both, rerank, diversify, and answer with an LLM.

[![crates.io](https://img.shields.io/crates/v/rune-chain-retrieval)](https://crates.io/crates/rune-chain-retrieval)
[![docs.rs](https://img.shields.io/docsrs/rune-chain-retrieval)](https://docs.rs/rune-chain-retrieval)
[![license](https://img.shields.io/crates/l/rune-chain-retrieval)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Implements Retrieval-Augmented Generation (RAG): given a question, it embeds
the query, fetches the most similar documents from a vector store, and prompts
an LLM with the retrieved context. Plug in any [`Embedder`] from
`rune-chain-embed` and any [`Llm`] from the `rune-chain-*` provider crates.

Beyond plain vector search it ships composable retrievers, all behind one
`Retriever` trait (`query, top_k → ranked ScoredDocument`s; `top_k = 0`
always returns an empty list):

| Building block | What it does |
|---|---|
| `Bm25Retriever` / `Bm25Index` | Okapi BM25 keyword search, configurable `k1`/`b`, Unicode-aware `SimpleTokenizer` |
| `EmbeddingRetriever`, `InMemoryVectorStore` | Vector search (cosine scores for the in-memory store) |
| `HybridRetriever` | Reciprocal rank fusion (configurable `k`) or weighted score fusion with min-max / max normalisation |
| `MmrRetriever` | Maximal marginal relevance diversification (`λ`, `fetch_k`) |
| `MultiQueryRetriever` | An LLM writes query variants; results are fused by RRF |
| `RerankingRetriever` + `Reranker` | Second-stage reranking: `ApiReranker` (Cohere, Jina, Voyage) or local `TokenOverlapReranker` |
| `ContextualCompressionRetriever` + `DocumentCompressor` | Post-retrieval hook; `CompressorPipeline` dedupes, thresholds, truncates |
| `RetrieverExt` | `.with_min_score(x)?`, `.deduplicated()` (by SHA-256 content hash) |

## Installation

```toml
[dependencies]
rune-chain-retrieval = "0.2"
rune-chain-embed     = "0.1"  # for OpenAiEmbedder
```

## Usage

```rust
use std::sync::Arc;
use rune_chain_core::{Chain, prompt_args};
use rune_chain_embed::{Embedder, OpenAiEmbedder};
use rune_chain_retrieval::{InMemoryVectorStore, RetrievalQaChain};

let embedder: Arc<dyn Embedder> = Arc::new(OpenAiEmbedder::from_env()?);
let store = Arc::new(InMemoryVectorStore::new(Arc::clone(&embedder)));

// Index documents once
store.add_texts(&[
    "The capital of France is Paris.",
    "The capital of Germany is Berlin.",
    "The capital of Japan is Tokyo.",
]).await?;

// Query many times
let chain = RetrievalQaChain::new(llm, Arc::clone(&embedder), store);
let answer = chain
    .invoke(prompt_args! { "input" => "What is the capital of France?" })
    .await?;
println!("{answer}"); // "Paris"
```

## Documents with metadata

```rust
use rune_chain_retrieval::{Document, InMemoryVectorStore};

let docs = vec![
    Document::from_content("Paris is the capital of France.")
        .with_meta("source", "geography.md")
        .with_meta("page", "12"),
];
store.add_documents(docs).await?;
```

## Custom vector store

Implement `VectorStore` to use a production-grade vector database:

```rust
use async_trait::async_trait;
use rune_chain_retrieval::{Document, StoreError, VectorStore};

struct QdrantStore { /* ... */ }

#[async_trait]
impl VectorStore for QdrantStore {
    async fn add(&self, docs: &[(Document, Vec<f32>)]) -> Result<(), StoreError> { /* ... */ Ok(()) }
    async fn search(&self, emb: &[f32], top_k: usize) -> Result<Vec<Document>, StoreError> { /* ... */ Ok(vec![]) }
}
```

## rune-vectorstore backends

`VectorStoreBackend` runs the chain on any `rune_vectorstore::VectorStore`,
such as its in-memory flat (exact) or HNSW (approximate) index:

```rust
use rune_chain_retrieval::{RetrievalQaChain, VectorStoreBackend};
use rune_vectorstore::{HnswParams, IndexKind, InMemoryVectorStore, Options};

let store = Arc::new(VectorStoreBackend::new(InMemoryVectorStore::new(
    Options::default().with_index(IndexKind::Hnsw(HnswParams::default())),
)));
let chain = RetrievalQaChain::new(llm, embedder, store);
```

## Hybrid search with reranking

```rust
use std::sync::Arc;
use rune_chain_retrieval::{
    ApiReranker, Bm25Retriever, Document, FusionStrategy, HybridRetriever,
    RerankingRetriever, RetrievalQaChain, Retriever,
};

let docs: Vec<Document> = load_documents();
let keyword = Arc::new(Bm25Retriever::from_documents(docs.clone()));
let vector = Arc::new(InMemoryVectorStore::new(Arc::clone(&embedder)));
vector.add_documents(docs).await?;

let hybrid = HybridRetriever::new()
    .with_retriever(keyword, 1.0)?
    .with_retriever(vector, 1.0)?
    .with_strategy(FusionStrategy::ReciprocalRank { k: 60.0 })?;

let reranker = ApiReranker::from_env(rune_chain_retrieval::RerankProvider::Cohere)?;
let retriever = RerankingRetriever::new(Arc::new(hybrid), Arc::new(reranker))
    .with_fetch_k(50);

let chain = RetrievalQaChain::with_retriever(llm, Arc::new(retriever))
    .top_k(5)
    .min_score(0.2); // drop weak rerank hits before they reach the prompt
```

## Rerank APIs

`ApiReranker` speaks to three hosted rerankers. All use a bearer token and
a JSON body with `model`, `query` and plain-string `documents`:

| Provider | Endpoint | Default model | Key env var | Count field | Result field |
|---|---|---|---|---|---|
| Cohere | `POST https://api.cohere.com/v2/rerank` | `rerank-v3.5` | `COHERE_API_KEY` | `top_n` | `results[].{index, relevance_score}` |
| Jina | `POST https://api.jina.ai/v1/rerank` | `jina-reranker-v2-base-multilingual` | `JINA_API_KEY` | `top_n` | `results[].{index, relevance_score}` |
| Voyage | `POST https://api.voyageai.com/v1/rerank` | `rerank-2.5` | `VOYAGE_API_KEY` | `top_k` | `data[].{index, relevance_score}` |

Hardening: `https://` base URLs only (the built-in client also refuses
plain-HTTP and redirects), 30 s request / 10 s connect timeout, responses
capped at 4 MiB while streaming, at most 1 000 documents per request, out-of-range
or repeated indices rejected, and the API key prints as `[REDACTED]` in
`Debug`. `build_request_body` and `parse_response` are exposed as a
sans-I/O core for custom transports.

## Other retrievers

```rust
// Diversify: fetch 20 candidates, keep 5 by MMR (λ = 0.5 balances relevance and novelty)
let mmr = MmrRetriever::new(base.clone(), embedder.clone()).with_lambda(0.5)?.with_fetch_k(20);

// Multi-query: the LLM writes 3 rephrasings, results fused by RRF
let multi = MultiQueryRetriever::new(llm, base.clone()).with_num_queries(3);

// Post-retrieval hook
let pipeline = CompressorPipeline::new()
    .step(CompressionStep::Dedupe)?
    .step(CompressionStep::MinScore(0.1))?
    .compressor(Arc::new(MyLlmExtractor));
let compressed = ContextualCompressionRetriever::new(base, Arc::new(pipeline)).with_fetch_k(20);
```

## Configuration

```rust
let chain = RetrievalQaChain::new(llm, embedder, store)
    .top_k(8)                                      // retrieve 8 documents (default: 4)
    .with_system("Answer in bullet points only.");  // custom system prompt
```

## Migrating from 0.1

0.2 is additive for code, but a few behaviours changed:

- `InMemoryVectorStore` ranks `NaN` similarities last instead of leaving
  them wherever the sort put them.
- `InMemoryVectorStore::similarity_search(_, 0)` and
  `RetrievalQaChain` with `top_k(0)` no longer call the embedder; they
  return no documents straight away (so an embedder error is not raised).
- `Document` now implements `PartialEq` and `Eq`.
- New dependencies: `reqwest` (already used through `rune-chain-embed`),
  `serde`, `sha2`, `futures`.

## License

MIT
