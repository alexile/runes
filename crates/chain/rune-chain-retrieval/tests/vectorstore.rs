//! `RetrievalQaChain` running on `rune-vectorstore`'s in-memory backends.

#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]

use std::sync::Arc;

use async_trait::async_trait;
use rune_chain_core::{Chain, GenerateResult, Llm, LlmError, Message, Role, prompt_args};
use rune_chain_embed::{EmbedError, Embedder};
use rune_chain_retrieval::{Document, RetrievalQaChain, VectorStore, VectorStoreBackend};
use rune_vectorstore::{
    HnswParams, InMemoryVectorStore, IndexKind, Options, Query, VectorStore as _,
};
use tokio::sync::Mutex;

/// Bag-of-words embedder over a fixed vocabulary, L2-normalised.
struct BagOfWords;

const VOCAB: &[&str] = &[
    "paris", "france", "berlin", "germany", "tokyo", "japan", "rust", "memory", "safety", "python",
    "dynamic", "typing", "capital", "language",
];

#[async_trait]
impl Embedder for BagOfWords {
    async fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbedError> {
        Ok(texts
            .iter()
            .map(|text| {
                let lower = text.to_lowercase();
                let mut v: Vec<f32> = VOCAB
                    .iter()
                    .map(|w| if lower.contains(w) { 1.0 } else { 0.0 })
                    .collect();
                // Constant bias keeps every vector non-zero under cosine.
                v.push(0.1);
                let n = v.iter().map(|x| x * x).sum::<f32>().sqrt();
                for x in &mut v {
                    *x /= n;
                }
                v
            })
            .collect())
    }
}

struct CaptureLlm(Arc<Mutex<Vec<Message>>>);

#[async_trait]
impl Llm for CaptureLlm {
    async fn generate(&self, messages: &[Message]) -> Result<GenerateResult, LlmError> {
        self.0.lock().await.extend_from_slice(messages);
        Ok(GenerateResult::from_text("ok"))
    }
}

const CORPUS: &[(&str, &str)] = &[
    ("Paris is the capital of France.", "geo"),
    ("Berlin is the capital of Germany.", "geo"),
    ("Tokyo is the capital of Japan.", "geo"),
    ("Rust is a language focused on memory safety.", "lang"),
    ("Python is a language with dynamic typing.", "lang"),
];

async fn load(kind: IndexKind) -> Arc<VectorStoreBackend<InMemoryVectorStore>> {
    let store = Arc::new(VectorStoreBackend::new(InMemoryVectorStore::new(
        Options::default().with_index(kind),
    )));
    let texts: Vec<&str> = CORPUS.iter().map(|(t, _)| *t).collect();
    let vectors = BagOfWords.embed_batch(&texts).await.unwrap();
    let docs: Vec<(Document, Vec<f32>)> = CORPUS
        .iter()
        .zip(vectors)
        .map(|((t, topic), v)| (Document::new(*t).with_meta("topic", *topic), v))
        .collect();
    store.add(&docs).await.unwrap();
    store
}

fn kinds() -> [IndexKind; 2] {
    [IndexKind::Flat, IndexKind::Hnsw(HnswParams::default())]
}

#[tokio::test]
async fn chain_answers_from_in_memory_vectorstore() {
    for kind in kinds() {
        let store = load(kind).await;
        let captured = Arc::new(Mutex::new(Vec::new()));
        let chain = RetrievalQaChain::new(
            CaptureLlm(Arc::clone(&captured)),
            Arc::new(BagOfWords),
            store,
        )
        .top_k(1);
        let answer = chain
            .invoke(prompt_args! { "input" => "What is the capital of Japan?" })
            .await
            .unwrap();
        assert_eq!(answer, "ok");
        let text = captured
            .lock()
            .await
            .iter()
            .find(|m| m.role == Role::Human)
            .unwrap()
            .content
            .text_content();
        assert!(
            text.contains("Tokyo is the capital of Japan."),
            "{kind:?}: {text}"
        );
        assert!(
            !text.contains("Paris"),
            "{kind:?}: top_k = 1 must keep one doc"
        );
    }
}

#[tokio::test]
async fn recall_at_k_on_toy_set() {
    // query → the documents that must appear in its top-k.
    let cases: &[(&str, usize, &[&str])] = &[
        ("capital of France", 1, &["Paris"]),
        ("Germany", 1, &["Berlin"]),
        ("memory safety", 1, &["Rust"]),
        ("dynamic typing", 1, &["Python"]),
        ("which language", 2, &["Rust", "Python"]),
        ("capital", 3, &["Paris", "Berlin", "Tokyo"]),
    ];
    for kind in kinds() {
        let store = load(kind).await;
        let (mut found, mut wanted) = (0, 0);
        for (q, k, expected) in cases {
            let emb = BagOfWords.embed(q).await.unwrap();
            let docs = store.search(&emb, *k).await.unwrap();
            assert_eq!(docs.len(), *k);
            wanted += expected.len();
            found += expected
                .iter()
                .filter(|e| docs.iter().any(|d| d.content.starts_with(**e)))
                .count();
        }
        assert_eq!(found, wanted, "{kind:?}: recall@k = {found}/{wanted}");
    }
}

#[tokio::test]
async fn metadata_and_backend_access_survive_the_adapter() {
    let store = load(IndexKind::Flat).await;
    let emb = BagOfWords.embed("Rust memory safety").await.unwrap();
    let docs = store.search(&emb, 1).await.unwrap();
    assert_eq!(docs[0].metadata["topic"], "lang");

    let backend = store.inner();
    assert_eq!(backend.len().await.unwrap(), CORPUS.len());
    let filtered = backend
        .query(
            &Query::new(emb, 5)
                .with_filter(rune_vectorstore::Filter::default().must_equal("topic", "geo")),
        )
        .await
        .unwrap();
    assert_eq!(filtered.len(), 3);
    assert_eq!(backend.delete(&["doc-0"]).await.unwrap(), 1);
    assert_eq!(backend.len().await.unwrap(), CORPUS.len() - 1);
}

#[tokio::test]
async fn backend_errors_become_store_errors() {
    let store = load(IndexKind::Flat).await;
    let err = store.search(&[1.0, 2.0], 1).await.unwrap_err();
    assert!(err.to_string().contains("dimensions"), "{err}");
}
