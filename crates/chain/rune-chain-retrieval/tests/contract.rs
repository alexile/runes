//! `RetrievalQaChain` against the shared `Chain` contract, on both the
//! built-in store and the `rune-vectorstore` adapter.

#![allow(clippy::unwrap_used, reason = "test assertions")]

use std::sync::Arc;

use async_trait::async_trait;
use rune_chain_core::testing::{check_chain, check_chain_rejects};
use rune_chain_core::{Chain, GenerateResult, Llm, LlmError, Message, prompt_args};
use rune_chain_embed::{EmbedError, Embedder};
use rune_chain_retrieval::{
    Document, InMemoryVectorStore, RetrievalQaChain, VectorStore, VectorStoreBackend,
};

/// Two-dimensional embedding: how much the text mentions France vs Germany.
struct CountryEmbedder;

#[async_trait]
impl Embedder for CountryEmbedder {
    async fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbedError> {
        Ok(texts
            .iter()
            .map(|t| {
                let f = if t.contains("France") { 1.0 } else { 0.1 };
                let g = if t.contains("Germany") { 1.0 } else { 0.1 };
                vec![f, g]
            })
            .collect())
    }
}

struct Broken;

#[async_trait]
impl Embedder for Broken {
    async fn embed_batch(&self, _: &[&str]) -> Result<Vec<Vec<f32>>, EmbedError> {
        Err(EmbedError::Other("unreachable".into()))
    }
}

/// Answers with the first context line it was given.
struct FirstContextLine;

#[async_trait]
impl Llm for FirstContextLine {
    async fn generate(&self, messages: &[Message]) -> Result<GenerateResult, LlmError> {
        let human = messages.last().unwrap().content.text_content();
        let line = human.lines().nth(1).unwrap_or_default().to_owned();
        Ok(GenerateResult::from_text(line))
    }
}

async fn memory_store() -> Arc<InMemoryVectorStore> {
    let store = Arc::new(InMemoryVectorStore::new(Arc::new(CountryEmbedder)));
    store
        .add_texts(&["Paris is in France.", "Berlin is in Germany."])
        .await
        .unwrap();
    store
}

#[tokio::test]
async fn meets_the_chain_contract_on_the_in_memory_store() {
    let chain = RetrievalQaChain::new(
        FirstContextLine,
        Arc::new(CountryEmbedder),
        memory_store().await,
    )
    .top_k(1);
    check_chain(
        &chain,
        &prompt_args! { "input" => "Where is Germany's capital?" },
    )
    .await
    .unwrap();
    let answer = chain
        .invoke(prompt_args! { "input" => "Capital of France?" })
        .await
        .unwrap();
    assert!(answer.contains("Paris"), "{answer}");
}

#[tokio::test]
async fn meets_the_chain_contract_on_a_vectorstore_backend() {
    let backend = VectorStoreBackend::new(rune_vectorstore::InMemoryVectorStore::new(
        rune_vectorstore::Options::default(),
    ));
    backend
        .add(&[
            (Document::new("Paris is in France."), vec![1.0, 0.1]),
            (Document::new("Berlin is in Germany."), vec![0.1, 1.0]),
        ])
        .await
        .unwrap();
    let chain = RetrievalQaChain::new(
        FirstContextLine,
        Arc::new(CountryEmbedder),
        Arc::new(backend),
    )
    .top_k(1);
    check_chain(&chain, &prompt_args! { "input" => "Germany?" })
        .await
        .unwrap();
    let answer = chain
        .invoke(prompt_args! { "input" => "Germany?" })
        .await
        .unwrap();
    assert!(answer.contains("Berlin"), "{answer}");
}

#[tokio::test]
async fn rejects_missing_question_and_embedding_failure() {
    let chain = RetrievalQaChain::new(
        FirstContextLine,
        Arc::new(CountryEmbedder),
        memory_store().await,
    );
    check_chain_rejects(&chain, &prompt_args! { "question" => "x" })
        .await
        .unwrap();

    let broken = RetrievalQaChain::new(FirstContextLine, Arc::new(Broken), memory_store().await);
    check_chain_rejects(&broken, &prompt_args! { "input" => "x" })
        .await
        .unwrap();
}

#[tokio::test]
async fn empty_store_still_answers() {
    let store = Arc::new(InMemoryVectorStore::new(Arc::new(CountryEmbedder)));
    assert!(store.is_empty().await);
    let chain = RetrievalQaChain::new(FirstContextLine, Arc::new(CountryEmbedder), store);
    check_chain(&chain, &prompt_args! { "input" => "anything" })
        .await
        .unwrap();
}
