//! `SemanticChunker` over the `rune-chain-embed` trait with a deterministic
//! fake embedder (no network).

#![cfg(feature = "embed")]
#![allow(clippy::unwrap_used, reason = "test assertions")]

use std::sync::Mutex;

use async_trait::async_trait;
use rune_chain_embed::{EmbedError, Embedder};
use rune_chain_splitter::{BreakpointThreshold, SemanticChunker, SplitError};

/// Counts topic keywords: axis 0 = cats, axis 1 = rockets, axis 2 = other.
#[derive(Default)]
struct TopicEmbedder {
    batches: Mutex<Vec<usize>>,
}

#[async_trait]
impl Embedder for TopicEmbedder {
    async fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbedError> {
        self.batches.lock().unwrap().push(texts.len());
        Ok(texts
            .iter()
            .map(|t| {
                let count = |w: &str| {
                    #[allow(clippy::cast_precision_loss, reason = "small counts")]
                    let n = t.matches(w).count() as f32;
                    n
                };
                vec![count("cat"), count("rocket"), 0.1]
            })
            .collect())
    }
}

const TEXT: &str = "The cat sleeps. A cat purrs softly. My cat hunts mice. \
                    The rocket launches. A rocket burns fuel. Each rocket reaches orbit.";

#[tokio::test]
async fn splits_between_topics() {
    let embedder = TopicEmbedder::default();
    let chunks = SemanticChunker::new().chunk(TEXT, &embedder).await.unwrap();
    let texts: Vec<&str> = chunks.iter().map(|c| c.text.as_str()).collect();
    assert_eq!(
        texts,
        [
            "The cat sleeps. A cat purrs softly. My cat hunts mice. ",
            "The rocket launches. A rocket burns fuel. Each rocket reaches orbit."
        ]
    );
    assert_eq!(chunks[1].metadata["sentence_start"], "3");
    assert_eq!(chunks[1].metadata["sentence_end"], "6");
    assert_eq!(&TEXT[chunks[1].byte_range.clone()], chunks[1].text);
}

#[tokio::test]
async fn every_threshold_finds_the_topic_shift() {
    for t in [
        BreakpointThreshold::Percentile(95.0),
        BreakpointThreshold::StandardDeviation(1.0),
        BreakpointThreshold::Interquartile(1.5),
        BreakpointThreshold::ChunkCount(2),
    ] {
        let chunks = SemanticChunker::new()
            .threshold(t)
            .buffer_size(0)
            .chunk(TEXT, &TopicEmbedder::default())
            .await
            .unwrap();
        assert_eq!(chunks.len(), 2, "{t:?}");
        assert!(chunks[1].text.starts_with("The rocket"), "{t:?}");
    }
}

#[tokio::test]
async fn batches_respect_batch_size() {
    let embedder = TopicEmbedder::default();
    SemanticChunker::new()
        .batch_size(4)
        .chunk(TEXT, &embedder)
        .await
        .unwrap();
    assert_eq!(*embedder.batches.lock().unwrap(), [4, 2]);
}

#[tokio::test]
async fn short_text_makes_no_request() {
    let embedder = TopicEmbedder::default();
    let c = SemanticChunker::new();
    assert_eq!(c.chunk("", &embedder).await.unwrap().len(), 0);
    assert_eq!(c.chunk("One sentence.", &embedder).await.unwrap().len(), 1);
    assert!(embedder.batches.lock().unwrap().is_empty());
}

struct Failing;

#[async_trait]
impl Embedder for Failing {
    async fn embed_batch(&self, _: &[&str]) -> Result<Vec<Vec<f32>>, EmbedError> {
        Err(EmbedError::ProviderError("quota".into()))
    }
}

struct Short;

#[async_trait]
impl Embedder for Short {
    async fn embed_batch(&self, _: &[&str]) -> Result<Vec<Vec<f32>>, EmbedError> {
        Ok(vec![vec![1.0]])
    }
}

#[tokio::test]
async fn embedder_failures_are_reported() {
    let c = SemanticChunker::new();
    let err = c.chunk(TEXT, &Failing).await.unwrap_err();
    assert!(matches!(err, SplitError::Embed(_)));
    assert!(err.to_string().contains("quota"));
    assert!(matches!(
        c.chunk(TEXT, &Short).await,
        Err(SplitError::EmbeddingCountMismatch {
            expected: 6,
            got: 1
        })
    ));
    let dyn_embedder: &dyn Embedder = &TopicEmbedder::default();
    assert!(c.chunk(TEXT, dyn_embedder).await.is_ok());
}
