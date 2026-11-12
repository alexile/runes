//! End-to-end behaviour of the retriever building blocks, with deterministic
//! fakes (no network).

#![allow(clippy::unwrap_used, reason = "test assertions")]
#![allow(clippy::assert_is_empty, reason = "emptiness is the expectation")]

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use proptest::prelude::*;
use proptest::test_runner::RngSeed;
use rune_chain_core::{Chain, GenerateResult, Llm, LlmError, Message, prompt_args};
use rune_chain_embed::{EmbedError, Embedder};
use rune_chain_retrieval::{
    Bm25Retriever, CompressionStep, CompressorPipeline, ContextualCompressionRetriever, Document,
    EmbeddingRetriever, FusionStrategy, HybridRetriever, InMemoryVectorStore, MmrRetriever,
    MultiQueryRetriever, Normalization, RerankingRetriever, RetrievalQaChain, Retriever,
    RetrieverExt, ScoredDocument, TokenOverlapReranker, reciprocal_rank_fusion,
    weighted_score_fusion,
};

const VOCAB: &[&str] = &[
    "rust", "memory", "safety", "python", "typing", "garbage", "java",
];

/// Bag-of-words over a fixed vocabulary with a bias term.
struct BagOfWords;

#[async_trait]
impl Embedder for BagOfWords {
    async fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbedError> {
        Ok(texts
            .iter()
            .map(|t| {
                let lower = t.to_lowercase();
                let mut v: Vec<f32> = VOCAB
                    .iter()
                    .map(|w| if lower.contains(w) { 1.0 } else { 0.0 })
                    .collect();
                v.push(0.1);
                v
            })
            .collect())
    }
}

/// Returns a fixed reply and records the prompts it saw.
struct Scripted(&'static str);

#[async_trait]
impl Llm for Scripted {
    async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
        Ok(GenerateResult::from_text(self.0))
    }
}

struct Failing;

#[async_trait]
impl Llm for Failing {
    async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
        Err(LlmError::request_failed("down"))
    }
}

fn corpus() -> Vec<Document> {
    vec![
        Document::new("Rust gives memory safety without garbage collection."),
        Document::new("Rust memory safety via the borrow checker."),
        Document::new("Python typing is optional."),
        Document::new("Java uses garbage collection."),
    ]
}

async fn vector_store() -> Arc<InMemoryVectorStore> {
    let store = Arc::new(InMemoryVectorStore::new(Arc::new(BagOfWords)));
    store.add_documents(corpus()).await.unwrap();
    store
}

fn contents(docs: &[ScoredDocument]) -> Vec<&str> {
    docs.iter().map(|d| d.document.content.as_str()).collect()
}

#[tokio::test]
async fn every_retriever_returns_empty_for_zero_k() {
    let bm25: Arc<dyn Retriever> = Arc::new(Bm25Retriever::from_documents(corpus()));
    let vector: Arc<dyn Retriever> = vector_store().await;
    let embedder: Arc<dyn Embedder> = Arc::new(BagOfWords);
    let retrievers: Vec<Arc<dyn Retriever>> = vec![
        Arc::clone(&bm25),
        Arc::clone(&vector),
        Arc::new(EmbeddingRetriever::new(
            Arc::clone(&embedder),
            vector_store().await,
        )),
        Arc::new(
            HybridRetriever::new()
                .with_retriever(Arc::clone(&bm25), 1.0)
                .unwrap(),
        ),
        Arc::new(MmrRetriever::new(
            Arc::clone(&vector),
            Arc::clone(&embedder),
        )),
        Arc::new(MultiQueryRetriever::new(Failing, Arc::clone(&bm25))),
        Arc::new(RerankingRetriever::new(
            Arc::clone(&bm25),
            Arc::new(TokenOverlapReranker::new()),
        )),
        Arc::new(ContextualCompressionRetriever::new(
            Arc::clone(&bm25),
            Arc::new(CompressorPipeline::new()),
        )),
        Arc::new(Arc::clone(&bm25).deduplicated()),
        Arc::new(Arc::clone(&bm25).with_min_score(0.0).unwrap()),
    ];
    for r in retrievers {
        assert!(r.retrieve("rust memory", 0).await.unwrap().is_empty());
    }
}

#[tokio::test]
async fn hybrid_combines_keyword_and_vector() {
    let bm25: Arc<dyn Retriever> = Arc::new(Bm25Retriever::from_documents(corpus()));
    let vector: Arc<dyn Retriever> = vector_store().await;
    for strategy in [
        FusionStrategy::ReciprocalRank { k: 60.0 },
        FusionStrategy::WeightedScore {
            normalization: Normalization::MinMax,
        },
    ] {
        let hybrid = HybridRetriever::new()
            .with_retriever(Arc::clone(&bm25), 0.5)
            .unwrap()
            .with_retriever(Arc::clone(&vector), 0.5)
            .unwrap()
            .with_strategy(strategy)
            .unwrap()
            .with_fetch_k(4);
        let hits = hybrid.retrieve("rust memory safety", 2).await.unwrap();
        assert_eq!(hits.len(), 2);
        assert!(hits.iter().all(|h| h.document.content.starts_with("Rust")));
        // Deterministic across calls.
        assert_eq!(
            hits,
            hybrid.retrieve("rust memory safety", 2).await.unwrap()
        );
    }
}

#[tokio::test]
async fn mmr_skips_near_duplicates() {
    let vector: Arc<dyn Retriever> = vector_store().await;
    let plain = vector.retrieve("rust memory safety", 2).await.unwrap();
    assert!(plain.iter().all(|h| h.document.content.starts_with("Rust")));

    let mmr = MmrRetriever::new(Arc::clone(&vector), Arc::new(BagOfWords))
        .with_lambda(0.3)
        .unwrap()
        .with_fetch_k(4);
    let hits = mmr.retrieve("rust memory safety", 2).await.unwrap();
    assert!(hits[0].document.content.starts_with("Rust"));
    assert!(
        !hits[1].document.content.starts_with("Rust"),
        "{:?}",
        contents(&hits)
    );
    assert!(
        MmrRetriever::new(vector, Arc::new(BagOfWords))
            .with_lambda(-0.1)
            .is_err()
    );
}

#[tokio::test]
async fn multi_query_fuses_variant_results() {
    let bm25: Arc<dyn Retriever> = Arc::new(Bm25Retriever::from_documents(corpus()));
    // The original query matches nothing; the variants do.
    let r = MultiQueryRetriever::new(Scripted("1. python typing\n2. java garbage"), bm25);
    let hits = r.retrieve("zzz", 5).await.unwrap();
    let got: HashSet<&str> = contents(&hits).into_iter().collect();
    assert!(got.contains("Python typing is optional."));
    assert!(got.contains("Java uses garbage collection."));
}

#[tokio::test]
async fn multi_query_propagates_llm_errors() {
    let bm25: Arc<dyn Retriever> = Arc::new(Bm25Retriever::from_documents(corpus()));
    let r = MultiQueryRetriever::new(Failing, bm25);
    assert!(r.retrieve("rust", 3).await.is_err());
}

#[tokio::test]
async fn reranking_reorders_candidates() {
    let bm25: Arc<dyn Retriever> = Arc::new(Bm25Retriever::from_documents(corpus()));
    let r = RerankingRetriever::new(bm25, Arc::new(TokenOverlapReranker::new()));
    let hits = r.retrieve("borrow checker rust", 1).await.unwrap();
    assert_eq!(
        hits[0].document.content,
        "Rust memory safety via the borrow checker."
    );
    assert!((hits[0].score - 1.0).abs() < f32::EPSILON);
}

#[tokio::test]
async fn compression_dedupes_and_thresholds() {
    let mut docs = corpus();
    docs.push(Document::new("Python typing is optional.").with_meta("copy", "yes"));
    let bm25: Arc<dyn Retriever> = Arc::new(Bm25Retriever::from_documents(docs));
    let pipeline = CompressorPipeline::new()
        .step(CompressionStep::Dedupe)
        .unwrap()
        .step(CompressionStep::MinScore(0.01))
        .unwrap();
    let r = ContextualCompressionRetriever::new(bm25, Arc::new(pipeline)).with_fetch_k(10);
    let hits = r.retrieve("python", 5).await.unwrap();
    assert_eq!(contents(&hits), ["Python typing is optional."]);
}

#[tokio::test]
async fn chain_runs_on_any_retriever_with_threshold() {
    /// Echoes the human prompt so the test can see the context.
    struct Echo;
    #[async_trait]
    impl Llm for Echo {
        async fn generate(&self, m: &[Message]) -> Result<GenerateResult, LlmError> {
            Ok(GenerateResult::from_text(
                m.last().unwrap().content.text_content(),
            ))
        }
    }
    let bm25: Arc<dyn Retriever> = Arc::new(Bm25Retriever::from_documents(corpus()));
    let chain = RetrievalQaChain::with_retriever(Echo, Arc::clone(&bm25)).top_k(1);
    let out = chain
        .invoke(prompt_args! { "input" => "java" })
        .await
        .unwrap();
    assert!(out.contains("Java uses garbage collection."));

    let strict = RetrievalQaChain::with_retriever(Echo, bm25).min_score(1e6);
    let out = strict
        .invoke(prompt_args! { "input" => "java" })
        .await
        .unwrap();
    assert!(out.contains("No relevant context"));
}

fn arb_lists() -> impl Strategy<Value = Vec<Vec<ScoredDocument>>> {
    prop::collection::vec(
        prop::collection::vec((0u8..12, -10.0f32..10.0), 0..10),
        0..4,
    )
    .prop_map(|lists| {
        lists
            .into_iter()
            .map(|l| {
                l.into_iter()
                    .map(|(id, s)| ScoredDocument::new(Document::new(format!("doc{id}")), s))
                    .collect()
            })
            .collect()
    })
}

proptest! {
    #![proptest_config(ProptestConfig {
        rng_seed: RngSeed::Fixed(0x0b25_f00d),
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn fusion_output_is_unique_sorted_and_complete(lists in arb_lists()) {
        let distinct: HashSet<String> = lists
            .iter()
            .flatten()
            .map(|d| d.document.content.clone())
            .collect();
        for fused in [
            reciprocal_rank_fusion(&lists, &[], 60.0).unwrap(),
            weighted_score_fusion(&lists, &[], Normalization::MinMax).unwrap(),
        ] {
            let names: HashSet<String> =
                fused.iter().map(|d| d.document.content.clone()).collect();
            prop_assert_eq!(names.len(), fused.len());
            prop_assert_eq!(&names, &distinct);
            prop_assert!(fused.windows(2).all(|w| w[0].score >= w[1].score));
            prop_assert!(fused.iter().all(|d| d.score.is_finite()));
        }
    }

    #[test]
    fn bm25_never_exceeds_k_and_is_sorted(
        texts in prop::collection::vec("[a-d ]{0,12}", 0..8),
        query in "[a-d ]{0,6}",
        k in 0usize..6,
    ) {
        let mut index = rune_chain_retrieval::Bm25Index::new();
        index.extend(texts.iter().map(Document::new));
        let hits = index.search(&query, k);
        prop_assert!(hits.len() <= k);
        prop_assert!(hits.windows(2).all(|w| w[0].score >= w[1].score));
        prop_assert!(hits.iter().all(|h| h.score.is_finite() && h.score > 0.0));
    }
}
