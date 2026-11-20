//! `RagTarget`: retrieved contexts reach the chain and the RAG metrics.
#![cfg(feature = "retrieval")]

use async_trait::async_trait;
use rune_chain_core::{Chain, ChainError, GenerateResult, PromptArgs};
use rune_chain_eval::RagTarget;
use rune_chain_eval::{
    Dataset, Evaluation, Example, Target, judge::GroundednessJudge, judge::Judge,
};
use rune_chain_retrieval::{Document, RetrievalError, Retriever, ScoredDocument};

struct Fixed;

#[async_trait]
impl Retriever for Fixed {
    async fn retrieve(
        &self,
        _q: &str,
        top_k: usize,
    ) -> Result<Vec<ScoredDocument>, RetrievalError> {
        Ok([
            "Paris is the capital of France.",
            "Bananas are yellow.",
            "Rome is in Italy.",
        ]
        .into_iter()
        .take(top_k)
        .map(|t| ScoredDocument::new(Document::new(t), 1.0))
        .collect())
    }
}

/// Echoes the context it was given.
struct Echo;

#[async_trait]
impl Chain for Echo {
    async fn call(&self, input: PromptArgs) -> Result<GenerateResult, ChainError> {
        Ok(GenerateResult::from_text(
            input["context"].as_str().unwrap_or_default(),
        ))
    }
}

#[tokio::test]
async fn contexts_flow_through() {
    let target = RagTarget::new(Fixed, Echo).top_k(2);
    let ex = Example::from_question("1", "Capital of France?");
    let out = target.run(&ex).await.unwrap();
    assert_eq!(out.contexts.len(), 2);
    assert!(out.output.starts_with("[1] Paris is the capital"));
    assert!(out.output.contains("[2] Bananas"));

    let judge = Judge::new(rune_chain_core::testing::FakeLlm::from_fn(|req| {
        let p = req.prompt().unwrap_or_default();
        let grounded = p.contains("Context 1:") && !p.contains("Context 2:");
        Ok(GenerateResult::from_text(format!(
            r#"{{"reasoning": "r", "grounded": {grounded}}}"#
        )))
    }));
    let run = Evaluation::new("rag")
        .evaluator(GroundednessJudge::new(judge))
        .run(&Dataset::new(vec![ex]).unwrap(), &target)
        .await
        .unwrap();
    assert_eq!(run.metric("groundedness").unwrap().pass_rate, 1.0);
}
