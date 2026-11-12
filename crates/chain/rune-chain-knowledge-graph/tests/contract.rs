//! `KnowledgeGraph` as a `Chain`: the shared contract, plus graph state
//! across calls.

#![allow(clippy::unwrap_used, reason = "test assertions")]

use async_trait::async_trait;
use rune_chain_core::testing::{check_chain, check_chain_rejects};
use rune_chain_core::{Chain, ChainError, GenerateResult, Llm, LlmError, Message, prompt_args};
use rune_chain_knowledge_graph::KnowledgeGraph;

struct Extractor(&'static str);

#[async_trait]
impl Llm for Extractor {
    async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
        Ok(GenerateResult::from_text(self.0))
    }
}

const TRIPLES: &str = r#"[{"subject":"Paris","relation":"is_capital_of","object":"France"},
{"subject":"France","relation":"is_in","object":"Europe"}]"#;

struct Down;

#[async_trait]
impl Llm for Down {
    async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
        Err(LlmError::request_failed("down"))
    }
}

#[tokio::test]
async fn meets_the_chain_contract() {
    let kg = KnowledgeGraph::new(Extractor(TRIPLES));
    check_chain(
        &kg,
        &prompt_args! { "input" => "Paris is the capital of France." },
    )
    .await
    .unwrap();
    // Repeated extraction of the same facts does not duplicate entities.
    assert_eq!(kg.entity_count().await, 3);
    assert_eq!(
        kg.path_between("Paris", "Europe").await.unwrap(),
        ["Paris", "France", "Europe"]
    );
}

#[tokio::test]
async fn output_lists_one_triple_per_line() {
    let kg = KnowledgeGraph::new(Extractor(TRIPLES));
    let out = kg.invoke(prompt_args! { "input" => "x" }).await.unwrap();
    assert_eq!(out.lines().count(), 2);
    assert!(out.starts_with("Paris --[is_capital_of]--> France"));
}

#[tokio::test]
async fn empty_extraction_yields_a_placeholder() {
    let kg = KnowledgeGraph::new(Extractor(r#"{"entities": [], "relations": []}"#));
    let out = kg.invoke(prompt_args! { "input" => "x" }).await.unwrap();
    assert_eq!(out, "No relationships extracted.");
    assert_eq!(kg.fact_count().await, 0);
}

#[tokio::test]
async fn unparseable_extraction_is_a_parse_error() {
    let kg = KnowledgeGraph::new(Extractor("I could not find any relationships."));
    let err = kg
        .invoke(prompt_args! { "input" => "x" })
        .await
        .unwrap_err();
    assert!(matches!(err, ChainError::ParseError(_)), "{err}");
}

#[tokio::test]
async fn rejects_missing_input_and_llm_failure() {
    let kg = KnowledgeGraph::new(Extractor(TRIPLES));
    check_chain_rejects(&kg, &prompt_args! { "text" => "x" })
        .await
        .unwrap();

    check_chain_rejects(&KnowledgeGraph::new(Down), &prompt_args! { "input" => "x" })
        .await
        .unwrap();

    check_chain_rejects(&kg, &prompt_args! { "input" => "x", "document_id" => 3 })
        .await
        .unwrap();
}
