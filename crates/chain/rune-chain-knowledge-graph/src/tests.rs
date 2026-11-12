use async_trait::async_trait;
use rune_chain_core::{Chain, GenerateResult, LlmError, Message, prompt_args};

use crate::{KnowledgeGraph, Triple};

/// Fake LLM that always returns the same JSON payload.
struct StaticLlm(String);

#[async_trait]
impl rune_chain_core::Llm for StaticLlm {
    async fn generate(&self, _messages: &[Message]) -> Result<GenerateResult, LlmError> {
        Ok(GenerateResult::from_text(self.0.clone()))
    }
}

fn social_kg() -> KnowledgeGraph<StaticLlm> {
    // Alice knows Bob; Bob works_at Acme; Alice founded Acme; Acme located_in Paris
    KnowledgeGraph::new(StaticLlm(
        r#"[
          {"subject":"Alice","relation":"knows","object":"Bob"},
          {"subject":"Bob","relation":"works_at","object":"Acme"},
          {"subject":"Alice","relation":"founded","object":"Acme"},
          {"subject":"Acme","relation":"located_in","object":"Paris"}
        ]"#
        .to_string(),
    ))
}

async fn loaded_kg() -> KnowledgeGraph<StaticLlm> {
    let kg = social_kg();
    kg.extract("seed").await.unwrap();
    kg
}

// ── Extraction ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn extract_returns_correct_triples() {
    let triples = social_kg().extract("any text").await.unwrap();
    assert_eq!(triples.len(), 4);
    assert!(
        triples
            .iter()
            .any(|t| t.subject() == "Alice" && t.relation() == "knows")
    );
}

#[tokio::test]
async fn extract_deduplicates_entities() {
    let kg = loaded_kg().await;
    // Alice, Bob, Acme, Paris = 4 distinct entities
    assert_eq!(kg.entity_count().await, 4);
}

#[tokio::test]
async fn extract_accumulates_across_calls() {
    let kg = social_kg();
    kg.extract("first").await.unwrap();
    kg.extract("second").await.unwrap();
    // Same entities reused, so entity count stays 4, but triple count doubles
    assert_eq!(kg.entity_count().await, 4);
    assert_eq!(kg.triple_count().await, 8);
}

#[tokio::test]
async fn extract_empty_response_adds_nothing() {
    let kg = KnowledgeGraph::new(StaticLlm("[]".to_string()));
    kg.extract("text").await.unwrap();
    assert_eq!(kg.entity_count().await, 0);
    assert_eq!(kg.triple_count().await, 0);
}

#[tokio::test]
async fn extract_batch_processes_all_chunks() {
    let kg = social_kg();
    kg.extract_batch(&["chunk one", "chunk two"]).await.unwrap();
    // Each call returns 4 triples; 8 total stored
    assert_eq!(kg.triple_count().await, 8);
}

// ── Query: entity ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn entity_returns_some_for_known_name() {
    let kg = loaded_kg().await;
    assert!(kg.entity("Alice").await.is_some());
    assert!(kg.entity("Bob").await.is_some());
}

#[tokio::test]
async fn entity_returns_none_for_unknown_name() {
    let kg = loaded_kg().await;
    assert!(kg.entity("Unknown").await.is_none());
}

// ── Query: relations_of ───────────────────────────────────────────────────────

#[tokio::test]
async fn relations_of_alice_has_knows_and_founded() {
    let kg = loaded_kg().await;
    let rels = kg.relations_of("Alice").await;
    assert_eq!(rels.len(), 2);
    let labels: Vec<&str> = rels.iter().map(super::triple::Triple::relation).collect();
    assert!(labels.contains(&"knows"));
    assert!(labels.contains(&"founded"));
}

#[tokio::test]
async fn relations_of_unknown_entity_returns_empty() {
    let kg = loaded_kg().await;
    assert_eq!(kg.relations_of("Nobody").await, [] as [Triple; 0]);
}

#[tokio::test]
async fn relations_of_leaf_entity_returns_empty() {
    let kg = loaded_kg().await;
    // Paris has no outgoing edges
    assert_eq!(kg.relations_of("Paris").await, [] as [Triple; 0]);
}

// ── Query: path_between ───────────────────────────────────────────────────────

#[tokio::test]
async fn path_between_direct_edge() {
    let kg = loaded_kg().await;
    let path = kg.path_between("Alice", "Bob").await.unwrap();
    assert_eq!(path, vec!["Alice", "Bob"]);
}

#[tokio::test]
async fn path_between_two_hops() {
    let kg = loaded_kg().await;
    // Alice → Acme → Paris
    let path = kg.path_between("Alice", "Paris").await.unwrap();
    assert_eq!(path.first().unwrap(), "Alice");
    assert_eq!(path.last().unwrap(), "Paris");
    assert!(path.len() <= 3);
}

#[tokio::test]
async fn path_between_no_route_returns_none() {
    let kg = loaded_kg().await;
    // Paris has no outgoing edges, so Paris → Alice is impossible
    assert!(kg.path_between("Paris", "Alice").await.is_none());
}

#[tokio::test]
async fn path_between_self_returns_single_element() {
    let kg = loaded_kg().await;
    let path = kg.path_between("Alice", "Alice").await.unwrap();
    assert_eq!(path, vec!["Alice"]);
}

#[tokio::test]
async fn path_between_unknown_entity_returns_none() {
    let kg = loaded_kg().await;
    assert!(kg.path_between("Alice", "Ghost").await.is_none());
}

// ── Query: subgraph_around ────────────────────────────────────────────────────

#[tokio::test]
async fn subgraph_around_depth_0_returns_only_self() {
    let kg = loaded_kg().await;
    let ctx = kg.subgraph_around("Alice", 0).await;
    assert_eq!(ctx.len(), 1);
    assert!(ctx.contains(&"Alice".to_string()));
}

#[tokio::test]
async fn subgraph_around_depth_1_includes_direct_neighbors() {
    let kg = loaded_kg().await;
    let ctx = kg.subgraph_around("Alice", 1).await;
    assert!(ctx.contains(&"Alice".to_string()));
    assert!(ctx.contains(&"Bob".to_string()));
    assert!(ctx.contains(&"Acme".to_string()));
}

#[tokio::test]
async fn subgraph_around_depth_2_reaches_paris() {
    let kg = loaded_kg().await;
    let ctx = kg.subgraph_around("Alice", 2).await;
    assert!(ctx.contains(&"Paris".to_string()));
}

// ── Query: triples ────────────────────────────────────────────────────────────

#[tokio::test]
async fn triples_returns_all_stored() {
    let kg = loaded_kg().await;
    let all = kg.triples().await;
    assert_eq!(all.len(), 4);
}

// ── Chain impl ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn chain_invoke_extracts_and_returns_formatted_output() {
    let kg = social_kg();
    let result = kg
        .invoke(prompt_args! { "input" => "Alice knows Bob." })
        .await
        .unwrap();
    assert!(result.contains("Alice"));
    assert!(result.contains("-->"));
}

#[tokio::test]
async fn chain_invoke_missing_key_returns_error() {
    let kg = social_kg();
    let err = kg.invoke(prompt_args! { "wrong" => "x" }).await;
    assert!(err.is_err());
}

#[tokio::test]
async fn chain_invoke_empty_triples_returns_no_relationships_message() {
    let kg = KnowledgeGraph::new(StaticLlm("[]".to_string()));
    let result = kg
        .invoke(prompt_args! { "input" => "nothing here" })
        .await
        .unwrap();
    assert!(result.contains("No relationships"));
}

// ── GraphView + algo integration ──────────────────────────────────────────────

#[tokio::test]
async fn graph_view_exposes_node_count() {
    let kg = loaded_kg().await;
    let view = kg.graph().await;
    assert_eq!(view.node_count(), 4);
}

#[allow(
    clippy::significant_drop_tightening,
    reason = "test mocks hold the guard for the whole call"
)]
#[tokio::test]
async fn graph_view_algo_page_rank() {
    let kg = loaded_kg().await;
    let view = kg.graph().await;
    let scores = rune_graph::algo::page_rank(&view, 0.85, 50);
    assert_eq!(scores.len(), 4);
    let total: f64 = scores.values().sum();
    assert!((total - 1.0).abs() < 1e-9);
}

#[allow(
    clippy::significant_drop_tightening,
    reason = "test mocks hold the guard for the whole call"
)]
#[tokio::test]
async fn graph_view_algo_weakly_connected() {
    let kg = loaded_kg().await;
    let view = kg.graph().await;
    let comps = rune_graph::algo::weakly_connected_components(&view);
    // All 4 entities are connected
    assert_eq!(comps.len(), 1);
    assert_eq!(comps[0].len(), 4);
}

// ── Triple display and validity ───────────────────────────────────────────────

#[test]
fn triple_display_format() {
    let t = Triple::new("A", "rel", "B");
    assert_eq!(t.to_string(), "A --[rel]--> B");
}

#[test]
fn triple_empty_field_is_invalid() {
    assert!(!Triple::new("", "r", "B").is_valid());
    assert!(!Triple::new("A", "", "B").is_valid());
    assert!(!Triple::new("A", "r", "").is_valid());
    assert!(Triple::new("A", "r", "B").is_valid());
}

#[test]
fn triple_trims_whitespace() {
    let t = Triple::new("  Alice  ", " knows ", "  Bob  ");
    assert_eq!(t.subject(), "Alice");
    assert_eq!(t.relation(), "knows");
    assert_eq!(t.object(), "Bob");
}
