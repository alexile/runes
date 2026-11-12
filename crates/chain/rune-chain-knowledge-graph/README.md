# rune-chain-knowledge-graph

> GraphRAG for the `rune-chain` LLM framework: schema-validated entity and relation extraction, entity resolution, provenance, and bounded k-hop retrieval with cited context.

[![crates.io](https://img.shields.io/crates/v/rune-chain-knowledge-graph)](https://crates.io/crates/rune-chain-knowledge-graph)
[![docs.rs](https://img.shields.io/docsrs/rune-chain-knowledge-graph)](https://docs.rs/rune-chain-knowledge-graph)
[![license](https://img.shields.io/crates/l/rune-chain-knowledge-graph)](LICENSE)

## What it does

Feed it documents and any `rune-chain-core` LLM. It builds a
[`rune-graph`](https://crates.io/crates/rune-graph) property graph of entities and
facts, then answers questions with a small, cited slice of that graph.

- **Structured extraction.** Each chunk goes through `Llm::generate_structured` with a
  JSON schema (`ResponseFormat::JsonSchema`): typed entities, plus relations with a
  confidence and a verbatim evidence quote.
- **Untrusted input, validated output.** The chunk is fenced between markers it cannot
  close, and the prompt tells the model to treat it as data. Every reply is checked:
  per-chunk caps on entities and relations, name and label length limits, optional
  allow-lists of relation and entity types, and a minimum confidence. The whole graph
  is capped too, so neither a model nor a hostile document can flood it. Dropped items
  are counted per reason in the `ExtractionReport`.
- **Entity resolution.** Names match case- and punctuation-insensitively
  (`"Acme Corp."` = `"acme corp"`). With an `EntityEmbedder`, near-duplicates of a
  compatible type are merged as aliases. Repeated facts are stored once, with a
  `support` count and the highest confidence seen.
- **Provenance everywhere.** Every node and edge records its document id, chunk index
  and byte span of the evidence in the original document.
- **GraphRAG retrieval.** `retrieve` finds seed entities by keyword (and embedding)
  match, expands k hops with node, fact and fan-out limits, and renders a compact
  context with numbered citations.
- **Communities.** `communities` runs label propagation and gives each group a one-line
  structural summary. It makes no model calls.

## Installation

```toml
[dependencies]
rune-chain-knowledge-graph = "0.4"
rune-chain-core            = "0.2"
# plus any rune-chain-* LLM provider
```

Features:

- `embed`: adds `FromEmbedder`, which wraps any `rune_chain_embed::Embedder` (OpenAI,
  Cohere, Voyage, Jina, cached, batched) as an `EntityEmbedder`.

## End-to-end example

```rust
use async_trait::async_trait;
use rune_chain_core::{GenerateResult, Llm, LlmError, Message};
use rune_chain_knowledge_graph::{ExtractionConfig, KnowledgeGraph, RetrievalConfig};

// Stands in for any rune-chain provider.
struct Model;

#[async_trait]
impl Llm for Model {
    async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
        Ok(GenerateResult::from_text(r#"{
          "entities": [
            {"name": "Ada Lovelace", "type": "person"},
            {"name": "Analytical Engine", "type": "machine"},
            {"name": "Charles Babbage", "type": "person"}
          ],
          "relations": [
            {"subject": "Ada Lovelace", "relation": "wrote programs for",
             "object": "Analytical Engine", "confidence": 0.95,
             "evidence": "Ada Lovelace wrote programs for the Analytical Engine"},
            {"subject": "Charles Babbage", "relation": "designed",
             "object": "Analytical Engine", "confidence": 0.9,
             "evidence": "designed by Charles Babbage"}
          ]
        }"#))
    }
}

# tokio_test::block_on(async {
let config = ExtractionConfig::default()
    .with_allowed_relations(["wrote_programs_for", "designed", "worked_with"]);
let kg = KnowledgeGraph::new(Model).with_config(config)?;

let doc = "Ada Lovelace wrote programs for the Analytical Engine, \
           a machine designed by Charles Babbage.";
let report = kg.extract_document("history.txt", doc).await?;
assert_eq!(report.facts.len(), 2);
assert!(report.rejections.is_empty());

// Provenance: byte spans into the original document.
let fact = &kg.relations_of("ada lovelace").await[0];
let source = &fact.provenance[0];
assert_eq!(&doc[source.span.clone()], "Ada Lovelace wrote programs for the Analytical Engine");

// GraphRAG retrieval.
let ctx = kg
    .retrieve("Who designed the machine Ada Lovelace programmed?", &RetrievalConfig::default())
    .await?;
println!("{}", ctx.text);
# Ok::<(), rune_chain_knowledge_graph::KgError>(())
# }).unwrap();
```

`ctx.text` looks like this:

```text
Facts:
[1] Ada Lovelace --[wrote_programs_for]--> Analytical Engine (confidence 0.95; source history.txt@0-53)
[2] Charles Babbage --[designed]--> Analytical Engine (confidence 0.90; source history.txt@65-92)
Entities:
- Ada Lovelace (person)
- Analytical Engine (machine)
- Charles Babbage (person)
```

Put it into the answering prompt as data, fenced the same way as any retrieved text,
and ask the model to cite `[n]`. `ctx.facts[n - 1]` holds the full provenance of each
citation.

## Limits

Everything is bounded by configuration, not by the input:

| What | Setting (default) |
|---|---|
| Model calls per document | `max_chunks_per_document` (1024) |
| Chunk size / overlap | `chunk_bytes` (4000) / `chunk_overlap` (200); hard cap `max_chunk_bytes` (32 KiB) |
| Items per reply | `max_entities_per_chunk` (64), `max_relations_per_chunk` (128) |
| Name / label / evidence length | `max_name_chars` (100), `max_label_chars` (48), `max_evidence_chars` (300) |
| Whole graph | `max_entities` (100 000), `max_facts` (500 000) |
| Provenance and aliases per item | `max_provenance` (8), `max_aliases` (8) |
| Retrieval | `hops` (2, at most 6), `max_nodes` (40), `max_facts` (80), `max_neighbors_per_node` (25), `max_context_chars` (6000) |

## API at a glance

| Item | Purpose |
|---|---|
| `KnowledgeGraph::new(llm)` / `with_config` / `with_embedder` | Build |
| `extract(text)`, `extract_document(id, text)`, `extract_chunks(id, &[(offset, chunk)])` | Extract, returning an `ExtractionReport` |
| `entity(name)`, `entities()`, `relations_of(name)`, `facts()`, `triples()` | Inspect |
| `path_between(a, b)`, `subgraph_around(name, depth, max_nodes)` | Traverse |
| `retrieve(query, &RetrievalConfig)` | GraphRAG context (`GraphContext`) |
| `communities(max_iterations, max_communities)` | Label-propagation groups with summaries |
| `graph()` | Read guard over the `rune_graph::Graph`, for `rune_graph::algo` |
| `extraction_schema(&config)` | The JSON schema sent to the model |
| `Chain` impl | `"input"` (+ optional `"document_id"`) in, one fact per line out |

## Migrating from 0.3

- Extraction now calls `Llm::generate_structured` with a JSON schema and expects
  `{"entities": [...], "relations": [...]}`. A bare array of
  `{"subject", "relation", "object"}` objects is still accepted. Providers without a
  native JSON mode get the schema as a system instruction through the default
  `generate_structured`.
- `extract` returns an `ExtractionReport` instead of `Vec<Triple>`; the facts are in
  `report.facts`. `extract_batch(&[&str])` is replaced by `extract_document` (which
  chunks for you) and `extract_chunks` (pre-split chunks with offsets).
- A reply that is not valid JSON is now a `KgError::Parse` (`ChainError::ParseError`
  through `Chain`), not an empty result.
- Relation labels are normalised to `snake_case` (`"works at"` becomes `works_at`), and
  entity names match case- and punctuation-insensitively.
- Repeated facts are stored once (with `support` and provenance) rather than as
  parallel edges. `triple_count` is now `fact_count`.
- `relations_of` returns `Vec<Fact>` covering both directions; `entity` returns an
  `Entity` (use `entity_id` for the `NodeId`); `subgraph_around` takes a `max_nodes`
  cap and returns sorted names.
- New limits apply by default (see the table above), and `KgError` has new variants
  and is `#[non_exhaustive]`.

## License

MIT
