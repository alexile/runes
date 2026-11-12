use std::collections::HashMap;
use std::ops::Deref;
use std::sync::Arc;

use tokio::sync::{RwLock, RwLockReadGuard};

use rune_chain_core::Llm;
use rune_graph::{Graph, GraphError, NodeId, props};

use crate::error::KgError;
use crate::extractor;
use crate::triple::Triple;

/// A read guard over the underlying [`Graph`], returned by
/// [`KnowledgeGraph::graph`].
///
/// Derefs to `&Graph`, giving access to the full `rune-graph` API including
/// all `rune_graph::algo` functions.
///
/// # Example
///
/// ```rust,no_run
/// # use rune_chain_knowledge_graph::KnowledgeGraph;
/// # use rune_chain_core::{Llm, Message, GenerateResult, LlmError};
/// # use async_trait::async_trait;
/// # struct FakeLlm;
/// # #[async_trait] impl Llm for FakeLlm {
/// #   async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
/// #     Ok(GenerateResult::from_text("[]"))
/// #   }
/// # }
/// # tokio_test::block_on(async {
/// use rune_graph::algo;
/// let kg = KnowledgeGraph::new(FakeLlm);
/// let view = kg.graph().await;
/// let _scores = algo::page_rank(&view, 0.85, 50);
/// # });
/// ```
pub struct GraphView<'a>(RwLockReadGuard<'a, KgInner>);

impl Deref for GraphView<'_> {
    type Target = Graph;
    fn deref(&self) -> &Graph {
        &self.0.graph
    }
}

/// Internal state protected by an async read-write lock so that `&self`
/// methods on [`KnowledgeGraph`] can still mutate it (required by the
/// [`Chain`](rune_chain_core::Chain) trait which takes `&self`).
pub struct KgInner {
    pub(crate) graph: Graph,
    /// Entity name → `NodeId` in the graph.
    pub(crate) entities: HashMap<String, NodeId>,
    pub(crate) triple_count: usize,
}

impl KgInner {
    fn new() -> Self {
        Self {
            graph: Graph::new(),
            entities: HashMap::new(),
            triple_count: 0,
        }
    }

    /// Return the `NodeId` for `name`, creating the node if it does not exist.
    fn get_or_insert_entity(&mut self, name: &str) -> NodeId {
        if let Some(&id) = self.entities.get(name) {
            return id;
        }
        let id = self.graph.add_node(&["Entity"], props! { "name" => name });
        self.entities.insert(name.to_string(), id);
        id
    }

    /// Add a triple into the graph, deduplicating entities.
    pub(crate) fn insert_triple(&mut self, triple: &Triple) -> Result<(), GraphError> {
        let subject_id = self.get_or_insert_entity(triple.subject());
        let object_id = self.get_or_insert_entity(triple.object());
        self.graph
            .add_edge(subject_id, object_id, triple.relation(), props! {})?;
        self.triple_count += 1;
        Ok(())
    }
}

/// An LLM-powered knowledge graph that extracts entity-relation-entity triples
/// from text and stores them in a [`rune_graph::Graph`] property graph.
///
/// # How it works
///
/// 1. Call [`extract`](Self::extract) with a passage of text.
/// 2. The LLM is prompted to identify all `(subject, relation, object)` triples.
/// 3. Triples are added to an internal [`Graph`]: entities become nodes, relations
///    become labelled directed edges.
/// 4. Query the graph with [`relations_of`](Self::relations_of),
///    [`path_between`](Self::path_between), or
///    [`subgraph_around`](Self::subgraph_around) — or access the raw [`Graph`] for full `rune-graph` API.
///
/// The struct implements [`Chain`](rune_chain_core::Chain): pass `"input"` text
/// through `invoke` to extract triples and receive them formatted as a string.
///
/// # Example
///
/// ```rust,no_run
/// use rune_chain_knowledge_graph::KnowledgeGraph;
/// # use rune_chain_core::{Llm, Message, GenerateResult, LlmError};
/// # use async_trait::async_trait;
/// # struct FakeLlm;
/// # #[async_trait] impl Llm for FakeLlm {
/// #   async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
/// #     Ok(GenerateResult::from_text(r#"[{"subject":"Alice","relation":"knows","object":"Bob"}]"#))
/// #   }
/// # }
/// # tokio_test::block_on(async {
/// let mut kg = KnowledgeGraph::new(FakeLlm);
/// kg.extract("Alice knows Bob. Bob works at Acme.").await.unwrap();
/// assert_eq!(kg.entity_count().await, 3);
/// # });
/// ```
pub struct KnowledgeGraph<L: Llm> {
    pub(crate) llm: L,
    pub(crate) inner: Arc<RwLock<KgInner>>,
}

impl<L: Llm> KnowledgeGraph<L> {
    /// Create an empty knowledge graph backed by `llm` for extraction.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use rune_chain_knowledge_graph::KnowledgeGraph;
    /// # use rune_chain_core::{Llm, Message, GenerateResult, LlmError};
    /// # use async_trait::async_trait;
    /// # struct FakeLlm;
    /// # #[async_trait] impl Llm for FakeLlm {
    /// #   async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
    /// #     Ok(GenerateResult::from_text("[]"))
    /// #   }
    /// # }
    /// let kg = KnowledgeGraph::new(FakeLlm);
    /// ```
    pub fn new(llm: L) -> Self {
        Self {
            llm,
            inner: Arc::new(RwLock::new(KgInner::new())),
        }
    }

    /// Extract triples from `text` and add them to the graph.
    ///
    /// Calls the LLM once per invocation. Large documents should be
    /// pre-chunked with [`rune_chain_splitter`](https://docs.rs/rune-chain-splitter)
    /// and passed chunk-by-chunk.
    ///
    /// Returns the triples extracted in this call.
    ///
    /// # Errors
    ///
    /// Returns [`KgError::Llm`] if the LLM call fails, [`KgError::Parse`]
    /// if the response cannot be interpreted (the graph is not modified in that
    /// case), or [`KgError::Graph`] if a triple cannot be stored.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use rune_chain_knowledge_graph::KnowledgeGraph;
    /// # use rune_chain_core::{Llm, Message, GenerateResult, LlmError};
    /// # use async_trait::async_trait;
    /// # struct FakeLlm;
    /// # #[async_trait] impl Llm for FakeLlm {
    /// #   async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
    /// #     Ok(GenerateResult::from_text(r#"[{"subject":"Paris","relation":"is_capital_of","object":"France"}]"#))
    /// #   }
    /// # }
    /// # tokio_test::block_on(async {
    /// let mut kg = KnowledgeGraph::new(FakeLlm);
    /// let triples = kg.extract("Paris is the capital of France.").await.unwrap();
    /// assert_eq!(triples[0].subject(), "Paris");
    /// # });
    /// ```
    pub async fn extract(&self, text: &str) -> Result<Vec<Triple>, KgError> {
        let messages = extractor::build_messages(text);
        let response = self.llm.generate(&messages).await?;
        let raw = response.generation.trim().to_string();
        let triples = extractor::parse_triples(&raw);
        let mut inner = self.inner.write().await;
        for triple in &triples {
            inner.insert_triple(triple)?;
        }
        drop(inner);
        Ok(triples)
    }

    /// Extract from multiple text chunks in order, accumulating into one graph.
    ///
    /// Useful for processing the output of a text splitter. LLM calls are
    /// made sequentially.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use rune_chain_knowledge_graph::KnowledgeGraph;
    /// # use rune_chain_core::{Llm, Message, GenerateResult, LlmError};
    /// # use async_trait::async_trait;
    /// # struct FakeLlm;
    /// # #[async_trait] impl Llm for FakeLlm {
    /// #   async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
    /// #     Ok(GenerateResult::from_text("[]"))
    /// #   }
    /// # }
    /// # tokio_test::block_on(async {
    /// let kg = KnowledgeGraph::new(FakeLlm);
    /// let chunks = vec!["Alice knows Bob.", "Bob works at Acme."];
    /// let all = kg.extract_batch(&chunks).await.unwrap();
    /// # });
    /// ```
    pub async fn extract_batch(&self, chunks: &[&str]) -> Result<Vec<Triple>, KgError> {
        let mut all = Vec::new();
        for chunk in chunks {
            all.extend(self.extract(chunk).await?);
        }
        Ok(all)
    }

    // ── Query methods ─────────────────────────────────────────────────────────

    /// Return the [`NodeId`] of the named entity, if it has been extracted.
    pub async fn entity(&self, name: &str) -> Option<NodeId> {
        self.inner.read().await.entities.get(name).copied()
    }

    /// Return all triples where `name` is the subject.
    ///
    /// Returns an empty `Vec` if the entity is unknown.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use rune_chain_knowledge_graph::KnowledgeGraph;
    /// # use rune_chain_core::{Llm, Message, GenerateResult, LlmError};
    /// # use async_trait::async_trait;
    /// # struct FakeLlm;
    /// # #[async_trait] impl Llm for FakeLlm {
    /// #   async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
    /// #     Ok(GenerateResult::from_text(r#"[{"subject":"Alice","relation":"knows","object":"Bob"}]"#))
    /// #   }
    /// # }
    /// # tokio_test::block_on(async {
    /// let kg = KnowledgeGraph::new(FakeLlm);
    /// kg.extract("Alice knows Bob.").await.unwrap();
    /// let rels = kg.relations_of("Alice").await;
    /// assert_eq!(rels[0].relation(), "knows");
    /// # });
    /// ```
    pub async fn relations_of(&self, name: &str) -> Vec<Triple> {
        let inner = self.inner.read().await;
        let Some(&node_id) = inner.entities.get(name) else {
            return Vec::new();
        };
        inner
            .graph
            .outgoing_edges(node_id)
            .filter_map(|eid| {
                let edge = inner.graph.edge(eid)?;
                let object_name = inner.graph.node(edge.target())?.get("name")?.to_string();
                Some(Triple::new(name, edge.label(), object_name))
            })
            .collect()
    }

    /// Find the shortest path between two named entities and return the sequence
    /// of entity names. Returns `None` if no path exists or either entity is
    /// unknown.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use rune_chain_knowledge_graph::KnowledgeGraph;
    /// # use rune_chain_core::{Llm, Message, GenerateResult, LlmError};
    /// # use async_trait::async_trait;
    /// # struct FakeLlm;
    /// # #[async_trait] impl Llm for FakeLlm {
    /// #   async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
    /// #     Ok(GenerateResult::from_text(r#"[{"subject":"Alice","relation":"knows","object":"Bob"},{"subject":"Bob","relation":"works_at","object":"Acme"}]"#))
    /// #   }
    /// # }
    /// # tokio_test::block_on(async {
    /// let kg = KnowledgeGraph::new(FakeLlm);
    /// kg.extract("Alice knows Bob. Bob works at Acme.").await.unwrap();
    /// let path = kg.path_between("Alice", "Acme").await.unwrap();
    /// assert_eq!(path, vec!["Alice", "Bob", "Acme"]);
    /// # });
    /// ```
    #[allow(
        clippy::significant_drop_tightening,
        reason = "the guard must outlive the values borrowed from it"
    )]
    pub async fn path_between(&self, from: &str, to: &str) -> Option<Vec<String>> {
        let inner = self.inner.read().await;
        let &from_id = inner.entities.get(from)?;
        let &to_id = inner.entities.get(to)?;
        let node_path = inner.graph.shortest_path(from_id, to_id)?;
        node_path
            .iter()
            .map(|&nid| {
                inner
                    .graph
                    .node(nid)?
                    .get("name")
                    .map(std::string::ToString::to_string)
            })
            .collect()
    }

    /// Return all entity names reachable from `name` within `depth` hops,
    /// including `name` itself. Useful for building prompt context around an
    /// entity.
    ///
    /// Returns an empty `Vec` if the entity is unknown.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use rune_chain_knowledge_graph::KnowledgeGraph;
    /// # use rune_chain_core::{Llm, Message, GenerateResult, LlmError};
    /// # use async_trait::async_trait;
    /// # struct FakeLlm;
    /// # #[async_trait] impl Llm for FakeLlm {
    /// #   async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
    /// #     Ok(GenerateResult::from_text(r#"[{"subject":"Alice","relation":"knows","object":"Bob"}]"#))
    /// #   }
    /// # }
    /// # tokio_test::block_on(async {
    /// let kg = KnowledgeGraph::new(FakeLlm);
    /// kg.extract("Alice knows Bob.").await.unwrap();
    /// let ctx = kg.subgraph_around("Alice", 1).await;
    /// assert!(ctx.contains(&"Bob".to_string()));
    /// # });
    /// ```
    pub async fn subgraph_around(&self, name: &str, depth: usize) -> Vec<String> {
        let inner = self.inner.read().await;
        let Some(&start) = inner.entities.get(name) else {
            return Vec::new();
        };

        // BFS capped at `depth` hops.
        let mut visited = std::collections::HashSet::new();
        let mut queue = std::collections::VecDeque::new();
        visited.insert(start);
        queue.push_back((start, 0usize));

        while let Some((node, hop)) = queue.pop_front() {
            if hop >= depth {
                continue;
            }
            for neighbor in inner.graph.neighbors(node) {
                if visited.insert(neighbor) {
                    queue.push_back((neighbor, hop + 1));
                }
            }
        }

        visited
            .iter()
            .filter_map(|&nid| {
                inner
                    .graph
                    .node(nid)?
                    .get("name")
                    .map(std::string::ToString::to_string)
            })
            .collect()
    }

    /// All triples currently stored in the graph.
    pub async fn triples(&self) -> Vec<Triple> {
        let inner = self.inner.read().await;
        inner
            .graph
            .edges()
            .filter_map(|(eid, edge)| {
                let label = edge.label().to_string();
                let subject = inner.graph.node(edge.source())?.get("name")?.to_string();
                let object = inner.graph.node(edge.target())?.get("name")?.to_string();
                let _ = eid;
                Some(Triple::new(subject, label, object))
            })
            .collect()
    }

    /// Number of unique entities in the graph.
    pub async fn entity_count(&self) -> usize {
        self.inner.read().await.entities.len()
    }

    /// Total number of triples extracted across all calls.
    pub async fn triple_count(&self) -> usize {
        self.inner.read().await.triple_count
    }

    /// Direct access to the underlying property graph for advanced queries,
    /// persistence, or algorithm calls from `rune_graph::algo`.
    ///
    /// Returns a [`GraphView`] that derefs to `&Graph` and holds the read lock
    /// for its lifetime.
    pub async fn graph(&self) -> GraphView<'_> {
        GraphView(self.inner.read().await)
    }
}
