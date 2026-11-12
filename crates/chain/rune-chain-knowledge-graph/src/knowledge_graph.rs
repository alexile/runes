use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::ops::Deref;
use std::sync::Arc;

use tokio::sync::{RwLock, RwLockReadGuard};

use rune_chain_core::Llm;
use rune_graph::{EdgeId, Graph, NodeId, Value, props};

use crate::community::{self, Community};
use crate::config::{ExtractionConfig, MAX_HOPS, RetrievalConfig};
use crate::embedding::{self, EntityEmbedder};
use crate::error::KgError;
use crate::extractor::{self, Parsed, ParsedEntity};
use crate::normalize;
use crate::report::ExtractionReport;
use crate::retrieval::{self, GraphContext};
use crate::triple::{Entity, Fact, Provenance, Triple};

/// Document id used by [`KnowledgeGraph::extract`].
pub const DEFAULT_DOCUMENT_ID: &str = "input";

/// Longest accepted document id, in bytes.
const MAX_DOCUMENT_ID_BYTES: usize = 256;

/// A read guard over the underlying [`Graph`], returned by
/// [`KnowledgeGraph::graph`].
///
/// Derefs to `&Graph`, giving access to the full `rune-graph` API including
/// all `rune_graph::algo` functions. Entity nodes carry the label `Entity`
/// and the properties `name`, `key`, `type` (when known), `mentions`, and
/// `document` / `start` / `end` for the first mention; fact edges carry
/// `confidence`, `support` and the same three provenance properties.
/// `(Entity, key)` is indexed, so `nodes_by_property("Entity", "key", ..)`
/// finds an entity by its normalised name without a scan.
///
/// # Example
///
/// ```rust
/// # use rune_chain_knowledge_graph::KnowledgeGraph;
/// # use rune_chain_core::{Llm, Message, GenerateResult, LlmError};
/// # use async_trait::async_trait;
/// # struct FakeLlm;
/// # #[async_trait] impl Llm for FakeLlm {
/// #   async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
/// #     Ok(GenerateResult::from_text(r#"{"entities":[],"relations":[]}"#))
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

#[derive(Debug, Clone)]
pub struct NodeMeta {
    pub name: String,
    pub entity_type: Option<String>,
    pub aliases: Vec<String>,
    /// Resolution keys: the name's key first, then the aliases' keys.
    pub keys: Vec<String>,
    pub mentions: u32,
    pub provenance: Vec<Provenance>,
}

#[derive(Debug, Clone)]
pub struct EdgeMeta {
    pub source: NodeId,
    pub relation: String,
    pub target: NodeId,
    pub confidence: f32,
    pub support: u32,
    pub provenance: Vec<Provenance>,
}

/// Graph state plus the indexes kept next to it.
pub struct KgInner {
    pub graph: Graph,
    /// Entity key (names and aliases) to node.
    pub keys: HashMap<String, NodeId>,
    pub nodes: HashMap<NodeId, NodeMeta>,
    /// `(source, relation, target)` to edge.
    pub fact_index: HashMap<(NodeId, String, NodeId), EdgeId>,
    pub edges: HashMap<EdgeId, EdgeMeta>,
    /// Word to the entities whose name or alias contains it.
    pub words: HashMap<String, Vec<NodeId>>,
    /// Entity embeddings, in creation order.
    pub embeddings: Vec<(NodeId, Vec<f32>)>,
}

impl Default for KgInner {
    fn default() -> Self {
        let mut graph = Graph::new();
        // Lets callers of `graph()` find entities with `nodes_by_property`.
        graph.create_index("Entity", "key");
        Self {
            graph,
            keys: HashMap::new(),
            nodes: HashMap::new(),
            fact_index: HashMap::new(),
            edges: HashMap::new(),
            words: HashMap::new(),
            embeddings: Vec::new(),
        }
    }
}

impl KgInner {
    pub fn fact(&self, id: EdgeId) -> Option<Fact> {
        let meta = self.edges.get(&id)?;
        Some(Fact {
            triple: Triple::new(
                self.nodes.get(&meta.source)?.name.clone(),
                meta.relation.clone(),
                self.nodes.get(&meta.target)?.name.clone(),
            ),
            confidence: meta.confidence,
            support: meta.support,
            provenance: meta.provenance.clone(),
        })
    }

    pub fn entity(&self, id: NodeId) -> Option<Entity> {
        let meta = self.nodes.get(&id)?;
        Some(Entity {
            name: meta.name.clone(),
            entity_type: meta.entity_type.clone(),
            aliases: meta.aliases.clone(),
            mentions: meta.mentions,
            provenance: meta.provenance.clone(),
        })
    }

    pub fn lookup(&self, name: &str) -> Option<NodeId> {
        self.keys.get(&normalize::entity_key(name)).copied()
    }

    fn index_words(&mut self, id: NodeId, key: &str) {
        for word in key.split(' ') {
            let posting = self.words.entry(word.to_string()).or_default();
            if posting.last() != Some(&id) && !posting.contains(&id) {
                posting.push(id);
            }
        }
    }

    fn best_similar(
        &self,
        vector: &[f32],
        entity_type: Option<&str>,
        threshold: f32,
    ) -> Option<NodeId> {
        let mut best: Option<(f32, NodeId)> = None;
        for (id, v) in &self.embeddings {
            let Some(sim) = embedding::cosine(vector, v) else {
                continue;
            };
            if sim < threshold || best.is_some_and(|(b, _)| sim <= b) {
                continue;
            }
            let compatible = match (
                entity_type,
                self.nodes.get(id).and_then(|m| m.entity_type.as_deref()),
            ) {
                (Some(a), Some(b)) => a == b,
                _ => true,
            };
            if compatible {
                best = Some((sim, *id));
            }
        }
        best.map(|(_, id)| id)
    }

    fn add_alias(&mut self, id: NodeId, entity: &ParsedEntity, max_aliases: usize) {
        self.keys.insert(entity.key.clone(), id);
        let Some(meta) = self.nodes.get_mut(&id) else {
            return;
        };
        if meta.aliases.len() < max_aliases && !meta.aliases.contains(&entity.name) {
            meta.aliases.push(entity.name.clone());
        }
        if !meta.keys.contains(&entity.key) {
            meta.keys.push(entity.key.clone());
        }
        self.index_words(id, &entity.key);
    }

    fn new_entity(&mut self, entity: &ParsedEntity, first: &Provenance) -> NodeId {
        let mut properties = props! {
            "name" => entity.name.as_str(),
            "key" => entity.key.as_str(),
            "mentions" => 0_i64,
        };
        if let Some(t) = &entity.entity_type {
            properties.insert("type".into(), Value::from(t.as_str()));
        }
        properties.extend(provenance_props(first));
        let id = self.graph.add_node(&["Entity"], properties);
        self.keys.insert(entity.key.clone(), id);
        self.nodes.insert(
            id,
            NodeMeta {
                name: entity.name.clone(),
                entity_type: entity.entity_type.clone(),
                aliases: Vec::new(),
                keys: vec![entity.key.clone()],
                mentions: 0,
                provenance: Vec::new(),
            },
        );
        self.index_words(id, &entity.key);
        id
    }

    fn record_mention(
        &mut self,
        id: NodeId,
        entity_type: Option<&String>,
        provenance: Provenance,
        max_provenance: usize,
    ) -> Result<(), KgError> {
        let Some(meta) = self.nodes.get_mut(&id) else {
            return Ok(());
        };
        meta.mentions = meta.mentions.saturating_add(1);
        if meta.provenance.len() < max_provenance {
            meta.provenance.push(provenance);
        }
        let mentions = i64::from(meta.mentions);
        let fill_type = meta.entity_type.is_none() && entity_type.is_some();
        if fill_type {
            meta.entity_type = entity_type.cloned();
        }
        self.graph
            .set_node_property(id, "mentions", Value::Int(mentions))?;
        if fill_type && let Some(t) = entity_type {
            self.graph
                .set_node_property(id, "type", Value::from(t.as_str()))?;
        }
        Ok(())
    }
}

fn provenance_props(p: &Provenance) -> HashMap<String, Value> {
    props! {
        "document" => p.document_id.as_str(),
        "start" => i64::try_from(p.span.start).unwrap_or(i64::MAX),
        "end" => i64::try_from(p.span.end).unwrap_or(i64::MAX),
    }
}

/// One chunk to extract from: where it sits in which document.
struct ChunkRef<'a> {
    document_id: &'a str,
    index: usize,
    offset: usize,
    text: &'a str,
}

/// An LLM-built knowledge graph with provenance, entity resolution and
/// GraphRAG-style retrieval.
///
/// # How it works
///
/// 1. [`extract_document`](Self::extract_document) splits a document into
///    overlapping chunks and asks the model, through
///    [`Llm::generate_structured`] with a JSON schema, for typed entities and
///    relations with a confidence and a verbatim evidence quote. The chunk is
///    fenced as untrusted data in the prompt.
/// 2. The reply is validated against [`ExtractionConfig`]: per-chunk caps,
///    name and label lengths, optional allow-lists, minimum confidence.
/// 3. Entities are resolved by normalised name (`"Acme Corp."` and
///    `"acme corp"` are one node) and, with an [`EntityEmbedder`], by
///    embedding similarity. Facts are deduplicated; repeated sightings raise
///    `support` and keep the highest confidence.
/// 4. Every node and edge records where it came from ([`Provenance`]).
/// 5. [`retrieve`](Self::retrieve) finds seed entities for a question,
///    expands a bounded neighbourhood and renders a compact, cited context
///    string for the answering prompt.
///
/// The struct implements [`Chain`](rune_chain_core::Chain): pass `"input"`
/// text (and optionally `"document_id"`) through `invoke` to extract facts
/// and receive them formatted one per line.
///
/// # Example
///
/// ```rust
/// use rune_chain_knowledge_graph::{KnowledgeGraph, RetrievalConfig};
/// # use rune_chain_core::{Llm, Message, GenerateResult, LlmError};
/// # use async_trait::async_trait;
/// # struct FakeLlm;
/// # #[async_trait] impl Llm for FakeLlm {
/// #   async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
/// #     Ok(GenerateResult::from_text(r#"{"entities":[{"name":"Alice","type":"person"}],
/// #       "relations":[{"subject":"Alice","relation":"knows","object":"Bob",
/// #       "confidence":0.9,"evidence":"Alice knows Bob"}]}"#))
/// #   }
/// # }
/// # tokio_test::block_on(async {
/// let kg = KnowledgeGraph::new(FakeLlm);
/// let report = kg.extract_document("notes.txt", "Alice knows Bob.").await.unwrap();
/// assert_eq!(report.facts.len(), 1);
/// assert_eq!(report.facts[0].provenance[0].span, 0..15);
///
/// let ctx = kg.retrieve("Who does Alice know?", &RetrievalConfig::default()).await.unwrap();
/// assert!(ctx.text.contains("Alice --[knows]--> Bob"));
/// # });
/// ```
pub struct KnowledgeGraph<L: Llm> {
    llm: L,
    config: ExtractionConfig,
    embedder: Option<Arc<dyn EntityEmbedder>>,
    inner: RwLock<KgInner>,
}

impl<L: Llm> KnowledgeGraph<L> {
    /// Create an empty knowledge graph backed by `llm`, with the default
    /// [`ExtractionConfig`] and no embedder.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use rune_chain_knowledge_graph::KnowledgeGraph;
    /// # use rune_chain_core::{Llm, Message, GenerateResult, LlmError};
    /// # use async_trait::async_trait;
    /// # struct FakeLlm;
    /// # #[async_trait] impl Llm for FakeLlm {
    /// #   async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
    /// #     Ok(GenerateResult::from_text("{}"))
    /// #   }
    /// # }
    /// # tokio_test::block_on(async {
    /// let kg = KnowledgeGraph::new(FakeLlm);
    /// assert_eq!(kg.entity_count().await, 0);
    /// # });
    /// ```
    pub fn new(llm: L) -> Self {
        Self {
            llm,
            config: ExtractionConfig::default(),
            embedder: None,
            inner: RwLock::new(KgInner::default()),
        }
    }

    /// Replace the extraction configuration.
    ///
    /// # Errors
    ///
    /// [`KgError::InvalidInput`] if a value is out of range (a zero size,
    /// an overlap not smaller than the chunk size, a confidence or
    /// similarity outside `[0, 1]`).
    ///
    /// # Example
    ///
    /// ```rust
    /// # use rune_chain_knowledge_graph::{ExtractionConfig, KnowledgeGraph};
    /// # use rune_chain_core::{Llm, Message, GenerateResult, LlmError};
    /// # use async_trait::async_trait;
    /// # struct FakeLlm;
    /// # #[async_trait] impl Llm for FakeLlm {
    /// #   async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
    /// #     Ok(GenerateResult::from_text("{}"))
    /// #   }
    /// # }
    /// let config = ExtractionConfig::default().with_allowed_relations(["works_at", "founded"]);
    /// let kg = KnowledgeGraph::new(FakeLlm).with_config(config).unwrap();
    /// ```
    pub fn with_config(mut self, config: ExtractionConfig) -> Result<Self, KgError> {
        config.validate()?;
        self.config = config;
        Ok(self)
    }

    /// Use `embedder` to merge near-duplicate entity names (see
    /// [`ExtractionConfig::merge_similarity`]) and to find retrieval seeds by
    /// meaning.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use rune_chain_knowledge_graph::{BoxError, EntityEmbedder, KnowledgeGraph};
    /// # use rune_chain_core::{Llm, Message, GenerateResult, LlmError};
    /// # use async_trait::async_trait;
    /// # struct FakeLlm;
    /// # #[async_trait] impl Llm for FakeLlm {
    /// #   async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
    /// #     Ok(GenerateResult::from_text("{}"))
    /// #   }
    /// # }
    /// struct Flat;
    /// #[async_trait]
    /// impl EntityEmbedder for Flat {
    ///     async fn embed(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, BoxError> {
    ///         Ok(texts.iter().map(|_| vec![1.0]).collect())
    ///     }
    /// }
    /// let kg = KnowledgeGraph::new(FakeLlm).with_embedder(Flat);
    /// ```
    #[must_use]
    pub fn with_embedder(mut self, embedder: impl EntityEmbedder + 'static) -> Self {
        self.embedder = Some(Arc::new(embedder));
        self
    }

    /// The model used for extraction.
    pub const fn llm(&self) -> &L {
        &self.llm
    }

    /// The extraction configuration in use.
    pub const fn config(&self) -> &ExtractionConfig {
        &self.config
    }

    /// Extract facts from `text` as document [`DEFAULT_DOCUMENT_ID`].
    ///
    /// Shorthand for [`extract_document`](Self::extract_document).
    ///
    /// # Errors
    ///
    /// As for [`extract_document`](Self::extract_document).
    ///
    /// # Example
    ///
    /// ```rust
    /// # use rune_chain_knowledge_graph::KnowledgeGraph;
    /// # use rune_chain_core::{Llm, Message, GenerateResult, LlmError};
    /// # use async_trait::async_trait;
    /// # struct FakeLlm;
    /// # #[async_trait] impl Llm for FakeLlm {
    /// #   async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
    /// #     Ok(GenerateResult::from_text(r#"[{"subject":"Paris","relation":"capital of","object":"France"}]"#))
    /// #   }
    /// # }
    /// # tokio_test::block_on(async {
    /// let kg = KnowledgeGraph::new(FakeLlm);
    /// let report = kg.extract("Paris is the capital of France.").await.unwrap();
    /// assert_eq!(report.facts[0].triple.relation(), "capital_of");
    /// # });
    /// ```
    pub async fn extract(&self, text: &str) -> Result<ExtractionReport, KgError> {
        self.extract_document(DEFAULT_DOCUMENT_ID, text).await
    }

    /// Split `text` into chunks (see [`ExtractionConfig::chunk_bytes`]),
    /// extract from each in order, and add the results to the graph.
    ///
    /// One model call per chunk, made sequentially. Provenance spans are
    /// byte offsets into `text`. Chunks extracted before a failing one stay
    /// in the graph.
    ///
    /// # Errors
    ///
    /// - [`KgError::InvalidInput`] for an empty, over-long (256 bytes) or
    ///   control-character document id.
    /// - [`KgError::InputTooLarge`] if `text` needs more than
    ///   [`ExtractionConfig::max_chunks_per_document`] chunks; nothing is
    ///   sent to the model in that case.
    /// - [`KgError::Llm`] if a model call fails.
    /// - [`KgError::Parse`] if a reply is not JSON of the expected shape or
    ///   was cut off by the output-token limit.
    /// - [`KgError::Embed`] if the embedder fails.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use rune_chain_knowledge_graph::KnowledgeGraph;
    /// # use rune_chain_core::{Llm, Message, GenerateResult, LlmError};
    /// # use async_trait::async_trait;
    /// # struct FakeLlm;
    /// # #[async_trait] impl Llm for FakeLlm {
    /// #   async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
    /// #     Ok(GenerateResult::from_text(r#"{"entities":[],"relations":[
    /// #       {"subject":"Bob","relation":"works_at","object":"Acme","confidence":0.8,
    /// #        "evidence":"Bob works at Acme"}]}"#))
    /// #   }
    /// # }
    /// # tokio_test::block_on(async {
    /// let kg = KnowledgeGraph::new(FakeLlm);
    /// let report = kg.extract_document("hr/2024.txt", "Intro. Bob works at Acme.").await.unwrap();
    /// let source = &report.facts[0].provenance[0];
    /// assert_eq!(source.document_id, "hr/2024.txt");
    /// assert_eq!(source.span, 7..24);
    /// # });
    /// ```
    pub async fn extract_document(
        &self,
        document_id: &str,
        text: &str,
    ) -> Result<ExtractionReport, KgError> {
        check_document_id(document_id)?;
        let most = self
            .config
            .max_chunks_per_document
            .saturating_mul(self.config.chunk_bytes);
        if text.len() > most {
            return Err(KgError::InputTooLarge {
                what: "document (bytes)",
                size: text.len(),
                limit: most,
            });
        }
        let chunks = extractor::split(text, self.config.chunk_bytes, self.config.chunk_overlap);
        if chunks.len() > self.config.max_chunks_per_document {
            return Err(KgError::InputTooLarge {
                what: "document (chunks)",
                size: chunks.len(),
                limit: self.config.max_chunks_per_document,
            });
        }
        let mut report = ExtractionReport::default();
        for (index, (offset, chunk)) in chunks.into_iter().enumerate() {
            let one = self
                .extract_chunk(ChunkRef {
                    document_id,
                    index,
                    offset,
                    text: chunk,
                })
                .await?;
            report.absorb(one);
        }
        Ok(report)
    }

    /// Extract from pre-split chunks of one document.
    ///
    /// `chunks` are `(byte offset in the document, chunk text)` pairs, as
    /// produced by any splitter that tracks offsets; the offsets are only
    /// used for provenance.
    ///
    /// # Errors
    ///
    /// As for [`extract_document`](Self::extract_document), plus
    /// [`KgError::InputTooLarge`] for a chunk over
    /// [`ExtractionConfig::max_chunk_bytes`] (checked before any model call).
    ///
    /// # Example
    ///
    /// ```rust
    /// # use rune_chain_knowledge_graph::KnowledgeGraph;
    /// # use rune_chain_core::{Llm, Message, GenerateResult, LlmError};
    /// # use async_trait::async_trait;
    /// # struct FakeLlm;
    /// # #[async_trait] impl Llm for FakeLlm {
    /// #   async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
    /// #     Ok(GenerateResult::from_text("{}"))
    /// #   }
    /// # }
    /// # tokio_test::block_on(async {
    /// let kg = KnowledgeGraph::new(FakeLlm);
    /// let report = kg
    ///     .extract_chunks("book", &[(0, "Chapter one."), (5000, "Chapter two.")])
    ///     .await
    ///     .unwrap();
    /// assert_eq!(report.chunks, 2);
    /// # });
    /// ```
    pub async fn extract_chunks(
        &self,
        document_id: &str,
        chunks: &[(usize, &str)],
    ) -> Result<ExtractionReport, KgError> {
        check_document_id(document_id)?;
        if chunks.len() > self.config.max_chunks_per_document {
            return Err(KgError::InputTooLarge {
                what: "document (chunks)",
                size: chunks.len(),
                limit: self.config.max_chunks_per_document,
            });
        }
        if let Some((_, big)) = chunks
            .iter()
            .find(|(_, c)| c.len() > self.config.max_chunk_bytes)
        {
            return Err(KgError::InputTooLarge {
                what: "chunk (bytes)",
                size: big.len(),
                limit: self.config.max_chunk_bytes,
            });
        }
        let mut report = ExtractionReport::default();
        for (index, &(offset, text)) in chunks.iter().enumerate() {
            let one = self
                .extract_chunk(ChunkRef {
                    document_id,
                    index,
                    offset,
                    text,
                })
                .await?;
            report.absorb(one);
        }
        Ok(report)
    }

    async fn extract_chunk(&self, chunk: ChunkRef<'_>) -> Result<ExtractionReport, KgError> {
        let mut report = ExtractionReport {
            chunks: 1,
            ..ExtractionReport::default()
        };
        if chunk.text.trim().is_empty() {
            return Ok(report);
        }
        let messages = extractor::build_messages(chunk.text, &self.config);
        let format = extractor::response_format(&self.config);
        let result = self.llm.generate_structured(&messages, &format).await?;
        report.usage.clone_from(&result.tokens);
        let truncated = result.is_truncated();
        let parsed = format
            .parse_json(&result.generation)
            .map_err(|e| e.message().to_string())
            .and_then(|value| extractor::validate(&value, chunk.text, &self.config))
            .map_err(|e| {
                if truncated {
                    KgError::Parse(format!("reply cut off by the output-token limit: {e}"))
                } else {
                    KgError::Parse(e)
                }
            })?;

        // Embed names the graph does not know yet, outside the lock.
        let vectors = self.embed_new(&parsed.entities).await?;
        self.store(&chunk, parsed, &vectors, &mut report).await?;
        Ok(report)
    }

    async fn embed_new(
        &self,
        entities: &[ParsedEntity],
    ) -> Result<HashMap<String, Vec<f32>>, KgError> {
        let Some(embedder) = &self.embedder else {
            return Ok(HashMap::new());
        };
        let unknown: Vec<&ParsedEntity> = {
            let inner = self.inner.read().await;
            entities
                .iter()
                .filter(|e| !inner.keys.contains_key(&e.key))
                .collect()
        };
        if unknown.is_empty() {
            return Ok(HashMap::new());
        }
        let names: Vec<&str> = unknown.iter().map(|e| e.name.as_str()).collect();
        let vectors = embedder.embed(&names).await.map_err(KgError::Embed)?;
        embedding::check_vectors(&vectors, names.len())?;
        Ok(unknown
            .into_iter()
            .map(|e| e.key.clone())
            .zip(vectors)
            .collect())
    }

    async fn store(
        &self,
        chunk: &ChunkRef<'_>,
        parsed: Parsed,
        vectors: &HashMap<String, Vec<f32>>,
        report: &mut ExtractionReport,
    ) -> Result<(), KgError> {
        let Parsed {
            entities,
            relations,
            rejections,
        } = parsed;
        report.rejections = rejections;
        let whole = chunk.offset..chunk.offset + chunk.text.len();
        let mut inner = self.inner.write().await;

        let mut resolved: HashMap<&str, NodeId> = HashMap::new();
        for e in &entities {
            let (span, exact) = chunk.text.find(&e.name).map_or_else(
                || (whole.clone(), false),
                |at| (chunk.offset + at..chunk.offset + at + e.name.len(), true),
            );
            let provenance = Provenance::new(chunk.document_id, chunk.index, span, exact);
            let id = if let Some(&id) = inner.keys.get(&e.key) {
                id
            } else if let Some(id) = vectors.get(&e.key).and_then(|v| {
                inner.best_similar(v, e.entity_type.as_deref(), self.config.merge_similarity)
            }) {
                inner.add_alias(id, e, self.config.max_aliases);
                report.merged_by_similarity += 1;
                id
            } else if inner.nodes.len() >= self.config.max_entities {
                report.rejections.capacity += 1;
                continue;
            } else {
                let id = inner.new_entity(e, &provenance);
                if let Some(v) = vectors.get(&e.key) {
                    inner.embeddings.push((id, v.clone()));
                }
                report.new_entities += 1;
                id
            };
            inner.record_mention(
                id,
                e.entity_type.as_ref(),
                provenance,
                self.config.max_provenance,
            )?;
            resolved.insert(e.key.as_str(), id);
        }

        for r in relations {
            let (Some(&source), Some(&target)) = (
                resolved.get(r.subject.as_str()),
                resolved.get(r.object.as_str()),
            ) else {
                report.rejections.capacity += 1;
                continue;
            };
            if source == target {
                // Two names merged into one entity.
                report.rejections.invalid += 1;
                continue;
            }
            let provenance = Provenance::new(
                chunk.document_id,
                chunk.index,
                chunk.offset + r.span.start..chunk.offset + r.span.end,
                r.exact,
            );
            let fact_key = (source, r.relation.clone(), target);
            if let Some(&edge) = inner.fact_index.get(&fact_key) {
                let max_provenance = self.config.max_provenance;
                let (confidence, support) = {
                    let Some(meta) = inner.edges.get_mut(&edge) else {
                        continue;
                    };
                    meta.support = meta.support.saturating_add(1);
                    meta.confidence = meta.confidence.max(r.confidence);
                    if meta.provenance.len() < max_provenance
                        && !meta.provenance.contains(&provenance)
                    {
                        meta.provenance.push(provenance.clone());
                    }
                    (meta.confidence, meta.support)
                };
                inner.graph.set_edge_property(
                    edge,
                    "confidence",
                    Value::Float(f64::from(confidence)),
                )?;
                inner
                    .graph
                    .set_edge_property(edge, "support", Value::Int(i64::from(support)))?;
                report.duplicate_facts += 1;
            } else if inner.edges.len() >= self.config.max_facts {
                report.rejections.capacity += 1;
                continue;
            } else {
                let mut properties = props! {
                    "confidence" => f64::from(r.confidence),
                    "support" => 1_i64,
                };
                properties.extend(provenance_props(&provenance));
                let edge = inner
                    .graph
                    .add_edge(source, target, &r.relation, properties)?;
                inner.fact_index.insert(fact_key, edge);
                inner.edges.insert(
                    edge,
                    EdgeMeta {
                        source,
                        relation: r.relation.clone(),
                        target,
                        confidence: r.confidence,
                        support: 1,
                        provenance: vec![provenance.clone()],
                    },
                );
            }
            let names = |id: NodeId| inner.nodes.get(&id).map(|m| m.name.clone());
            if let (Some(s), Some(o)) = (names(source), names(target)) {
                report.facts.push(Fact {
                    triple: Triple::new(s, r.relation, o),
                    confidence: r.confidence,
                    support: 1,
                    provenance: vec![provenance],
                });
            }
        }
        drop(inner);
        Ok(())
    }

    // ── Queries ───────────────────────────────────────────────────────────────

    /// Look up an entity by any of its names or aliases (case and
    /// punctuation are ignored).
    ///
    /// # Example
    ///
    /// ```rust
    /// # use rune_chain_knowledge_graph::KnowledgeGraph;
    /// # use rune_chain_core::{Llm, Message, GenerateResult, LlmError};
    /// # use async_trait::async_trait;
    /// # struct FakeLlm;
    /// # #[async_trait] impl Llm for FakeLlm {
    /// #   async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
    /// #     Ok(GenerateResult::from_text(r#"{"entities":[{"name":"Acme Corp.","type":"Org"}],"relations":[]}"#))
    /// #   }
    /// # }
    /// # tokio_test::block_on(async {
    /// let kg = KnowledgeGraph::new(FakeLlm);
    /// kg.extract("Acme Corp. was founded in 1990.").await.unwrap();
    /// let acme = kg.entity("ACME corp").await.unwrap();
    /// assert_eq!(acme.name, "Acme Corp.");
    /// assert_eq!(acme.entity_type.as_deref(), Some("org"));
    /// assert_eq!(acme.provenance[0].span, 0..10);
    /// # });
    /// ```
    pub async fn entity(&self, name: &str) -> Option<Entity> {
        let inner = self.inner.read().await;
        inner.lookup(name).and_then(|id| inner.entity(id))
    }

    /// The graph node of an entity, by any of its names or aliases.
    pub async fn entity_id(&self, name: &str) -> Option<NodeId> {
        self.inner.read().await.lookup(name)
    }

    /// All entities, sorted by name.
    pub async fn entities(&self) -> Vec<Entity> {
        let inner = self.inner.read().await;
        let mut out: Vec<Entity> = inner
            .nodes
            .keys()
            .filter_map(|&id| inner.entity(id))
            .collect();
        drop(inner);
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    /// All facts with `name` as subject or object, highest confidence first.
    ///
    /// Returns an empty `Vec` if the entity is unknown.
    ///
    /// # Example
    ///
    /// ```rust
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
    /// let facts = kg.relations_of("bob").await;
    /// assert_eq!(facts[0].triple.relation(), "knows");
    /// # });
    /// ```
    pub async fn relations_of(&self, name: &str) -> Vec<Fact> {
        let inner = self.inner.read().await;
        let Some(id) = inner.lookup(name) else {
            return Vec::new();
        };
        let mut facts: Vec<(EdgeId, Fact)> = inner
            .graph
            .outgoing_edges(id)
            .chain(inner.graph.incoming_edges(id))
            .filter_map(|e| Some((e, inner.fact(e)?)))
            .collect();
        drop(inner);
        facts.sort_by(|a, b| {
            b.1.confidence
                .total_cmp(&a.1.confidence)
                .then(a.0.cmp(&b.0))
        });
        facts.into_iter().map(|(_, f)| f).collect()
    }

    /// Shortest directed path between two entities, as canonical names.
    /// Returns `None` if no path exists or either entity is unknown.
    ///
    /// # Example
    ///
    /// ```rust
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
    pub async fn path_between(&self, from: &str, to: &str) -> Option<Vec<String>> {
        let inner = self.inner.read().await;
        let path = inner
            .graph
            .shortest_path(inner.lookup(from)?, inner.lookup(to)?)?;
        let names = path
            .iter()
            .map(|id| inner.nodes.get(id).map(|m| m.name.clone()))
            .collect();
        drop(inner);
        names
    }

    /// Names of the entities within `depth` hops of `name` (edges followed
    /// in both directions), including `name` itself, sorted. `depth` is
    /// capped at [`MAX_HOPS`] and the result at `max_nodes` entities.
    ///
    /// Returns an empty `Vec` if the entity is unknown.
    ///
    /// # Example
    ///
    /// ```rust
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
    /// assert_eq!(kg.subgraph_around("Bob", 1, 10).await, ["Alice", "Bob"]);
    /// # });
    /// ```
    pub async fn subgraph_around(&self, name: &str, depth: usize, max_nodes: usize) -> Vec<String> {
        let inner = self.inner.read().await;
        let Some(start) = inner.lookup(name) else {
            return Vec::new();
        };
        let depth = depth.min(MAX_HOPS);
        let mut visited = HashSet::from([start]);
        let mut queue = VecDeque::from([(start, 0usize)]);
        'bfs: while let Some((node, hop)) = queue.pop_front() {
            if hop >= depth {
                continue;
            }
            let mut next: Vec<NodeId> = inner
                .graph
                .neighbors(node)
                .chain(inner.graph.predecessors(node))
                .collect();
            next.sort_unstable();
            for n in next {
                if visited.len() >= max_nodes {
                    break 'bfs;
                }
                if visited.insert(n) {
                    queue.push_back((n, hop + 1));
                }
            }
        }
        let mut names: Vec<String> = visited
            .iter()
            .filter_map(|id| inner.nodes.get(id).map(|m| m.name.clone()))
            .take(max_nodes)
            .collect();
        drop(inner);
        names.sort();
        names
    }

    /// Every stored fact, sorted by triple.
    pub async fn facts(&self) -> Vec<Fact> {
        let inner = self.inner.read().await;
        let mut out: Vec<Fact> = inner.edges.keys().filter_map(|&e| inner.fact(e)).collect();
        drop(inner);
        out.sort_by(|a, b| a.triple.cmp(&b.triple));
        out
    }

    /// Every stored triple, sorted.
    pub async fn triples(&self) -> Vec<Triple> {
        self.facts().await.into_iter().map(|f| f.triple).collect()
    }

    /// Number of distinct entities.
    pub async fn entity_count(&self) -> usize {
        self.inner.read().await.nodes.len()
    }

    /// Number of distinct facts.
    pub async fn fact_count(&self) -> usize {
        self.inner.read().await.edges.len()
    }

    /// Distinct relation labels in use, sorted.
    pub async fn relation_types(&self) -> Vec<String> {
        let inner = self.inner.read().await;
        let set: BTreeSet<String> = inner.edges.values().map(|m| m.relation.clone()).collect();
        drop(inner);
        set.into_iter().collect()
    }

    /// Direct access to the underlying property graph for algorithms from
    /// `rune_graph::algo`, pattern matching or persistence.
    ///
    /// Holds the read lock for its lifetime, so extraction waits until the
    /// view is dropped.
    pub async fn graph(&self) -> GraphView<'_> {
        GraphView(self.inner.read().await)
    }

    // ── Retrieval ─────────────────────────────────────────────────────────────

    /// `GraphRAG` retrieval: find seed entities for `query`, expand a bounded
    /// neighbourhood and render it as a compact, cited context.
    ///
    /// Seeds come from word overlap between the query and entity names or
    /// aliases and, with an embedder, from cosine similarity between the
    /// query and entity names. From the seeds, edges are followed in both
    /// directions for up to `config.hops` hops, highest confidence first,
    /// within `config.max_nodes`, `config.max_facts` and
    /// `config.max_neighbors_per_node`. The text fits in
    /// `config.max_context_chars`.
    ///
    /// The context quotes names extracted from documents, so treat it as
    /// untrusted data in the answering prompt too.
    ///
    /// # Errors
    ///
    /// [`KgError::InvalidInput`] for an invalid `config`, [`KgError::Embed`]
    /// if the embedder fails.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use rune_chain_knowledge_graph::{KnowledgeGraph, RetrievalConfig};
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
    ///
    /// let ctx = kg.retrieve("Where does Alice's friend work?", &RetrievalConfig::default())
    ///     .await
    ///     .unwrap();
    /// assert_eq!(ctx.seeds[0].name, "Alice");
    /// assert_eq!(ctx.facts.len(), 2);
    /// assert!(ctx.text.contains("Bob --[works_at]--> Acme"));
    /// # });
    /// ```
    pub async fn retrieve(
        &self,
        query: &str,
        config: &RetrievalConfig,
    ) -> Result<GraphContext, KgError> {
        config.validate()?;
        let query = normalize::truncate_chars(query, config.max_query_chars);
        let query_vector = match &self.embedder {
            Some(embedder) if !query.trim().is_empty() => {
                let has_vectors = !self.inner.read().await.embeddings.is_empty();
                if has_vectors {
                    let v = embedder.embed_query(query).await.map_err(KgError::Embed)?;
                    embedding::check_vectors(std::slice::from_ref(&v), 1)?;
                    Some(v)
                } else {
                    None
                }
            }
            _ => None,
        };
        let inner = self.inner.read().await;
        let ctx = retrieval::retrieve(&inner, query, query_vector.as_deref(), config);
        drop(inner);
        Ok(ctx)
    }

    /// Group entities into communities by label propagation over the
    /// undirected graph, largest first, each with a short structural
    /// summary (no model call).
    ///
    /// Runs at most `max_iterations` rounds (capped at 50); cost is
    /// `O(iterations × edges)`. Returns at most `max_communities` groups.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use rune_chain_knowledge_graph::KnowledgeGraph;
    /// # use rune_chain_core::{Llm, Message, GenerateResult, LlmError};
    /// # use async_trait::async_trait;
    /// # struct FakeLlm;
    /// # #[async_trait] impl Llm for FakeLlm {
    /// #   async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
    /// #     Ok(GenerateResult::from_text(r#"[{"subject":"A","relation":"r","object":"B"},{"subject":"C","relation":"r","object":"D"}]"#))
    /// #   }
    /// # }
    /// # tokio_test::block_on(async {
    /// let kg = KnowledgeGraph::new(FakeLlm);
    /// kg.extract("...").await.unwrap();
    /// let groups = kg.communities(10, 20).await;
    /// assert_eq!(groups.len(), 2);
    /// assert_eq!(groups[0].members, ["A", "B"]);
    /// # });
    /// ```
    pub async fn communities(
        &self,
        max_iterations: usize,
        max_communities: usize,
    ) -> Vec<Community> {
        let inner = self.inner.read().await;
        let out = community::detect(&inner, max_iterations, max_communities);
        drop(inner);
        out
    }
}

fn check_document_id(id: &str) -> Result<(), KgError> {
    if id.is_empty() || id.len() > MAX_DOCUMENT_ID_BYTES || id.chars().any(char::is_control) {
        return Err(KgError::InvalidInput(format!(
            "document id must be 1 to {MAX_DOCUMENT_ID_BYTES} bytes without control characters"
        )));
    }
    Ok(())
}
