use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt::Write as _;

use rune_graph::{EdgeId, NodeId};

use crate::config::RetrievalConfig;
use crate::embedding;
use crate::knowledge_graph::KgInner;
use crate::normalize;
use crate::triple::{Entity, Fact};

/// Most distinct query words used for seed matching.
const MAX_QUERY_WORDS: usize = 64;

/// How a seed entity was matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SeedMatch {
    /// Words of the entity's name or alias appear in the query.
    Keyword,
    /// The query and the entity name have similar embeddings.
    Embedding,
}

/// A seed entity and its match score in `[0, 1]`.
#[derive(Debug, Clone, PartialEq)]
pub struct ScoredEntity {
    /// Canonical name.
    pub name: String,
    /// Share of the entity's words found in the query, or cosine similarity.
    pub score: f32,
    /// Which signal produced the score.
    pub matched_by: SeedMatch,
}

/// The result of [`KnowledgeGraph::retrieve`](crate::KnowledgeGraph::retrieve).
///
/// `text` is ready to drop into an answering prompt. Each fact line carries a
/// number and its first source, `[n] Subject --[relation]--> Object
/// (confidence 0.90; source doc@start-end)`, so the answer can cite `[n]`;
/// `facts[n - 1]` holds the full provenance.
#[derive(Debug, Clone, Default, PartialEq)]
#[non_exhaustive]
pub struct GraphContext {
    /// Seed entities, best first.
    pub seeds: Vec<ScoredEntity>,
    /// Entities reached, seeds first, then by hop distance.
    pub entities: Vec<Entity>,
    /// Facts rendered in `text`, in citation order.
    pub facts: Vec<Fact>,
    /// The rendered context.
    pub text: String,
    /// Whether facts or entities were left out of `text` to fit the budget.
    pub truncated: bool,
}

impl GraphContext {
    /// Whether nothing relevant was found.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.seeds.is_empty()
    }
}

fn keyword_score(key: &str, query: &BTreeSet<String>) -> f32 {
    let words: Vec<&str> = key.split(' ').collect();
    let content: Vec<&str> = words
        .iter()
        .copied()
        .filter(|w| !normalize::is_stopword(w))
        .collect();
    let words = if content.is_empty() { words } else { content };
    let matched = words.iter().filter(|w| query.contains(**w)).count();
    #[allow(clippy::cast_precision_loss, reason = "word counts are small")]
    let score = matched as f32 / words.len().max(1) as f32;
    score
}

fn degree(inner: &KgInner, id: NodeId) -> usize {
    inner.graph.degree(id).map_or(0, |(i, o)| i + o)
}

fn seeds(
    inner: &KgInner,
    query: &str,
    query_vector: Option<&[f32]>,
    config: &RetrievalConfig,
) -> Vec<(NodeId, ScoredEntity)> {
    let words: BTreeSet<String> = normalize::tokens(query).take(MAX_QUERY_WORDS * 4).collect();
    let words: BTreeSet<String> = words.into_iter().take(MAX_QUERY_WORDS).collect();

    let mut scores: HashMap<NodeId, (f32, SeedMatch)> = HashMap::new();
    let candidates: BTreeSet<NodeId> = words
        .iter()
        .filter(|w| !normalize::is_stopword(w))
        .filter_map(|w| inner.words.get(w))
        .flatten()
        .copied()
        .collect();
    for id in candidates {
        let Some(meta) = inner.nodes.get(&id) else {
            continue;
        };
        let score = meta
            .keys
            .iter()
            .map(|k| keyword_score(k, &words))
            .fold(0.0f32, f32::max);
        if score >= config.min_keyword_score && score > 0.0 {
            scores.insert(id, (score, SeedMatch::Keyword));
        }
    }
    if let Some(q) = query_vector {
        for (id, v) in &inner.embeddings {
            let Some(sim) = embedding::cosine(q, v) else {
                continue;
            };
            if sim >= config.min_similarity && scores.get(id).is_none_or(|(s, _)| sim > *s) {
                scores.insert(*id, (sim, SeedMatch::Embedding));
            }
        }
    }

    let mut ranked: Vec<(NodeId, f32, SeedMatch, usize, &str)> = scores
        .into_iter()
        .filter_map(|(id, (score, how))| {
            let name = inner.nodes.get(&id)?.name.as_str();
            Some((id, score, how, degree(inner, id), name))
        })
        .collect();
    ranked.sort_by(|a, b| {
        b.1.total_cmp(&a.1)
            .then(b.3.cmp(&a.3))
            .then(a.4.cmp(b.4))
            .then(a.0.cmp(&b.0))
    });
    ranked
        .into_iter()
        .take(config.max_seeds)
        .map(|(id, score, matched_by, _, name)| {
            (
                id,
                ScoredEntity {
                    name: name.to_string(),
                    score,
                    matched_by,
                },
            )
        })
        .collect()
}

/// The `limit` best edges around `node`: highest confidence, then oldest.
fn best_edges(inner: &KgInner, node: NodeId, config: &RetrievalConfig) -> Vec<(EdgeId, NodeId)> {
    let mut edges: Vec<(EdgeId, NodeId, f32)> = inner
        .graph
        .outgoing_edges(node)
        .chain(inner.graph.incoming_edges(node))
        .filter_map(|e| {
            let meta = inner.edges.get(&e)?;
            let other = if meta.source == node {
                meta.target
            } else {
                meta.source
            };
            (meta.confidence >= config.min_confidence).then_some((e, other, meta.confidence))
        })
        .collect();
    let order = |a: &(EdgeId, NodeId, f32), b: &(EdgeId, NodeId, f32)| {
        b.2.total_cmp(&a.2).then(a.0.cmp(&b.0))
    };
    let limit = config.max_neighbors_per_node;
    if limit == 0 {
        return Vec::new();
    }
    if edges.len() > limit {
        edges.select_nth_unstable_by(limit - 1, order);
        edges.truncate(limit);
    }
    edges.sort_by(order);
    edges.into_iter().map(|(e, n, _)| (e, n)).collect()
}

pub fn retrieve(
    inner: &KgInner,
    query: &str,
    query_vector: Option<&[f32]>,
    config: &RetrievalConfig,
) -> GraphContext {
    let seeds = seeds(inner, query, query_vector, config);
    let mut included: Vec<NodeId> = Vec::new();
    let mut seen: HashSet<NodeId> = HashSet::new();
    for (id, _) in &seeds {
        if included.len() < config.max_nodes && seen.insert(*id) {
            included.push(*id);
        }
    }

    let mut facts: Vec<EdgeId> = Vec::new();
    let mut fact_set: HashSet<EdgeId> = HashSet::new();
    let mut frontier = included.clone();
    for _ in 0..config.hops {
        let mut next = Vec::new();
        for &node in &frontier {
            for (edge, other) in best_edges(inner, node, config) {
                if included.len() >= config.max_nodes && !seen.contains(&other) {
                    continue;
                }
                if seen.insert(other) {
                    included.push(other);
                    next.push(other);
                }
                if facts.len() < config.max_facts && fact_set.insert(edge) {
                    facts.push(edge);
                }
            }
        }
        if next.is_empty() {
            break;
        }
        frontier = next;
    }

    let entities: Vec<Entity> = included.iter().filter_map(|&id| inner.entity(id)).collect();
    let facts: Vec<Fact> = facts.into_iter().filter_map(|e| inner.fact(e)).collect();
    render(
        seeds.into_iter().map(|(_, s)| s).collect(),
        entities,
        facts,
        config.max_context_chars,
    )
}

/// Appends whole lines to a text while it stays within a character budget.
struct Budget {
    text: String,
    used: usize,
    limit: usize,
    truncated: bool,
}

impl Budget {
    /// Add `header` (if not yet added) and `line`; `false` if they do not fit.
    fn push(&mut self, header: &mut Option<&str>, line: &str) -> bool {
        let head = header.map_or(0, |h| h.chars().count() + 1);
        let len = line.chars().count() + 1;
        if self.used + head + len > self.limit {
            self.truncated = true;
            return false;
        }
        for l in header.take().into_iter().chain([line]) {
            self.text.push_str(l);
            self.text.push('\n');
        }
        self.used += head + len;
        true
    }
}

fn fact_line(n: usize, fact: &Fact) -> String {
    let mut line = format!("[{n}] {} (confidence {:.2}", fact.triple, fact.confidence);
    if let Some(p) = fact.provenance.first() {
        let _ = write!(line, "; source {p}");
    }
    line.push(')');
    line
}

fn entity_line(e: &Entity) -> String {
    let mut line = format!("- {}", e.name);
    if let Some(t) = &e.entity_type {
        let _ = write!(line, " ({t})");
    }
    if !e.aliases.is_empty() {
        let _ = write!(line, ", also called {}", e.aliases.join(", "));
    }
    line
}

fn render(
    seeds: Vec<ScoredEntity>,
    entities: Vec<Entity>,
    facts: Vec<Fact>,
    limit: usize,
) -> GraphContext {
    let mut budget = Budget {
        text: String::new(),
        used: 0,
        limit,
        truncated: false,
    };
    let mut kept = Vec::new();
    let mut header = Some("Facts:");
    for fact in facts {
        if !budget.push(&mut header, &fact_line(kept.len() + 1, &fact)) {
            break;
        }
        kept.push(fact);
    }
    // Entities add their type and aliases; untyped ones are already named
    // in the facts.
    let mut header = Some("Entities:");
    for e in entities
        .iter()
        .filter(|e| e.entity_type.is_some() || !e.aliases.is_empty())
    {
        if !budget.push(&mut header, &entity_line(e)) {
            break;
        }
    }
    let mut text = budget.text;
    if text.ends_with('\n') {
        text.pop();
    }
    GraphContext {
        seeds,
        entities,
        facts: kept,
        text,
        truncated: budget.truncated,
    }
}

#[cfg(test)]
#[allow(
    clippy::field_reassign_with_default,
    reason = "configs are non-exhaustive, so callers set fields this way"
)]
mod tests {
    use super::*;

    fn words(s: &str) -> BTreeSet<String> {
        normalize::tokens(s).collect()
    }

    #[test]
    fn keyword_scores() {
        let q = words("Where is the Acme office?");
        assert!((keyword_score("acme corp", &q) - 0.5).abs() < f32::EPSILON);
        assert!((keyword_score("acme", &q) - 1.0).abs() < f32::EPSILON);
        assert!((keyword_score("the acme", &q) - 1.0).abs() < f32::EPSILON);
        assert!(keyword_score("bob", &q).abs() < f32::EPSILON);
        // An all-stopword name still needs its words in the query.
        assert!((keyword_score("the who", &words("the who")) - 1.0).abs() < f32::EPSILON);
    }

    fn fact_with(subject: &str) -> Fact {
        Fact {
            triple: crate::Triple::new(subject, "r", "B"),
            confidence: 1.0,
            support: 1,
            provenance: vec![],
        }
    }

    #[test]
    fn render_respects_budget_with_whole_lines() {
        let fact = Fact {
            triple: crate::Triple::new("A", "r", "B"),
            confidence: 1.0,
            support: 1,
            provenance: vec![],
        };
        let ctx = render(vec![], vec![], vec![fact.clone(), fact], 42);
        assert!(ctx.truncated);
        assert_eq!(ctx.facts.len(), 1);
        assert_eq!(ctx.text, "Facts:\n[1] A --[r]--> B (confidence 1.00)");
        assert!(ctx.text.chars().count() <= 42);

        let ctx = render(vec![], vec![], vec![], 0);
        assert!(ctx.text.is_empty() && !ctx.truncated);

        // A header is never left without a line under it.
        let ctx = render(vec![], vec![], vec![fact_with("A")], 20);
        assert!(ctx.text.is_empty() && ctx.truncated);
    }
}
