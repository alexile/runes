use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;

use rune_graph::NodeId;

use crate::knowledge_graph::KgInner;

/// Most label-propagation rounds [`KnowledgeGraph::communities`](crate::KnowledgeGraph::communities) runs.
pub const MAX_ITERATIONS: usize = 50;
/// Members listed per community; `size` has the full count.
const MAX_MEMBERS: usize = 25;
/// Relations listed per community summary.
const TOP_RELATIONS: usize = 3;

/// A group of densely connected entities, with a structural summary.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Community {
    /// Number of entities in the community.
    pub size: usize,
    /// Up to 25 member names, most connected first.
    pub members: Vec<String>,
    /// Facts with both ends inside the community.
    pub fact_count: usize,
    /// Most common relation labels inside the community, with counts.
    pub top_relations: Vec<(String, usize)>,
    /// One-line description, for example
    /// `"3 entities, 2 facts. Main entities: Bob, Alice, Acme. Main relations: works_at (2)."`.
    pub summary: String,
}

pub fn detect(inner: &KgInner, max_iterations: usize, max_communities: usize) -> Vec<Community> {
    let mut nodes: Vec<NodeId> = inner.nodes.keys().copied().collect();
    nodes.sort_unstable();
    let index: HashMap<NodeId, usize> = nodes.iter().enumerate().map(|(i, &n)| (n, i)).collect();
    let mut adjacency: Vec<Vec<usize>> = vec![Vec::new(); nodes.len()];
    for meta in inner.edges.values() {
        if let (Some(&a), Some(&b)) = (index.get(&meta.source), index.get(&meta.target)) {
            adjacency[a].push(b);
            adjacency[b].push(a);
        }
    }
    for list in &mut adjacency {
        list.sort_unstable();
    }

    let mut label: Vec<usize> = (0..nodes.len()).collect();
    for _ in 0..max_iterations.min(MAX_ITERATIONS) {
        let mut changed = false;
        for i in 0..nodes.len() {
            if adjacency[i].is_empty() {
                continue;
            }
            let mut counts: BTreeMap<usize, usize> = BTreeMap::new();
            for &j in &adjacency[i] {
                *counts.entry(label[j]).or_default() += 1;
            }
            // Most frequent neighbour label; ties go to the smallest label.
            let best = counts
                .iter()
                .max_by(|a, b| a.1.cmp(b.1).then(b.0.cmp(a.0)))
                .map_or(label[i], |(&l, _)| l);
            if best != label[i] {
                label[i] = best;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    let mut groups: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (i, &l) in label.iter().enumerate() {
        groups.entry(l).or_default().push(i);
    }
    let mut relation_counts: BTreeMap<usize, BTreeMap<&str, usize>> = BTreeMap::new();
    for meta in inner.edges.values() {
        if let (Some(&a), Some(&b)) = (index.get(&meta.source), index.get(&meta.target))
            && label[a] == label[b]
        {
            *relation_counts
                .entry(label[a])
                .or_default()
                .entry(meta.relation.as_str())
                .or_default() += 1;
        }
    }

    let mut out: Vec<(usize, Community)> = groups
        .into_iter()
        .map(|(l, members)| {
            let mut ranked: Vec<(usize, &str)> = members
                .iter()
                .map(|&i| {
                    let name = inner.nodes.get(&nodes[i]).map_or("", |m| m.name.as_str());
                    (adjacency[i].len(), name)
                })
                .collect();
            ranked.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(b.1)));
            let names: Vec<String> = ranked
                .iter()
                .take(MAX_MEMBERS)
                .map(|(_, n)| (*n).to_string())
                .collect();
            let counts = relation_counts.remove(&l).unwrap_or_default();
            let fact_count = counts.values().sum();
            let mut top: Vec<(String, usize)> = counts
                .into_iter()
                .map(|(r, c)| (r.to_string(), c))
                .collect();
            top.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
            top.truncate(TOP_RELATIONS);
            let summary = summarize(members.len(), fact_count, &names, &top);
            (
                l,
                Community {
                    size: members.len(),
                    members: names,
                    fact_count,
                    top_relations: top,
                    summary,
                },
            )
        })
        .collect();
    out.sort_by(|a, b| {
        b.1.size
            .cmp(&a.1.size)
            .then(b.1.fact_count.cmp(&a.1.fact_count))
            .then(a.0.cmp(&b.0))
    });
    out.into_iter()
        .take(max_communities)
        .map(|(_, c)| c)
        .collect()
}

fn summarize(size: usize, facts: usize, names: &[String], top: &[(String, usize)]) -> String {
    let plural = |n: usize, one: &str, many: &str| {
        if n == 1 {
            one.to_string()
        } else {
            many.to_string()
        }
    };
    let mut s = format!(
        "{size} {}, {facts} {}.",
        plural(size, "entity", "entities"),
        plural(facts, "fact", "facts")
    );
    let shown: Vec<&str> = names.iter().take(5).map(String::as_str).collect();
    if !shown.is_empty() {
        let _ = write!(s, " Main entities: {}.", shown.join(", "));
    }
    if !top.is_empty() {
        let rels: Vec<String> = top.iter().map(|(r, c)| format!("{r} ({c})")).collect();
        let _ = write!(s, " Main relations: {}.", rels.join(", "));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_text() {
        assert_eq!(
            summarize(1, 0, &["A".into()], &[]),
            "1 entity, 0 facts. Main entities: A."
        );
        assert_eq!(
            summarize(
                3,
                2,
                &["B".into(), "A".into(), "C".into()],
                &[("r".into(), 2)]
            ),
            "3 entities, 2 facts. Main entities: B, A, C. Main relations: r (2)."
        );
    }
}
