//! Secondary indexes kept in sync by [`Graph`](crate::Graph) mutations.

use std::collections::hash_set;
use std::collections::{HashMap, HashSet};

use crate::entry::NodeEntry;
use crate::id::NodeId;
use crate::value::Value;

/// Hashable mirror of [`Value`] used as an index key.
///
/// Equality follows `Value`'s `PartialEq`: `Int(1)` and `Float(1.0)` are
/// different keys, `0.0` and `-0.0` are the same key, and anything containing
/// `NaN` has no key at all (it never compares equal, so it can never match).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IndexKey {
    Null,
    Bool(bool),
    Int(i64),
    Float(u64),
    Str(String),
    List(Vec<Self>),
}

impl IndexKey {
    pub(crate) fn from_value(v: &Value) -> Option<Self> {
        Some(match v {
            Value::Null => Self::Null,
            Value::Bool(b) => Self::Bool(*b),
            Value::Int(n) => Self::Int(*n),
            Value::Float(f) if f.is_nan() => return None,
            // -0.0 == 0.0 under PartialEq, so they share a key.
            Value::Float(f) if *f == 0.0 => Self::Float(0.0_f64.to_bits()),
            Value::Float(f) => Self::Float(f.to_bits()),
            Value::Str(s) => Self::Str(s.clone()),
            Value::List(items) => Self::List(
                items
                    .iter()
                    .map(Self::from_value)
                    .collect::<Option<Vec<_>>>()?,
            ),
        })
    }
}

type ValueMap = HashMap<IndexKey, HashSet<NodeId>>;

/// Label → property key → value → nodes.
#[derive(Debug, Clone, Default)]
pub struct PropertyIndexes {
    by_label: HashMap<String, HashMap<String, ValueMap>>,
}

impl PropertyIndexes {
    pub(crate) fn contains(&self, label: &str, key: &str) -> bool {
        self.by_label
            .get(label)
            .is_some_and(|keys| keys.contains_key(key))
    }

    pub(crate) fn get(&self, label: &str, key: &str) -> Option<&ValueMap> {
        self.by_label.get(label)?.get(key)
    }

    /// Register an index and fill it from `nodes`. Returns `false` if it
    /// already existed.
    pub(crate) fn create<'a>(
        &mut self,
        label: &str,
        key: &str,
        nodes: impl Iterator<Item = (NodeId, &'a NodeEntry)>,
    ) -> bool {
        if self.contains(label, key) {
            return false;
        }
        let mut map = ValueMap::new();
        for (id, entry) in nodes {
            if let Some(k) = entry.get(key).and_then(IndexKey::from_value) {
                map.entry(k).or_default().insert(id);
            }
        }
        self.by_label
            .entry(label.to_string())
            .or_default()
            .insert(key.to_string(), map);
        true
    }

    pub(crate) fn drop_index(&mut self, label: &str, key: &str) -> bool {
        let Some(keys) = self.by_label.get_mut(label) else {
            return false;
        };
        let removed = keys.remove(key).is_some();
        if keys.is_empty() {
            self.by_label.remove(label);
        }
        removed
    }

    pub(crate) fn definitions(&self) -> impl Iterator<Item = (&str, &str)> {
        self.by_label
            .iter()
            .flat_map(|(label, keys)| keys.keys().map(move |key| (label.as_str(), key.as_str())))
    }

    pub(crate) fn insert_node(&mut self, id: NodeId, entry: &NodeEntry) {
        for label in entry.labels() {
            let Some(keys) = self.by_label.get_mut(label) else {
                continue;
            };
            for (key, map) in keys {
                if let Some(k) = entry.get(key).and_then(IndexKey::from_value) {
                    map.entry(k).or_default().insert(id);
                }
            }
        }
    }

    pub(crate) fn remove_node(&mut self, id: NodeId, entry: &NodeEntry) {
        for label in entry.labels() {
            let Some(keys) = self.by_label.get_mut(label) else {
                continue;
            };
            for (key, map) in keys {
                let Some(k) = entry.get(key).and_then(IndexKey::from_value) else {
                    continue;
                };
                if let Some(set) = map.get_mut(&k) {
                    set.remove(&id);
                    if set.is_empty() {
                        map.remove(&k);
                    }
                }
            }
        }
    }

    /// Empty every index but keep the definitions.
    pub(crate) fn clear_entries(&mut self) {
        for keys in self.by_label.values_mut() {
            for map in keys.values_mut() {
                map.clear();
            }
        }
    }
}

/// Iterator over the nodes returned by
/// [`Graph::nodes_by_property`](crate::Graph::nodes_by_property).
///
/// Backed by the property index when one exists for the `(label, key)` pair,
/// otherwise by a scan over the nodes carrying the label.
pub struct PropertyMatches<'a> {
    pub(crate) inner: MatchesInner<'a>,
}

pub enum MatchesInner<'a> {
    Indexed(Option<hash_set::Iter<'a, NodeId>>),
    Scan {
        nodes: &'a HashMap<NodeId, NodeEntry>,
        ids: Option<hash_set::Iter<'a, NodeId>>,
        key: &'a str,
        value: Value,
    },
}

impl Iterator for PropertyMatches<'_> {
    type Item = NodeId;

    fn next(&mut self) -> Option<NodeId> {
        match &mut self.inner {
            MatchesInner::Indexed(it) => it.as_mut()?.next().copied(),
            MatchesInner::Scan {
                nodes,
                ids,
                key,
                value,
            } => ids.as_mut()?.by_ref().copied().find(|id| {
                nodes
                    .get(id)
                    .and_then(|n| n.get(key))
                    .is_some_and(|v| v == value)
            }),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match &self.inner {
            MatchesInner::Indexed(it) => it.as_ref().map_or((0, Some(0)), Iterator::size_hint),
            MatchesInner::Scan { ids, .. } => {
                (0, ids.as_ref().map_or(Some(0), |it| it.size_hint().1))
            }
        }
    }
}
