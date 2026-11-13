//! JSON Lines import and export.
//!
//! One JSON object per line, written in this order:
//!
//! ```text
//! {"key":"name","label":"Person","type":"index"}
//! {"id":0,"labels":["Person"],"properties":{"age":30,"name":"Alice"},"type":"node"}
//! {"id":0,"label":"KNOWS","properties":{"since":2020},"source":0,"target":1,"type":"edge"}
//! ```
//!
//! Keys are written in sorted order; readers accept any order.
//!
//! When the newest nodes or edges were removed, a first line
//! `{"next_edge":3,"next_node":5,"type":"ids"}` records the id counters so
//! removed ids are not handed out again after a reload. It is left out
//! otherwise.
//!
//! Property values use plain JSON: `null`, booleans, numbers, strings and
//! arrays. Integers become [`Value::Int`]; numbers with a fraction or
//! exponent become [`Value::Float`]. Objects are not supported as values.

use std::collections::HashMap;
use std::io::{BufRead, Read, Write};

use serde_json::{Map, Number, Value as Json, json};

use crate::entry::{EdgeEntry, NodeEntry};
use crate::graph::Graph;
use crate::id::{EdgeId, NodeId};
use crate::persist::PersistError;
use crate::value::Value;

/// Limits applied by [`Graph::read_jsonl_with`].
///
/// # Example
///
/// ```rust
/// use rune_graph::JsonlOptions;
/// let opts = JsonlOptions::default().max_line_bytes(4096).max_records(Some(10_000));
/// assert_eq!(opts.max_line_bytes_limit(), 4096);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JsonlOptions {
    max_line_bytes: usize,
    max_records: Option<usize>,
}

impl JsonlOptions {
    /// Default longest accepted line: 16 MiB.
    pub const DEFAULT_MAX_LINE_BYTES: usize = 16 << 20;

    /// Refuse lines longer than `bytes` (excluding the newline).
    #[must_use]
    pub const fn max_line_bytes(mut self, bytes: usize) -> Self {
        self.max_line_bytes = bytes;
        self
    }

    /// Refuse inputs with more than `n` records (`None` = unlimited, the default).
    #[must_use]
    pub const fn max_records(mut self, n: Option<usize>) -> Self {
        self.max_records = n;
        self
    }

    /// The configured line limit in bytes.
    #[must_use]
    pub const fn max_line_bytes_limit(&self) -> usize {
        self.max_line_bytes
    }
}

impl Default for JsonlOptions {
    fn default() -> Self {
        Self {
            max_line_bytes: Self::DEFAULT_MAX_LINE_BYTES,
            max_records: None,
        }
    }
}

fn value_to_json(v: &Value) -> Result<Json, PersistError> {
    Ok(match v {
        Value::Null => Json::Null,
        Value::Bool(b) => Json::Bool(*b),
        Value::Int(n) => Json::Number((*n).into()),
        Value::Float(f) => {
            Json::Number(Number::from_f64(*f).ok_or_else(|| {
                PersistError::Encode(format!("{f} cannot be represented in JSON"))
            })?)
        }
        Value::Str(s) => Json::String(s.clone()),
        Value::List(items) => {
            Json::Array(items.iter().map(value_to_json).collect::<Result<_, _>>()?)
        }
    })
}

fn json_to_value(j: Json) -> Result<Value, String> {
    Ok(match j {
        Json::Null => Value::Null,
        Json::Bool(b) => Value::Bool(b),
        Json::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::Int(i)
            } else if n.is_f64() {
                Value::Float(n.as_f64().ok_or("number out of range")?)
            } else {
                return Err(format!("integer {n} does not fit in i64"));
            }
        }
        Json::String(s) => Value::Str(s),
        Json::Array(items) => Value::List(
            items
                .into_iter()
                .map(json_to_value)
                .collect::<Result<_, _>>()?,
        ),
        Json::Object(_) => return Err("objects are not supported as property values".into()),
    })
}

fn props_to_json(props: &HashMap<String, Value>) -> Result<Json, PersistError> {
    let mut keys: Vec<&String> = props.keys().collect();
    keys.sort_unstable();
    let mut map = Map::new();
    for k in keys {
        if let Some(v) = props.get(k) {
            map.insert(k.clone(), value_to_json(v)?);
        }
    }
    Ok(Json::Object(map))
}

// Keys are inserted alphabetically so the output is sorted whether or not
// serde_json's `preserve_order` feature is enabled somewhere in the build.
fn write_line(w: &mut impl Write, j: &Json) -> Result<(), PersistError> {
    serde_json::to_writer(&mut *w, j).map_err(|e| PersistError::Encode(e.to_string()))?;
    w.write_all(b"\n")?;
    Ok(())
}

/// Read one line of at most `max` bytes (newline excluded) into `buf`.
/// Returns `Ok(false)` at end of input.
fn read_line_bounded(
    r: &mut impl BufRead,
    buf: &mut Vec<u8>,
    max: usize,
) -> Result<bool, PersistError> {
    buf.clear();
    let cap = (max as u64).saturating_add(1);
    let n = r.by_ref().take(cap).read_until(b'\n', buf)?;
    if n == 0 {
        return Ok(false);
    }
    if buf.last() == Some(&b'\n') {
        buf.pop();
        if buf.last() == Some(&b'\r') {
            buf.pop();
        }
    } else if buf.len() > max {
        return Err(PersistError::TooLarge {
            limit: max as u64,
            actual: buf.len() as u64,
        });
    }
    Ok(true)
}

struct LineCtx(usize);

impl LineCtx {
    fn err(&self, msg: impl std::fmt::Display) -> PersistError {
        PersistError::Decode(format!("line {}: {msg}", self.0))
    }

    fn invalid(&self, msg: impl std::fmt::Display) -> PersistError {
        PersistError::Invalid(format!("line {}: {msg}", self.0))
    }
}

fn take_field<T: serde::de::DeserializeOwned>(
    obj: &mut Map<String, Json>,
    key: &str,
    ctx: &LineCtx,
) -> Result<T, PersistError> {
    let v = obj
        .remove(key)
        .ok_or_else(|| ctx.err(format!("missing field `{key}`")))?;
    serde_json::from_value(v).map_err(|e| ctx.err(format!("field `{key}`: {e}")))
}

fn take_props(
    obj: &mut Map<String, Json>,
    ctx: &LineCtx,
) -> Result<HashMap<String, Value>, PersistError> {
    match obj.remove("properties") {
        None | Some(Json::Null) => Ok(HashMap::new()),
        Some(Json::Object(map)) => map
            .into_iter()
            .map(|(k, v)| {
                json_to_value(v)
                    .map(|v| (k.clone(), v))
                    .map_err(|e| ctx.err(format!("property `{k}`: {e}")))
            })
            .collect(),
        Some(_) => Err(ctx.err("`properties` must be an object")),
    }
}

impl Graph {
    /// Stream the graph as JSON Lines: index definitions, then nodes, then
    /// edges, each sorted by id (see the [format](crate#json-lines)).
    ///
    /// Nothing but the sorted id lists is buffered; wrap `w` in a
    /// `BufWriter` for files.
    ///
    /// # Errors
    ///
    /// Returns [`PersistError::Encode`] for non-finite floats and
    /// [`PersistError::Io`] on write failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_graph::{Graph, props};
    ///
    /// let mut g = Graph::new();
    /// let a = g.add_node(&["Person"], props! { "name" => "Alice" });
    /// let b = g.add_node(&["Person"], props! { "name" => "Bob" });
    /// g.add_edge(a, b, "KNOWS", props! { "since" => 2020_i64 }).unwrap();
    ///
    /// let mut out = Vec::new();
    /// g.write_jsonl(&mut out).unwrap();
    /// let text = String::from_utf8(out).unwrap();
    /// assert_eq!(text.lines().count(), 3);
    ///
    /// let g2 = Graph::read_jsonl(text.as_bytes()).unwrap();
    /// assert_eq!(g2.edge_count(), 1);
    /// ```
    pub fn write_jsonl(&self, mut w: impl Write) -> Result<(), PersistError> {
        let mut node_ids: Vec<NodeId> = self.nodes().map(|(id, _)| id).collect();
        node_ids.sort_unstable();
        let mut edge_ids: Vec<EdgeId> = self.edges().map(|(id, _)| id).collect();
        edge_ids.sort_unstable();
        // A reader rebuilds the counters as max(id) + 1, which is only short
        // when the highest ids were removed. Spell them out in that case.
        let implied_node = node_ids.last().map_or(0, |id| id.0 + 1);
        let implied_edge = edge_ids.last().map_or(0, |id| id.0 + 1);
        if self.next_node > implied_node || self.next_edge > implied_edge {
            write_line(
                &mut w,
                &json!({"next_edge": self.next_edge, "next_node": self.next_node, "type": "ids"}),
            )?;
        }
        let mut indexes: Vec<(&str, &str)> = self.indexes().collect();
        indexes.sort_unstable();
        for (label, key) in indexes {
            write_line(
                &mut w,
                &json!({"key": key, "label": label, "type": "index"}),
            )?;
        }
        for id in node_ids {
            let Some(n) = self.node(id) else { continue };
            write_line(
                &mut w,
                &json!({
                    "id": id.0,
                    "labels": n.labels(),
                    "properties": props_to_json(n.properties())?,
                    "type": "node",
                }),
            )?;
        }
        for id in edge_ids {
            let Some(e) = self.edge(id) else { continue };
            write_line(
                &mut w,
                &json!({
                    "id": id.0,
                    "label": e.label(),
                    "properties": props_to_json(e.properties())?,
                    "source": e.source().0,
                    "target": e.target().0,
                    "type": "edge",
                }),
            )?;
        }
        w.flush()?;
        Ok(())
    }

    /// Build a graph from JSON Lines written by
    /// [`write_jsonl`](Self::write_jsonl), with default [`JsonlOptions`].
    ///
    /// # Errors
    ///
    /// See [`read_jsonl_with`](Self::read_jsonl_with).
    pub fn read_jsonl(r: impl BufRead) -> Result<Self, PersistError> {
        Self::read_jsonl_with(r, &JsonlOptions::default())
    }

    /// Build a graph from JSON Lines, reading one bounded line at a time.
    ///
    /// Ids and id counters are preserved. Blank lines are skipped. An edge must come after
    /// both of its endpoint nodes.
    ///
    /// # Errors
    ///
    /// [`PersistError::TooLarge`] for an over-long line or too many records,
    /// [`PersistError::Decode`] for malformed lines (with the line number),
    /// [`PersistError::Invalid`] for duplicate ids or dangling edges.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_graph::{Graph, JsonlOptions, PersistError};
    ///
    /// let input = r#"{"type":"node","id":7,"labels":["A"],"properties":{"x":1.5}}"#;
    /// let g = Graph::read_jsonl(input.as_bytes()).unwrap();
    /// assert!(g.contains_node(rune_graph::NodeId::from(7)));
    ///
    /// let tight = JsonlOptions::default().max_line_bytes(16);
    /// let err = Graph::read_jsonl_with(input.as_bytes(), &tight).unwrap_err();
    /// assert!(matches!(err, PersistError::TooLarge { .. }));
    /// ```
    pub fn read_jsonl_with(mut r: impl BufRead, opts: &JsonlOptions) -> Result<Self, PersistError> {
        let mut g = Self::new();
        let mut buf = Vec::new();
        let mut line_no = 0usize;
        let mut records = 0usize;
        while read_line_bounded(&mut r, &mut buf, opts.max_line_bytes)? {
            line_no += 1;
            if buf.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            records += 1;
            if let Some(max) = opts.max_records
                && records > max
            {
                return Err(PersistError::TooLarge {
                    limit: max as u64,
                    actual: records as u64,
                });
            }
            let ctx = LineCtx(line_no);
            let mut obj = match serde_json::from_slice::<Json>(&buf) {
                Ok(Json::Object(m)) => m,
                Ok(_) => return Err(ctx.err("expected a JSON object")),
                Err(e) => return Err(ctx.err(e)),
            };
            let kind: String = take_field(&mut obj, "type", &ctx)?;
            match kind.as_str() {
                "ids" => {
                    let next_node: u64 = take_field(&mut obj, "next_node", &ctx)?;
                    let next_edge: u64 = take_field(&mut obj, "next_edge", &ctx)?;
                    for (next, what) in [(next_node, "node"), (next_edge, "edge")] {
                        if next > crate::graph::MAX_RESTORED_ID {
                            return Err(
                                ctx.invalid(format!("next {what} id {next} is out of range"))
                            );
                        }
                    }
                    g.next_node = g.next_node.max(next_node);
                    g.next_edge = g.next_edge.max(next_edge);
                }
                "index" => {
                    let label: String = take_field(&mut obj, "label", &ctx)?;
                    let key: String = take_field(&mut obj, "key", &ctx)?;
                    g.create_index(&label, &key);
                }
                "node" => {
                    let id: u64 = take_field(&mut obj, "id", &ctx)?;
                    let labels: Vec<String> = match obj.get("labels") {
                        None | Some(Json::Null) => Vec::new(),
                        Some(_) => take_field(&mut obj, "labels", &ctx)?,
                    };
                    let props = take_props(&mut obj, &ctx)?;
                    g.insert_node_with_id(NodeId(id), NodeEntry::from_parts(labels, props))
                        .map_err(|e| ctx.invalid(e))?;
                }
                "edge" => {
                    let id: u64 = take_field(&mut obj, "id", &ctx)?;
                    let source: u64 = take_field(&mut obj, "source", &ctx)?;
                    let target: u64 = take_field(&mut obj, "target", &ctx)?;
                    let label: String = take_field(&mut obj, "label", &ctx)?;
                    let properties = take_props(&mut obj, &ctx)?;
                    g.insert_edge_with_id(
                        EdgeId(id),
                        EdgeEntry {
                            source: NodeId(source),
                            target: NodeId(target),
                            label,
                            properties,
                        },
                    )
                    .map_err(|e| ctx.invalid(e))?;
                }
                other => return Err(ctx.err(format!("unknown record type `{other}`"))),
            }
        }
        Ok(g)
    }
}
