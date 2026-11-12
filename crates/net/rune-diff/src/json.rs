//! Structural JSON diff with RFC 6901 pointers.

use serde_json::Value;

use crate::{DiffOp, DiffOptions, Masker, diff_slices};

/// What happened at a JSON location.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "kind", rename_all = "snake_case"))]
#[non_exhaustive]
pub enum JsonChangeKind {
    /// Only in the new document; the value as compact JSON.
    Added {
        /// The added value.
        value: String,
    },
    /// Only in the old document.
    Removed {
        /// The removed value.
        value: String,
    },
    /// Different scalar values, or different types.
    Changed {
        /// The old value.
        old: String,
        /// The new value.
        new: String,
    },
}

/// One difference between two JSON documents.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct JsonChange {
    /// [RFC 6901](https://www.rfc-editor.org/rfc/rfc6901) pointer: the old
    /// location for removals, the new one otherwise.
    pub pointer: String,
    /// What changed.
    pub kind: JsonChangeKind,
}

pub struct JsonDiffer<'a> {
    pub masker: &'a Masker,
    pub ignore: &'a [Vec<String>],
    pub options: &'a DiffOptions,
}

impl JsonDiffer<'_> {
    pub fn diff(&self, old: &Value, new: &Value) -> Vec<JsonChange> {
        let mut out = Vec::new();
        let mut path = Vec::new();
        self.walk(old, new, &mut path, &mut out);
        out
    }

    fn ignored(&self, path: &[String]) -> bool {
        self.ignore.iter().any(|pattern| {
            pattern.len() <= path.len() && pattern.iter().zip(path).all(|(p, s)| p == "*" || p == s)
        })
    }

    fn push(&self, path: &[String], kind: JsonChangeKind, out: &mut Vec<JsonChange>) {
        if !self.ignored(path) {
            out.push(JsonChange {
                pointer: pointer(path),
                kind,
            });
        }
    }

    fn walk(&self, old: &Value, new: &Value, path: &mut Vec<String>, out: &mut Vec<JsonChange>) {
        if self.ignored(path) {
            return;
        }
        match (old, new) {
            (Value::Object(a), Value::Object(b)) => {
                // Sorted key order, whatever serde_json's map preserves.
                let keys: std::collections::BTreeSet<&String> = a.keys().chain(b.keys()).collect();
                for k in keys {
                    path.push(k.clone());
                    match (a.get(k), b.get(k)) {
                        (Some(va), Some(vb)) => self.walk(va, vb, path, out),
                        (Some(va), None) => self.push(
                            path,
                            JsonChangeKind::Removed {
                                value: va.to_string(),
                            },
                            out,
                        ),
                        (None, Some(vb)) => self.push(
                            path,
                            JsonChangeKind::Added {
                                value: vb.to_string(),
                            },
                            out,
                        ),
                        (None, None) => {}
                    }
                    path.pop();
                }
            }
            (Value::Array(a), Value::Array(b)) => self.walk_arrays(a, b, path, out),
            (Value::String(a), Value::String(b)) => {
                if a != b && self.masker.mask(a) != self.masker.mask(b) {
                    self.push(path, changed(old, new), out);
                }
            }
            _ => {
                if old != new {
                    self.push(path, changed(old, new), out);
                }
            }
        }
    }

    /// Aligns array elements with Myers over their masked serializations,
    /// then pairs up replaced elements and recurses into them.
    fn walk_arrays(
        &self,
        a: &[Value],
        b: &[Value],
        path: &mut Vec<String>,
        out: &mut Vec<JsonChange>,
    ) {
        let key = |v: &Value| self.masker.mask(&v.to_string()).into_owned();
        let ka: Vec<String> = a.iter().map(key).collect();
        let kb: Vec<String> = b.iter().map(key).collect();
        let ops = diff_slices(&ka, &kb, self.options).ops;
        let mut i = 0;
        while i < ops.len() {
            match ops[i] {
                DiffOp::Equal { .. } => {}
                DiffOp::Delete {
                    old_index, old_len, ..
                } => {
                    // A delete followed by an insert is a replacement: pair
                    // elements up and diff them structurally.
                    let (new_index, new_len) = match ops.get(i + 1) {
                        Some(DiffOp::Insert {
                            new_index, new_len, ..
                        }) => {
                            i += 1;
                            (*new_index, *new_len)
                        }
                        _ => (0, 0),
                    };
                    let paired = old_len.min(new_len);
                    for j in 0..paired {
                        path.push((new_index + j).to_string());
                        self.walk(&a[old_index + j], &b[new_index + j], path, out);
                        path.pop();
                    }
                    for j in paired..old_len {
                        path.push((old_index + j).to_string());
                        self.push(
                            path,
                            JsonChangeKind::Removed {
                                value: a[old_index + j].to_string(),
                            },
                            out,
                        );
                        path.pop();
                    }
                    for j in paired..new_len {
                        path.push((new_index + j).to_string());
                        self.push(
                            path,
                            JsonChangeKind::Added {
                                value: b[new_index + j].to_string(),
                            },
                            out,
                        );
                        path.pop();
                    }
                }
                DiffOp::Insert {
                    new_index, new_len, ..
                } => {
                    for (j, value) in b.iter().enumerate().skip(new_index).take(new_len) {
                        path.push(j.to_string());
                        self.push(
                            path,
                            JsonChangeKind::Added {
                                value: value.to_string(),
                            },
                            out,
                        );
                        path.pop();
                    }
                }
            }
            i += 1;
        }
    }
}

fn changed(old: &Value, new: &Value) -> JsonChangeKind {
    JsonChangeKind::Changed {
        old: old.to_string(),
        new: new.to_string(),
    }
}

/// Builds an RFC 6901 pointer from unescaped segments.
pub fn pointer(path: &[String]) -> String {
    let mut out = String::new();
    for seg in path {
        out.push('/');
        out.push_str(&seg.replace('~', "~0").replace('/', "~1"));
    }
    out
}

/// Splits an RFC 6901 pointer into unescaped segments.
pub fn parse_pointer(text: &str) -> Option<Vec<String>> {
    if text.is_empty() {
        return Some(Vec::new());
    }
    let rest = text.strip_prefix('/')?;
    Some(
        rest.split('/')
            .map(|s| s.replace("~1", "/").replace("~0", "~"))
            .collect(),
    )
}

/// Number of leaves (scalars, empty arrays and empty objects).
pub fn leaf_count(value: &Value) -> usize {
    match value {
        Value::Array(a) if !a.is_empty() => a.iter().map(leaf_count).sum(),
        Value::Object(o) if !o.is_empty() => o.values().map(leaf_count).sum(),
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::MaskOptions;

    fn diff(a: &Value, b: &Value, ignore: &[&str]) -> Vec<(String, JsonChangeKind)> {
        let masker = Masker::new(&MaskOptions::default()).unwrap();
        let ignore: Vec<Vec<String>> = ignore.iter().map(|p| parse_pointer(p).unwrap()).collect();
        let d = JsonDiffer {
            masker: &masker,
            ignore: &ignore,
            options: &DiffOptions::default(),
        };
        d.diff(a, b)
            .into_iter()
            .map(|c| (c.pointer, c.kind))
            .collect()
    }

    #[test]
    fn objects_and_scalars() {
        let a = json!({"user": {"name": "ann", "age": 30, "a/b": 1}, "gone": true});
        let b = json!({"user": {"name": "bob", "age": 30, "a/b": 2}, "new": null});
        let got = diff(&a, &b, &[]);
        assert_eq!(
            got,
            [
                (
                    "/gone".into(),
                    JsonChangeKind::Removed {
                        value: "true".into()
                    }
                ),
                (
                    "/new".into(),
                    JsonChangeKind::Added {
                        value: "null".into()
                    }
                ),
                (
                    "/user/a~1b".into(),
                    JsonChangeKind::Changed {
                        old: "1".into(),
                        new: "2".into()
                    }
                ),
                (
                    "/user/name".into(),
                    JsonChangeKind::Changed {
                        old: "\"ann\"".into(),
                        new: "\"bob\"".into()
                    }
                ),
            ]
        );
    }

    #[test]
    fn arrays_align() {
        let a = json!([{"id": 1}, {"id": 2}, {"id": 3}]);
        let b = json!([{"id": 0}, {"id": 1}, {"id": 2}, {"id": 3}]);
        assert_eq!(
            diff(&a, &b, &[]),
            [(
                "/0".into(),
                JsonChangeKind::Added {
                    value: "{\"id\":0}".into()
                }
            )]
        );
        let b = json!([{"id": 1}, {"id": 9}, {"id": 3}]);
        assert_eq!(
            diff(&a, &b, &[]),
            [(
                "/1/id".into(),
                JsonChangeKind::Changed {
                    old: "2".into(),
                    new: "9".into()
                }
            )]
        );
    }

    #[test]
    fn volatile_and_ignored() {
        let a = json!({"ts": "2026-11-12T10:00:00Z", "items": [{"id": 1, "etag": "x"}], "n": 1});
        let b = json!({"ts": "2026-11-12T10:00:09Z", "items": [{"id": 1, "etag": "y"}], "n": 2});
        assert_eq!(diff(&a, &b, &["/items/*/etag", "/n"]), []);
        assert_eq!(diff(&a, &b, &["/items/*/etag"]).len(), 1);
    }

    #[test]
    fn pointers() {
        let segs = vec!["a/b".to_owned(), "m~n".to_owned(), String::new()];
        assert_eq!(pointer(&segs), "/a~1b/m~0n/");
        assert_eq!(parse_pointer(&pointer(&segs)).unwrap(), segs);
        assert_eq!(parse_pointer("x"), None);
        assert_eq!(leaf_count(&json!({"a": [1, 2], "b": {}})), 3);
    }
}
