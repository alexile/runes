//! YAML to JSON conversion on top of the `yaml-rust2` event parser.
//!
//! The tree is built directly from parser events so that limits apply while
//! it grows: nesting depth, and a node budget that alias expansion is
//! charged against (a "billion laughs" document fails instead of expanding).
//! Only the first document of a stream is kept.

use std::collections::HashMap;

use serde_json::{Map, Value};
use yaml_rust2::Yaml;
use yaml_rust2::parser::{Event, MarkedEventReceiver, Parser, Tag};
use yaml_rust2::scanner::{Marker, TScalarStyle};

use crate::OpenApiError;

/// Deepest collection nesting accepted.
const MAX_DEPTH: usize = 128;
/// Most JSON nodes produced, aliases counted at their expanded size.
const MAX_NODES: usize = 2_000_000;

/// Converts the first YAML document in `text` to JSON.
pub fn to_json(text: &str) -> Result<Value, OpenApiError> {
    let mut builder = Builder {
        stack: Vec::new(),
        anchors: HashMap::new(),
        root: None,
        budget: MAX_NODES,
        failure: None,
    };
    Parser::new_from_str(text)
        .load(&mut builder, false)
        .map_err(|error| OpenApiError::Parse(error.to_string()))?;
    if let Some(failure) = builder.failure {
        return Err(OpenApiError::TooLarge(failure.to_owned()));
    }
    Ok(builder.root.unwrap_or(Value::Null))
}

enum Key {
    Missing,
    Ready(String),
    /// A complex key (sequence or mapping): its value is dropped.
    Skip,
}

enum Frame {
    Sequence {
        items: Vec<Value>,
        anchor: usize,
        size: usize,
    },
    Mapping {
        map: Map<String, Value>,
        key: Key,
        anchor: usize,
        size: usize,
    },
}

struct Builder {
    stack: Vec<Frame>,
    /// Anchored values with their node counts.
    anchors: HashMap<usize, (Value, usize)>,
    root: Option<Value>,
    budget: usize,
    failure: Option<&'static str>,
}

impl Builder {
    fn fail(&mut self, reason: &'static str) {
        self.failure.get_or_insert(reason);
        self.stack.clear();
    }

    fn charge(&mut self, nodes: usize) -> bool {
        if nodes > self.budget {
            self.fail("YAML document too large (alias expansion or node count)");
            return false;
        }
        self.budget -= nodes;
        true
    }

    fn open(&mut self, frame: Frame) {
        if self.stack.len() >= MAX_DEPTH {
            self.fail("YAML document nested too deeply");
            return;
        }
        if self.charge(1) {
            self.stack.push(frame);
        }
    }

    /// Places a finished value (with `size` nodes) into its parent.
    fn place(&mut self, value: Value, size: usize, anchor: usize) {
        if anchor > 0 {
            self.anchors.insert(anchor, (value.clone(), size));
        }
        match self.stack.last_mut() {
            None => {
                if self.root.is_none() {
                    self.root = Some(value);
                }
            }
            Some(Frame::Sequence {
                items, size: total, ..
            }) => {
                items.push(value);
                *total += size;
            }
            Some(Frame::Mapping {
                map,
                key,
                size: total,
                ..
            }) => match std::mem::replace(key, Key::Missing) {
                Key::Missing => {
                    *key = match value {
                        Value::String(text) => Key::Ready(text),
                        Value::Null => Key::Ready(String::from("null")),
                        Value::Bool(flag) => Key::Ready(flag.to_string()),
                        Value::Number(number) => Key::Ready(number.to_string()),
                        Value::Array(_) | Value::Object(_) => Key::Skip,
                    };
                }
                Key::Ready(name) => {
                    map.insert(name, value);
                    *total += size;
                }
                Key::Skip => {}
            },
        }
    }

    fn scalar(&mut self, text: String, style: TScalarStyle, anchor: usize, tag: Option<&Tag>) {
        if !self.charge(1) {
            return;
        }
        let is_str_tag = tag.is_some_and(|tag| tag.suffix == "str");
        let value = if style != TScalarStyle::Plain || is_str_tag {
            Value::String(text)
        } else {
            match Yaml::from_str(&text) {
                Yaml::Null => Value::Null,
                Yaml::Boolean(flag) => Value::Bool(flag),
                Yaml::Integer(int) => Value::from(int),
                Yaml::Real(real) => real
                    .parse::<f64>()
                    .ok()
                    .and_then(serde_json::Number::from_f64)
                    .map_or(Value::String(real), Value::Number),
                _ => Value::String(text),
            }
        };
        self.place(value, 1, anchor);
    }
}

impl MarkedEventReceiver for Builder {
    fn on_event(&mut self, event: Event, _mark: Marker) {
        if self.failure.is_some() {
            return;
        }
        // Later documents of a multi-document stream are ignored.
        if self.root.is_some() && self.stack.is_empty() {
            return;
        }
        match event {
            Event::Scalar(text, style, anchor, tag) => {
                self.scalar(text, style, anchor, tag.as_ref());
            }
            Event::Alias(id) => {
                let (value, size) = self.anchors.get(&id).cloned().unwrap_or((Value::Null, 1));
                if self.charge(size) {
                    self.place(value, size, 0);
                }
            }
            Event::SequenceStart(anchor, _) => self.open(Frame::Sequence {
                items: Vec::new(),
                anchor,
                size: 1,
            }),
            Event::MappingStart(anchor, _) => self.open(Frame::Mapping {
                map: Map::new(),
                key: Key::Missing,
                anchor,
                size: 1,
            }),
            Event::SequenceEnd | Event::MappingEnd => match self.stack.pop() {
                Some(Frame::Sequence {
                    items,
                    anchor,
                    size,
                }) => self.place(Value::Array(items), size, anchor),
                Some(Frame::Mapping {
                    map, anchor, size, ..
                }) => self.place(Value::Object(map), size, anchor),
                None => {}
            },
            Event::Nothing
            | Event::StreamStart
            | Event::StreamEnd
            | Event::DocumentStart
            | Event::DocumentEnd => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use serde_json::json;

    use super::*;

    #[test]
    fn scalars_and_collections() {
        let value = to_json(
            "a: 1\nb: 1.5\nc: true\nd: ~\ne: '2'\nf: !!str 3\ng: [x, {h: i}]\n200: ok\nv: 3.0.3\n",
        )
        .unwrap();
        assert_eq!(
            value,
            json!({"a": 1, "b": 1.5, "c": true, "d": null, "e": "2", "f": "3",
                   "g": ["x", {"h": "i"}], "200": "ok", "v": "3.0.3"})
        );
    }

    #[test]
    fn anchors_and_aliases() {
        let value = to_json("base: &b {x: 1}\ncopy: *b\nlist: [&s s, *s]\n").unwrap();
        assert_eq!(
            value,
            json!({"base": {"x": 1}, "copy": {"x": 1}, "list": ["s", "s"]})
        );
    }

    #[test]
    fn complex_keys_are_dropped() {
        let value = to_json("? [a, b]\n: 1\nk: 2\n").unwrap();
        assert_eq!(value, json!({"k": 2}));
    }

    #[test]
    fn first_document_only() {
        assert_eq!(to_json("a: 1\n---\nb: 2\n").unwrap(), json!({"a": 1}));
        assert_eq!(to_json("").unwrap(), Value::Null);
    }

    #[test]
    fn billion_laughs_fails() {
        let mut text = String::from("a0: &a0 [x, x, x, x, x, x, x, x, x, x]\n");
        for level in 1..12 {
            let previous = level - 1;
            let _ = writeln!(
                text,
                "a{level}: &a{level} [*a{previous}, *a{previous}, *a{previous}, *a{previous}, *a{previous}, *a{previous}, *a{previous}, *a{previous}, *a{previous}, *a{previous}]"
            );
        }
        assert_eq!(to_json(&text).unwrap_err().code(), "too_large");
    }

    #[test]
    fn deep_nesting_fails() {
        // Either this crate's depth limit or the parser's own recursion
        // limit stops it; both are errors, not stack overflows.
        let text = format!("a: {}{}", "[".repeat(300), "]".repeat(300));
        let code = to_json(&text).unwrap_err().code();
        assert!(matches!(code, "too_large" | "parse_error"), "{code}");
    }

    #[test]
    fn syntax_errors() {
        assert_eq!(to_json("a: [1, 2\n").unwrap_err().code(), "parse_error");
    }
}
