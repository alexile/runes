//! A small, dependency-light JSON Schema validator.
//!
//! [`JsonSchema`] implements the subset of
//! [JSON Schema 2020-12](https://json-schema.org/draft/2020-12/json-schema-validation)
//! that structured LLM output needs in practice:
//!
//! - **any value:** `type` (a name or a list of names), `enum`, `const`,
//!   `allOf`, `anyOf`, `oneOf`, `not`, local `$ref` (`#`, `#/$defs/…`,
//!   `#/definitions/…` or any other JSON Pointer into the root schema), and
//!   the boolean schemas `true` and `false`;
//! - **objects:** `properties`, `required`, `additionalProperties`,
//!   `patternProperties`, `minProperties`, `maxProperties`;
//! - **arrays:** `items`, `prefixItems` (and the draft-07 array form of
//!   `items`), `minItems`, `maxItems`, `uniqueItems`;
//! - **strings:** `minLength`, `maxLength` (counted in Unicode scalar
//!   values), `pattern`;
//! - **numbers:** `minimum`, `maximum`, `exclusiveMinimum`,
//!   `exclusiveMaximum`, `multipleOf`.
//!
//! Annotation keywords (`title`, `description`, `default`, `examples`, …) and
//! `format` are accepted and ignored, as are keywords outside the subset.
//! Remote references are rejected when the schema is compiled.

use std::collections::HashMap;
use std::fmt;

use regex::Regex;
use serde_json::{Map, Number, Value};

use crate::StructuredError;

/// Upper bound on validator recursion, which also stops `$ref` cycles that
/// never descend into the instance (such as `{"$ref": "#"}`).
const MAX_DEPTH: usize = 128;

const TYPE_NAMES: [&str; 7] = [
    "null", "boolean", "object", "array", "string", "number", "integer",
];

/// One way in which a JSON instance fails its schema.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Violation {
    /// [RFC 6901](https://www.rfc-editor.org/rfc/rfc6901) JSON Pointer to the
    /// offending value; empty for the root.
    pub path: String,
    /// What is wrong, in words a model can act on.
    pub message: String,
}

impl Violation {
    fn new(path: &str, message: impl Into<String>) -> Self {
        Self {
            path: path.to_owned(),
            message: message.into(),
        }
    }
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let path = if self.path.is_empty() {
            "/"
        } else {
            &self.path
        };
        write!(f, "at {path}: {}", self.message)
    }
}

/// A compiled JSON Schema, ready to validate instances.
///
/// # Example
///
/// ```rust
/// use rune_chain_output_parser::JsonSchema;
/// use serde_json::json;
///
/// let schema = JsonSchema::new(json!({
///     "type": "object",
///     "properties": { "age": { "type": "integer", "minimum": 0 } },
///     "required": ["age"]
/// })).unwrap();
///
/// assert!(schema.validate(&json!({ "age": 7 })).is_ok());
/// let errors = schema.validate(&json!({ "age": -1 })).unwrap_err();
/// assert_eq!(errors[0].path, "/age");
/// ```
#[derive(Debug, Clone)]
pub struct JsonSchema {
    root: Value,
    patterns: HashMap<String, Regex>,
}

impl JsonSchema {
    /// Compile `schema`.
    ///
    /// Fails with [`StructuredError::InvalidSchema`] when the schema is not an
    /// object or boolean, names an unknown `type`, has a malformed
    /// `required` or `enum`, contains a `pattern` that is not a valid regular
    /// expression, or holds a `$ref` that is remote or does not resolve.
    pub fn new(schema: Value) -> Result<Self, StructuredError> {
        let mut patterns = HashMap::new();
        compile(&schema, &schema, "", &mut patterns, 0)?;
        Ok(Self {
            root: schema,
            patterns,
        })
    }

    /// The schema as it was given.
    #[must_use]
    pub const fn as_value(&self) -> &Value {
        &self.root
    }

    /// Validate `instance`, returning every violation found.
    pub fn validate(&self, instance: &Value) -> Result<(), Vec<Violation>> {
        let mut out = Vec::new();
        self.check(&self.root, instance, "", &mut out, 0);
        if out.is_empty() { Ok(()) } else { Err(out) }
    }

    /// Return `true` when `instance` satisfies the schema.
    #[must_use]
    pub fn is_valid(&self, instance: &Value) -> bool {
        self.validate(instance).is_ok()
    }

    fn passes(&self, schema: &Value, v: &Value, path: &str, depth: usize) -> bool {
        let mut tmp = Vec::new();
        self.check(schema, v, path, &mut tmp, depth);
        tmp.is_empty()
    }

    fn check(&self, schema: &Value, v: &Value, path: &str, out: &mut Vec<Violation>, depth: usize) {
        if depth > MAX_DEPTH {
            out.push(Violation::new(path, "schema nesting is too deep"));
            return;
        }
        let s = match schema {
            Value::Object(s) => s,
            Value::Bool(false) => {
                out.push(Violation::new(path, "no value is allowed here"));
                return;
            }
            // `true` and (already rejected at compile time) non-schemas.
            _ => return,
        };
        if let Some(Value::String(r)) = s.get("$ref")
            && let Some(target) = resolve_ref(&self.root, r)
        {
            self.check(target, v, path, out, depth + 1);
        }
        check_type(s, v, path, out);
        check_enum_const(s, v, path, out);
        self.check_combinators(s, v, path, out, depth);
        match v {
            Value::Object(o) => self.check_object(s, o, path, out, depth),
            Value::Array(a) => self.check_array(s, a, path, out, depth),
            Value::String(text) => self.check_string(s, text, path, out),
            Value::Number(n) => check_number(s, n, path, out),
            Value::Null | Value::Bool(_) => {}
        }
    }

    fn check_combinators(
        &self,
        s: &Map<String, Value>,
        v: &Value,
        path: &str,
        out: &mut Vec<Violation>,
        depth: usize,
    ) {
        if let Some(Value::Array(all)) = s.get("allOf") {
            for sub in all {
                self.check(sub, v, path, out, depth + 1);
            }
        }
        if let Some(Value::Array(any)) = s.get("anyOf")
            && !any.iter().any(|sub| self.passes(sub, v, path, depth + 1))
        {
            // Report the closest branch's violations when there is only one,
            // otherwise a summary: the model can't fix "one of these" lists.
            if let [only] = any.as_slice() {
                self.check(only, v, path, out, depth + 1);
            } else {
                out.push(Violation::new(
                    path,
                    format!("value matches none of the {} anyOf alternatives", any.len()),
                ));
            }
        }
        if let Some(Value::Array(one)) = s.get("oneOf") {
            let matched = one
                .iter()
                .filter(|sub| self.passes(sub, v, path, depth + 1))
                .count();
            if matched != 1 {
                out.push(Violation::new(
                    path,
                    format!(
                        "value must match exactly one oneOf alternative, but matches {matched}"
                    ),
                ));
            }
        }
        if let Some(not) = s.get("not")
            && self.passes(not, v, path, depth + 1)
        {
            out.push(Violation::new(
                path,
                "value matches a schema it must not match",
            ));
        }
    }

    fn check_object(
        &self,
        s: &Map<String, Value>,
        o: &Map<String, Value>,
        path: &str,
        out: &mut Vec<Violation>,
        depth: usize,
    ) {
        if let Some(Value::Array(req)) = s.get("required") {
            for key in req.iter().filter_map(Value::as_str) {
                if !o.contains_key(key) {
                    out.push(Violation::new(
                        path,
                        format!("missing required property \"{key}\""),
                    ));
                }
            }
        }
        check_count(
            s,
            "minProperties",
            "maxProperties",
            o.len(),
            "properties",
            path,
            out,
        );
        let props = s.get("properties").and_then(Value::as_object);
        let pattern_props = s.get("patternProperties").and_then(Value::as_object);
        for (key, val) in o {
            let child = child_path(path, key);
            let mut known = false;
            if let Some(sub) = props.and_then(|p| p.get(key)) {
                known = true;
                self.check(sub, val, &child, out, depth + 1);
            }
            for (pat, sub) in pattern_props.into_iter().flatten() {
                if self.patterns.get(pat).is_some_and(|re| re.is_match(key)) {
                    known = true;
                    self.check(sub, val, &child, out, depth + 1);
                }
            }
            if known {
                continue;
            }
            match s.get("additionalProperties") {
                Some(Value::Bool(false)) => out.push(Violation::new(
                    &child,
                    format!("property \"{key}\" is not allowed"),
                )),
                Some(sub) => self.check(sub, val, &child, out, depth + 1),
                None => {}
            }
        }
    }

    fn check_array(
        &self,
        s: &Map<String, Value>,
        a: &[Value],
        path: &str,
        out: &mut Vec<Violation>,
        depth: usize,
    ) {
        check_count(s, "minItems", "maxItems", a.len(), "items", path, out);
        // 2020-12 `prefixItems` + `items`, or draft-07 array-form `items`
        // (+ `additionalItems`).
        let (prefix, rest) = match (s.get("prefixItems"), s.get("items")) {
            (Some(Value::Array(p)), items) => (p.as_slice(), items),
            (_, Some(Value::Array(p))) => (p.as_slice(), s.get("additionalItems")),
            (_, items) => (&[][..], items),
        };
        for (i, item) in a.iter().enumerate() {
            let sub = prefix.get(i).or(rest);
            if let Some(sub) = sub {
                self.check(sub, item, &child_path(path, &i.to_string()), out, depth + 1);
            }
        }
        if s.get("uniqueItems") == Some(&Value::Bool(true)) {
            for (i, x) in a.iter().enumerate() {
                if a[..i].iter().any(|y| json_eq(x, y)) {
                    out.push(Violation::new(
                        &child_path(path, &i.to_string()),
                        "array items must be unique",
                    ));
                }
            }
        }
    }

    fn check_string(
        &self,
        s: &Map<String, Value>,
        text: &str,
        path: &str,
        out: &mut Vec<Violation>,
    ) {
        check_count(
            s,
            "minLength",
            "maxLength",
            text.chars().count(),
            "characters",
            path,
            out,
        );
        if let Some(Value::String(pat)) = s.get("pattern")
            && let Some(re) = self.patterns.get(pat)
            && !re.is_match(text)
        {
            out.push(Violation::new(
                path,
                format!("string does not match pattern {pat:?}"),
            ));
        }
    }
}

fn check_type(s: &Map<String, Value>, v: &Value, path: &str, out: &mut Vec<Violation>) {
    let ok = match s.get("type") {
        Some(Value::String(t)) => type_matches(t, v),
        Some(Value::Array(ts)) => ts
            .iter()
            .filter_map(Value::as_str)
            .any(|t| type_matches(t, v)),
        _ => true,
    };
    if !ok {
        let expected = match s.get("type") {
            Some(Value::String(t)) => t.clone(),
            Some(other) => other.to_string(),
            None => String::new(),
        };
        out.push(Violation::new(
            path,
            format!("expected type {expected}, found {}", type_name(v)),
        ));
    }
}

fn check_enum_const(s: &Map<String, Value>, v: &Value, path: &str, out: &mut Vec<Violation>) {
    if let Some(Value::Array(options)) = s.get("enum")
        && !options.iter().any(|o| json_eq(o, v))
    {
        let list: Vec<String> = options.iter().map(Value::to_string).collect();
        out.push(Violation::new(
            path,
            format!("value must be one of [{}]", list.join(", ")),
        ));
    }
    if let Some(c) = s.get("const")
        && !json_eq(c, v)
    {
        out.push(Violation::new(path, format!("value must equal {c}")));
    }
}

fn check_number(s: &Map<String, Value>, n: &Number, path: &str, out: &mut Vec<Violation>) {
    let Some(x) = n.as_f64() else { return };
    let bound = |k: &str| s.get(k).and_then(Value::as_f64);
    let mut fail = |msg: String| out.push(Violation::new(path, msg));
    if let Some(m) = bound("minimum")
        && x < m
    {
        fail(format!("{n} is less than the minimum {m}"));
    }
    if let Some(m) = bound("maximum")
        && x > m
    {
        fail(format!("{n} is greater than the maximum {m}"));
    }
    if let Some(m) = bound("exclusiveMinimum")
        && x <= m
    {
        fail(format!("{n} must be greater than {m}"));
    }
    if let Some(m) = bound("exclusiveMaximum")
        && x >= m
    {
        fail(format!("{n} must be less than {m}"));
    }
    if let Some(m) = bound("multipleOf")
        && m > 0.0
        && !is_multiple(n, x, s.get("multipleOf"), m)
    {
        fail(format!("{n} is not a multiple of {m}"));
    }
}

fn is_multiple(n: &Number, x: f64, divisor: Option<&Value>, m: f64) -> bool {
    if let (Some(a), Some(b)) = (n.as_i64(), divisor.and_then(Value::as_i64))
        && b != 0
    {
        return a % b == 0;
    }
    let q = x / m;
    q.is_finite() && (q - q.round()).abs() < 1e-9
}

#[allow(
    clippy::too_many_arguments,
    reason = "a shared helper for the three min/max count keyword pairs"
)]
fn check_count(
    s: &Map<String, Value>,
    min_key: &str,
    max_key: &str,
    len: usize,
    unit: &str,
    path: &str,
    out: &mut Vec<Violation>,
) {
    let len = u64::try_from(len).unwrap_or(u64::MAX);
    if let Some(min) = s.get(min_key).and_then(Value::as_u64)
        && len < min
    {
        out.push(Violation::new(
            path,
            format!("has {len} {unit}, fewer than the minimum {min}"),
        ));
    }
    if let Some(max) = s.get(max_key).and_then(Value::as_u64)
        && len > max
    {
        out.push(Violation::new(
            path,
            format!("has {len} {unit}, more than the maximum {max}"),
        ));
    }
}

fn type_matches(name: &str, v: &Value) -> bool {
    match name {
        "null" => v.is_null(),
        "boolean" => v.is_boolean(),
        "object" => v.is_object(),
        "array" => v.is_array(),
        "string" => v.is_string(),
        "number" => v.is_number(),
        "integer" => match v {
            Value::Number(n) => {
                n.is_i64()
                    || n.is_u64()
                    || n.as_f64()
                        .is_some_and(|f| f.is_finite() && f.fract() == 0.0)
            }
            _ => false,
        },
        _ => false,
    }
}

const fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// JSON equality per the spec: numbers compare by value, so `1` equals `1.0`.
fn json_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => num_eq(x, y),
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(p, q)| json_eq(p, q))
        }
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len()
                && x.iter()
                    .all(|(k, p)| y.get(k).is_some_and(|q| json_eq(p, q)))
        }
        _ => a == b,
    }
}

fn num_eq(x: &Number, y: &Number) -> bool {
    if let (Some(i), Some(j)) = (x.as_i64(), y.as_i64()) {
        return i == j;
    }
    if let (Some(i), Some(j)) = (x.as_u64(), y.as_u64()) {
        return i == j;
    }
    x.as_f64() == y.as_f64()
}

/// Append `segment` to a JSON Pointer, escaping `~` and `/` (RFC 6901 §3).
fn child_path(path: &str, segment: &str) -> String {
    let escaped = segment.replace('~', "~0").replace('/', "~1");
    format!("{path}/{escaped}")
}

fn resolve_ref<'a>(root: &'a Value, reference: &str) -> Option<&'a Value> {
    let pointer = reference.strip_prefix('#')?;
    if pointer.is_empty() {
        Some(root)
    } else {
        root.pointer(pointer)
    }
}

fn invalid(path: &str, msg: impl fmt::Display) -> StructuredError {
    let path = if path.is_empty() { "/" } else { path };
    StructuredError::InvalidSchema(format!("at {path}: {msg}"))
}

/// Walk the schema's subschemas, checking keyword shapes and compiling
/// every `pattern` / `patternProperties` regex once.
fn compile(
    root: &Value,
    schema: &Value,
    path: &str,
    patterns: &mut HashMap<String, Regex>,
    depth: usize,
) -> Result<(), StructuredError> {
    if depth > MAX_DEPTH {
        return Err(invalid(path, "schema nesting is too deep"));
    }
    let s = match schema {
        Value::Bool(_) => return Ok(()),
        Value::Object(s) => s,
        _ => return Err(invalid(path, "a schema must be an object or a boolean")),
    };
    compile_keywords(root, s, path, patterns)?;
    for key in ["properties", "patternProperties", "$defs", "definitions"] {
        if let Some(Value::Object(map)) = s.get(key) {
            for (name, sub) in map {
                let sub_path = child_path(&child_path(path, key), name);
                compile(root, sub, &sub_path, patterns, depth + 1)?;
            }
        }
    }
    for key in ["allOf", "anyOf", "oneOf", "prefixItems", "items"] {
        if let Some(Value::Array(list)) = s.get(key) {
            for (i, sub) in list.iter().enumerate() {
                let sub_path = child_path(&child_path(path, key), &i.to_string());
                compile(root, sub, &sub_path, patterns, depth + 1)?;
            }
        }
    }
    for key in ["items", "additionalProperties", "additionalItems", "not"] {
        if let Some(sub @ (Value::Object(_) | Value::Bool(_))) = s.get(key) {
            compile(root, sub, &child_path(path, key), patterns, depth + 1)?;
        }
    }
    Ok(())
}

fn compile_keywords(
    root: &Value,
    s: &Map<String, Value>,
    path: &str,
    patterns: &mut HashMap<String, Regex>,
) -> Result<(), StructuredError> {
    match s.get("type") {
        None => {}
        Some(Value::String(t)) => check_type_name(t, path)?,
        Some(Value::Array(ts)) => {
            for t in ts {
                let t = t
                    .as_str()
                    .ok_or_else(|| invalid(path, "\"type\" entries must be strings"))?;
                check_type_name(t, path)?;
            }
        }
        Some(_) => return Err(invalid(path, "\"type\" must be a string or an array")),
    }
    if let Some(req) = s.get("required")
        && !req
            .as_array()
            .is_some_and(|r| r.iter().all(Value::is_string))
    {
        return Err(invalid(path, "\"required\" must be an array of strings"));
    }
    if s.get("enum").is_some_and(|e| !e.is_array()) {
        return Err(invalid(path, "\"enum\" must be an array"));
    }
    if let Some(r) = s.get("$ref") {
        let r = r
            .as_str()
            .ok_or_else(|| invalid(path, "\"$ref\" must be a string"))?;
        if !r.starts_with('#') {
            return Err(invalid(
                path,
                format!("only local $ref is supported, got {r:?}"),
            ));
        }
        if resolve_ref(root, r).is_none() {
            return Err(invalid(path, format!("$ref {r:?} does not resolve")));
        }
    }
    let mut sources: Vec<&str> = Vec::new();
    if let Some(Value::String(p)) = s.get("pattern") {
        sources.push(p);
    }
    if let Some(Value::Object(pp)) = s.get("patternProperties") {
        sources.extend(pp.keys().map(String::as_str));
    }
    for src in sources {
        if !patterns.contains_key(src) {
            let re = Regex::new(src)
                .map_err(|e| invalid(path, format!("invalid pattern {src:?}: {e}")))?;
            patterns.insert(src.to_owned(), re);
        }
    }
    Ok(())
}

fn check_type_name(t: &str, path: &str) -> Result<(), StructuredError> {
    if TYPE_NAMES.contains(&t) {
        Ok(())
    } else {
        Err(invalid(path, format!("unknown type {t:?}")))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn schema(v: Value) -> JsonSchema {
        JsonSchema::new(v).unwrap()
    }

    fn paths(s: &JsonSchema, v: &Value) -> Vec<String> {
        s.validate(v)
            .err()
            .unwrap_or_default()
            .into_iter()
            .map(|v| v.path)
            .collect()
    }

    #[test]
    fn types() {
        let s = schema(json!({"type": "integer"}));
        assert!(s.is_valid(&json!(3)));
        assert!(s.is_valid(&json!(3.0)));
        assert!(!s.is_valid(&json!(3.5)));
        assert!(!s.is_valid(&json!("3")));
        let s = schema(json!({"type": ["string", "null"]}));
        assert!(s.is_valid(&json!(null)));
        assert!(s.is_valid(&json!("x")));
        assert!(!s.is_valid(&json!(1)));
    }

    #[test]
    fn boolean_schemas() {
        assert!(schema(json!(true)).is_valid(&json!({"any": 1})));
        assert!(!schema(json!(false)).is_valid(&json!(null)));
    }

    #[test]
    fn object_keywords() {
        let s = schema(json!({
            "type": "object",
            "properties": {"a": {"type": "string"}, "b": {"type": "number"}},
            "required": ["a", "b"],
            "additionalProperties": false
        }));
        assert!(s.is_valid(&json!({"a": "x", "b": 1})));
        let errs = s.validate(&json!({"a": 1, "c": true})).unwrap_err();
        assert_eq!(errs.len(), 3, "{errs:?}");
        assert!(errs.iter().any(|e| e.message.contains("\"b\"")));
        assert!(errs.iter().any(|e| e.path == "/a"));
        assert!(errs.iter().any(|e| e.path == "/c"));
    }

    #[test]
    fn additional_properties_schema_and_pattern_properties() {
        let s = schema(json!({
            "patternProperties": {"^x-": {"type": "string"}},
            "additionalProperties": {"type": "integer"}
        }));
        assert!(s.is_valid(&json!({"x-a": "s", "n": 1})));
        assert_eq!(paths(&s, &json!({"x-a": 1, "n": "s"})), ["/n", "/x-a"]);
    }

    #[test]
    fn property_counts() {
        let s = schema(json!({"minProperties": 1, "maxProperties": 2}));
        assert!(!s.is_valid(&json!({})));
        assert!(s.is_valid(&json!({"a": 1})));
        assert!(!s.is_valid(&json!({"a": 1, "b": 2, "c": 3})));
    }

    #[test]
    fn arrays() {
        let s = schema(json!({
            "type": "array",
            "items": {"type": "integer"},
            "minItems": 1,
            "maxItems": 3,
            "uniqueItems": true
        }));
        assert!(s.is_valid(&json!([1, 2])));
        assert!(!s.is_valid(&json!([])));
        assert!(!s.is_valid(&json!([1, 2, 3, 4])));
        assert_eq!(paths(&s, &json!([1, "x"])), ["/1"]);
        assert_eq!(paths(&s, &json!([1, 1.0])), ["/1"]);
    }

    #[test]
    fn prefix_items_both_drafts() {
        let new =
            schema(json!({"prefixItems": [{"type": "string"}], "items": {"type": "integer"}}));
        assert!(new.is_valid(&json!(["a", 1, 2])));
        assert!(!new.is_valid(&json!([1])));
        assert!(!new.is_valid(&json!(["a", "b"])));
        let old = schema(json!({"items": [{"type": "string"}], "additionalItems": false}));
        assert!(old.is_valid(&json!(["a"])));
        assert!(!old.is_valid(&json!(["a", 1])));
    }

    #[test]
    fn strings() {
        let s = schema(json!({"minLength": 2, "maxLength": 3, "pattern": "^[a-zé]+$"}));
        assert!(s.is_valid(&json!("éé")));
        assert!(!s.is_valid(&json!("a")));
        assert!(!s.is_valid(&json!("abcd")));
        assert!(!s.is_valid(&json!("AB")));
    }

    #[test]
    fn numbers() {
        let s = schema(json!({"minimum": 0, "exclusiveMaximum": 10, "multipleOf": 0.5}));
        assert!(s.is_valid(&json!(0)));
        assert!(s.is_valid(&json!(9.5)));
        assert!(!s.is_valid(&json!(-1)));
        assert!(!s.is_valid(&json!(10)));
        assert!(!s.is_valid(&json!(1.25)));
        let s = schema(json!({"multipleOf": 3}));
        assert!(s.is_valid(&json!(9)));
        assert!(!s.is_valid(&json!(10)));
    }

    #[test]
    fn enum_and_const() {
        let s = schema(json!({"enum": ["a", 1, null]}));
        assert!(s.is_valid(&json!(1.0)));
        assert!(s.is_valid(&json!(null)));
        assert!(!s.is_valid(&json!("b")));
        let s = schema(json!({"const": {"k": [1]}}));
        assert!(s.is_valid(&json!({"k": [1]})));
        assert!(!s.is_valid(&json!({"k": [2]})));
    }

    #[test]
    fn combinators() {
        let s = schema(json!({"anyOf": [{"type": "string"}, {"type": "integer"}]}));
        assert!(s.is_valid(&json!("x")));
        assert!(!s.is_valid(&json!(null)));
        let s = schema(json!({"oneOf": [{"type": "number"}, {"type": "integer"}]}));
        assert!(s.is_valid(&json!(1.5)));
        assert!(!s.is_valid(&json!(1)));
        let s = schema(json!({"allOf": [{"minimum": 1}, {"maximum": 2}], "not": {"const": 2}}));
        assert!(s.is_valid(&json!(1)));
        assert!(!s.is_valid(&json!(2)));
        assert!(!s.is_valid(&json!(3)));
    }

    #[test]
    fn refs() {
        let s = schema(json!({
            "$defs": {"node": {
                "type": "object",
                "properties": {"children": {"type": "array", "items": {"$ref": "#/$defs/node"}}},
                "required": ["children"]
            }},
            "$ref": "#/$defs/node"
        }));
        assert!(s.is_valid(&json!({"children": [{"children": []}]})));
        assert_eq!(
            paths(&s, &json!({"children": [{"kids": []}]})),
            ["/children/0"]
        );
    }

    #[test]
    fn self_ref_cycle_does_not_overflow() {
        let s = schema(json!({"$ref": "#"}));
        let errs = s.validate(&json!(1)).unwrap_err();
        assert!(errs[0].message.contains("too deep"));
    }

    #[test]
    fn pointer_escaping() {
        let s = schema(json!({"properties": {"a/b~c": {"type": "string"}}}));
        assert_eq!(paths(&s, &json!({"a/b~c": 1})), ["/a~1b~0c"]);
    }

    #[test]
    fn invalid_schemas_are_rejected() {
        for bad in [
            json!(1),
            json!({"type": "float"}),
            json!({"type": 3}),
            json!({"required": "a"}),
            json!({"enum": "a"}),
            json!({"pattern": "("}),
            json!({"$ref": "http://example.com/s.json"}),
            json!({"$ref": "#/$defs/missing"}),
            json!({"properties": {"a": 5}}),
        ] {
            assert!(
                matches!(
                    JsonSchema::new(bad.clone()),
                    Err(StructuredError::InvalidSchema(_))
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn violation_display() {
        let v = Violation::new("", "boom");
        assert_eq!(v.to_string(), "at /: boom");
        let v = Violation::new("/a", "boom");
        assert_eq!(v.to_string(), "at /a: boom");
    }
}
