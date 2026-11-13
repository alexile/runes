//! Provider dialects: tool definitions in the shapes `OpenAI`, Anthropic and
//! Gemini accept, and a lint for the schema keywords each one rejects or
//! ignores.
//!
//! The providers agree on the idea (a name, a description, a JSON Schema
//! for the arguments) but not on the details:
//!
//! | [`Dialect`] | Envelope | Names | Schema |
//! |---|---|---|---|
//! | [`OpenAi`](Dialect::OpenAi) | `{"type":"function","function":{name, description, parameters}}` | `[A-Za-z0-9_-]{1,64}` | JSON Schema, not enforced; no combinator at the root |
//! | [`OpenAiStrict`](Dialect::OpenAiStrict) | same, plus `"strict": true` | same | the structured-outputs subset: every property required, `additionalProperties: false` on every object, no `oneOf`/`allOf`/length keywords/`default` |
//! | [`Anthropic`](Dialect::Anthropic) | `{name, description, input_schema}` | `[A-Za-z0-9_-]{1,64}` | JSON Schema; no `oneOf`/`anyOf`/`allOf` at the root |
//! | [`Gemini`](Dialect::Gemini) | a `FunctionDeclaration`: `{name, description, parameters}` | letter or `_` first, then `[A-Za-z0-9_.:-]`, at most 64 | the `OpenAPI` 3 subset: upper-case types, `nullable`, `anyOf`, string-only `enum`; no `$ref`, `additionalProperties` or `const` |
//!
//! [`ToolDescriptor::export`](crate::ToolDescriptor::export) rewrites a
//! schema into the dialect where it can (making optional properties
//! nullable for strict mode, inlining `$ref`s and turning `["string",
//! "null"]` into `nullable` for Gemini), removes keywords the provider
//! would refuse, and reports every change as a [`SchemaFinding`]. When a
//! keyword the provider rejects cannot be rewritten or removed without
//! changing what the tool accepts structurally, export fails with
//! [`Error::UnsupportedSchema`](crate::Error::UnsupportedSchema).
//!
//! Removed constraints are no longer seen by the model, so check the
//! arguments that come back with
//! [`ToolDescriptor::validate_arguments`](crate::ToolDescriptor::validate_arguments)
//! against the original schema.
//!
//! The provider rules here reflect their public documentation as of late
//! 2025; they change, so treat findings as guidance and keep the original
//! schema as the source of truth.

use std::fmt;

use serde_json::{Map, Value};

use crate::Error;
use crate::args::{push_token, resolve_ref};
use crate::text::{MAX_DESCRIPTION_CHARS, find_hidden};

/// Deepest subschema nesting the dialect rewriter follows.
const MAX_WALK_DEPTH: usize = 64;
/// Most subschemas one rewrite or walk may visit. `$ref` inlining copies
/// subtrees, so a chain of references can otherwise grow exponentially.
const MAX_WALK_STEPS: usize = 20_000;
/// `OpenAI` strict mode: deepest object nesting.
const OPENAI_MAX_NESTING: usize = 10;
/// `OpenAI` strict mode: most object properties in one schema.
const OPENAI_MAX_PROPERTIES: usize = 5000;
/// `OpenAI` strict mode: most enum values in one schema.
const OPENAI_MAX_ENUM_VALUES: usize = 1000;
/// String formats `OpenAI` strict mode accepts.
const OPENAI_FORMATS: &[&str] = &[
    "date-time",
    "time",
    "date",
    "duration",
    "email",
    "hostname",
    "ipv4",
    "ipv6",
    "uuid",
];
/// Keywords that only annotate a schema.
const ANNOTATIONS: &[&str] = &[
    "$schema",
    "$id",
    "$comment",
    "examples",
    "deprecated",
    "readOnly",
    "writeOnly",
];

/// A provider's tool-definition format.
///
/// ```
/// use rune_tool_schema::Dialect;
///
/// assert!(Dialect::OpenAi.validate_name("get_weather").is_ok());
/// assert!(Dialect::OpenAi.validate_name("files.read").is_err());
/// assert!(Dialect::Gemini.validate_name("files.read").is_ok());
/// assert!(Dialect::Gemini.validate_name("1st").is_err());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Dialect {
    /// `OpenAI` function calling (Chat Completions envelope), schema not
    /// enforced.
    OpenAi,
    /// `OpenAI` function calling with `"strict": true` (structured outputs).
    OpenAiStrict,
    /// Anthropic Messages API tools.
    Anthropic,
    /// Gemini function declarations.
    Gemini,
}

impl Dialect {
    /// Every dialect.
    pub const ALL: [Self; 4] = [
        Self::OpenAi,
        Self::OpenAiStrict,
        Self::Anthropic,
        Self::Gemini,
    ];

    /// Short lowercase name: `openai`, `openai_strict`, `anthropic`,
    /// `gemini`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OpenAi => "openai",
            Self::OpenAiStrict => "openai_strict",
            Self::Anthropic => "anthropic",
            Self::Gemini => "gemini",
        }
    }

    /// Longest tool name the provider accepts, in characters.
    #[must_use]
    pub const fn max_name_len(self) -> usize {
        64
    }

    /// Check a tool name against the provider's rules (see the
    /// [module docs](self)).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidName`] naming the rule broken.
    pub fn validate_name(self, name: &str) -> Result<(), Error> {
        let reason = if name.is_empty() {
            Some("empty")
        } else if name.len() > self.max_name_len() {
            Some("longer than 64 characters")
        } else {
            match self {
                Self::OpenAi | Self::OpenAiStrict | Self::Anthropic => (!name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')))
                .then_some("only A-Z, a-z, 0-9, '_' and '-' are allowed"),
                Self::Gemini => {
                    let first_ok = name
                        .bytes()
                        .next()
                        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_');
                    if first_ok {
                        (!name.bytes().all(|b| {
                            b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'-')
                        }))
                        .then_some("only A-Z, a-z, 0-9, '_', '.', ':' and '-' are allowed")
                    } else {
                        Some("must start with a letter or '_'")
                    }
                }
            }
        };
        reason.map_or(Ok(()), |reason| {
            Err(Error::InvalidName {
                name: name.to_owned(),
                reason,
            })
        })
    }

    /// Lint an input schema: every keyword this provider would reject or
    /// ignore, and what [`ToolDescriptor::export`](crate::ToolDescriptor::export)
    /// does about it.
    ///
    /// ```
    /// use rune_tool_schema::{Action, Dialect, Severity};
    /// use serde_json::json;
    ///
    /// let schema = json!({
    ///     "type": "object",
    ///     "properties": {
    ///         "q": { "type": "string", "maxLength": 200 },
    ///         "limit": { "type": "integer" }
    ///     },
    ///     "required": ["q"]
    /// });
    /// let findings = Dialect::OpenAiStrict.lint(&schema);
    /// let summary: Vec<_> = findings
    ///     .iter()
    ///     .map(|f| (f.pointer.as_str(), f.keyword.as_str(), f.action))
    ///     .collect();
    /// assert_eq!(summary, [
    ///     ("/properties/q/maxLength", "maxLength", Action::Removed),
    ///     ("/properties/limit", "required", Action::Rewritten),
    /// ]);
    /// assert!(findings.iter().all(|f| f.severity == Severity::Rejected));
    /// assert!(Dialect::Anthropic.lint(&schema).is_empty());
    /// ```
    #[must_use]
    pub fn lint(self, schema: &Value) -> Vec<SchemaFinding> {
        convert(self, schema).1
    }
}

impl fmt::Display for Dialect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How the provider treats a keyword as written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Severity {
    /// The request fails, or the keyword is outside the provider's
    /// supported subset.
    Rejected,
    /// Accepted but not used.
    Ignored,
}

/// What export did about a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Action {
    /// Left in place. A [`Severity::Rejected`] finding left in place makes
    /// export fail.
    Kept,
    /// Removed from the exported schema.
    Removed,
    /// Rewritten into an equivalent or close form the provider accepts.
    Rewritten,
}

/// One keyword a provider rejects or ignores.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SchemaFinding {
    /// JSON Pointer to the schema location, in the schema as written with
    /// `$ref`s followed. Keys longer than 128 characters are shortened.
    pub pointer: String,
    /// The keyword concerned.
    pub keyword: String,
    /// How the provider treats it.
    pub severity: Severity,
    /// What export did about it.
    pub action: Action,
    /// One sentence of explanation.
    pub message: String,
}

impl SchemaFinding {
    /// Whether this finding stops export: rejected and left in place.
    #[must_use]
    pub fn is_blocking(&self) -> bool {
        self.severity == Severity::Rejected && self.action == Action::Kept
    }
}

impl fmt::Display for SchemaFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let pointer = if self.pointer.is_empty() {
            "/"
        } else {
            &self.pointer
        };
        write!(f, "{pointer}: {} ({}", self.message, self.keyword)?;
        match self.action {
            Action::Kept => f.write_str(")"),
            Action::Removed => f.write_str(", removed)"),
            Action::Rewritten => f.write_str(", rewritten)"),
        }
    }
}

/// Options for [`ToolDescriptor::export_with`](crate::ToolDescriptor::export_with).
///
/// ```
/// use rune_tool_schema::ExportOptions;
///
/// let options = ExportOptions::default().with_max_description_chars(1024);
/// assert!(options.sanitize);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExportOptions {
    /// Longest description accepted, in characters, after sanitizing.
    /// Default [`MAX_DESCRIPTION_CHARS`].
    pub max_description_chars: usize,
    /// Strip [hidden characters](crate::is_hidden_char) from the
    /// description and from `description` and `title` strings inside the
    /// schema. When off, hidden characters there are an error. Hidden
    /// characters in property names or `enum` values are always an error,
    /// since removing them would change the arguments. Default on.
    pub sanitize: bool,
}

impl Default for ExportOptions {
    fn default() -> Self {
        Self {
            max_description_chars: MAX_DESCRIPTION_CHARS,
            sanitize: true,
        }
    }
}

impl ExportOptions {
    /// Set [`Self::max_description_chars`].
    #[must_use]
    pub const fn with_max_description_chars(mut self, max: usize) -> Self {
        self.max_description_chars = max;
        self
    }

    /// Set [`Self::sanitize`].
    #[must_use]
    pub const fn with_sanitize(mut self, sanitize: bool) -> Self {
        self.sanitize = sanitize;
        self
    }
}

/// A tool definition in one provider's format.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct ProviderTool {
    /// The dialect it was exported for.
    pub dialect: Dialect,
    /// The JSON to put in the request's tool list.
    pub definition: Value,
    /// What was rewritten or removed on the way (none blocking).
    pub findings: Vec<SchemaFinding>,
}

/// Undo the strict-mode rewrite on arguments a model sent back: remove
/// object properties whose value is `null` when the original `schema`
/// neither requires them nor accepts `null` for them.
///
/// [`Dialect::OpenAiStrict`] makes every optional property required and
/// nullable, so the model answers `"units": null` where the tool expects
/// the key to be absent. Run this before
/// [`ToolDescriptor::validate_arguments`](crate::ToolDescriptor::validate_arguments)
/// on the original descriptor. Local `$ref`s are followed, to a bounded
/// depth.
///
/// ```
/// use rune_tool_schema::drop_optional_nulls;
/// use serde_json::json;
///
/// let schema = json!({
///     "type": "object",
///     "properties": {
///         "city": { "type": "string" },
///         "units": { "type": "string" },
///         "note": { "type": ["string", "null"] }
///     },
///     "required": ["city"]
/// });
/// let mut args = json!({ "city": "Oslo", "units": null, "note": null });
/// drop_optional_nulls(&schema, &mut args);
/// assert_eq!(args, json!({ "city": "Oslo", "note": null }));
/// ```
pub fn drop_optional_nulls(schema: &Value, arguments: &mut Value) {
    let mut budget = MAX_WALK_STEPS;
    drop_nulls(schema, schema, arguments, 0, &mut budget);
}

/// Spend one step of a walk's budget; `false` once it is used up.
const fn spend(budget: &mut usize) -> bool {
    if *budget == 0 {
        return false;
    }
    *budget -= 1;
    true
}

fn drop_nulls(root: &Value, schema: &Value, value: &mut Value, depth: usize, budget: &mut usize) {
    if depth > MAX_WALK_DEPTH || !spend(budget) {
        return;
    }
    let Some(map) = schema.as_object() else {
        return;
    };
    if let Some(target) = map
        .get("$ref")
        .and_then(Value::as_str)
        .and_then(|r| resolve_ref(root, r))
    {
        drop_nulls(root, target, value, depth + 1, budget);
    }
    match value {
        Value::Object(object) => {
            let Some(props) = map.get("properties").and_then(Value::as_object) else {
                return;
            };
            let required = |name: &str| {
                map.get("required")
                    .and_then(Value::as_array)
                    .is_some_and(|r| r.iter().any(|n| n.as_str() == Some(name)))
            };
            object.retain(|name, v| {
                !(v.is_null()
                    && !required(name)
                    && props
                        .get(name)
                        .is_some_and(|s| !accepts_null(root, s, 0, budget)))
            });
            for (name, v) in object.iter_mut() {
                if let Some(sub) = props.get(name) {
                    drop_nulls(root, sub, v, depth + 1, budget);
                }
            }
        }
        Value::Array(items) => {
            if let Some(item_schema) = map.get("items").filter(|s| s.is_object()) {
                for item in items {
                    drop_nulls(root, item_schema, item, depth + 1, budget);
                }
            }
        }
        _ => {}
    }
}

/// Whether `schema` plausibly accepts `null` (type, enum, combinators,
/// refs, or no type constraint at all). Answers yes when the walk runs
/// out of depth or budget, which keeps the value.
fn accepts_null(root: &Value, schema: &Value, depth: usize, budget: &mut usize) -> bool {
    if depth > MAX_WALK_DEPTH || !spend(budget) {
        return true;
    }
    let Some(map) = schema.as_object() else {
        return schema.as_bool().unwrap_or(true);
    };
    if let Some(target) = map
        .get("$ref")
        .and_then(Value::as_str)
        .and_then(|r| resolve_ref(root, r))
    {
        return accepts_null(root, target, depth + 1, budget);
    }
    for key in ["anyOf", "oneOf"] {
        if let Some(list) = map.get(key).and_then(Value::as_array) {
            return list
                .iter()
                .any(|s| accepts_null(root, s, depth + 1, budget));
        }
    }
    if let Some(values) = map.get("enum").and_then(Value::as_array) {
        return values.iter().any(Value::is_null);
    }
    if let Some(constant) = map.get("const") {
        return constant.is_null();
    }
    match map.get("type") {
        None => true,
        Some(_) => type_includes(map, "null"),
    }
}

/// Convert `schema` into `dialect`, returning the converted schema and
/// every finding (blocking ones included).
pub fn convert(dialect: Dialect, schema: &Value) -> (Value, Vec<SchemaFinding>) {
    let mut converter = Converter {
        dialect,
        root: schema,
        findings: Vec::new(),
        ref_stack: Vec::new(),
        properties: 0,
        enum_values: 0,
        steps: 0,
    };
    let mut pointer = String::new();
    converter.check_root(schema);
    let rewritten = match dialect {
        Dialect::OpenAi | Dialect::Anthropic => schema.clone(),
        Dialect::OpenAiStrict => {
            let out = converter.strict(schema, &pointer, 0, 0);
            if converter.properties > OPENAI_MAX_PROPERTIES {
                converter.blocking("", "properties", "more than 5000 properties in one schema");
            }
            if converter.enum_values > OPENAI_MAX_ENUM_VALUES {
                converter.blocking("", "enum", "more than 1000 enum values in one schema");
            }
            out
        }
        Dialect::Gemini => converter.gemini(schema, &mut pointer, 0),
    };
    (rewritten, converter.findings)
}

/// The definition envelope for `dialect`.
pub fn envelope(dialect: Dialect, name: &str, description: &str, schema: Value) -> Value {
    match dialect {
        Dialect::OpenAi => serde_json::json!({
            "type": "function",
            "function": { "name": name, "description": description, "parameters": schema }
        }),
        Dialect::OpenAiStrict => serde_json::json!({
            "type": "function",
            "function": {
                "name": name, "description": description, "parameters": schema, "strict": true
            }
        }),
        Dialect::Anthropic => serde_json::json!({
            "name": name, "description": description, "input_schema": schema
        }),
        Dialect::Gemini => {
            let has_properties = schema
                .get("properties")
                .and_then(Value::as_object)
                .is_some_and(|p| !p.is_empty());
            let mut declaration = serde_json::json!({ "name": name, "description": description });
            // Gemini refuses an OBJECT without properties; a tool without
            // arguments simply has no `parameters`.
            if has_properties && let Value::Object(map) = &mut declaration {
                map.insert("parameters".to_owned(), schema);
            }
            declaration
        }
    }
}

/// Strip hidden characters from `description` and `title` strings in a
/// schema, down to a bounded depth.
pub fn sanitize_annotations(schema: &mut Value, depth: usize) {
    if depth > MAX_WALK_DEPTH {
        return;
    }
    match schema {
        Value::Object(map) => {
            for (key, value) in map.iter_mut() {
                match value {
                    Value::String(text) if matches!(key.as_str(), "description" | "title") => {
                        if let std::borrow::Cow::Owned(clean) = crate::strip_hidden(text) {
                            *text = clean;
                        }
                    }
                    other => sanitize_annotations(other, depth + 1),
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                sanitize_annotations(item, depth + 1);
            }
        }
        _ => {}
    }
}

/// The first hidden character anywhere in `value` (object keys included),
/// as a JSON Pointer and the character.
pub fn find_hidden_in(value: &Value, pointer: &mut String, depth: usize) -> Option<(String, char)> {
    if depth > MAX_WALK_DEPTH {
        return None;
    }
    match value {
        Value::String(text) => find_hidden(text).map(|(_, c)| (pointer.clone(), c)),
        Value::Array(items) => items.iter().enumerate().find_map(|(i, item)| {
            let len = pointer.len();
            push_token(pointer, &i.to_string());
            let found = find_hidden_in(item, pointer, depth + 1);
            pointer.truncate(len);
            found
        }),
        Value::Object(map) => map.iter().find_map(|(key, item)| {
            let len = pointer.len();
            push_token(pointer, key);
            let found = find_hidden(key)
                .map(|(_, c)| (pointer.clone(), c))
                .or_else(|| find_hidden_in(item, pointer, depth + 1));
            pointer.truncate(len);
            found
        }),
        _ => None,
    }
}

struct Converter<'a> {
    dialect: Dialect,
    root: &'a Value,
    findings: Vec<SchemaFinding>,
    /// The `$ref` targets being inlined, by identity, so aliases of the
    /// same location (`#/$defs/a`, `#/%24defs/a`) are caught as cycles.
    ref_stack: Vec<&'a Value>,
    properties: usize,
    enum_values: usize,
    steps: usize,
}

fn at(pointer: &str, key: &str) -> String {
    let mut p = pointer.to_owned();
    push_token(&mut p, key);
    p
}

impl Converter<'_> {
    fn push(
        &mut self,
        pointer: &str,
        keyword: &str,
        severity: Severity,
        action: Action,
        message: &str,
    ) {
        self.findings.push(SchemaFinding {
            pointer: pointer.to_owned(),
            keyword: keyword.to_owned(),
            severity,
            action,
            message: message.to_owned(),
        });
    }

    fn blocking(&mut self, pointer: &str, keyword: &str, message: &str) {
        self.push(pointer, keyword, Severity::Rejected, Action::Kept, message);
    }

    /// Rules every dialect applies to the root schema.
    fn check_root(&mut self, schema: &Value) {
        let is_object = schema.get("type").and_then(Value::as_str) == Some("object");
        if !is_object {
            self.blocking("", "type", "the root schema must have \"type\": \"object\"");
        }
        let forbidden: &[&str] = match self.dialect {
            Dialect::OpenAi | Dialect::OpenAiStrict => &["anyOf", "oneOf", "allOf", "enum", "not"],
            Dialect::Anthropic => &["anyOf", "oneOf", "allOf"],
            Dialect::Gemini => &[],
        };
        for keyword in forbidden {
            if schema.get(keyword).is_some() {
                self.blocking(
                    &at("", keyword),
                    keyword,
                    "not allowed at the top level of a tool's input schema",
                );
            }
        }
    }

    /// Add the node count of `value` to the steps taken; `false` when that
    /// exceeds the budget.
    fn charge(&mut self, value: &Value) -> bool {
        let mut stack = vec![value];
        while let Some(node) = stack.pop() {
            self.steps += 1;
            if self.steps > MAX_WALK_STEPS {
                return false;
            }
            match node {
                Value::Array(items) => stack.extend(items),
                Value::Object(map) => stack.extend(map.values()),
                _ => {}
            }
        }
        true
    }

    /// Count one visited subschema; `true` when the walk must stop because
    /// it is too deep or has used up its step budget.
    fn too_deep(&mut self, pointer: &str, depth: usize) -> bool {
        self.steps += 1;
        if self.steps == MAX_WALK_STEPS + 1 {
            self.blocking(pointer, "", "schema too large to convert");
        }
        if self.steps > MAX_WALK_STEPS {
            return true;
        }
        if depth > MAX_WALK_DEPTH {
            self.blocking(pointer, "", "schema nested too deeply to convert");
            true
        } else {
            false
        }
    }

    // ---- OpenAI strict ----

    fn strict(&mut self, node: &Value, pointer: &str, depth: usize, nesting: usize) -> Value {
        if self.too_deep(pointer, depth) {
            // The finding blocks export, so the output is never used.
            return Value::Null;
        }
        let Value::Object(map) = node else {
            self.blocking(
                pointer,
                "",
                "strict mode needs every subschema to be an object",
            );
            return Value::Null;
        };
        let mut out = Map::new();
        let is_string = type_includes(map, "string");
        for (key, value) in map {
            let here = at(pointer, key);
            match key.as_str() {
                "type"
                | "description"
                | "title"
                | "const"
                | "pattern"
                | "minimum"
                | "maximum"
                | "exclusiveMinimum"
                | "exclusiveMaximum"
                | "multipleOf"
                | "minItems"
                | "maxItems"
                | "$ref"
                | "required"
                | "additionalProperties" => {
                    out.insert(key.clone(), value.clone());
                }
                "enum" => {
                    self.enum_values += value.as_array().map_or(0, Vec::len);
                    out.insert(key.clone(), value.clone());
                }
                "format" => {
                    if is_string && value.as_str().is_some_and(|f| OPENAI_FORMATS.contains(&f)) {
                        out.insert(key.clone(), value.clone());
                    } else {
                        self.push(
                            &here,
                            key,
                            Severity::Rejected,
                            Action::Removed,
                            "format not supported in strict mode",
                        );
                    }
                }
                "anyOf" | "oneOf" => {
                    if key == "oneOf" {
                        self.push(
                            &here,
                            key,
                            Severity::Rejected,
                            Action::Rewritten,
                            "oneOf is not supported in strict mode; rewritten as anyOf",
                        );
                    }
                    let list = self.strict_list(value, &here, depth, nesting);
                    out.insert("anyOf".to_owned(), list);
                }
                "allOf"
                | "not"
                | "if"
                | "then"
                | "else"
                | "prefixItems"
                | "patternProperties"
                | "dependentRequired"
                | "dependentSchemas"
                | "unevaluatedProperties"
                | "propertyNames"
                | "contains" => {
                    self.blocking(&here, key, "not supported in strict mode");
                    out.insert(key.clone(), value.clone());
                }
                "properties" => {
                    let mut props = Map::new();
                    if let Value::Object(children) = value {
                        self.properties += children.len();
                        for (name, child) in children {
                            let p = at(&here, name);
                            props.insert(
                                name.clone(),
                                self.strict(child, &p, depth + 1, nesting + 1),
                            );
                        }
                    }
                    out.insert(key.clone(), Value::Object(props));
                }
                "items" => {
                    if value.is_object() {
                        let p = here;
                        out.insert(key.clone(), self.strict(value, &p, depth + 1, nesting));
                    } else {
                        self.blocking(
                            &here,
                            key,
                            "tuple-style items are not supported in strict mode",
                        );
                        out.insert(key.clone(), value.clone());
                    }
                }
                "$defs" | "definitions" => {
                    let mut defs = Map::new();
                    if let Value::Object(children) = value {
                        for (name, child) in children {
                            let p = at(&here, name);
                            defs.insert(name.clone(), self.strict(child, &p, depth + 1, 0));
                        }
                    }
                    out.insert(key.clone(), Value::Object(defs));
                }
                k if ANNOTATIONS.contains(&k) => {
                    self.push(
                        &here,
                        key,
                        Severity::Ignored,
                        Action::Removed,
                        "annotation outside the strict-mode subset",
                    );
                }
                _ => {
                    self.push(
                        &here,
                        key,
                        Severity::Rejected,
                        Action::Removed,
                        "keyword not supported in strict mode",
                    );
                }
            }
        }
        if out.contains_key("properties") || type_includes(map, "object") {
            if nesting > OPENAI_MAX_NESTING {
                self.blocking(
                    pointer,
                    "properties",
                    "objects nested more than 10 levels deep",
                );
            }
            self.strict_object(&mut out, pointer);
        }
        Value::Object(out)
    }

    fn strict_list(&mut self, value: &Value, pointer: &str, depth: usize, nesting: usize) -> Value {
        let Value::Array(items) = value else {
            return value.clone();
        };
        Value::Array(
            items
                .iter()
                .enumerate()
                .map(|(i, item)| {
                    let p = at(pointer, &i.to_string());
                    self.strict(item, &p, depth + 1, nesting)
                })
                .collect(),
        )
    }

    /// `additionalProperties: false` and every property required.
    fn strict_object(&mut self, out: &mut Map<String, Value>, pointer: &str) {
        match out.get("additionalProperties") {
            None | Some(Value::Bool(false)) => {}
            Some(_) => self.push(
                &at(pointer, "additionalProperties"),
                "additionalProperties",
                Severity::Rejected,
                Action::Rewritten,
                "strict mode needs additionalProperties: false; extra keys are no longer allowed",
            ),
        }
        out.insert("additionalProperties".to_owned(), Value::Bool(false));
        let required: Vec<String> = out
            .get("required")
            .and_then(Value::as_array)
            .map(|names| {
                names
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        let mut all = Vec::new();
        if let Some(Value::Object(props)) = out.get_mut("properties") {
            for (name, schema) in props.iter_mut() {
                all.push(Value::String(name.clone()));
                if !required.contains(name) {
                    make_nullable(schema);
                    self.push(
                        &at(&at(pointer, "properties"), name),
                        "required",
                        Severity::Rejected,
                        Action::Rewritten,
                        "strict mode needs every property required; made nullable instead",
                    );
                }
            }
        }
        out.insert("required".to_owned(), Value::Array(all));
    }

    // ---- Gemini ----

    fn gemini(&mut self, node: &Value, pointer: &mut String, depth: usize) -> Value {
        if self.too_deep(pointer, depth) {
            // The finding blocks export, so the output is never used.
            return Value::Null;
        }
        let Value::Object(map) = node else {
            self.blocking(pointer, "", "Gemini needs every subschema to be an object");
            return Value::Null;
        };
        if let Some(reference) = map.get("$ref") {
            return self.gemini_ref(map, reference, pointer, depth);
        }
        let mut out = Map::new();
        let mut nullable = false;
        let mut alternatives: Vec<Value> = Vec::new();
        let declared = lower_type(map);
        for (key, value) in map {
            let here = at(pointer, key);
            match key.as_str() {
                "type" => match value {
                    Value::String(t) if t == "null" => {
                        self.blocking(&here, key, "Gemini has no null type");
                    }
                    Value::String(t) => {
                        out.insert(key.clone(), Value::String(t.to_ascii_uppercase()));
                    }
                    Value::Array(types) => {
                        let mut kept: Vec<&str> = Vec::new();
                        for t in types.iter().filter_map(Value::as_str) {
                            if t == "null" {
                                nullable = true;
                            } else {
                                kept.push(t);
                            }
                        }
                        match kept.as_slice() {
                            [] => self.blocking(&here, key, "Gemini has no null type"),
                            [one] => {
                                out.insert(key.clone(), Value::String(one.to_ascii_uppercase()));
                            }
                            many => {
                                self.push(&here, key, Severity::Rejected, Action::Rewritten,
                                    "type lists are not supported; rewritten as anyOf");
                                alternatives.extend(many.iter().map(|t| {
                                    serde_json::json!({ "type": t.to_ascii_uppercase() })
                                }));
                            }
                        }
                        if nullable && kept.len() == 1 {
                            self.push(&here, key, Severity::Rejected, Action::Rewritten,
                                "null in a type list is written as nullable: true");
                        }
                    }
                    _ => self.blocking(&here, key, "type must be a string"),
                },
                "description" | "title" | "pattern" | "minLength" | "maxLength" | "minItems"
                | "maxItems" | "minProperties" | "maxProperties" | "minimum" | "maximum"
                | "required" | "nullable" | "propertyOrdering" | "example" | "default" => {
                    out.insert(key.clone(), value.clone());
                }
                "format" => {
                    let ok = matches!(
                        (declared.as_deref(), value.as_str()),
                        (Some("string"), Some("enum" | "date-time"))
                            | (Some("number"), Some("float" | "double"))
                            | (Some("integer"), Some("int32" | "int64"))
                    );
                    if ok {
                        out.insert(key.clone(), value.clone());
                    } else {
                        self.push(&here, key, Severity::Rejected, Action::Removed,
                            "format not supported by Gemini for this type");
                    }
                }
                "enum" => self.gemini_enum(value, &here, &mut out, &mut nullable),
                "const" => match value {
                    Value::String(_) => {
                        self.push(&here, key, Severity::Rejected, Action::Rewritten,
                            "const is not supported; rewritten as a one-value enum");
                        out.insert("enum".to_owned(), Value::Array(vec![value.clone()]));
                        out.entry("type").or_insert_with(|| "STRING".into());
                    }
                    _ => self.push(&here, key, Severity::Rejected, Action::Removed,
                        "const is not supported, and Gemini enums hold only strings"),
                },
                "properties" => {
                    let mut props = Map::new();
                    if let Value::Object(children) = value {
                        for (name, child) in children {
                            let mut p = at(&here, name);
                            props.insert(name.clone(), self.gemini(child, &mut p, depth + 1));
                        }
                    }
                    out.insert(key.clone(), Value::Object(props));
                }
                "items" => {
                    if value.is_object() {
                        let mut p = here;
                        out.insert(key.clone(), self.gemini(value, &mut p, depth + 1));
                    } else {
                        self.blocking(&here, key, "tuple-style items are not supported by Gemini");
                    }
                }
                "anyOf" | "oneOf" => {
                    if key == "oneOf" {
                        self.push(&here, key, Severity::Rejected, Action::Rewritten,
                            "oneOf is not supported; rewritten as anyOf");
                    }
                    if let Value::Array(list) = value {
                        for (i, item) in list.iter().enumerate() {
                            if is_null_schema(item) {
                                nullable = true;
                                continue;
                            }
                            let mut p = at(&here, &i.to_string());
                            alternatives.push(self.gemini(item, &mut p, depth + 1));
                        }
                    }
                }
                "allOf" => match value.as_array().map(Vec::as_slice) {
                    Some([only]) => {
                        let mut p = at(&here, "0");
                        if let Value::Object(merged) = self.gemini(only, &mut p, depth + 1) {
                            for (k, v) in merged {
                                out.entry(k).or_insert(v);
                            }
                        }
                    }
                    _ => self.blocking(&here, key, "allOf is not supported by Gemini"),
                },
                "$defs" | "definitions" => {}
                "additionalProperties" => self.push(&here, key, Severity::Rejected, Action::Removed,
                    "Gemini does not accept additionalProperties; validate arguments for unknown keys"),
                k if ANNOTATIONS.contains(&k) => self.push(&here, key, Severity::Ignored, Action::Removed,
                    "annotation outside Gemini's schema subset"),
                _ => self.push(&here, key, Severity::Rejected, Action::Removed,
                    "keyword not supported by Gemini"),
            }
        }
        match alternatives.len() {
            0 => {}
            1 if !out.contains_key("type") => {
                if let Some(Value::Object(only)) = alternatives.pop() {
                    for (k, v) in only {
                        out.entry(k).or_insert(v);
                    }
                }
            }
            _ => {
                out.insert("anyOf".to_owned(), Value::Array(alternatives));
            }
        }
        if nullable {
            out.insert("nullable".to_owned(), Value::Bool(true));
        }
        Value::Object(out)
    }

    fn gemini_enum(
        &mut self,
        value: &Value,
        here: &str,
        out: &mut Map<String, Value>,
        nullable: &mut bool,
    ) {
        let Value::Array(values) = value else {
            self.push(
                here,
                "enum",
                Severity::Rejected,
                Action::Removed,
                "enum must be an array",
            );
            return;
        };
        if values.iter().any(Value::is_null) {
            *nullable = true;
        }
        let strings: Vec<Value> = values.iter().filter(|v| !v.is_null()).cloned().collect();
        if strings.iter().all(Value::is_string) {
            out.insert("enum".to_owned(), Value::Array(strings));
            out.entry("type").or_insert_with(|| "STRING".into());
        } else {
            self.push(
                here,
                "enum",
                Severity::Rejected,
                Action::Removed,
                "Gemini enums hold only strings",
            );
            // Keep the type the values imply, so the property is not left
            // untyped.
            if let Some(inferred) = common_type(&strings) {
                out.entry("type").or_insert_with(|| inferred.into());
            }
        }
    }

    /// Inline a `$ref`, overlaying its sibling keywords.
    fn gemini_ref(
        &mut self,
        map: &Map<String, Value>,
        reference: &Value,
        pointer: &mut String,
        depth: usize,
    ) -> Value {
        let here = at(pointer, "$ref");
        let target = reference.as_str().and_then(|r| resolve_ref(self.root, r));
        let Some(target) = target else {
            self.blocking(
                &here,
                "$ref",
                "$ref does not resolve to a location in this schema",
            );
            return Value::Object(map.clone());
        };
        if self
            .ref_stack
            .iter()
            .any(|seen| std::ptr::eq(*seen, target))
        {
            self.blocking(
                &here,
                "$ref",
                "recursive schemas cannot be inlined for Gemini",
            );
            return Value::Object(Map::new());
        }
        self.push(
            &here,
            "$ref",
            Severity::Rejected,
            Action::Rewritten,
            "$ref inlined",
        );
        // Inlining copies the target; charge its size so a chain of
        // references cannot multiply the output.
        if !self.charge(target) {
            self.blocking(&here, "$ref", "schema too large to convert");
            return Value::Null;
        }
        let mut merged = match target {
            Value::Object(target) => target.clone(),
            other => return self.gemini(other, pointer, depth + 1),
        };
        for (key, value) in map {
            if key != "$ref" {
                merged.insert(key.clone(), value.clone());
            }
        }
        self.ref_stack.push(target);
        let out = self.gemini(&Value::Object(merged), pointer, depth + 1);
        self.ref_stack.pop();
        out
    }
}

fn type_includes(map: &Map<String, Value>, name: &str) -> bool {
    match map.get("type") {
        Some(Value::String(t)) => t == name,
        Some(Value::Array(ts)) => ts.iter().any(|t| t.as_str() == Some(name)),
        _ => false,
    }
}

/// The single non-null type declared, if any.
fn lower_type(map: &Map<String, Value>) -> Option<String> {
    match map.get("type") {
        Some(Value::String(t)) => Some(t.clone()),
        Some(Value::Array(ts)) => {
            let mut non_null = ts.iter().filter_map(Value::as_str).filter(|t| *t != "null");
            match (non_null.next(), non_null.next()) {
                (Some(t), None) => Some(t.to_owned()),
                _ => None,
            }
        }
        _ => None,
    }
}

/// The Gemini type shared by every value, if there is one.
fn common_type(values: &[Value]) -> Option<&'static str> {
    let kind = |v: &Value| match v {
        Value::Bool(_) => Some("BOOLEAN"),
        Value::Number(n) if n.is_i64() || n.is_u64() => Some("INTEGER"),
        Value::Number(_) => Some("NUMBER"),
        Value::String(_) => Some("STRING"),
        _ => None,
    };
    let first = kind(values.first()?)?;
    values
        .iter()
        .all(|v| kind(v) == Some(first))
        .then_some(first)
}

/// `{"type": "null"}`, possibly with annotations.
fn is_null_schema(value: &Value) -> bool {
    value.get("type").and_then(Value::as_str) == Some("null")
        && value.as_object().is_some_and(|m| {
            m.keys()
                .all(|k| matches!(k.as_str(), "type" | "description" | "title"))
        })
}

/// Let a strict-mode schema also accept `null`.
fn make_nullable(schema: &mut Value) {
    let Value::Object(map) = schema else {
        return;
    };
    if type_includes(map, "null")
        || map
            .get("anyOf")
            .and_then(Value::as_array)
            .is_some_and(|alts| alts.iter().any(is_null_schema))
    {
        return;
    }
    let simple = !map.contains_key("const") && !map.contains_key("$ref");
    match map.get_mut("type") {
        Some(Value::String(t)) if simple => {
            let t = std::mem::take(t);
            map.insert("type".to_owned(), serde_json::json!([t, "null"]));
            if let Some(Value::Array(values)) = map.get_mut("enum") {
                values.push(Value::Null);
            }
            return;
        }
        Some(Value::Array(types)) if simple => {
            types.push("null".into());
            if let Some(Value::Array(values)) = map.get_mut("enum") {
                values.push(Value::Null);
            }
            return;
        }
        _ => {}
    }
    if let Some(Value::Array(alts)) = map.get_mut("anyOf") {
        alts.push(serde_json::json!({ "type": "null" }));
        return;
    }
    let inner = std::mem::take(map);
    map.insert(
        "anyOf".to_owned(),
        serde_json::json!([Value::Object(inner), { "type": "null" }]),
    );
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn blocking(findings: &[SchemaFinding]) -> Vec<&str> {
        findings
            .iter()
            .filter(|f| f.is_blocking())
            .map(|f| f.pointer.as_str())
            .collect()
    }

    #[test]
    fn names_per_provider() {
        let long = "a".repeat(65);
        for dialect in Dialect::ALL {
            assert!(dialect.validate_name("get_weather-2").is_ok(), "{dialect}");
            assert!(dialect.validate_name("").is_err());
            assert!(dialect.validate_name(&long).is_err());
            assert!(dialect.validate_name(&long[..64]).is_ok());
            assert!(dialect.validate_name("a b").is_err());
            assert!(dialect.validate_name("café").is_err());
        }
        for name in ["ns.tool", "ns:tool"] {
            assert!(Dialect::Gemini.validate_name(name).is_ok());
            assert!(Dialect::OpenAi.validate_name(name).is_err());
            assert!(Dialect::Anthropic.validate_name(name).is_err());
        }
        assert!(Dialect::Gemini.validate_name("_x").is_ok());
        assert!(Dialect::Gemini.validate_name("-x").is_err());
        assert!(Dialect::OpenAi.validate_name("-x").is_ok());
    }

    /// Known answer: an optional enum, a nested object, a free-form map.
    #[test]
    fn strict_known_answer() {
        let schema = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {
                "city": { "type": "string", "minLength": 1 },
                "units": { "type": "string", "enum": ["c", "f"], "default": "c" },
                "when": { "type": "string", "format": "date" },
                "geo": {
                    "type": "object",
                    "properties": { "lat": { "type": "number" } },
                    "required": ["lat"]
                },
                "labels": { "type": "object", "additionalProperties": { "type": "string" } },
                "pick": { "oneOf": [{ "type": "integer", "format": "uint8" }, { "const": "all" }] }
            },
            "required": ["city", "geo"]
        });
        let (out, findings) = convert(Dialect::OpenAiStrict, &schema);
        assert_eq!(
            out,
            json!({
                "type": "object",
                "properties": {
                    "city": { "type": "string" },
                    "units": { "type": ["string", "null"], "enum": ["c", "f", null] },
                    "when": { "type": ["string", "null"], "format": "date" },
                    "geo": {
                        "type": "object",
                        "properties": { "lat": { "type": "number" } },
                        "required": ["lat"],
                        "additionalProperties": false
                    },
                    "labels": {
                        "type": ["object", "null"],
                        "additionalProperties": false,
                        "required": []
                    },
                    "pick": {
                        "anyOf": [{ "type": "integer" }, { "const": "all" }, { "type": "null" }]
                    }
                },
                "required": ["city", "geo", "labels", "pick", "units", "when"],
                "additionalProperties": false
            })
        );
        let summary: Vec<(&str, Severity, Action)> = findings
            .iter()
            .map(|f| (f.pointer.as_str(), f.severity, f.action))
            .collect();
        assert_eq!(
            summary,
            [
                ("/$schema", Severity::Ignored, Action::Removed),
                (
                    "/properties/city/minLength",
                    Severity::Rejected,
                    Action::Removed
                ),
                (
                    "/properties/labels/additionalProperties",
                    Severity::Rejected,
                    Action::Rewritten
                ),
                (
                    "/properties/pick/oneOf",
                    Severity::Rejected,
                    Action::Rewritten
                ),
                (
                    "/properties/pick/oneOf/0/format",
                    Severity::Rejected,
                    Action::Removed
                ),
                (
                    "/properties/units/default",
                    Severity::Rejected,
                    Action::Removed
                ),
                ("/properties/labels", Severity::Rejected, Action::Rewritten),
                ("/properties/pick", Severity::Rejected, Action::Rewritten),
                ("/properties/units", Severity::Rejected, Action::Rewritten),
                ("/properties/when", Severity::Rejected, Action::Rewritten),
            ]
        );
        assert_eq!(blocking(&findings), [] as [&str; 0]);
    }

    #[test]
    fn root_combinators_block() {
        let schema = json!({ "type": "object", "anyOf": [{ "required": ["a"] }] });
        for dialect in [Dialect::OpenAi, Dialect::OpenAiStrict, Dialect::Anthropic] {
            assert_eq!(blocking(&dialect.lint(&schema)), ["/anyOf"], "{dialect}");
        }
        assert_eq!(blocking(&Dialect::Gemini.lint(&schema)), [] as [&str; 0]);
        assert_eq!(
            blocking(&Dialect::Anthropic.lint(&json!({"type": "string"}))),
            [""]
        );
    }

    #[test]
    fn strict_blocks_what_it_cannot_express() {
        let mut deep = json!({ "type": "object", "properties": {} });
        for _ in 0..11 {
            deep = json!({ "type": "object", "properties": { "a": deep }, "required": ["a"] });
        }
        assert_ne!(
            blocking(&Dialect::OpenAiStrict.lint(&deep)),
            [] as [&str; 0]
        );
        let schema = json!({
            "type": "object",
            "properties": {
                "both": { "allOf": [{ "type": "string" }, { "pattern": "x" }] },
                "pair": { "type": "array", "items": [{ "type": "string" }] },
                "any": true
            }
        });
        assert_eq!(
            blocking(&Dialect::OpenAiStrict.lint(&schema)),
            [
                "/properties/any",
                "/properties/both/allOf",
                "/properties/pair/items"
            ]
        );
    }

    /// Known answer: the shape schemars generates for an optional nested
    /// struct, a `u16` and an `Option<String>`.
    #[test]
    fn gemini_known_answer() {
        let schema = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "title": "Args",
            "type": "object",
            "properties": {
                "port": { "type": "integer", "format": "uint16", "minimum": 0, "maximum": 65535 },
                "note": { "type": ["string", "null"] },
                "mode": { "const": "fast" },
                "target": { "anyOf": [{ "$ref": "#/$defs/Target" }, { "type": "null" }] },
                "level": { "enum": [1, 2] }
            },
            "required": ["port"],
            "additionalProperties": false,
            "$defs": {
                "Target": {
                    "type": "object",
                    "properties": { "host": { "type": "string", "format": "hostname" } },
                    "required": ["host"]
                }
            }
        });
        let (out, findings) = convert(Dialect::Gemini, &schema);
        assert_eq!(
            out,
            json!({
                "title": "Args",
                "type": "OBJECT",
                "properties": {
                    "port": { "type": "INTEGER", "minimum": 0, "maximum": 65535 },
                    "note": { "type": "STRING", "nullable": true },
                    "mode": { "type": "STRING", "enum": ["fast"] },
                    "target": {
                        "type": "OBJECT",
                        "properties": { "host": { "type": "STRING" } },
                        "required": ["host"],
                        "nullable": true
                    },
                    "level": { "type": "INTEGER" }
                },
                "required": ["port"]
            })
        );
        assert_eq!(blocking(&findings), [] as [&str; 0]);
        let keywords: Vec<&str> = findings.iter().map(|f| f.keyword.as_str()).collect();
        assert_eq!(
            keywords,
            [
                "$schema",
                "additionalProperties",
                "enum",
                "const",
                "type",
                "format",
                "$ref",
                "format"
            ]
        );
    }

    #[test]
    fn gemini_blocks_recursion_and_tuples() {
        let schema = json!({
            "type": "object",
            "properties": {
                "tree": { "$ref": "#/$defs/Node" },
                "pair": { "type": "array", "items": [{ "type": "string" }] }
            },
            "$defs": {
                "Node": { "type": "object", "properties": { "kids": { "type": "array", "items": { "$ref": "#/$defs/Node" } } } }
            }
        });
        assert_eq!(
            blocking(&Dialect::Gemini.lint(&schema)),
            [
                "/properties/pair/items",
                "/properties/tree/properties/kids/items/$ref"
            ]
        );
    }

    /// Refs that fan out: inlining would produce 2^40 copies.
    #[test]
    fn exponential_inlining_is_refused() {
        let mut defs = Map::new();
        defs.insert(
            "l0".into(),
            json!({"type": "string", "default": "x".repeat(1000)}),
        );
        for i in 1..=40 {
            let below = format!("#/$defs/l{}", i - 1);
            defs.insert(
                format!("l{i}"),
                json!({"type": "object", "properties": {"a": {"$ref": below}, "b": {"$ref": below}}}),
            );
        }
        let schema = json!({
            "type": "object",
            "properties": {"root": {"$ref": "#/$defs/l40"}},
            "$defs": defs
        });
        let (_, findings) = convert(Dialect::Gemini, &schema);
        assert!(findings.len() < 2 * MAX_WALK_STEPS);
        assert!(
            findings
                .iter()
                .any(|f| f.is_blocking() && f.message.contains("too large"))
        );
        let mut args = json!({"root": {"a": null, "b": {"a": null}}});
        drop_optional_nulls(&schema, &mut args);
    }

    #[test]
    fn ref_aliases_are_caught_as_cycles() {
        let schema = json!({
            "type": "object",
            "properties": {"n": {"$ref": "#/$defs/n"}},
            "$defs": {"n": {"type": "object", "properties": {"m": {"$ref": "#/%24defs/n"}}}}
        });
        assert!(
            blocking(&Dialect::Gemini.lint(&schema))
                .iter()
                .any(|p| p.ends_with("/m/$ref"))
        );
    }

    #[test]
    fn hidden_characters_are_found_in_keys_and_values() {
        let schema = json!({ "properties": { "a\u{200b}": {} } });
        let found = find_hidden_in(&schema, &mut String::new(), 0);
        assert_eq!(
            found,
            Some(("/properties/a\u{200b}".to_owned(), '\u{200b}'))
        );
        let mut schema = json!({ "description": "x\u{202e}y", "properties": { "a": { "title": "t\u{e0041}" } } });
        sanitize_annotations(&mut schema, 0);
        assert_eq!(
            schema,
            json!({ "description": "xy", "properties": { "a": { "title": "t" } } })
        );
    }
}
