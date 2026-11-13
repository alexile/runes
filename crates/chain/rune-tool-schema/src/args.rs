//! [`Validator`]: check model-produced tool arguments against the tool's
//! JSON Schema before the tool runs.
//!
//! Models get arguments wrong in small ways (a string where an integer
//! belongs, a missing field, an invented one), and arguments can also be
//! steered by injected text. The validator covers the part of JSON Schema
//! that tool definitions use:
//!
//! | Applies to | Keywords |
//! |---|---|
//! | any value | `type`, `enum`, `const`, `anyOf`, `oneOf`, `allOf`, `$ref` (local), `true`/`false` schemas |
//! | strings | `minLength`, `maxLength`, `pattern` |
//! | numbers | `minimum`, `maximum`, `exclusiveMinimum`, `exclusiveMaximum`, `multipleOf` |
//! | arrays | `items` (one schema or a tuple), `minItems`, `maxItems` |
//! | objects | `properties`, `required`, `additionalProperties`, `minProperties`, `maxProperties` |
//!
//! Annotation keywords (`description`, `title`, `default`, `examples`,
//! `format`, ...) and keywords outside this table are not checked, so a
//! value is only refused for a rule it really breaks.
//!
//! Every violation carries a [JSON Pointer](https://www.rfc-editor.org/rfc/rfc6901)
//! to the offending value. Hostile input is bounded: nesting depth, value
//! count and total work have [`Limits`], patterns run on the linear-time
//! [`regex`] engine with a compiled-size cap, and nothing panics.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::fmt;

use regex::{Regex, RegexBuilder};
use serde_json::{Map, Number, Value};

use crate::Error;

/// Bounds on schemas and on the values checked against them.
///
/// ```
/// use rune_tool_schema::Limits;
///
/// let mut limits = Limits::default();
/// limits.max_depth = 8;
/// assert_eq!(limits.max_violations, 16);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Limits {
    /// Deepest nesting of arrays and objects accepted in a value. Default 32.
    pub max_depth: usize,
    /// Most arrays, objects and scalars a value may contain in total.
    /// Default 10 000.
    pub max_nodes: usize,
    /// Deepest nesting of subschemas, counting `$ref` hops. Bounds the
    /// recursion on schemas that refer to themselves. Default 128.
    pub max_schema_depth: usize,
    /// Most schema checks one validation may perform; bounds the work
    /// `anyOf`/`oneOf` can multiply. Default 1 000 000.
    pub max_steps: usize,
    /// Most violations reported; the rest are counted, not kept. Default 16.
    pub max_violations: usize,
    /// Longest `pattern` accepted, in bytes. Default 1024.
    pub max_pattern_len: usize,
    /// Compiled-size cap handed to the regex engine for each `pattern`, in
    /// bytes. Default 1 MiB.
    pub regex_size_limit: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_depth: 32,
            max_nodes: 10_000,
            max_schema_depth: 128,
            max_steps: 1_000_000,
            max_violations: 16,
            max_pattern_len: 1024,
            regex_size_limit: 1 << 20,
        }
    }
}

/// What rule a value broke.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ViolationKind {
    /// The value's JSON type is not among those allowed.
    Type {
        /// The allowed type or types, as written in the schema.
        expected: String,
        /// The value's type (`integer` for numbers without a fraction).
        found: &'static str,
    },
    /// A required property is absent; the pointer names the property.
    Missing,
    /// A property the schema does not allow (`additionalProperties: false`).
    Unknown,
    /// Not one of the `enum` values.
    Enum,
    /// Not equal to the `const` value.
    Const,
    /// Fewer characters than `minLength`.
    MinLength(u64),
    /// More characters than `maxLength`.
    MaxLength(u64),
    /// Does not match `pattern`.
    Pattern(String),
    /// Below `minimum`, or not above `exclusiveMinimum` when `exclusive`.
    Minimum {
        /// The bound.
        limit: Number,
        /// Whether the bound itself is excluded.
        exclusive: bool,
    },
    /// Above `maximum`, or not below `exclusiveMaximum` when `exclusive`.
    Maximum {
        /// The bound.
        limit: Number,
        /// Whether the bound itself is excluded.
        exclusive: bool,
    },
    /// Not a multiple of `multipleOf`.
    MultipleOf(Number),
    /// Fewer items than `minItems`.
    MinItems(u64),
    /// More items than `maxItems`.
    MaxItems(u64),
    /// Fewer properties than `minProperties`.
    MinProperties(u64),
    /// More properties than `maxProperties`.
    MaxProperties(u64),
    /// Matches none of the `anyOf` (or `oneOf`) alternatives.
    NoMatch,
    /// Matches more than one `oneOf` alternative.
    AmbiguousMatch(usize),
    /// The schema here is `false`: no value is allowed.
    NotAllowed,
    /// Nested deeper than [`Limits::max_depth`].
    TooDeep(usize),
    /// More values than [`Limits::max_nodes`].
    TooLarge(usize),
    /// Checking needed more work than [`Limits::max_steps`], or recursed
    /// deeper than [`Limits::max_schema_depth`].
    TooComplex,
}

impl fmt::Display for ViolationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Type { expected, found } => write!(f, "expected {expected}, got {found}"),
            Self::Missing => f.write_str("missing required property"),
            Self::Unknown => f.write_str("unknown property"),
            Self::Enum => f.write_str("not one of the allowed values"),
            Self::Const => f.write_str("does not equal the required constant"),
            Self::MinLength(n) => write!(f, "shorter than {n} characters"),
            Self::MaxLength(n) => write!(f, "longer than {n} characters"),
            Self::Pattern(p) => write!(f, "does not match pattern {p:?}"),
            Self::Minimum {
                limit,
                exclusive: false,
            } => write!(f, "less than the minimum {limit}"),
            Self::Minimum {
                limit,
                exclusive: true,
            } => write!(f, "not greater than {limit}"),
            Self::Maximum {
                limit,
                exclusive: false,
            } => write!(f, "greater than the maximum {limit}"),
            Self::Maximum {
                limit,
                exclusive: true,
            } => write!(f, "not less than {limit}"),
            Self::MultipleOf(n) => write!(f, "not a multiple of {n}"),
            Self::MinItems(n) => write!(f, "fewer than {n} items"),
            Self::MaxItems(n) => write!(f, "more than {n} items"),
            Self::MinProperties(n) => write!(f, "fewer than {n} properties"),
            Self::MaxProperties(n) => write!(f, "more than {n} properties"),
            Self::NoMatch => f.write_str("matches none of the allowed alternatives"),
            Self::AmbiguousMatch(n) => {
                write!(f, "must match exactly one alternative, matches {n}")
            }
            Self::NotAllowed => f.write_str("no value is allowed here"),
            Self::TooDeep(n) => write!(f, "nested deeper than {n} levels"),
            Self::TooLarge(n) => write!(f, "more than {n} values"),
            Self::TooComplex => f.write_str("too complex to check within the limits"),
        }
    }
}

/// One broken rule: where, and which.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// JSON Pointer to the offending value (`""` is the whole argument
    /// object). Keys longer than 128 characters are shortened with `…`.
    pub pointer: String,
    /// The rule broken.
    pub kind: ViolationKind,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let pointer = if self.pointer.is_empty() {
            "/"
        } else {
            &self.pointer
        };
        write!(f, "{pointer}: {}", self.kind)
    }
}

/// Every violation found (up to [`Limits::max_violations`]), in document
/// order. Displays as one line per violation, short enough to hand back to
/// a model so it can correct its call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violations {
    list: Vec<Violation>,
    omitted: usize,
}

impl Violations {
    /// The violations kept.
    #[must_use]
    pub fn as_slice(&self) -> &[Violation] {
        &self.list
    }

    /// How many more were found but not kept.
    #[must_use]
    pub const fn omitted(&self) -> usize {
        self.omitted
    }

    /// The violations kept, by value.
    #[must_use]
    pub fn into_vec(self) -> Vec<Violation> {
        self.list
    }

    /// Iterate over the violations kept.
    pub fn iter(&self) -> std::slice::Iter<'_, Violation> {
        self.list.iter()
    }
}

impl<'a> IntoIterator for &'a Violations {
    type Item = &'a Violation;
    type IntoIter = std::slice::Iter<'a, Violation>;

    fn into_iter(self) -> Self::IntoIter {
        self.list.iter()
    }
}

impl fmt::Display for Violations {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, violation) in self.list.iter().enumerate() {
            if i > 0 {
                f.write_str("\n")?;
            }
            write!(f, "{violation}")?;
        }
        if self.omitted > 0 {
            write!(f, "\n(and {} more)", self.omitted)?;
        }
        Ok(())
    }
}

impl std::error::Error for Violations {}

/// Why [`ToolDescriptor::parse_arguments`](crate::ToolDescriptor::parse_arguments)
/// or [`ToolDescriptor::validate_arguments`](crate::ToolDescriptor::validate_arguments)
/// refused a call.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ArgumentError {
    /// The tool's own input schema cannot be used for checking.
    #[error(transparent)]
    Schema(Error),
    /// The arguments break the schema.
    #[error("invalid arguments:\n{0}")]
    Invalid(Violations),
    /// The arguments match the schema but not the Rust type.
    #[error("arguments do not fit the expected type: {0}")]
    Deserialize(String),
}

/// A compiled input schema that checks argument values.
///
/// Compiling checks the schema itself once: keyword values have the right
/// JSON types, `$ref`s point inside the document, and every `pattern`
/// compiles within the size limit. Keep the validator around and reuse it
/// for every call of the tool.
///
/// ```
/// use rune_tool_schema::{Validator, ViolationKind};
/// use serde_json::json;
///
/// let validator = Validator::new(&json!({
///     "type": "object",
///     "properties": {
///         "city": { "type": "string", "minLength": 1 },
///         "days": { "type": "integer", "minimum": 1, "maximum": 14 }
///     },
///     "required": ["city"],
///     "additionalProperties": false
/// }))?;
///
/// assert!(validator.validate(&json!({ "city": "Oslo", "days": 3 })).is_ok());
///
/// let errors = validator.validate(&json!({ "days": 30, "units": "C" })).unwrap_err();
/// let found: Vec<String> = errors.iter().map(ToString::to_string).collect();
/// assert_eq!(found, [
///     "/city: missing required property",
///     "/days: greater than the maximum 14",
///     "/units: unknown property",
/// ]);
/// # Ok::<(), rune_tool_schema::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct Validator {
    schema: Value,
    patterns: HashMap<String, Regex>,
    limits: Limits,
}

impl Validator {
    /// Compile `schema` with the default [`Limits`].
    ///
    /// # Errors
    ///
    /// [`Error::InvalidSchema`] naming the first problem found.
    pub fn new(schema: &Value) -> Result<Self, Error> {
        Self::with_limits(schema, Limits::default())
    }

    /// Compile `schema` with the given limits.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidSchema`] naming the first problem found.
    pub fn with_limits(schema: &Value, limits: Limits) -> Result<Self, Error> {
        let mut compiler = Compiler {
            root: schema,
            limits: &limits,
            patterns: HashMap::new(),
            visited_refs: HashSet::new(),
        };
        compiler.walk(schema, &mut String::new(), 0)?;
        let patterns = compiler.patterns;
        Ok(Self {
            schema: schema.clone(),
            patterns,
            limits,
        })
    }

    /// The schema for `T`, generated with [`schemars`](https://docs.rs/schemars).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidSchema`] if the generated schema cannot be compiled,
    /// for example because of a `pattern` the regex engine does not support.
    #[cfg(feature = "schemars")]
    pub fn for_type<T: schemars::JsonSchema>() -> Result<Self, Error> {
        Self::new(&crate::json_schema_for::<T>())
    }

    /// The schema this validator checks against.
    #[must_use]
    pub const fn schema(&self) -> &Value {
        &self.schema
    }

    /// The limits in force.
    #[must_use]
    pub const fn limits(&self) -> &Limits {
        &self.limits
    }

    /// Check `value`.
    ///
    /// # Errors
    ///
    /// The [`Violations`] found, in document order.
    pub fn validate(&self, value: &Value) -> Result<(), Violations> {
        if let Some(violation) = measure(value, &self.limits) {
            return Err(Violations {
                list: vec![violation],
                omitted: 0,
            });
        }
        let mut run = Run {
            validator: self,
            steps: 0,
            exhausted: false,
        };
        let mut sink = Sink::new(self.limits.max_violations);
        run.check(&self.schema, value, &mut String::new(), 0, &mut sink);
        if run.exhausted {
            return Err(Violations {
                list: vec![Violation {
                    pointer: String::new(),
                    kind: ViolationKind::TooComplex,
                }],
                omitted: 0,
            });
        }
        if sink.list.is_empty() {
            Ok(())
        } else {
            Err(Violations {
                list: sink.list,
                omitted: sink.omitted,
            })
        }
    }

    /// Whether `value` passes [`Self::validate`].
    #[must_use]
    pub fn is_valid(&self, value: &Value) -> bool {
        self.validate(value).is_ok()
    }
}

/// Append one reference token to a JSON Pointer, escaping `~` and `/` and
/// shortening very long keys.
pub fn push_token(pointer: &mut String, token: &str) {
    const MAX_TOKEN_CHARS: usize = 128;
    pointer.push('/');
    for (i, c) in token.chars().enumerate() {
        if i == MAX_TOKEN_CHARS {
            pointer.push('…');
            break;
        }
        match c {
            '~' => pointer.push_str("~0"),
            '/' => pointer.push_str("~1"),
            c => pointer.push(c),
        }
    }
}

/// Run `f` with `token` appended to `pointer`, then restore it.
fn with_token<R>(pointer: &mut String, token: &str, f: impl FnOnce(&mut String) -> R) -> R {
    let len = pointer.len();
    push_token(pointer, token);
    let result = f(pointer);
    pointer.truncate(len);
    result
}

/// Resolve a local `$ref` (`#` or `#/json/pointer`) against `root`.
pub fn resolve_ref<'a>(root: &'a Value, reference: &str) -> Option<&'a Value> {
    let fragment = reference.strip_prefix('#')?;
    if fragment.is_empty() {
        Some(root)
    } else if fragment.starts_with('/') {
        root.pointer(&percent_decode(fragment)?)
    } else {
        None
    }
}

/// Decode `%XX` escapes in a URI fragment; `None` on a malformed escape or
/// a non-UTF-8 result.
fn percent_decode(text: &str) -> Option<String> {
    if !text.contains('%') {
        return Some(text.to_owned());
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = text.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Check depth and size before validating, so the validator itself never
/// recurses deeper than the limits allow.
fn measure(value: &Value, limits: &Limits) -> Option<Violation> {
    let mut nodes = 0usize;
    let mut stack: Vec<(&Value, usize)> = vec![(value, 0)];
    while let Some((value, depth)) = stack.pop() {
        nodes += 1;
        if nodes > limits.max_nodes {
            return Some(Violation {
                pointer: String::new(),
                kind: ViolationKind::TooLarge(limits.max_nodes),
            });
        }
        let children: Box<dyn Iterator<Item = &Value>> = match value {
            Value::Array(items) => Box::new(items.iter()),
            Value::Object(map) => Box::new(map.values()),
            _ => continue,
        };
        if depth >= limits.max_depth {
            return Some(Violation {
                pointer: String::new(),
                kind: ViolationKind::TooDeep(limits.max_depth),
            });
        }
        stack.extend(children.map(|child| (child, depth + 1)));
    }
    None
}

/// Checks a schema once and compiles its patterns.
struct Compiler<'a> {
    root: &'a Value,
    limits: &'a Limits,
    patterns: HashMap<String, Regex>,
    visited_refs: HashSet<String>,
}

impl Compiler<'_> {
    fn invalid(pointer: &str, reason: impl Into<String>) -> Error {
        Error::InvalidSchema {
            pointer: pointer.to_owned(),
            reason: reason.into(),
        }
    }

    fn walk(&mut self, schema: &Value, pointer: &mut String, depth: usize) -> Result<(), Error> {
        if depth > self.limits.max_schema_depth {
            return Err(Self::invalid(
                pointer,
                format!(
                    "nested deeper than {} subschemas",
                    self.limits.max_schema_depth
                ),
            ));
        }
        let map = match schema {
            Value::Bool(_) => return Ok(()),
            Value::Object(map) => map,
            _ => {
                return Err(Self::invalid(
                    pointer,
                    "a schema must be an object or a boolean",
                ));
            }
        };
        self.check_keywords(map, pointer)?;
        for (key, value) in map {
            match key.as_str() {
                "properties" | "$defs" | "definitions" => {
                    if let Value::Object(children) = value {
                        for (name, child) in children {
                            with_token(pointer, key, |p| {
                                with_token(p, name, |p| self.walk(child, p, depth + 1))
                            })?;
                        }
                    }
                }
                "additionalProperties" => {
                    with_token(pointer, key, |p| self.walk(value, p, depth + 1))?;
                }
                "items" => match value {
                    Value::Array(children) => self.walk_list(key, children, pointer, depth)?,
                    other => with_token(pointer, key, |p| self.walk(other, p, depth + 1))?,
                },
                "anyOf" | "oneOf" | "allOf" => {
                    if let Value::Array(children) = value {
                        self.walk_list(key, children, pointer, depth)?;
                    }
                }
                "$ref" => self.follow_ref(value, pointer, depth)?,
                _ => {}
            }
        }
        Ok(())
    }

    fn walk_list(
        &mut self,
        key: &str,
        children: &[Value],
        pointer: &mut String,
        depth: usize,
    ) -> Result<(), Error> {
        with_token(pointer, key, |p| {
            children.iter().enumerate().try_for_each(|(i, child)| {
                with_token(p, &i.to_string(), |p| self.walk(child, p, depth + 1))
            })
        })
    }

    fn follow_ref(&mut self, value: &Value, pointer: &str, depth: usize) -> Result<(), Error> {
        let Some(reference) = value.as_str() else {
            return Err(Self::invalid(pointer, "$ref must be a string"));
        };
        let Some(target) = resolve_ref(self.root, reference) else {
            return Err(Self::invalid(
                pointer,
                format!("$ref {reference:?} does not resolve to a location in this schema"),
            ));
        };
        if self.visited_refs.insert(reference.to_owned()) {
            let mut target_pointer = reference.trim_start_matches('#').to_owned();
            self.walk(target, &mut target_pointer, depth + 1)?;
        }
        Ok(())
    }

    /// Keyword values of the right JSON type; patterns compiled.
    fn check_keywords(&mut self, map: &Map<String, Value>, pointer: &str) -> Result<(), Error> {
        let at = |key: &str| {
            let mut p = pointer.to_owned();
            push_token(&mut p, key);
            p
        };
        for (key, value) in map {
            let ok = match key.as_str() {
                "type" => match value {
                    Value::String(t) => is_type_name(t),
                    Value::Array(ts) => ts.iter().all(|t| t.as_str().is_some_and(is_type_name)),
                    _ => false,
                },
                "minLength" | "maxLength" | "minItems" | "maxItems" | "minProperties"
                | "maxProperties" => value.is_u64(),
                "minimum" | "maximum" => value.is_number(),
                "exclusiveMinimum" | "exclusiveMaximum" => value.is_number() || value.is_boolean(),
                "multipleOf" => value.as_f64().is_some_and(|n| n > 0.0),
                "required" => value
                    .as_array()
                    .is_some_and(|names| names.iter().all(Value::is_string)),
                "enum" => value.is_array(),
                "properties" | "$defs" | "definitions" => value.is_object(),
                "additionalProperties" => value.is_object() || value.is_boolean(),
                "items" => value.is_object() || value.is_boolean() || value.is_array(),
                "anyOf" | "oneOf" | "allOf" => {
                    value.as_array().is_some_and(|list| !list.is_empty())
                }
                "pattern" => {
                    let Some(pattern) = value.as_str() else {
                        return Err(Self::invalid(&at(key), "pattern must be a string"));
                    };
                    self.compile_pattern(pattern, &at(key))?;
                    true
                }
                _ => true,
            };
            if !ok {
                return Err(Self::invalid(
                    &at(key),
                    format!("{key} has a value of the wrong type"),
                ));
            }
        }
        Ok(())
    }

    fn compile_pattern(&mut self, pattern: &str, pointer: &str) -> Result<(), Error> {
        if self.patterns.contains_key(pattern) {
            return Ok(());
        }
        if pattern.len() > self.limits.max_pattern_len {
            return Err(Self::invalid(
                pointer,
                format!("pattern longer than {} bytes", self.limits.max_pattern_len),
            ));
        }
        let regex = RegexBuilder::new(pattern)
            .size_limit(self.limits.regex_size_limit)
            .dfa_size_limit(self.limits.regex_size_limit)
            .build()
            .map_err(|err| Self::invalid(pointer, format!("unusable pattern: {err}")))?;
        self.patterns.insert(pattern.to_owned(), regex);
        Ok(())
    }
}

fn is_type_name(name: &str) -> bool {
    matches!(
        name,
        "string" | "number" | "integer" | "boolean" | "object" | "array" | "null"
    )
}

/// Collects violations up to a cap.
struct Sink {
    list: Vec<Violation>,
    omitted: usize,
    cap: usize,
}

impl Sink {
    const fn new(cap: usize) -> Self {
        Self {
            list: Vec::new(),
            omitted: 0,
            cap,
        }
    }

    fn push(&mut self, pointer: &str, kind: ViolationKind) {
        if self.list.len() < self.cap {
            self.list.push(Violation {
                pointer: pointer.to_owned(),
                kind,
            });
        } else {
            self.omitted += 1;
        }
    }

    const fn failed(&self) -> bool {
        !self.list.is_empty() || self.omitted > 0
    }

    /// A trial sink only needs to know whether anything failed.
    const fn full(&self) -> bool {
        self.cap == 0 && self.omitted > 0
    }
}

/// One validation pass.
struct Run<'a> {
    validator: &'a Validator,
    steps: usize,
    exhausted: bool,
}

impl Run<'_> {
    fn check(
        &mut self,
        schema: &Value,
        value: &Value,
        pointer: &mut String,
        depth: usize,
        sink: &mut Sink,
    ) {
        if self.exhausted || sink.full() {
            return;
        }
        self.steps += 1;
        if self.steps > self.validator.limits.max_steps
            || depth > self.validator.limits.max_schema_depth
        {
            self.exhausted = true;
            return;
        }
        let map = match schema {
            Value::Bool(true) => return,
            Value::Object(map) => map,
            _ => return sink.push(pointer, ViolationKind::NotAllowed),
        };
        if let Some(reference) = map.get("$ref").and_then(Value::as_str)
            && let Some(target) = resolve_ref(&self.validator.schema, reference)
        {
            self.check(target, value, pointer, depth + 1, sink);
        }
        if !Self::check_type(map, value, pointer, sink) {
            // Further keywords would only repeat the type mismatch.
            return;
        }
        if let Some(allowed) = map.get("enum").and_then(Value::as_array)
            && !allowed.iter().any(|candidate| json_eq(candidate, value))
        {
            sink.push(pointer, ViolationKind::Enum);
        }
        if let Some(expected) = map.get("const")
            && !json_eq(expected, value)
        {
            sink.push(pointer, ViolationKind::Const);
        }
        match value {
            Value::String(text) => self.check_string(map, text, pointer, sink),
            Value::Number(number) => check_number(map, number, pointer, sink),
            Value::Array(items) => self.check_array(map, items, pointer, depth, sink),
            Value::Object(object) => self.check_object(map, object, pointer, depth, sink),
            Value::Null | Value::Bool(_) => {}
        }
        self.check_combinators(map, value, pointer, depth, sink);
    }

    /// `false` when the type does not match (and that was reported).
    fn check_type(map: &Map<String, Value>, value: &Value, pointer: &str, sink: &mut Sink) -> bool {
        let Some(declared) = map.get("type") else {
            return true;
        };
        let ok = match declared {
            Value::String(name) => type_matches(name, value),
            Value::Array(names) => names
                .iter()
                .filter_map(Value::as_str)
                .any(|name| type_matches(name, value)),
            _ => true,
        };
        if !ok {
            let expected = match declared {
                Value::String(name) => name.clone(),
                Value::Array(names) => names
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(" or "),
                _ => String::new(),
            };
            sink.push(
                pointer,
                ViolationKind::Type {
                    expected,
                    found: type_name(value),
                },
            );
        }
        ok
    }

    fn check_string(&self, map: &Map<String, Value>, text: &str, pointer: &str, sink: &mut Sink) {
        let length = || text.chars().count() as u64;
        if let Some(min) = map.get("minLength").and_then(Value::as_u64)
            && length() < min
        {
            sink.push(pointer, ViolationKind::MinLength(min));
        }
        if let Some(max) = map.get("maxLength").and_then(Value::as_u64)
            && length() > max
        {
            sink.push(pointer, ViolationKind::MaxLength(max));
        }
        if let Some(pattern) = map.get("pattern").and_then(Value::as_str)
            && let Some(regex) = self.validator.patterns.get(pattern)
            && !regex.is_match(text)
        {
            sink.push(pointer, ViolationKind::Pattern(pattern.to_owned()));
        }
    }

    fn check_array(
        &mut self,
        map: &Map<String, Value>,
        items: &[Value],
        pointer: &mut String,
        depth: usize,
        sink: &mut Sink,
    ) {
        let len = items.len() as u64;
        if let Some(min) = map.get("minItems").and_then(Value::as_u64)
            && len < min
        {
            sink.push(pointer, ViolationKind::MinItems(min));
        }
        if let Some(max) = map.get("maxItems").and_then(Value::as_u64)
            && len > max
        {
            sink.push(pointer, ViolationKind::MaxItems(max));
        }
        match map.get("items") {
            Some(Value::Array(tuple)) => {
                for (i, (schema, item)) in tuple.iter().zip(items).enumerate() {
                    with_token(pointer, &i.to_string(), |p| {
                        self.check(schema, item, p, depth + 1, sink);
                    });
                }
            }
            Some(schema @ (Value::Object(_) | Value::Bool(_))) => {
                for (i, item) in items.iter().enumerate() {
                    with_token(pointer, &i.to_string(), |p| {
                        self.check(schema, item, p, depth + 1, sink);
                    });
                }
            }
            _ => {}
        }
    }

    fn check_object(
        &mut self,
        map: &Map<String, Value>,
        object: &Map<String, Value>,
        pointer: &mut String,
        depth: usize,
        sink: &mut Sink,
    ) {
        let count = object.len() as u64;
        if let Some(min) = map.get("minProperties").and_then(Value::as_u64)
            && count < min
        {
            sink.push(pointer, ViolationKind::MinProperties(min));
        }
        if let Some(max) = map.get("maxProperties").and_then(Value::as_u64)
            && count > max
        {
            sink.push(pointer, ViolationKind::MaxProperties(max));
        }
        if let Some(required) = map.get("required").and_then(Value::as_array) {
            for name in required.iter().filter_map(Value::as_str) {
                if !object.contains_key(name) {
                    with_token(pointer, name, |p| sink.push(p, ViolationKind::Missing));
                }
            }
        }
        let properties = map.get("properties").and_then(Value::as_object);
        let additional = map.get("additionalProperties");
        for (key, value) in object {
            with_token(pointer, key, |p| {
                if let Some(schema) = properties.and_then(|props| props.get(key)) {
                    self.check(schema, value, p, depth + 1, sink);
                } else {
                    match additional {
                        Some(Value::Bool(false)) => sink.push(p, ViolationKind::Unknown),
                        Some(schema @ Value::Object(_)) => {
                            self.check(schema, value, p, depth + 1, sink);
                        }
                        _ => {}
                    }
                }
            });
        }
    }

    fn check_combinators(
        &mut self,
        map: &Map<String, Value>,
        value: &Value,
        pointer: &mut String,
        depth: usize,
        sink: &mut Sink,
    ) {
        if let Some(all) = map.get("allOf").and_then(Value::as_array) {
            for schema in all {
                self.check(schema, value, pointer, depth + 1, sink);
            }
        }
        if let Some(any) = map.get("anyOf").and_then(Value::as_array)
            && !any.is_empty()
        {
            let matched = any
                .iter()
                .any(|schema| self.passes(schema, value, pointer, depth + 1));
            if !matched {
                sink.push(pointer, ViolationKind::NoMatch);
            }
        }
        if let Some(one) = map.get("oneOf").and_then(Value::as_array)
            && !one.is_empty()
        {
            let mut matched = 0;
            for schema in one {
                if self.passes(schema, value, pointer, depth + 1) {
                    matched += 1;
                }
            }
            match matched {
                1 => {}
                0 => sink.push(pointer, ViolationKind::NoMatch),
                n => sink.push(pointer, ViolationKind::AmbiguousMatch(n)),
            }
        }
    }

    /// Whether `value` passes `schema`, stopping at the first violation.
    fn passes(
        &mut self,
        schema: &Value,
        value: &Value,
        pointer: &mut String,
        depth: usize,
    ) -> bool {
        let mut trial = Sink::new(0);
        self.check(schema, value, pointer, depth, &mut trial);
        !trial.failed()
    }
}

fn type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(n) if is_integer(n) => "integer",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// JSON Schema counts `2.0` as an integer.
fn is_integer(n: &Number) -> bool {
    n.is_i64()
        || n.is_u64()
        || n.as_f64()
            .is_some_and(|f| f.is_finite() && f.fract() == 0.0)
}

fn type_matches(name: &str, value: &Value) -> bool {
    match name {
        "string" => value.is_string(),
        "integer" => value.as_number().is_some_and(is_integer),
        "number" => value.is_number(),
        "boolean" => value.is_boolean(),
        "object" => value.is_object(),
        "array" => value.is_array(),
        "null" => value.is_null(),
        _ => false,
    }
}

/// JSON equality where `1` and `1.0` are the same number, as JSON Schema
/// requires for `enum` and `const`.
fn json_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => cmp_numbers(x, y) == Some(Ordering::Equal),
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(x, y)| json_eq(x, y))
        }
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len()
                && x.iter()
                    .all(|(key, xv)| y.get(key).is_some_and(|yv| json_eq(xv, yv)))
        }
        _ => a == b,
    }
}

/// Exact for integers up to 128 bits, `f64` otherwise.
fn cmp_numbers(a: &Number, b: &Number) -> Option<Ordering> {
    match (as_i128(a), as_i128(b)) {
        (Some(x), Some(y)) => Some(x.cmp(&y)),
        _ => a.as_f64()?.partial_cmp(&b.as_f64()?),
    }
}

fn as_i128(n: &Number) -> Option<i128> {
    n.as_i64()
        .map(i128::from)
        .or_else(|| n.as_u64().map(i128::from))
}

fn check_number(map: &Map<String, Value>, number: &Number, pointer: &str, sink: &mut Sink) {
    let bound = |key: &str| map.get(key).and_then(Value::as_number);
    let flag = |key: &str| map.get(key).and_then(Value::as_bool).unwrap_or(false);
    // `exclusiveMinimum: <number>` (2019+), or the older
    // `minimum` + `exclusiveMinimum: true`.
    let lower = bound("exclusiveMinimum")
        .map(|n| (n, true))
        .into_iter()
        .chain(bound("minimum").map(|n| (n, flag("exclusiveMinimum"))));
    for (limit, exclusive) in lower {
        let below = match cmp_numbers(number, limit) {
            Some(Ordering::Less) => true,
            Some(Ordering::Equal) => exclusive,
            _ => false,
        };
        if below {
            sink.push(
                pointer,
                ViolationKind::Minimum {
                    limit: limit.clone(),
                    exclusive,
                },
            );
        }
    }
    let upper = bound("exclusiveMaximum")
        .map(|n| (n, true))
        .into_iter()
        .chain(bound("maximum").map(|n| (n, flag("exclusiveMaximum"))));
    for (limit, exclusive) in upper {
        let above = match cmp_numbers(number, limit) {
            Some(Ordering::Greater) => true,
            Some(Ordering::Equal) => exclusive,
            _ => false,
        };
        if above {
            sink.push(
                pointer,
                ViolationKind::Maximum {
                    limit: limit.clone(),
                    exclusive,
                },
            );
        }
    }
    if let Some(divisor) = bound("multipleOf")
        && !is_multiple(number, divisor)
    {
        sink.push(pointer, ViolationKind::MultipleOf(divisor.clone()));
    }
}

fn is_multiple(number: &Number, divisor: &Number) -> bool {
    if let (Some(n), Some(d)) = (as_i128(number), as_i128(divisor)) {
        return d != 0 && n % d == 0;
    }
    match (number.as_f64(), divisor.as_f64()) {
        (Some(n), Some(d)) if d > 0.0 => {
            let quotient = n / d;
            if !quotient.is_finite() {
                return false;
            }
            (quotient - quotient.round()).abs() <= 1e-9 * quotient.abs().max(1.0)
        }
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn messages(schema: &Value, value: &Value) -> Vec<String> {
        match Validator::new(schema).unwrap().validate(value) {
            Ok(()) => Vec::new(),
            Err(errors) => errors.iter().map(ToString::to_string).collect(),
        }
    }

    fn schema() -> Value {
        json!({
            "type": "object",
            "properties": {
                "host": {"type": "string", "minLength": 1, "maxLength": 10, "pattern": "^[a-z.]*$"},
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "mode": {"enum": ["fast", "slow"]},
                "kind": {"const": "scan"},
                "tags": {"type": "array", "items": {"type": "string"}, "minItems": 1, "maxItems": 2},
                "opts": {
                    "type": "object",
                    "properties": {"deep": {"type": "boolean"}},
                    "additionalProperties": false
                },
                "either": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                "one": {"oneOf": [{"type": "integer"}, {"type": "number", "minimum": 0}]},
                "ratio": {"type": "number", "exclusiveMaximum": 1, "multipleOf": 0.25},
                "maybe": {"type": ["string", "null"]},
                "extra": {"type": "object", "additionalProperties": {"type": "integer"}, "maxProperties": 2}
            },
            "required": ["host"],
            "additionalProperties": false
        })
    }

    #[test]
    fn accepts_valid_arguments() {
        let ok = json!({
            "host": "a.b", "port": 443, "mode": "fast", "kind": "scan", "tags": ["x"],
            "opts": {"deep": true}, "either": null, "one": 0.5, "ratio": 0.75,
            "maybe": null, "extra": {"a": 1, "b": 2}
        });
        assert_eq!(messages(&schema(), &ok), Vec::<String>::new());
        // 2.0 is an integer in JSON Schema, and equals 2 for enum/const.
        assert_eq!(
            messages(&schema(), &json!({"host": "h", "port": 2.0})),
            [] as [&str; 0]
        );
        assert_eq!(
            messages(&json!({"enum": [1]}), &json!(1.0)),
            [] as [&str; 0]
        );
    }

    #[test]
    fn rejects_each_rule_with_a_pointer() {
        let s = schema();
        let cases = [
            (json!({}), "/host: missing required property"),
            (json!({"host": 1}), "/host: expected string, got integer"),
            (json!({"host": ""}), "/host: shorter than 1 characters"),
            (
                json!({"host": "abcdefghijk"}),
                "/host: longer than 10 characters",
            ),
            (
                json!({"host": "A"}),
                "/host: does not match pattern \"^[a-z.]*$\"",
            ),
            (
                json!({"host": "h", "port": 0}),
                "/port: less than the minimum 1",
            ),
            (
                json!({"host": "h", "port": 70000}),
                "/port: greater than the maximum 65535",
            ),
            (
                json!({"host": "h", "port": 1.5}),
                "/port: expected integer, got number",
            ),
            (
                json!({"host": "h", "mode": "x"}),
                "/mode: not one of the allowed values",
            ),
            (
                json!({"host": "h", "kind": "x"}),
                "/kind: does not equal the required constant",
            ),
            (
                json!({"host": "h", "tags": [1]}),
                "/tags/0: expected string, got integer",
            ),
            (
                json!({"host": "h", "tags": []}),
                "/tags: fewer than 1 items",
            ),
            (
                json!({"host": "h", "tags": ["a", "b", "c"]}),
                "/tags: more than 2 items",
            ),
            (
                json!({"host": "h", "opts": {"x": 1}}),
                "/opts/x: unknown property",
            ),
            (
                json!({"host": "h", "either": 1}),
                "/either: matches none of the allowed alternatives",
            ),
            (
                json!({"host": "h", "one": 3}),
                "/one: must match exactly one alternative, matches 2",
            ),
            (
                json!({"host": "h", "one": "x"}),
                "/one: matches none of the allowed alternatives",
            ),
            (json!({"host": "h", "ratio": 1}), "/ratio: not less than 1"),
            (
                json!({"host": "h", "ratio": 0.3}),
                "/ratio: not a multiple of 0.25",
            ),
            (
                json!({"host": "h", "maybe": 1}),
                "/maybe: expected string or null, got integer",
            ),
            (
                json!({"host": "h", "extra": {"a": "x"}}),
                "/extra/a: expected integer, got string",
            ),
            (
                json!({"host": "h", "extra": {"a": 1, "b": 1, "c": 1}}),
                "/extra: more than 2 properties",
            ),
            (json!({"host": "h", "evil": 1}), "/evil: unknown property"),
            (json!([]), "/: expected object, got array"),
        ];
        for (value, expected) in cases {
            assert_eq!(messages(&s, &value), [expected], "{value}");
        }
    }

    #[test]
    fn reports_every_violation_in_order() {
        let found = messages(&schema(), &json!({"port": "x", "evil": true}));
        assert_eq!(
            found,
            [
                "/host: missing required property",
                "/evil: unknown property",
                "/port: expected integer, got string",
            ]
        );
    }

    #[test]
    fn violation_count_is_capped() {
        let props: Map<String, Value> = (0..40).map(|i| (format!("k{i}"), json!(1))).collect();
        let s = json!({"type": "object", "additionalProperties": false});
        let errors = Validator::new(&s)
            .unwrap()
            .validate(&Value::Object(props))
            .unwrap_err();
        assert_eq!(errors.as_slice().len(), 16);
        assert_eq!(errors.omitted(), 24);
        assert!(errors.to_string().ends_with("(and 24 more)"));
    }

    #[test]
    fn local_refs_resolve_and_recursion_is_bounded() {
        let s = json!({
            "$defs": {
                "node": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "child": {"$ref": "#/$defs/node"}
                    },
                    "required": ["name"]
                }
            },
            "$ref": "#/$defs/node"
        });
        let v = Validator::new(&s).unwrap();
        assert!(v.is_valid(&json!({"name": "a", "child": {"name": "b"}})));
        assert_eq!(
            messages(&s, &json!({"name": "a", "child": {}})),
            ["/child/name: missing required property"]
        );
        // A schema that refers to itself without consuming the value.
        let looping = json!({"$ref": "#"});
        let errors = Validator::new(&looping)
            .unwrap()
            .validate(&json!(1))
            .unwrap_err();
        assert_eq!(errors.as_slice()[0].kind, ViolationKind::TooComplex);
    }

    #[test]
    fn bad_schemas_are_refused_at_compile_time() {
        for (schema, pointer) in [
            (json!({"type": "file"}), "/type"),
            (json!({"minLength": "3"}), "/minLength"),
            (
                json!({"properties": {"a": {"pattern": "(?=x)"}}}),
                "/properties/a/pattern",
            ),
            (json!({"pattern": "a".repeat(2000)}), "/pattern"),
            (json!({"pattern": "\\w{1000}{1000}"}), "/pattern"),
            (json!({"$ref": "https://example.com/s.json"}), ""),
            (json!({"$ref": "#/$defs/missing"}), ""),
            (json!({"anyOf": []}), "/anyOf"),
            (json!({"properties": {"a": 3}}), "/properties/a"),
            (json!({"multipleOf": 0}), "/multipleOf"),
        ] {
            match Validator::new(&schema) {
                Err(Error::InvalidSchema { pointer: p, .. }) => assert_eq!(p, pointer, "{schema}"),
                other => panic!("{schema}: {other:?}"),
            }
        }
    }

    #[test]
    fn deep_and_large_values_are_refused() {
        let mut deep = json!(1);
        for _ in 0..40 {
            deep = json!([deep]);
        }
        let errors = Validator::new(&json!({}))
            .unwrap()
            .validate(&deep)
            .unwrap_err();
        assert_eq!(errors.as_slice()[0].kind, ViolationKind::TooDeep(32));

        let wide = Value::Array(vec![json!(0); 20_000]);
        let errors = Validator::new(&json!({}))
            .unwrap()
            .validate(&wide)
            .unwrap_err();
        assert_eq!(errors.as_slice()[0].kind, ViolationKind::TooLarge(10_000));
    }

    #[test]
    fn combinator_blowup_hits_the_step_budget() {
        // Each level refers to the one below twice, so the schema stays
        // small while the work doubles per level.
        let mut defs = Map::new();
        defs.insert("l0".into(), json!({"type": "integer", "minimum": 1}));
        for i in 1..=40 {
            let below = format!("#/$defs/l{}", i - 1);
            defs.insert(
                format!("l{i}"),
                json!({"anyOf": [{"$ref": below}, {"$ref": below}]}),
            );
        }
        let s = json!({"$defs": defs, "$ref": "#/$defs/l40"});
        let errors = Validator::new(&s).unwrap().validate(&json!(0)).unwrap_err();
        assert_eq!(errors.as_slice()[0].kind, ViolationKind::TooComplex);
    }

    #[test]
    fn pointers_escape_and_bound_keys() {
        let s = json!({"type": "object", "additionalProperties": false});
        assert_eq!(
            messages(&s, &json!({"a/b~c": 1})),
            ["/a~1b~0c: unknown property"]
        );
        let long = "k".repeat(500);
        let found = messages(&s, &json!({ long: 1 }));
        assert!(found[0].len() < 160, "{}", found[0]);
        assert_eq!(resolve_ref(&json!({"a b": 1}), "#/a%20b"), Some(&json!(1)));
    }

    #[test]
    fn large_integers_compare_exactly() {
        let s = json!({"maximum": 9_007_199_254_740_993_u64});
        assert_eq!(
            messages(&s, &json!(9_007_199_254_740_993_u64)),
            [] as [&str; 0]
        );
        assert_ne!(
            messages(&s, &json!(9_007_199_254_740_994_u64)),
            [] as [&str; 0]
        );
        assert_eq!(
            messages(&json!({"multipleOf": 3}), &json!(u64::MAX)),
            [] as [&str; 0]
        );
    }

    #[test]
    fn draft4_exclusive_flags() {
        let s = json!({"minimum": 0, "exclusiveMinimum": true});
        assert_eq!(messages(&s, &json!(0)), ["/: not greater than 0"]);
        assert_eq!(messages(&s, &json!(0.1)), [] as [&str; 0]);
    }

    #[test]
    fn tuple_items_and_false_schemas() {
        let s = json!({"items": [{"type": "string"}, false]});
        assert_eq!(messages(&s, &json!(["a"])), [] as [&str; 0]);
        assert_eq!(
            messages(&s, &json!(["a", 1])),
            ["/1: no value is allowed here"]
        );
    }
}
