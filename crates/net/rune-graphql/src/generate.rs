//! Bounded operation generation: one operation per root field, with typed
//! variables, a depth- and size-bounded selection set, an example request
//! and insertion points.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use rune_http_model::{HttpBody, HttpRequest};
use serde_json::{Map, Value};
use url::Url;

use crate::schema::{InputValue, OperationKind, Schema, TypeDef, TypeKind, TypeRef};

/// The endpoint used when [`Options::endpoint`] is not set.
pub const DEFAULT_ENDPOINT: &str = "http://localhost/graphql";

/// Deepest input-object nesting synthesized for variable values.
const MAX_INPUT_DEPTH: usize = 8;

/// How example variable values are chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum ExampleStrategy {
    /// Declared default values first, then values synthesized from types.
    #[default]
    PreferDefaults,
    /// Values synthesized from types only.
    TypeDefaults,
}

/// How a generated operation is sent over HTTP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum Transport {
    /// `POST` with a JSON body `{"query", "variables", "operationName"}`.
    #[default]
    PostJson,
    /// `GET` with `query`, `variables` and `operationName` URL parameters.
    /// Mutations and subscriptions still use `POST` (GraphQL over HTTP).
    Get,
}

/// Import and generation options.
///
/// ```
/// use rune_graphql::{Options, Transport, Url};
///
/// let options = Options::default()
///     .with_endpoint(Url::parse("http://127.0.0.1:4000/graphql").unwrap())
///     .with_max_depth(3)
///     .with_header("Authorization", "Bearer {{token}}")
///     .with_transport(Transport::Get);
/// assert_eq!(options.max_depth, 3);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Options {
    /// Where requests are sent; [`DEFAULT_ENDPOINT`] (with a warning) when
    /// unset.
    pub endpoint: Option<Url>,
    /// Most fields on any path of a selection, root field included
    /// (`{ user { name } }` has depth 2). Values below 2 count as 2.
    pub max_depth: usize,
    /// Most fields selected from one type in one selection set.
    pub max_fields_per_selection: usize,
    /// Most fields selected in one whole operation.
    pub max_selections: usize,
    /// Most operations generated; [`GraphQlSpec::truncated`] reports a cut.
    pub max_operations: usize,
    /// Largest input accepted, in bytes.
    pub max_input_bytes: usize,
    /// Generate mutations.
    pub include_mutations: bool,
    /// Generate subscriptions.
    pub include_subscriptions: bool,
    /// Select deprecated fields and generate deprecated root fields.
    pub include_deprecated: bool,
    /// How variable values are chosen.
    pub example_strategy: ExampleStrategy,
    /// How requests are sent.
    pub transport: Transport,
    /// Extra headers on every request, such as credentials.
    pub headers: Vec<(String, String)>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            endpoint: None,
            max_depth: 4,
            max_fields_per_selection: 32,
            max_selections: 512,
            max_operations: 10_000,
            max_input_bytes: 16 * 1024 * 1024,
            include_mutations: true,
            include_subscriptions: false,
            include_deprecated: true,
            example_strategy: ExampleStrategy::default(),
            transport: Transport::default(),
            headers: Vec::new(),
        }
    }
}

impl Options {
    /// Sets [`endpoint`](Self::endpoint).
    #[must_use]
    pub fn with_endpoint(mut self, endpoint: Url) -> Self {
        self.endpoint = Some(endpoint);
        self
    }

    /// Sets [`max_depth`](Self::max_depth).
    #[must_use]
    pub const fn with_max_depth(mut self, max: usize) -> Self {
        self.max_depth = max;
        self
    }

    /// Sets [`max_fields_per_selection`](Self::max_fields_per_selection).
    #[must_use]
    pub const fn with_max_fields_per_selection(mut self, max: usize) -> Self {
        self.max_fields_per_selection = max;
        self
    }

    /// Sets [`max_selections`](Self::max_selections).
    #[must_use]
    pub const fn with_max_selections(mut self, max: usize) -> Self {
        self.max_selections = max;
        self
    }

    /// Sets [`max_operations`](Self::max_operations).
    #[must_use]
    pub const fn with_max_operations(mut self, max: usize) -> Self {
        self.max_operations = max;
        self
    }

    /// Sets [`max_input_bytes`](Self::max_input_bytes).
    #[must_use]
    pub const fn with_max_input_bytes(mut self, max: usize) -> Self {
        self.max_input_bytes = max;
        self
    }

    /// Sets [`include_mutations`](Self::include_mutations).
    #[must_use]
    pub const fn with_mutations(mut self, include: bool) -> Self {
        self.include_mutations = include;
        self
    }

    /// Sets [`include_subscriptions`](Self::include_subscriptions).
    #[must_use]
    pub const fn with_subscriptions(mut self, include: bool) -> Self {
        self.include_subscriptions = include;
        self
    }

    /// Sets [`include_deprecated`](Self::include_deprecated).
    #[must_use]
    pub const fn with_deprecated(mut self, include: bool) -> Self {
        self.include_deprecated = include;
        self
    }

    /// Sets [`example_strategy`](Self::example_strategy).
    #[must_use]
    pub const fn with_example_strategy(mut self, strategy: ExampleStrategy) -> Self {
        self.example_strategy = strategy;
        self
    }

    /// Sets [`transport`](Self::transport).
    #[must_use]
    pub const fn with_transport(mut self, transport: Transport) -> Self {
        self.transport = transport;
        self
    }

    /// Adds a header to every request.
    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    fn depth_bound(&self) -> usize {
        self.max_depth.max(2)
    }
}

/// Where a generated request can be mutated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum InsertionLocation {
    /// A leaf inside the `variables` object; the name is its JSON pointer
    /// (`/input/email`, `/ids/0`).
    Variable,
}

/// A scalar or enum spot in the variables, with its GraphQL type.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct InsertionPoint {
    /// Where the value sits.
    pub location: InsertionLocation,
    /// JSON pointer into `variables`.
    pub name: String,
    /// The variable the value belongs to.
    pub variable: String,
    /// The declared type at this spot, such as `ID!`.
    pub graphql_type: String,
    /// What kind of named type it is (scalar or enum).
    pub kind: TypeKind,
    /// Whether the value must not be null.
    pub required: bool,
    /// The value in the example request.
    pub value: Value,
    /// Allowed values when the type is an enum.
    pub enum_values: Vec<String>,
}

/// One generated operation: a root field called with every required
/// argument, selecting a bounded tree of its result.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct Operation {
    /// `query`, `mutation` or `subscription`.
    pub kind: OperationKind,
    /// `Root.field`, such as `Query.user`.
    pub coordinate: String,
    /// The root field.
    pub field: String,
    /// The operation name used in the document.
    pub name: String,
    /// The root field's `description`.
    pub description: Option<String>,
    /// Whether the root field is deprecated.
    pub deprecated: bool,
    /// The GraphQL document.
    pub document: String,
    /// The variables object sent with it.
    pub variables: Value,
    /// The depth of the selection (see [`Options::max_depth`]).
    pub depth: usize,
    /// Object, interface and union types the selection reaches, sorted.
    pub types: Vec<String>,
    /// `Type.field` coordinates the selection reads, sorted.
    pub fields: Vec<String>,
    /// The example request.
    pub request: HttpRequest,
    /// Leaf spots in [`variables`](Self::variables).
    pub insertion_points: Vec<InsertionPoint>,
}

impl Operation {
    /// The insertion point at the given JSON pointer.
    #[must_use]
    pub fn insertion_point(&self, pointer: &str) -> Option<&InsertionPoint> {
        self.insertion_points
            .iter()
            .find(|point| point.name == pointer)
    }

    /// Builds the request again with other options (endpoint, transport,
    /// headers); the document and variables stay the same.
    #[must_use]
    pub fn to_request(&self, options: &Options) -> HttpRequest {
        build_request(
            self.kind,
            &self.name,
            &self.document,
            &self.variables,
            options,
        )
    }

    /// The same request with `variables` replaced, for sending payloads.
    #[must_use]
    pub fn to_request_with(&self, variables: &Value, options: &Options) -> HttpRequest {
        build_request(self.kind, &self.name, &self.document, variables, options)
    }
}

/// Where the schema came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum SchemaSource {
    /// Schema definition language.
    Sdl,
    /// An introspection result.
    Introspection,
}

/// An imported GraphQL API: its schema and generated operations.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct GraphQlSpec {
    /// Where the schema came from.
    pub source: SchemaSource,
    /// The type model.
    pub schema: Schema,
    /// One per root field: queries, then mutations, then subscriptions.
    pub operations: Vec<Operation>,
    /// Non-fatal problems: the schema's warnings plus generation notes.
    pub warnings: Vec<String>,
    /// Whether [`Options::max_operations`] stopped generation early.
    pub truncated: bool,
}

impl GraphQlSpec {
    /// The operation for a root coordinate such as `Query.user`.
    #[must_use]
    pub fn operation(&self, coordinate: &str) -> Option<&Operation> {
        self.operations
            .iter()
            .find(|operation| operation.coordinate == coordinate)
    }

    /// Operations whose selection reaches the named type: the requests to
    /// replay per role when testing type-level authorization.
    pub fn operations_for_type<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Operation> {
        self.operations
            .iter()
            .filter(move |operation| operation.types.iter().any(|ty| ty == name))
    }

    /// Operations whose selection reads `Type.field`: the requests to replay
    /// per role when testing field-level authorization.
    pub fn operations_for_field<'a>(
        &'a self,
        coordinate: &'a str,
    ) -> impl Iterator<Item = &'a Operation> {
        self.operations
            .iter()
            .filter(move |operation| operation.fields.iter().any(|field| field == coordinate))
    }

    /// Every type reached by some operation, with the operations reaching
    /// it (indices into [`operations`](Self::operations)).
    #[must_use]
    pub fn operations_by_type(&self) -> BTreeMap<&str, Vec<usize>> {
        let mut map: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
        for (index, operation) in self.operations.iter().enumerate() {
            for ty in &operation.types {
                map.entry(ty.as_str()).or_default().push(index);
            }
        }
        map
    }
}

/// Generates one operation per root field of `schema`.
///
/// ```
/// use rune_graphql::{Options, generate, parse_sdl, validate};
///
/// let schema = parse_sdl("type Query { user(id: ID!): User } type User { id: ID! friends: [User] }")?;
/// let spec = generate(schema, &Options::default());
/// let user = spec.operation("Query.user").unwrap();
/// assert_eq!(user.document, "query User($id: ID!) { user(id: $id) { id } }");
/// assert!(validate(&user.document, &spec.schema).is_empty());
/// # Ok::<(), rune_graphql::GraphQlError>(())
/// ```
#[must_use]
pub fn generate(schema: Schema, options: &Options) -> GraphQlSpec {
    generate_from(schema, SchemaSource::Sdl, options)
}

pub fn generate_from(schema: Schema, source: SchemaSource, options: &Options) -> GraphQlSpec {
    let mut warnings = schema.warnings.clone();
    if options.endpoint.is_none() {
        warnings.push(format!(
            "no GraphQL endpoint given; using {DEFAULT_ENDPOINT} (set Options::endpoint)"
        ));
    }
    let mut operations = Vec::new();
    let mut truncated = false;
    let mut used_names = BTreeSet::new();
    let kinds = [
        (OperationKind::Query, true),
        (OperationKind::Mutation, options.include_mutations),
        (OperationKind::Subscription, options.include_subscriptions),
    ];
    'kinds: for (kind, enabled) in kinds {
        let Some(root) = schema.root_type(kind).filter(|_| enabled) else {
            continue;
        };
        for field in &root.fields {
            if field.deprecated && !options.include_deprecated {
                continue;
            }
            if operations.len() >= options.max_operations {
                truncated = true;
                break 'kinds;
            }
            let mut name = pascal(&field.name);
            if !used_names.insert(name.clone()) {
                name = format!("{name}{}", pascal(kind.as_str()));
                let base = name.clone();
                let mut counter = 2;
                while !used_names.insert(name.clone()) {
                    name = format!("{base}{counter}");
                    counter += 1;
                }
            }
            match Builder::new(&schema, options).operation(kind, root, field, name) {
                Ok(operation) => operations.push(operation),
                Err(problem) => warnings.push(problem),
            }
        }
    }
    if operations.is_empty() && !truncated {
        warnings.push(String::from("no operations generated"));
    }
    GraphQlSpec {
        source,
        schema,
        operations,
        warnings,
        truncated,
    }
}

fn pascal(name: &str) -> String {
    let mut chars = name.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().chain(chars).collect()
    })
}

fn escape_pointer(segment: &str) -> String {
    segment.replace('~', "~0").replace('/', "~1")
}

fn scalar_example(name: &str) -> Value {
    match name {
        "Int" | "Long" | "BigInt" | "Short" | "PositiveInt" | "UnsignedInt" => Value::from(1),
        "Float" | "Decimal" | "BigDecimal" => serde_json::json!(1.5),
        "Boolean" => Value::Bool(true),
        "ID" => Value::from("1"),
        "DateTime" | "Timestamp" | "Instant" => Value::from("2024-01-01T00:00:00Z"),
        "Date" => Value::from("2024-01-01"),
        "Time" => Value::from("00:00:00"),
        "UUID" | "Uuid" => Value::from("00000000-0000-4000-8000-000000000000"),
        "Email" | "EmailAddress" => Value::from("user@example.test"),
        "URI" | "URL" | "Url" | "Uri" => Value::from("https://example.test/"),
        "JSON" | "Json" | "JSONObject" => Value::Object(Map::new()),
        _ => Value::from("string"),
    }
}

/// Builds one operation.
struct Builder<'s> {
    schema: &'s Schema,
    options: &'s Options,
    declarations: Vec<String>,
    variables: Map<String, Value>,
    variable_types: Vec<(String, TypeRef)>,
    selections: usize,
    depth: usize,
    types: BTreeSet<String>,
    fields: BTreeSet<String>,
}

impl<'s> Builder<'s> {
    fn new(schema: &'s Schema, options: &'s Options) -> Self {
        Self {
            schema,
            options,
            declarations: Vec::new(),
            variables: Map::new(),
            variable_types: Vec::new(),
            selections: 0,
            depth: 0,
            types: BTreeSet::new(),
            fields: BTreeSet::new(),
        }
    }

    fn input_type_ok(&self, ty: &TypeRef) -> bool {
        self.schema
            .kind_of(ty.name())
            .is_some_and(TypeKind::is_input)
    }

    /// Declares a variable for `argument` and returns `name: $var`.
    fn bind(&mut self, preferred: &str, argument: &InputValue) -> String {
        let mut variable = preferred.to_owned();
        let mut counter = 2;
        while self.variables.contains_key(&variable) {
            variable = format!("{preferred}_{counter}");
            counter += 1;
        }
        let value = self.argument_value(argument);
        self.declarations
            .push(format!("${variable}: {}", argument.ty));
        self.variables.insert(variable.clone(), value);
        self.variable_types
            .push((variable.clone(), argument.ty.clone()));
        format!("{}: ${variable}", argument.name)
    }

    fn argument_value(&self, argument: &InputValue) -> Value {
        if self.options.example_strategy == ExampleStrategy::PreferDefaults
            && let Some(default) = &argument.default_value
        {
            return default.clone();
        }
        self.input_example(&argument.ty, 0, &mut Vec::new())
            .unwrap_or(Value::Null)
    }

    fn input_example(
        &self,
        ty: &TypeRef,
        depth: usize,
        visiting: &mut Vec<String>,
    ) -> Option<Value> {
        if depth > MAX_INPUT_DEPTH {
            return None;
        }
        match ty {
            TypeRef::NonNull(inner) => self.input_example(inner, depth + 1, visiting),
            TypeRef::List(inner) => Some(Value::Array(
                self.input_example(inner, depth + 1, visiting)
                    .into_iter()
                    .collect(),
            )),
            TypeRef::Named(name) => match self.schema.get(name) {
                Some(def) if def.kind == TypeKind::Enum => Some(
                    def.enum_values
                        .iter()
                        .find(|value| !value.deprecated)
                        .or_else(|| def.enum_values.first())
                        .map_or(Value::Null, |value| Value::from(value.name.as_str())),
                ),
                Some(def) if def.kind == TypeKind::InputObject => {
                    if visiting.contains(name) {
                        return None;
                    }
                    visiting.push(name.clone());
                    let object = self.input_object(def, depth, visiting);
                    visiting.pop();
                    Some(Value::Object(object))
                }
                _ => Some(scalar_example(name)),
            },
        }
    }

    fn input_object(
        &self,
        def: &TypeDef,
        depth: usize,
        visiting: &mut Vec<String>,
    ) -> Map<String, Value> {
        let mut object = Map::new();
        let limit = if def.one_of {
            1
        } else {
            self.options.max_fields_per_selection.max(1)
        };
        for field in &def.input_fields {
            if object.len() >= limit {
                break;
            }
            let value = if self.options.example_strategy == ExampleStrategy::PreferDefaults {
                field.default_value.clone()
            } else {
                None
            }
            .or_else(|| self.input_example(&field.ty, depth + 1, visiting));
            match value {
                Some(value) => {
                    object.insert(field.name.clone(), value);
                }
                None if field.ty.is_non_null() => {
                    object.insert(field.name.clone(), Value::Null);
                }
                None => {}
            }
        }
        object
    }

    /// The selection set of `type_name`, whose fields sit at `level`.
    fn selection_set(&mut self, type_name: &str, level: usize, path: &mut Vec<String>) -> String {
        self.depth = self.depth.max(level);
        let Some(def) = self.schema.get(type_name) else {
            return String::from("{ __typename }");
        };
        self.types.insert(type_name.to_owned());
        let mut parts = Vec::new();
        path.push(type_name.to_owned());
        match def.kind {
            TypeKind::Object | TypeKind::Interface => {
                let mut taken = 0;
                for field in &def.fields {
                    if taken >= self.options.max_fields_per_selection
                        || self.selections >= self.options.max_selections
                    {
                        break;
                    }
                    if field.deprecated && !self.options.include_deprecated {
                        continue;
                    }
                    let target = field.ty.name();
                    let Some(target_kind) = self.schema.kind_of(target) else {
                        continue;
                    };
                    if target_kind.is_composite()
                        && (level >= self.options.depth_bound()
                            || path.iter().any(|seen| seen == target))
                    {
                        continue;
                    }
                    if !target_kind.is_composite() && !target_kind.is_leaf() {
                        continue;
                    }
                    let required: Vec<&InputValue> = field
                        .arguments
                        .iter()
                        .filter(|arg| arg.is_required())
                        .collect();
                    if required.iter().any(|arg| !self.input_type_ok(&arg.ty)) {
                        continue;
                    }
                    taken += 1;
                    self.selections += 1;
                    self.fields.insert(format!("{type_name}.{}", field.name));
                    let mut text = field.name.clone();
                    if !required.is_empty() {
                        let bound: Vec<String> = required
                            .into_iter()
                            .map(|arg| self.bind(&format!("{}_{}", field.name, arg.name), arg))
                            .collect();
                        let _ = write!(text, "({})", bound.join(", "));
                    }
                    if target_kind.is_composite() {
                        let inner = self.selection_set(target, level + 1, path);
                        let _ = write!(text, " {inner}");
                    }
                    parts.push(text);
                }
            }
            TypeKind::Union => {
                parts.push(String::from("__typename"));
                for member in &def.members {
                    if self.selections >= self.options.max_selections {
                        break;
                    }
                    if path.iter().any(|seen| seen == member)
                        || self.schema.kind_of(member) != Some(TypeKind::Object)
                    {
                        continue;
                    }
                    let inner = self.selection_set(member, level, path);
                    parts.push(format!("... on {member} {inner}"));
                }
            }
            _ => {}
        }
        path.pop();
        if parts.is_empty() {
            parts.push(String::from("__typename"));
        }
        format!("{{ {} }}", parts.join(" "))
    }

    fn operation(
        mut self,
        kind: OperationKind,
        root: &TypeDef,
        field: &crate::schema::Field,
        name: String,
    ) -> Result<Operation, String> {
        let coordinate = format!("{}.{}", root.name, field.name);
        let target_kind = self.schema.kind_of(field.ty.name()).ok_or_else(|| {
            format!(
                "`{coordinate}`: result type `{}` is undefined; skipped",
                field.ty.name()
            )
        })?;
        if !target_kind.is_leaf() && !target_kind.is_composite() {
            return Err(format!(
                "`{coordinate}`: result type is not an output type; skipped"
            ));
        }
        let mut arguments = Vec::new();
        for argument in &field.arguments {
            if !self.input_type_ok(&argument.ty) {
                if argument.is_required() {
                    return Err(format!(
                        "`{coordinate}`: argument `{}` has a non-input type; skipped",
                        argument.name
                    ));
                }
                continue;
            }
            arguments.push(self.bind(&argument.name, argument));
        }
        self.fields.insert(coordinate.clone());
        self.types.insert(root.name.clone());
        self.selections += 1;
        self.depth = 1;
        let selection = if target_kind.is_composite() {
            let mut path = vec![root.name.clone()];
            self.selection_set(field.ty.name(), 2, &mut path)
        } else {
            String::new()
        };
        let mut document = format!("{kind} {name}");
        if !self.declarations.is_empty() {
            let _ = write!(document, "({})", self.declarations.join(", "));
        }
        let _ = write!(document, " {{ {}", field.name);
        if !arguments.is_empty() {
            let _ = write!(document, "({})", arguments.join(", "));
        }
        if !selection.is_empty() {
            let _ = write!(document, " {selection}");
        }
        document.push_str(" }");
        let mut insertion_points = Vec::new();
        for (variable, ty) in &self.variable_types {
            if let Some(value) = self.variables.get(variable) {
                self.points(
                    &mut insertion_points,
                    variable,
                    &format!("/{}", escape_pointer(variable)),
                    ty,
                    value,
                    0,
                );
            }
        }
        let variables = Value::Object(self.variables);
        let request = build_request(kind, &name, &document, &variables, self.options);
        Ok(Operation {
            kind,
            coordinate,
            field: field.name.clone(),
            name,
            description: field.description.clone(),
            deprecated: field.deprecated,
            document,
            variables,
            depth: self.depth,
            types: self.types.into_iter().collect(),
            fields: self.fields.into_iter().collect(),
            request,
            insertion_points,
        })
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "recursive walk threading the pointer and type"
    )]
    fn points(
        &self,
        out: &mut Vec<InsertionPoint>,
        variable: &str,
        pointer: &str,
        ty: &TypeRef,
        value: &Value,
        depth: usize,
    ) {
        if depth > MAX_INPUT_DEPTH * 2 + 2 {
            return;
        }
        let required = ty.is_non_null();
        match (ty.nullable(), value) {
            (TypeRef::List(inner), Value::Array(items)) => {
                for (index, item) in items.iter().enumerate() {
                    self.points(
                        out,
                        variable,
                        &format!("{pointer}/{index}"),
                        inner,
                        item,
                        depth + 1,
                    );
                }
            }
            (TypeRef::Named(name), Value::Object(fields))
                if self.schema.kind_of(name) == Some(TypeKind::InputObject) =>
            {
                if let Some(def) = self.schema.get(name) {
                    for (key, item) in fields {
                        if let Some(field) = def.input_field(key) {
                            self.points(
                                out,
                                variable,
                                &format!("{pointer}/{}", escape_pointer(key)),
                                &field.ty,
                                item,
                                depth + 1,
                            );
                        }
                    }
                }
            }
            (TypeRef::Named(name), _) => {
                let def = self.schema.get(name);
                let kind = def.map_or(TypeKind::Scalar, |def| def.kind);
                if kind.is_leaf() {
                    out.push(InsertionPoint {
                        location: InsertionLocation::Variable,
                        name: pointer.to_owned(),
                        variable: variable.to_owned(),
                        graphql_type: ty.to_string(),
                        kind,
                        required,
                        value: value.clone(),
                        enum_values: def
                            .map(|def| {
                                def.enum_values
                                    .iter()
                                    .map(|value| value.name.clone())
                                    .collect()
                            })
                            .unwrap_or_default(),
                    });
                }
            }
            _ => {}
        }
    }
}

fn build_request(
    kind: OperationKind,
    name: &str,
    document: &str,
    variables: &Value,
    options: &Options,
) -> HttpRequest {
    let endpoint = options
        .endpoint
        .clone()
        .or_else(|| Url::parse(DEFAULT_ENDPOINT).ok());
    let mut request = match (options.transport, kind, endpoint) {
        (Transport::Get, OperationKind::Query, Some(mut url)) => {
            url.query_pairs_mut()
                .append_pair("query", document)
                .append_pair("variables", &variables.to_string())
                .append_pair("operationName", name);
            HttpRequest::new("GET", url.as_str())
        }
        (_, _, endpoint) => {
            let body = serde_json::json!({
                "query": document,
                "variables": variables,
                "operationName": name,
            });
            HttpRequest::new(
                "POST",
                endpoint.map_or_else(|| DEFAULT_ENDPOINT.to_owned(), String::from),
            )
            .with_header("Content-Type", "application/json")
            .with_body(HttpBody::from_text(body.to_string()))
        }
    };
    request = request.with_header(
        "Accept",
        "application/graphql-response+json, application/json",
    );
    for (header, value) in &options.headers {
        request = request.with_header(header.as_str(), value.as_str());
    }
    request
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_type_system;

    fn spec(sdl: &str, options: &Options) -> GraphQlSpec {
        generate(parse_type_system(sdl).unwrap(), options)
    }

    #[test]
    fn nested_required_arguments_are_hoisted() {
        let spec = spec(
            "type Query { user(id: ID!): User } \
             type User { id: ID! posts(first: Int!, after: String): [Post] } \
             type Post { title: String }",
            &Options::default(),
        );
        let user = spec.operation("Query.user").unwrap();
        assert_eq!(
            user.document,
            "query User($id: ID!, $posts_first: Int!) { user(id: $id) { id posts(first: $posts_first) { title } } }"
        );
        assert_eq!(
            user.variables,
            serde_json::json!({"id": "1", "posts_first": 1})
        );
        assert_eq!(user.depth, 3);
        assert_eq!(
            user.fields,
            ["Post.title", "Query.user", "User.id", "User.posts"]
        );
        assert_eq!(user.insertion_points.len(), 2);
        assert!(user.insertion_point("/posts_first").unwrap().required);
    }

    #[test]
    fn names_are_unique_across_kinds() {
        let spec = spec(
            "type Query { item: Int } type Mutation { item: Int } type Subscription { item: Int }",
            &Options::default().with_subscriptions(true),
        );
        let names: Vec<_> = spec.operations.iter().map(|op| op.name.as_str()).collect();
        assert_eq!(names, ["Item", "ItemMutation", "ItemSubscription"]);
    }

    #[test]
    fn get_transport_only_for_queries() {
        let options = Options::default()
            .with_transport(Transport::Get)
            .with_header("Authorization", "Bearer t");
        let spec = spec("type Query { a: Int } type Mutation { b: Int }", &options);
        let query = &spec.operations[0].request;
        assert_eq!(query.method, "GET");
        assert!(
            query
                .url
                .starts_with("http://localhost/graphql?query=query+A")
        );
        assert_eq!(query.header("Authorization"), Some("Bearer t"));
        assert_eq!(spec.operations[1].request.method, "POST");
        assert!(
            spec.warnings
                .iter()
                .any(|warning| warning.contains("no GraphQL endpoint"))
        );
    }

    #[test]
    fn one_of_and_recursive_inputs() {
        let spec = spec(
            "type Query { find(by: By!, tree: Tree): Int } \
             input By @oneOf { id: ID email: String } \
             input Tree { value: Int children: [Tree!] parent: Tree }",
            &Options::default(),
        );
        let find = spec.operation("Query.find").unwrap();
        assert_eq!(
            find.variables,
            serde_json::json!({"by": {"id": "1"}, "tree": {"value": 1, "children": []}})
        );
        let names: Vec<_> = find
            .insertion_points
            .iter()
            .map(|p| p.name.as_str())
            .collect();
        assert_eq!(names, ["/by/id", "/tree/value"]);
    }

    #[test]
    fn truncation() {
        let spec = spec(
            "type Query { a: Int b: Int c: Int }",
            &Options::default().with_max_operations(2),
        );
        assert!(spec.truncated);
        assert_eq!(spec.operations.len(), 2);
    }
}
