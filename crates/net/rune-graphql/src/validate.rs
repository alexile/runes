//! Validation of executable documents against a schema
//! ([spec §5](https://spec.graphql.org/October2021/#sec-Validation)).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::GraphQlError;
use crate::parser::{
    AstValue, Directive, ExecutableDocument, FragmentDefinition, MAX_NESTING, Selection,
    parse_executable,
};
use crate::schema::{OperationKind, Schema, TypeKind, TypeRef};

/// A rule an operation breaks.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ValidationError {
    /// A stable rule code, such as `unknown_field` or `syntax`.
    pub rule: &'static str,
    /// What is wrong, naming the offending element.
    pub message: String,
}

impl ValidationError {
    fn new(rule: &'static str, message: impl Into<String>) -> Self {
        Self {
            rule,
            message: message.into(),
        }
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.rule, self.message)
    }
}

/// Validates an executable document against `schema`; an empty result
/// means it is valid.
///
/// Covered rules: syntax; operation name uniqueness and lone anonymous
/// operations; root type existence; fields defined on their parent type;
/// leaf fields without and composite fields with selections; argument
/// names, required arguments and literal value kinds (null into non-null,
/// enum values, input object fields, built-in scalar kinds); variable
/// uniqueness, input types, definition, use and type compatibility (the
/// spec's `IsVariableUsageAllowed`); fragment existence, use, type
/// conditions on composite types and spread cycles. Field-merge conflicts
/// (`OverlappingFieldsCanBeMerged`) are not checked.
///
/// ```
/// use rune_graphql::{parse_sdl, validate};
///
/// let schema = parse_sdl("type Query { user(id: ID!): User } type User { name: String }")?;
/// assert!(validate("query($id: ID!) { user(id: $id) { name } }", &schema).is_empty());
///
/// let errors = validate("{ user { email } }", &schema);
/// let rules: Vec<_> = errors.iter().map(|error| error.rule).collect();
/// assert_eq!(rules, ["missing_argument", "unknown_field"]);
/// # Ok::<(), rune_graphql::GraphQlError>(())
/// ```
#[must_use]
pub fn validate(document: &str, schema: &Schema) -> Vec<ValidationError> {
    match parse_executable(document) {
        Ok(document) => Validator::new(schema, &document).run(),
        Err(error) => vec![ValidationError::new("syntax", error.to_string())],
    }
}

/// The depth of the deepest operation in a document: the most fields on
/// any path, fragments expanded (`{ user { name } }` is 2).
///
/// ```
/// use rune_graphql::query_depth;
///
/// assert_eq!(query_depth("{ a { b { c } } d }")?, 3);
/// assert_eq!(query_depth("{ ...F } fragment F on Query { a { b } }")?, 2);
/// # Ok::<(), rune_graphql::GraphQlError>(())
/// ```
pub fn query_depth(document: &str) -> Result<usize, GraphQlError> {
    let document = parse_executable(document)?;
    let fragments: BTreeMap<&str, &FragmentDefinition> = document
        .fragments
        .iter()
        .map(|fragment| (fragment.name.as_str(), fragment))
        .collect();
    let mut stack = Vec::new();
    let mut known = BTreeMap::new();
    Ok(document
        .operations
        .iter()
        .map(|operation| depth_of(&operation.selections, &fragments, &mut stack, &mut known))
        .max()
        .unwrap_or(0))
}

/// `known` keeps each fragment's depth once computed, so a fragment
/// spread many times is walked once rather than once per path.
fn depth_of<'a>(
    selections: &'a [Selection],
    fragments: &BTreeMap<&str, &'a FragmentDefinition>,
    stack: &mut Vec<&'a str>,
    known: &mut BTreeMap<&'a str, usize>,
) -> usize {
    if stack.len() > MAX_NESTING {
        return 0;
    }
    selections
        .iter()
        .map(|selection| match selection {
            Selection::Field(field) => {
                1 + field
                    .selections
                    .as_deref()
                    .map_or(0, |inner| depth_of(inner, fragments, stack, known))
            }
            Selection::Inline { selections, .. } => depth_of(selections, fragments, stack, known),
            Selection::Spread { name, .. } => {
                let Some(fragment) = fragments.get(name.as_str()) else {
                    return 0;
                };
                if let Some(&depth) = known.get(fragment.name.as_str()) {
                    return depth;
                }
                if stack.contains(&fragment.name.as_str()) {
                    return 0;
                }
                stack.push(fragment.name.as_str());
                let depth = depth_of(&fragment.selections, fragments, stack, known);
                stack.pop();
                known.insert(fragment.name.as_str(), depth);
                depth
            }
        })
        .max()
        .unwrap_or(0)
}

struct Variable<'d> {
    ty: &'d TypeRef,
    has_default: bool,
}

struct Validator<'s, 'd> {
    schema: &'s Schema,
    document: &'d ExecutableDocument,
    fragments: BTreeMap<&'d str, &'d FragmentDefinition>,
    errors: Vec<ValidationError>,
    used_fragments: BTreeSet<&'d str>,
    /// Fragments already walked in the current operation, with the
    /// shallowest depth they were walked at. A fragment's contents are
    /// checked against its own type condition, so a second walk at the
    /// same depth or deeper finds nothing new; skipping it keeps
    /// validation linear when fragments spread each other many times.
    walked: BTreeMap<&'d str, usize>,
    reported: BTreeSet<String>,
}

impl<'s, 'd> Validator<'s, 'd> {
    const fn new(schema: &'s Schema, document: &'d ExecutableDocument) -> Self {
        Self {
            schema,
            document,
            fragments: BTreeMap::new(),
            errors: Vec::new(),
            used_fragments: BTreeSet::new(),
            walked: BTreeMap::new(),
            reported: BTreeSet::new(),
        }
    }

    fn error(&mut self, rule: &'static str, message: impl Into<String>) {
        let message = message.into();
        // Fragments are re-walked per operation: report each problem once.
        if self.reported.insert(format!("{rule}\u{0}{message}")) {
            self.errors.push(ValidationError::new(rule, message));
        }
    }

    fn run(mut self) -> Vec<ValidationError> {
        let document = self.document;
        for fragment in &document.fragments {
            if self.fragments.insert(&fragment.name, fragment).is_some() {
                self.error(
                    "duplicate_fragment",
                    format!("fragment `{}` is defined more than once", fragment.name),
                );
            }
            match self.schema.kind_of(&fragment.type_condition) {
                Some(kind) if kind.is_composite() => {}
                Some(_) => self.error(
                    "invalid_type_condition",
                    format!(
                        "fragment `{}` is on `{}`, which is not an object, interface or union",
                        fragment.name, fragment.type_condition
                    ),
                ),
                None => self.error(
                    "unknown_type",
                    format!(
                        "fragment `{}` is on unknown type `{}`",
                        fragment.name, fragment.type_condition
                    ),
                ),
            }
        }
        let mut names = BTreeSet::new();
        let anonymous = document
            .operations
            .iter()
            .filter(|operation| operation.name.is_none())
            .count();
        if anonymous > 0 && document.operations.len() > 1 {
            self.error(
                "lone_anonymous_operation",
                "an anonymous operation must be the only operation in the document",
            );
        }
        for operation in &document.operations {
            if let Some(name) = &operation.name
                && !names.insert(name.as_str())
            {
                self.error(
                    "duplicate_operation",
                    format!("operation `{name}` is defined more than once"),
                );
            }
            let label = operation.name.as_deref().map_or_else(
                || String::from("anonymous operation"),
                |name| format!("operation `{name}`"),
            );
            let mut variables: BTreeMap<&str, Variable<'_>> = BTreeMap::new();
            for definition in &operation.variables {
                if variables.contains_key(definition.name.as_str()) {
                    self.error(
                        "duplicate_variable",
                        format!(
                            "{label}: variable `${}` is declared more than once",
                            definition.name
                        ),
                    );
                    continue;
                }
                match self.schema.kind_of(definition.ty.name()) {
                    Some(kind) if kind.is_input() => {}
                    Some(_) => self.error(
                        "non_input_variable",
                        format!(
                            "{label}: variable `${}` has non-input type `{}`",
                            definition.name, definition.ty
                        ),
                    ),
                    None => self.error(
                        "unknown_type",
                        format!(
                            "{label}: variable `${}` has unknown type `{}`",
                            definition.name, definition.ty
                        ),
                    ),
                }
                if let Some(default) = &definition.default {
                    self.check_literal(
                        default,
                        &definition.ty,
                        &format!("default of `${}`", definition.name),
                        0,
                    );
                }
                variables.insert(
                    &definition.name,
                    Variable {
                        ty: &definition.ty,
                        has_default: definition
                            .default
                            .as_ref()
                            .is_some_and(|value| *value != AstValue::Null),
                    },
                );
            }
            let Some(root) = self.schema.root_name(operation.kind) else {
                self.error(
                    "unknown_root",
                    format!("{label}: the schema has no {} type", operation.kind),
                );
                continue;
            };
            let mut used = BTreeSet::new();
            let mut stack = Vec::new();
            self.walked.clear();
            self.directives(&operation.directives, &variables, &mut used, &label);
            self.selections(
                root,
                &operation.selections,
                &variables,
                &mut used,
                &mut stack,
                &label,
                0,
            );
            for definition in &operation.variables {
                if !used.contains(definition.name.as_str()) {
                    self.error(
                        "unused_variable",
                        format!("{label}: variable `${}` is never used", definition.name),
                    );
                }
            }
        }
        for fragment in &document.fragments {
            if !self.used_fragments.contains(fragment.name.as_str()) {
                self.error(
                    "unused_fragment",
                    format!("fragment `{}` is never used", fragment.name),
                );
            }
        }
        self.errors
    }

    fn directives(
        &mut self,
        directives: &'d [Directive],
        variables: &BTreeMap<&str, Variable<'_>>,
        used: &mut BTreeSet<&'d str>,
        label: &str,
    ) {
        for directive in directives {
            for (_, value) in &directive.arguments {
                self.variable_uses(value, None, variables, used, label);
            }
        }
    }

    /// Records the variables a value uses, checking each against
    /// `location` when given.
    fn variable_uses(
        &mut self,
        value: &'d AstValue,
        location: Option<(&TypeRef, bool)>,
        variables: &BTreeMap<&str, Variable<'_>>,
        used: &mut BTreeSet<&'d str>,
        label: &str,
    ) {
        if let (AstValue::Variable(name), Some((expected, location_default))) = (value, location) {
            used.insert(name);
            match variables.get(name.as_str()) {
                None => self.error(
                    "undefined_variable",
                    format!("{label}: variable `${name}` is not declared"),
                ),
                Some(variable) => {
                    if !usage_allowed(
                        variable.ty,
                        variable.has_default,
                        expected,
                        location_default,
                    ) {
                        self.error(
                            "variable_type",
                            format!(
                                "{label}: variable `${name}` of type `{}` cannot be used where `{expected}` is expected",
                                variable.ty
                            ),
                        );
                    }
                }
            }
            return;
        }
        let mut names = Vec::new();
        value.variables(&mut |name| names.push(name));
        for name in names {
            used.insert(name);
            if !variables.contains_key(name) {
                self.error(
                    "undefined_variable",
                    format!("{label}: variable `${name}` is not declared"),
                );
            }
        }
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "recursive walk threading validation state"
    )]
    fn selections(
        &mut self,
        parent: &str,
        selections: &'d [Selection],
        variables: &BTreeMap<&str, Variable<'_>>,
        used: &mut BTreeSet<&'d str>,
        stack: &mut Vec<&'d str>,
        label: &str,
        depth: usize,
    ) {
        if depth > MAX_NESTING {
            return;
        }
        let schema = self.schema;
        for selection in selections {
            match selection {
                Selection::Field(field) => {
                    self.directives(&field.directives, variables, used, label);
                    if field.name == "__typename" {
                        if field.selections.is_some() {
                            self.error(
                                "leaf_selection",
                                format!("{label}: `__typename` cannot have a selection"),
                            );
                        }
                        continue;
                    }
                    if matches!(field.name.as_str(), "__schema" | "__type")
                        && schema.root_name(OperationKind::Query) == Some(parent)
                    {
                        for (_, value) in &field.arguments {
                            self.variable_uses(value, None, variables, used, label);
                        }
                        continue;
                    }
                    let Some(definition) = schema.field(parent, &field.name) else {
                        self.error(
                            "unknown_field",
                            format!("{label}: `{parent}` has no field `{}`", field.name),
                        );
                        for (_, value) in &field.arguments {
                            self.variable_uses(value, None, variables, used, label);
                        }
                        continue;
                    };
                    let coordinate = format!("{parent}.{}", field.name);
                    for (name, value) in &field.arguments {
                        if let Some(argument) = definition.argument(name) {
                            {
                                self.variable_uses(
                                    value,
                                    Some((&argument.ty, argument.default_value.is_some())),
                                    variables,
                                    used,
                                    label,
                                );
                                self.check_literal(
                                    value,
                                    &argument.ty,
                                    &format!("`{coordinate}({name}:)`"),
                                    0,
                                );
                            }
                        } else {
                            self.error(
                                "unknown_argument",
                                format!("{label}: `{coordinate}` has no argument `{name}`"),
                            );
                            self.variable_uses(value, None, variables, used, label);
                        }
                    }
                    for argument in &definition.arguments {
                        if argument.is_required()
                            && !field
                                .arguments
                                .iter()
                                .any(|(name, _)| *name == argument.name)
                        {
                            self.error(
                                "missing_argument",
                                format!(
                                    "{label}: `{coordinate}` requires argument `{}`",
                                    argument.name
                                ),
                            );
                        }
                    }
                    let target = definition.ty.name();
                    match (schema.kind_of(target), &field.selections) {
                        (Some(kind), Some(_)) if kind.is_leaf() => self.error(
                            "leaf_selection",
                            format!(
                                "{label}: `{coordinate}` is a leaf and cannot have a selection"
                            ),
                        ),
                        (Some(kind), None) if kind.is_composite() => self.error(
                            "missing_selection",
                            format!("{label}: `{coordinate}` of type `{target}` needs a selection"),
                        ),
                        (Some(kind), Some(inner)) if kind.is_composite() => {
                            self.selections(
                                target,
                                inner,
                                variables,
                                used,
                                stack,
                                label,
                                depth + 1,
                            );
                        }
                        _ => {}
                    }
                }
                Selection::Inline {
                    type_condition,
                    directives,
                    selections,
                } => {
                    self.directives(directives, variables, used, label);
                    let target = type_condition.as_deref().unwrap_or(parent);
                    if self.type_condition_ok(target, parent, label) {
                        self.selections(
                            target,
                            selections,
                            variables,
                            used,
                            stack,
                            label,
                            depth + 1,
                        );
                    }
                }
                Selection::Spread { name, directives } => {
                    self.directives(directives, variables, used, label);
                    let Some(&fragment) = self.fragments.get(name.as_str()) else {
                        self.error(
                            "unknown_fragment",
                            format!("{label}: fragment `{name}` is not defined"),
                        );
                        continue;
                    };
                    self.used_fragments.insert(&fragment.name);
                    if stack.contains(&fragment.name.as_str()) {
                        self.error(
                            "fragment_cycle",
                            format!("fragment `{name}` spreads itself"),
                        );
                        continue;
                    }
                    if !self.type_condition_ok(&fragment.type_condition, parent, label) {
                        continue;
                    }
                    if self
                        .walked
                        .get(fragment.name.as_str())
                        .is_some_and(|&shallowest| shallowest <= depth)
                    {
                        continue;
                    }
                    self.walked.insert(&fragment.name, depth);
                    stack.push(&fragment.name);
                    self.directives(&fragment.directives, variables, used, label);
                    self.selections(
                        &fragment.type_condition,
                        &fragment.selections,
                        variables,
                        used,
                        stack,
                        label,
                        depth + 1,
                    );
                    stack.pop();
                }
            }
        }
    }

    fn type_condition_ok(&mut self, target: &str, parent: &str, label: &str) -> bool {
        match self.schema.kind_of(target) {
            Some(kind) if kind.is_composite() => {
                let possible: BTreeSet<&str> =
                    self.schema.possible_types(target).into_iter().collect();
                let overlap = self
                    .schema
                    .possible_types(parent)
                    .into_iter()
                    .any(|ty| possible.contains(ty));
                if !overlap {
                    self.error(
                        "impossible_spread",
                        format!("{label}: `{target}` can never apply within `{parent}`"),
                    );
                }
                overlap
            }
            Some(_) => {
                self.error(
                    "invalid_type_condition",
                    format!("{label}: `{target}` is not an object, interface or union"),
                );
                false
            }
            None => {
                self.error("unknown_type", format!("{label}: unknown type `{target}`"));
                false
            }
        }
    }

    /// Checks a literal against its expected input type.
    fn check_literal(&mut self, value: &AstValue, expected: &TypeRef, at: &str, depth: usize) {
        if depth > MAX_NESTING {
            return;
        }
        let mismatch = |found: &str| format!("{at}: {found} is not a valid `{expected}`");
        match (value, expected) {
            (AstValue::Null, TypeRef::NonNull(_)) => self.error("value_type", mismatch("null")),
            (AstValue::Variable(_) | AstValue::Null, _) => {}
            (AstValue::List(items), TypeRef::List(inner)) => {
                for item in items {
                    self.check_literal(item, inner, at, depth + 1);
                }
            }
            // Input coercion wraps a single value in a list.
            (_, TypeRef::NonNull(inner) | TypeRef::List(inner)) => {
                self.check_literal(value, inner, at, depth + 1);
            }
            (_, TypeRef::Named(name)) => {
                let Some(def) = self.schema.get(name) else {
                    return;
                };
                match def.kind {
                    TypeKind::Enum => match value {
                        AstValue::Enum(text)
                            if def.enum_values.iter().any(|known| known.name == *text) => {}
                        AstValue::Enum(text) => {
                            self.error("value_type", mismatch(&format!("`{text}`")));
                        }
                        _ => self.error("value_type", mismatch("a non-enum literal")),
                    },
                    TypeKind::InputObject => {
                        let AstValue::Object(fields) = value else {
                            self.error("value_type", mismatch("a non-object literal"));
                            return;
                        };
                        let def = def.clone();
                        for (field, item) in fields {
                            match def.input_field(field) {
                                Some(input) => {
                                    self.check_literal(
                                        item,
                                        &input.ty,
                                        &format!("{at}.{field}"),
                                        depth + 1,
                                    );
                                }
                                None => self.error(
                                    "unknown_input_field",
                                    format!("{at}: `{name}` has no field `{field}`"),
                                ),
                            }
                        }
                        for input in &def.input_fields {
                            if input.is_required()
                                && !fields.iter().any(|(field, _)| *field == input.name)
                            {
                                self.error(
                                    "missing_input_field",
                                    format!("{at}: `{name}.{}` is required", input.name),
                                );
                            }
                        }
                    }
                    _ => {
                        let ok = match (name.as_str(), value) {
                            ("Int", AstValue::Int(_))
                            | ("Float", AstValue::Int(_) | AstValue::Float(_))
                            | ("String", AstValue::String(_))
                            | ("Boolean", AstValue::Boolean(_))
                            | ("ID", AstValue::Int(_) | AstValue::String(_)) => true,
                            ("Int" | "Float" | "String" | "Boolean" | "ID", _) => false,
                            // Custom scalars accept any literal.
                            _ => true,
                        };
                        if !ok {
                            self.error("value_type", mismatch("the literal"));
                        }
                    }
                }
            }
        }
    }
}

/// The spec's `IsVariableUsageAllowed` and `AreTypesCompatible`.
fn usage_allowed(
    variable: &TypeRef,
    has_default: bool,
    location: &TypeRef,
    location_default: bool,
) -> bool {
    if let (TypeRef::NonNull(inner), false) = (location, variable.is_non_null()) {
        if !has_default && !location_default {
            return false;
        }
        return compatible(variable, inner);
    }
    compatible(variable, location)
}

fn compatible(variable: &TypeRef, location: &TypeRef) -> bool {
    match (variable, location) {
        (TypeRef::NonNull(variable), TypeRef::NonNull(location))
        | (TypeRef::List(variable), TypeRef::List(location)) => compatible(variable, location),
        (_, TypeRef::NonNull(_)) => false,
        (TypeRef::NonNull(variable), location) => compatible(variable, location),
        (TypeRef::List(_), _) | (_, TypeRef::List(_)) => false,
        (TypeRef::Named(variable), TypeRef::Named(location)) => variable == location,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_type_system;

    fn schema() -> Schema {
        parse_type_system(
            "type Query { user(id: ID!): User users(role: Role, filter: Filter, ids: [ID!]): [User] node: Node search: [Hit] }
             type User implements Node { id: ID! name: String friends(first: Int = 5): [User] }
             type Bot implements Node { id: ID! }
             interface Node { id: ID! }
             union Hit = User | Bot
             enum Role { ADMIN USER }
             input Filter { name: String! age: Int }",
        )
        .unwrap()
    }

    fn rules(document: &str) -> Vec<&'static str> {
        validate(document, &schema())
            .into_iter()
            .map(|error| error.rule)
            .collect()
    }

    #[test]
    fn valid_documents() {
        for document in [
            "{ user(id: 1) { id name friends { id } } }",
            "query Q($id: ID!) { user(id: $id) { ...U } } fragment U on User { name }",
            "query($r: Role = ADMIN) { users(role: $r, filter: {name: \"x\"}, ids: \"1\") { id } }",
            "{ node { id ... on User { name } ... on Bot { id } } search { __typename ... on Bot { id } } }",
            "query($skip: Boolean!) { __typename @skip(if: $skip) __schema { types { name } } }",
            "query($f: Int) { user(id: \"1\") { friends(first: $f) { id } } }",
        ] {
            assert_eq!(rules(document), Vec::<&str>::new(), "{document}");
        }
    }

    #[test]
    fn invalid_documents() {
        let cases: [(&str, &[&str]); 14] = [
            ("{ user(id: 1) { nope } }", &["unknown_field"]),
            ("{ user { id } }", &["missing_argument"]),
            ("{ user(id: 1) }", &["missing_selection"]),
            ("{ user(id: 1) { id { x } } }", &["leaf_selection"]),
            ("{ user(id: 1, x: 2) { id } }", &["unknown_argument"]),
            ("{ user(id: $v) { id } }", &["undefined_variable"]),
            (
                "query($v: ID) { user(id: \"1\") { id } }",
                &["unused_variable"],
            ),
            ("query($v: ID) { user(id: $v) { id } }", &["variable_type"]),
            (
                "query($v: User) { user(id: $v) { id } }",
                &["non_input_variable", "variable_type"],
            ),
            (
                "{ users(role: OWNER, filter: {age: \"x\"}) { id } }",
                &["value_type", "value_type", "missing_input_field"],
            ),
            (
                "{ user(id: 1) { ...F } } fragment F on User { ...F }",
                &["fragment_cycle"],
            ),
            (
                "{ user(id: 1) { ... on Bot { id } } }",
                &["impossible_spread"],
            ),
            (
                "{ a: __typename } fragment F on Role { x }",
                &["invalid_type_condition", "unused_fragment"],
            ),
            (
                "query A { __typename } query A { __typename } { __typename }",
                &["lone_anonymous_operation", "duplicate_operation"],
            ),
        ];
        for (document, expected) in cases {
            assert_eq!(rules(document), expected, "{document}");
        }
        assert_eq!(rules("mutation { x }"), ["unknown_root"]);
        assert_eq!(rules("{ "), ["syntax"]);
    }

    #[test]
    fn depth() {
        assert_eq!(query_depth("{ a }").unwrap(), 1);
        assert_eq!(query_depth("{ a { ... on X { b { c } } } }").unwrap(), 3);
        assert_eq!(
            query_depth("{ ...F } fragment F on Q { ...F a }").unwrap(),
            1
        );
        assert!(query_depth("{").is_err());
    }

    #[test]
    fn compatibility() {
        let int = TypeRef::named("Int");
        assert!(usage_allowed(&int.clone().non_null(), false, &int, false));
        assert!(!usage_allowed(&int, false, &int.clone().non_null(), false));
        assert!(usage_allowed(&int, true, &int.clone().non_null(), false));
        assert!(usage_allowed(&int, false, &int.clone().non_null(), true));
        assert!(!usage_allowed(&int.clone().list(), false, &int, false));
        assert!(usage_allowed(
            &int.clone().non_null().list(),
            false,
            &int.list(),
            false
        ));
    }

    /// `F0` spreads `F1` twice, `F1` spreads `F2` twice, and so on: valid,
    /// small, and 2^levels paths when every spread is walked again.
    fn fan_out(levels: usize) -> String {
        use std::fmt::Write as _;
        let mut document = String::from("query Q { ...F0 }");
        for level in 0..levels {
            let next = level + 1;
            let _ = write!(
                document,
                " fragment F{level} on Query {{ ...F{next} a {{ ...F{next} }} }}"
            );
        }
        let _ = write!(document, " fragment F{levels} on Query {{ x }}");
        document
    }

    #[test]
    fn fragment_fan_out_is_linear() {
        let schema = crate::parse_sdl("type Query { a: Query x: Int }").unwrap();
        let document = fan_out(40);
        let started = std::time::Instant::now();
        assert_eq!(query_depth(&document).unwrap(), 41);
        assert_eq!(validate(&document, &schema), Vec::new());
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }
}
