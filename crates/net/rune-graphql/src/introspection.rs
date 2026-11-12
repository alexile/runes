//! Introspection results ([spec §4](https://spec.graphql.org/October2021/#sec-Introspection))
//! to and from the [`Schema`] model.

use serde_json::{Map, Value, json};

use crate::GraphQlError;
use crate::parser::parse_const_value;
use crate::schema::{EnumValue, Field, InputValue, Schema, TypeDef, TypeKind, TypeRef};

/// Deepest `ofType` chain accepted.
const MAX_TYPE_REF_DEPTH: usize = 32;

/// Reads an introspection result: `{"data": {"__schema": …}}`, or the
/// `__schema` object with or without its wrapper.
///
/// Malformed entries (a field without a name or type, an unknown kind, an
/// unparsable `defaultValue`) are skipped with a warning.
///
/// ```
/// use rune_graphql::{TypeKind, parse_introspection};
/// use serde_json::json;
///
/// let schema = parse_introspection(&json!({"data": {"__schema": {
///     "queryType": {"name": "Query"},
///     "types": [{"kind": "OBJECT", "name": "Query", "fields": [
///         {"name": "ping", "args": [], "type": {"kind": "SCALAR", "name": "String"}}
///     ]}]
/// }}}))?;
/// assert_eq!(schema.field("Query", "ping").map(|field| field.ty.to_string()), Some("String".into()));
/// # Ok::<(), rune_graphql::GraphQlError>(())
/// ```
pub fn parse_introspection(document: &Value) -> Result<Schema, GraphQlError> {
    let root = document
        .pointer("/data/__schema")
        .or_else(|| document.get("__schema"))
        .or_else(|| document.get("types").map(|_| document))
        .ok_or_else(|| GraphQlError::NotIntrospection(String::from("missing `__schema`")))?;
    let types = root
        .get("types")
        .and_then(Value::as_array)
        .ok_or_else(|| GraphQlError::NotIntrospection(String::from("missing `types` array")))?;
    let root_name = |key: &str| {
        root.get(key)
            .and_then(|ty| ty.get("name"))
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    let mut schema = Schema {
        query_type: root_name("queryType"),
        mutation_type: root_name("mutationType"),
        subscription_type: root_name("subscriptionType"),
        ..Schema::default()
    };
    let mut warnings = Vec::new();
    for (index, entry) in types.iter().enumerate() {
        let Some(name) = entry.get("name").and_then(Value::as_str) else {
            warnings.push(format!("types[{index}] has no name; skipped"));
            continue;
        };
        if name.starts_with("__") {
            continue;
        }
        let Some(kind) = entry
            .get("kind")
            .and_then(Value::as_str)
            .and_then(TypeKind::from_introspection)
        else {
            warnings.push(format!("type `{name}` has an unknown kind; skipped"));
            continue;
        };
        let mut ty = TypeDef::new(name, kind);
        ty.description = string(entry, "description");
        ty.one_of = entry.get("isOneOf").and_then(Value::as_bool) == Some(true);
        for field in array(entry, "fields") {
            match read_field(field, &mut warnings) {
                Some(field) => ty.fields.push(field),
                None => warnings.push(format!("a field of `{name}` is malformed; skipped")),
            }
        }
        for input in array(entry, "inputFields") {
            match read_input(input, &mut warnings) {
                Some(input) => ty.input_fields.push(input),
                None => warnings.push(format!("an input field of `{name}` is malformed; skipped")),
            }
        }
        ty.interfaces = names(entry, "interfaces");
        ty.members = names(entry, "possibleTypes");
        if kind != TypeKind::Union {
            ty.members.clear();
        }
        ty.enum_values = array(entry, "enumValues")
            .filter_map(|value| {
                let mut enum_value = EnumValue::new(value.get("name").and_then(Value::as_str)?);
                enum_value.description = string(value, "description");
                enum_value.deprecated = deprecated(value);
                Some(enum_value)
            })
            .collect();
        if schema.types.insert(name.to_owned(), ty).is_some() {
            warnings.push(format!("type `{name}` listed more than once; last kept"));
        }
    }
    schema.warnings = warnings;
    schema.finish();
    Ok(schema)
}

fn array<'a>(value: &'a Value, key: &str) -> impl Iterator<Item = &'a Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
}

fn string(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn names(value: &Value, key: &str) -> Vec<String> {
    array(value, key)
        .filter_map(|item| string(item, "name"))
        .collect()
}

fn deprecated(value: &Value) -> bool {
    value.get("isDeprecated").and_then(Value::as_bool) == Some(true)
}

fn read_type_ref(value: &Value, depth: usize) -> Option<TypeRef> {
    if depth > MAX_TYPE_REF_DEPTH {
        return None;
    }
    match value.get("kind").and_then(Value::as_str)? {
        "NON_NULL" => {
            let inner = read_type_ref(value.get("ofType")?, depth + 1)?;
            // `!!` is not a type: keep one wrapper.
            Some(if inner.is_non_null() {
                inner
            } else {
                inner.non_null()
            })
        }
        "LIST" => Some(read_type_ref(value.get("ofType")?, depth + 1)?.list()),
        _ => Some(TypeRef::named(value.get("name").and_then(Value::as_str)?)),
    }
}

fn read_input(value: &Value, warnings: &mut Vec<String>) -> Option<InputValue> {
    let name = value.get("name").and_then(Value::as_str)?;
    let mut input = InputValue::new(name, read_type_ref(value.get("type")?, 0)?);
    input.description = string(value, "description");
    input.deprecated = deprecated(value);
    if let Some(text) = value.get("defaultValue").and_then(Value::as_str) {
        match parse_const_value(text) {
            Ok(literal) => input.default_value = Some(literal.to_json()),
            Err(_) => warnings.push(format!("`{name}` has an unparsable defaultValue; ignored")),
        }
    }
    Some(input)
}

fn read_field(value: &Value, warnings: &mut Vec<String>) -> Option<Field> {
    let mut field = Field::new(
        value.get("name").and_then(Value::as_str)?,
        read_type_ref(value.get("type")?, 0)?,
    );
    field.description = string(value, "description");
    field.deprecated = deprecated(value);
    if field.deprecated {
        field.deprecation_reason = string(value, "deprecationReason");
    }
    for argument in array(value, "args") {
        match read_input(argument, warnings) {
            Some(argument) => field.arguments.push(argument),
            None => warnings.push(format!(
                "an argument of `{}` is malformed; skipped",
                field.name
            )),
        }
    }
    Some(field)
}

fn write_type_ref(ty: &TypeRef) -> Value {
    match ty {
        TypeRef::Named(name) => json!({"kind": Value::Null, "name": name, "ofType": Value::Null}),
        TypeRef::List(inner) => {
            json!({"kind": "LIST", "name": Value::Null, "ofType": write_type_ref(inner)})
        }
        TypeRef::NonNull(inner) => {
            json!({"kind": "NON_NULL", "name": Value::Null, "ofType": write_type_ref(inner)})
        }
    }
}

/// Fills the `kind` of named type references.
fn fill_kinds(schema: &Schema, value: &mut Value) {
    if let Some(object) = value.as_object_mut() {
        if object.get("kind") == Some(&Value::Null) {
            let kind = object
                .get("name")
                .and_then(Value::as_str)
                .and_then(|name| schema.kind_of(name))
                .unwrap_or(TypeKind::Scalar);
            object.insert(String::from("kind"), Value::from(kind.introspection_name()));
        }
        if let Some(inner) = object.get_mut("ofType") {
            fill_kinds(schema, inner);
        }
    }
}

fn graphql_literal(value: &Value) -> String {
    match value {
        Value::Object(fields) => format!(
            "{{{}}}",
            fields
                .iter()
                .map(|(name, item)| format!("{name}: {}", graphql_literal(item)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Value::Array(items) => format!(
            "[{}]",
            items
                .iter()
                .map(graphql_literal)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        other => other.to_string(),
    }
}

impl Schema {
    /// Writes the schema as an introspection result
    /// (`{"__schema": {…}}`), the shape servers answer the standard
    /// introspection query with. Default values of enum type are written as
    /// strings, since the model keeps defaults as JSON.
    ///
    /// ```
    /// use rune_graphql::{parse_introspection, parse_sdl};
    ///
    /// let schema = parse_sdl("type Query { user(id: ID!): User } type User { id: ID! }")?;
    /// let again = parse_introspection(&schema.to_introspection())?;
    /// assert_eq!(again.types, schema.types);
    /// # Ok::<(), rune_graphql::GraphQlError>(())
    /// ```
    #[must_use]
    pub fn to_introspection(&self) -> Value {
        let type_ref = |ty: &TypeRef| {
            let mut value = write_type_ref(ty);
            fill_kinds(self, &mut value);
            value
        };
        let input = |value: &InputValue| {
            json!({
                "name": value.name,
                "description": value.description,
                "type": type_ref(&value.ty),
                "defaultValue": value.default_value.as_ref().map(graphql_literal),
                "isDeprecated": value.deprecated,
                "deprecationReason": Value::Null,
            })
        };
        let named = |names: &[String]| -> Value {
            names
                .iter()
                .map(|name| {
                    let kind = self.kind_of(name).unwrap_or(TypeKind::Object);
                    json!({"kind": kind.introspection_name(), "name": name, "ofType": Value::Null})
                })
                .collect()
        };
        let types: Vec<Value> = self
            .types
            .values()
            .map(|ty| {
                let mut entry = Map::new();
                entry.insert("kind".into(), ty.kind.introspection_name().into());
                entry.insert("name".into(), ty.name.clone().into());
                entry.insert("description".into(), ty.description.clone().into());
                let has_fields = matches!(ty.kind, TypeKind::Object | TypeKind::Interface);
                entry.insert(
                    "fields".into(),
                    if has_fields {
                        ty.fields
                            .iter()
                            .map(|field| {
                                json!({
                                    "name": field.name,
                                    "description": field.description,
                                    "args": field.arguments.iter().map(input).collect::<Vec<_>>(),
                                    "type": type_ref(&field.ty),
                                    "isDeprecated": field.deprecated,
                                    "deprecationReason": field.deprecation_reason,
                                })
                            })
                            .collect()
                    } else {
                        Value::Null
                    },
                );
                entry.insert(
                    "inputFields".into(),
                    if ty.kind == TypeKind::InputObject {
                        ty.input_fields.iter().map(input).collect()
                    } else {
                        Value::Null
                    },
                );
                entry.insert(
                    "interfaces".into(),
                    if has_fields {
                        named(&ty.interfaces)
                    } else {
                        Value::Null
                    },
                );
                entry.insert(
                    "enumValues".into(),
                    if ty.kind == TypeKind::Enum {
                        ty.enum_values
                            .iter()
                            .map(|value| {
                                json!({
                                    "name": value.name,
                                    "description": value.description,
                                    "isDeprecated": value.deprecated,
                                    "deprecationReason": Value::Null,
                                })
                            })
                            .collect()
                    } else {
                        Value::Null
                    },
                );
                entry.insert(
                    "possibleTypes".into(),
                    match ty.kind {
                        TypeKind::Union => named(&ty.members),
                        TypeKind::Interface => {
                            let possible: Vec<String> = self
                                .possible_types(&ty.name)
                                .into_iter()
                                .map(str::to_owned)
                                .collect();
                            named(&possible)
                        }
                        _ => Value::Null,
                    },
                );
                if ty.kind == TypeKind::InputObject {
                    entry.insert("isOneOf".into(), ty.one_of.into());
                }
                Value::Object(entry)
            })
            .collect();
        let root = |name: &Option<String>| {
            name.as_ref()
                .map_or(Value::Null, |name| json!({"name": name}))
        };
        json!({"__schema": {
            "queryType": root(&self.query_type),
            "mutationType": root(&self.mutation_type),
            "subscriptionType": root(&self.subscription_type),
            "types": types,
            "directives": [],
        }})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_type_system;

    #[test]
    fn round_trip() {
        let schema = parse_type_system(
            r#"
            type Query { search(q: String! = "x", kinds: [Kind!] = [A], f: F = {n: 1}): [Hit] old: Int @deprecated(reason: "r") }
            union Hit = A | B
            type A implements N { id: ID! }
            type B { id: ID }
            interface N { id: ID! }
            enum Kind { A B @deprecated }
            input F @oneOf { n: Int }
            "#,
        )
        .unwrap();
        let value = schema.to_introspection();
        let again = parse_introspection(&json!({"data": value})).unwrap();
        assert_eq!(again.types, schema.types);
        assert_eq!(again.query_type, schema.query_type);
        assert!(again.warnings.is_empty(), "{:?}", again.warnings);
    }

    #[test]
    fn tolerant() {
        let schema = parse_introspection(&json!({"__schema": {
            "queryType": {"name": "Query"},
            "types": [
                {"kind": "OBJECT", "name": "Query", "fields": [
                    {"name": "ok", "args": [{"name": "a", "type": {"kind": "SCALAR", "name": "Int"}, "defaultValue": "{{"}],
                     "type": {"kind": "NON_NULL", "ofType": {"kind": "SCALAR", "name": "Int"}}},
                    {"name": "broken"}
                ]},
                {"kind": "WAT", "name": "Odd"},
                {"kind": "OBJECT"},
                {"kind": "OBJECT", "name": "__Type"}
            ]
        }}))
        .unwrap();
        assert_eq!(schema.get("Query").unwrap().fields.len(), 1);
        assert!(schema.get("Odd").is_none());
        assert!(schema.get("__Type").is_none());
        assert_eq!(schema.warnings.len(), 4, "{:?}", schema.warnings);
        assert_eq!(
            parse_introspection(&json!({"data": {}}))
                .unwrap_err()
                .code(),
            "not_introspection"
        );
    }

    #[test]
    fn deep_type_refs_are_cut() {
        let mut ty = json!({"kind": "SCALAR", "name": "Int"});
        for _ in 0..40 {
            ty = json!({"kind": "LIST", "ofType": ty});
        }
        let schema = parse_introspection(&json!({"types": [
            {"kind": "OBJECT", "name": "Query", "fields": [{"name": "x", "args": [], "type": ty}]}
        ]}))
        .unwrap();
        assert_eq!(schema.get("Query").unwrap().fields.len(), 0);
    }
}
