//! The GraphQL type model shared by SDL and introspection import.

use std::collections::BTreeMap;
use std::fmt;

use serde_json::Value;

/// The five scalars every schema has.
pub const BUILT_IN_SCALARS: [&str; 5] = ["Int", "Float", "String", "Boolean", "ID"];

/// An operation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum OperationKind {
    /// A read (`query`).
    Query,
    /// A write (`mutation`).
    Mutation,
    /// A stream (`subscription`).
    Subscription,
}

impl OperationKind {
    /// The keyword: `query`, `mutation` or `subscription`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Query => "query",
            Self::Mutation => "mutation",
            Self::Subscription => "subscription",
        }
    }

    /// Parses the keyword.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "query" => Self::Query,
            "mutation" => Self::Mutation,
            "subscription" => Self::Subscription,
            _ => return None,
        })
    }
}

impl fmt::Display for OperationKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A type reference such as `[User!]!`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum TypeRef {
    /// A named type.
    Named(String),
    /// A list of the inner type.
    List(Box<Self>),
    /// The inner type, never null.
    NonNull(Box<Self>),
}

impl TypeRef {
    /// A named type reference.
    #[must_use]
    pub fn named(name: impl Into<String>) -> Self {
        Self::Named(name.into())
    }

    /// Wraps the type in a list.
    #[must_use]
    pub fn list(self) -> Self {
        Self::List(Box::new(self))
    }

    /// Makes the type non-null.
    #[must_use]
    pub fn non_null(self) -> Self {
        Self::NonNull(Box::new(self))
    }

    /// The innermost named type.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Named(name) => name,
            Self::List(inner) | Self::NonNull(inner) => inner.name(),
        }
    }

    /// Whether the outermost wrapper is non-null.
    #[must_use]
    pub const fn is_non_null(&self) -> bool {
        matches!(self, Self::NonNull(_))
    }

    /// Whether the type (ignoring an outer non-null) is a list.
    #[must_use]
    pub fn is_list(&self) -> bool {
        match self {
            Self::Named(_) => false,
            Self::List(_) => true,
            Self::NonNull(inner) => inner.is_list(),
        }
    }

    /// The type without an outer non-null.
    #[must_use]
    pub fn nullable(&self) -> &Self {
        match self {
            Self::NonNull(inner) => inner,
            other => other,
        }
    }
}

impl fmt::Display for TypeRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Named(name) => formatter.write_str(name),
            Self::List(inner) => write!(formatter, "[{inner}]"),
            Self::NonNull(inner) => write!(formatter, "{inner}!"),
        }
    }
}

/// What kind of type a [`TypeDef`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum TypeKind {
    /// A leaf value.
    Scalar,
    /// An object with fields.
    Object,
    /// An abstract type with fields.
    Interface,
    /// An abstract type over object types.
    Union,
    /// A leaf with a fixed set of values.
    Enum,
    /// A structured argument value.
    InputObject,
}

impl TypeKind {
    /// The introspection `__TypeKind` name, such as `INPUT_OBJECT`.
    #[must_use]
    pub const fn introspection_name(self) -> &'static str {
        match self {
            Self::Scalar => "SCALAR",
            Self::Object => "OBJECT",
            Self::Interface => "INTERFACE",
            Self::Union => "UNION",
            Self::Enum => "ENUM",
            Self::InputObject => "INPUT_OBJECT",
        }
    }

    /// Parses an introspection `__TypeKind` name.
    #[must_use]
    pub fn from_introspection(text: &str) -> Option<Self> {
        Some(match text {
            "SCALAR" => Self::Scalar,
            "OBJECT" => Self::Object,
            "INTERFACE" => Self::Interface,
            "UNION" => Self::Union,
            "ENUM" => Self::Enum,
            "INPUT_OBJECT" => Self::InputObject,
            _ => return None,
        })
    }

    /// Scalars and enums: selected without a sub-selection.
    #[must_use]
    pub const fn is_leaf(self) -> bool {
        matches!(self, Self::Scalar | Self::Enum)
    }

    /// Objects, interfaces and unions: selected with a sub-selection.
    #[must_use]
    pub const fn is_composite(self) -> bool {
        matches!(self, Self::Object | Self::Interface | Self::Union)
    }

    /// Scalars, enums and input objects: usable as argument types.
    #[must_use]
    pub const fn is_input(self) -> bool {
        matches!(self, Self::Scalar | Self::Enum | Self::InputObject)
    }
}

/// A field of an object or interface type.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct Field {
    /// Field name.
    pub name: String,
    /// `description`.
    pub description: Option<String>,
    /// Declared arguments.
    pub arguments: Vec<InputValue>,
    /// The result type.
    pub ty: TypeRef,
    /// Whether the field is `@deprecated`.
    pub deprecated: bool,
    /// The deprecation reason.
    pub deprecation_reason: Option<String>,
}

impl Field {
    /// A field with no arguments.
    #[must_use]
    pub fn new(name: impl Into<String>, ty: TypeRef) -> Self {
        Self {
            name: name.into(),
            description: None,
            arguments: Vec::new(),
            ty,
            deprecated: false,
            deprecation_reason: None,
        }
    }

    /// The argument with the given name.
    #[must_use]
    pub fn argument(&self, name: &str) -> Option<&InputValue> {
        self.arguments.iter().find(|argument| argument.name == name)
    }
}

/// An argument or input object field.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct InputValue {
    /// Name.
    pub name: String,
    /// `description`.
    pub description: Option<String>,
    /// The value type.
    pub ty: TypeRef,
    /// The default value, as JSON (enum values become strings).
    pub default_value: Option<Value>,
    /// Whether it is `@deprecated`.
    pub deprecated: bool,
}

impl InputValue {
    /// An input value with no default.
    #[must_use]
    pub fn new(name: impl Into<String>, ty: TypeRef) -> Self {
        Self {
            name: name.into(),
            description: None,
            ty,
            default_value: None,
            deprecated: false,
        }
    }

    /// Whether a value must be supplied: non-null with no default.
    #[must_use]
    pub const fn is_required(&self) -> bool {
        self.ty.is_non_null() && self.default_value.is_none()
    }
}

/// An enum value.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct EnumValue {
    /// The value.
    pub name: String,
    /// `description`.
    pub description: Option<String>,
    /// Whether it is `@deprecated`.
    pub deprecated: bool,
}

impl EnumValue {
    /// A plain enum value.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: None,
            deprecated: false,
        }
    }
}

/// A named type definition.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct TypeDef {
    /// Type name.
    pub name: String,
    /// What kind of type it is.
    pub kind: TypeKind,
    /// `description`.
    pub description: Option<String>,
    /// Fields of an object or interface.
    pub fields: Vec<Field>,
    /// Interfaces an object or interface implements.
    pub interfaces: Vec<String>,
    /// Member types of a union.
    pub members: Vec<String>,
    /// Values of an enum.
    pub enum_values: Vec<EnumValue>,
    /// Fields of an input object.
    pub input_fields: Vec<InputValue>,
    /// Whether an input object is `@oneOf`: exactly one field is set.
    pub one_of: bool,
}

impl TypeDef {
    /// An empty type of the given kind.
    #[must_use]
    pub fn new(name: impl Into<String>, kind: TypeKind) -> Self {
        Self {
            name: name.into(),
            kind,
            description: None,
            fields: Vec::new(),
            interfaces: Vec::new(),
            members: Vec::new(),
            enum_values: Vec::new(),
            input_fields: Vec::new(),
            one_of: false,
        }
    }

    /// The object or interface field with the given name.
    #[must_use]
    pub fn field(&self, name: &str) -> Option<&Field> {
        self.fields.iter().find(|field| field.name == name)
    }

    /// The input object field with the given name.
    #[must_use]
    pub fn input_field(&self, name: &str) -> Option<&InputValue> {
        self.input_fields.iter().find(|field| field.name == name)
    }
}

/// A GraphQL schema: named types plus the root operation types.
///
/// ```
/// use rune_graphql::{OperationKind, TypeKind, parse_sdl};
///
/// let schema = parse_sdl("type Query { me: User } type User { id: ID! }")?;
/// assert_eq!(schema.root_type(OperationKind::Query).map(|ty| ty.name.as_str()), Some("Query"));
/// assert_eq!(schema.get("User").map(|ty| ty.kind), Some(TypeKind::Object));
/// assert!(schema.get("Boolean").is_some()); // built-in scalars are always there
/// # Ok::<(), rune_graphql::GraphQlError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct Schema {
    /// The query root type name.
    pub query_type: Option<String>,
    /// The mutation root type name.
    pub mutation_type: Option<String>,
    /// The subscription root type name.
    pub subscription_type: Option<String>,
    /// Every named type, built-in scalars included, by name.
    pub types: BTreeMap<String, TypeDef>,
    /// Non-fatal problems found while reading the schema.
    pub warnings: Vec<String>,
}

impl Schema {
    /// The type with the given name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&TypeDef> {
        self.types.get(name)
    }

    /// The root type name for an operation kind.
    #[must_use]
    pub fn root_name(&self, kind: OperationKind) -> Option<&str> {
        match kind {
            OperationKind::Query => self.query_type.as_deref(),
            OperationKind::Mutation => self.mutation_type.as_deref(),
            OperationKind::Subscription => self.subscription_type.as_deref(),
        }
    }

    /// The root type for an operation kind.
    #[must_use]
    pub fn root_type(&self, kind: OperationKind) -> Option<&TypeDef> {
        self.root_name(kind).and_then(|name| self.get(name))
    }

    /// The kind of the named type; `None` when it is undefined.
    #[must_use]
    pub fn kind_of(&self, name: &str) -> Option<TypeKind> {
        self.get(name).map(|ty| ty.kind)
    }

    /// The field `field` on object or interface `type_name`.
    #[must_use]
    pub fn field(&self, type_name: &str, field: &str) -> Option<&Field> {
        self.get(type_name).and_then(|ty| ty.field(field))
    }

    /// The object types a composite type can be at run time: itself for an
    /// object, the members of a union, the implementors of an interface.
    #[must_use]
    pub fn possible_types(&self, name: &str) -> Vec<&str> {
        match self.get(name) {
            Some(ty) if ty.kind == TypeKind::Object => vec![ty.name.as_str()],
            Some(ty) if ty.kind == TypeKind::Union => {
                ty.members.iter().map(String::as_str).collect()
            }
            Some(ty) if ty.kind == TypeKind::Interface => self
                .types
                .values()
                .filter(|candidate| {
                    candidate.kind == TypeKind::Object
                        && candidate
                            .interfaces
                            .iter()
                            .any(|interface| interface == name)
                })
                .map(|candidate| candidate.name.as_str())
                .collect(),
            _ => Vec::new(),
        }
    }

    /// Every `Type.field` coordinate of object and interface types, in
    /// type then field order: the units of field-level authorization.
    #[must_use]
    pub fn field_coordinates(&self) -> Vec<String> {
        self.types
            .values()
            .filter(|ty| matches!(ty.kind, TypeKind::Object | TypeKind::Interface))
            .flat_map(|ty| {
                ty.fields
                    .iter()
                    .map(move |field| format!("{}.{}", ty.name, field.name))
            })
            .collect()
    }

    /// Adds the built-in scalars, picks default root types, and records
    /// warnings for undefined references.
    pub(crate) fn finish(&mut self) {
        for scalar in BUILT_IN_SCALARS {
            self.types
                .entry(scalar.to_owned())
                .or_insert_with(|| TypeDef::new(scalar, TypeKind::Scalar));
        }
        for (kind, default) in [
            (OperationKind::Query, "Query"),
            (OperationKind::Mutation, "Mutation"),
            (OperationKind::Subscription, "Subscription"),
        ] {
            let slot = match kind {
                OperationKind::Query => &mut self.query_type,
                OperationKind::Mutation => &mut self.mutation_type,
                OperationKind::Subscription => &mut self.subscription_type,
            };
            if slot.is_none() && self.types.contains_key(default) {
                *slot = Some(default.to_owned());
            }
            if let Some(name) = slot.clone() {
                match self.types.get(&name).map(|ty| ty.kind) {
                    Some(TypeKind::Object) => {}
                    Some(_) => {
                        self.warnings
                            .push(format!("{kind} root type `{name}` is not an object type"));
                        *slot = None;
                    }
                    None => {
                        self.warnings
                            .push(format!("{kind} root type `{name}` is not defined"));
                        *slot = None;
                    }
                }
            }
        }
        if self.query_type.is_none() {
            self.warnings
                .push(String::from("schema has no query root type"));
        }
        self.check_references();
    }

    fn check_references(&mut self) {
        let mut problems = Vec::new();
        let defined = |name: &str| self.types.contains_key(name);
        for ty in self.types.values() {
            for field in &ty.fields {
                if !defined(field.ty.name()) {
                    problems.push(format!(
                        "field `{}.{}` has undefined type `{}`",
                        ty.name,
                        field.name,
                        field.ty.name()
                    ));
                }
                for argument in &field.arguments {
                    if !defined(argument.ty.name()) {
                        problems.push(format!(
                            "argument `{}.{}({}:)` has undefined type `{}`",
                            ty.name,
                            field.name,
                            argument.name,
                            argument.ty.name()
                        ));
                    }
                }
            }
            for field in &ty.input_fields {
                if !defined(field.ty.name()) {
                    problems.push(format!(
                        "input field `{}.{}` has undefined type `{}`",
                        ty.name,
                        field.name,
                        field.ty.name()
                    ));
                }
            }
            for member in &ty.members {
                if self.kind_of(member) != Some(TypeKind::Object) {
                    problems.push(format!(
                        "union `{}` member `{member}` is not a defined object type",
                        ty.name
                    ));
                }
            }
            for interface in &ty.interfaces {
                if self.kind_of(interface) != Some(TypeKind::Interface) {
                    problems.push(format!(
                        "type `{}` implements `{interface}`, which is not a defined interface",
                        ty.name
                    ));
                }
            }
        }
        self.warnings.extend(problems);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_ref_display_and_queries() {
        let ty = TypeRef::named("User").non_null().list().non_null();
        assert_eq!(ty.to_string(), "[User!]!");
        assert_eq!(ty.name(), "User");
        assert!(ty.is_non_null());
        assert!(ty.is_list());
        assert_eq!(ty.nullable().to_string(), "[User!]");
        assert!(!TypeRef::named("Int").is_list());
    }

    #[test]
    fn kinds() {
        assert!(TypeKind::Enum.is_leaf());
        assert!(TypeKind::Union.is_composite());
        assert!(TypeKind::InputObject.is_input());
        assert!(!TypeKind::Object.is_input());
        for kind in [
            TypeKind::Scalar,
            TypeKind::Object,
            TypeKind::Interface,
            TypeKind::Union,
            TypeKind::Enum,
            TypeKind::InputObject,
        ] {
            assert_eq!(
                TypeKind::from_introspection(kind.introspection_name()),
                Some(kind)
            );
        }
        assert_eq!(
            OperationKind::parse("mutation"),
            Some(OperationKind::Mutation)
        );
        assert_eq!(OperationKind::Subscription.to_string(), "subscription");
    }

    #[test]
    fn finish_warns_and_defaults() {
        let mut schema = Schema::default();
        let mut query = TypeDef::new("Query", TypeKind::Object);
        query
            .fields
            .push(Field::new("x", TypeRef::named("Missing")));
        schema.types.insert(query.name.clone(), query);
        schema.mutation_type = Some(String::from("Nope"));
        schema.finish();
        assert_eq!(schema.query_type.as_deref(), Some("Query"));
        assert_eq!(schema.mutation_type, None);
        assert!(schema.get("ID").is_some());
        assert_eq!(schema.warnings.len(), 2, "{:?}", schema.warnings);
    }
}
