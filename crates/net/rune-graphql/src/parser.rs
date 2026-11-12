//! Recursive-descent parser for type-system (SDL) and executable documents
//! ([spec §2–3](https://spec.graphql.org/October2021/#sec-Language)).
//!
//! SDL is folded straight into a [`Schema`]; executable documents become a
//! small AST used by validation. Nesting is bounded so hostile input cannot
//! exhaust the stack.

use std::collections::btree_map::Entry;

use serde_json::{Map, Number, Value};

use crate::GraphQlError;
use crate::lexer::{Kind, Lexer, Token, syntax_error};
use crate::schema::{
    BUILT_IN_SCALARS, EnumValue, Field, InputValue, OperationKind, Schema, TypeDef, TypeKind,
    TypeRef,
};

/// Deepest nesting of lists, objects, types and selection sets.
pub const MAX_NESTING: usize = 64;

/// A value literal.
#[derive(Debug, Clone, PartialEq)]
pub enum AstValue {
    Variable(String),
    Int(String),
    Float(String),
    String(String),
    Boolean(bool),
    Null,
    Enum(String),
    List(Vec<Self>),
    Object(Vec<(String, Self)>),
}

impl AstValue {
    /// The JSON form: enums become strings, variables `null`.
    pub fn to_json(&self) -> Value {
        match self {
            Self::Int(text) => text.parse::<i64>().map_or_else(
                |_| {
                    text.parse::<f64>()
                        .ok()
                        .and_then(Number::from_f64)
                        .map_or(Value::Null, Value::Number)
                },
                Value::from,
            ),
            Self::Float(text) => text
                .parse::<f64>()
                .ok()
                .and_then(Number::from_f64)
                .map_or(Value::Null, Value::Number),
            Self::String(text) | Self::Enum(text) => Value::String(text.clone()),
            Self::Boolean(flag) => Value::Bool(*flag),
            Self::Null | Self::Variable(_) => Value::Null,
            Self::List(items) => Value::Array(items.iter().map(Self::to_json).collect()),
            Self::Object(fields) => Value::Object(
                fields
                    .iter()
                    .map(|(name, value)| (name.clone(), value.to_json()))
                    .collect::<Map<_, _>>(),
            ),
        }
    }

    /// Calls `visit` for every variable the value uses.
    pub fn variables<'a>(&'a self, visit: &mut impl FnMut(&'a str)) {
        match self {
            Self::Variable(name) => visit(name),
            Self::List(items) => items.iter().for_each(|item| item.variables(visit)),
            Self::Object(fields) => fields.iter().for_each(|(_, item)| item.variables(visit)),
            _ => {}
        }
    }
}

/// `@name(arguments)`.
#[derive(Debug, Clone, PartialEq)]
pub struct Directive {
    pub name: String,
    pub arguments: Vec<(String, AstValue)>,
}

/// One selection in a selection set.
#[derive(Debug, Clone, PartialEq)]
pub enum Selection {
    Field(FieldSelection),
    Spread {
        name: String,
        directives: Vec<Directive>,
    },
    Inline {
        type_condition: Option<String>,
        directives: Vec<Directive>,
        selections: Vec<Self>,
    },
}

/// A field selection.
#[derive(Debug, Clone, PartialEq)]
pub struct FieldSelection {
    pub name: String,
    pub arguments: Vec<(String, AstValue)>,
    pub directives: Vec<Directive>,
    /// `None` when the field has no selection set.
    pub selections: Option<Vec<Selection>>,
}

/// `$name: Type = default`.
#[derive(Debug, Clone, PartialEq)]
pub struct VariableDefinition {
    pub name: String,
    pub ty: TypeRef,
    pub default: Option<AstValue>,
}

/// An operation definition.
#[derive(Debug, Clone, PartialEq)]
pub struct OperationDefinition {
    pub kind: OperationKind,
    pub name: Option<String>,
    pub variables: Vec<VariableDefinition>,
    pub directives: Vec<Directive>,
    pub selections: Vec<Selection>,
}

/// A fragment definition.
#[derive(Debug, Clone, PartialEq)]
pub struct FragmentDefinition {
    pub name: String,
    pub type_condition: String,
    pub directives: Vec<Directive>,
    pub selections: Vec<Selection>,
}

/// An executable document.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ExecutableDocument {
    pub operations: Vec<OperationDefinition>,
    pub fragments: Vec<FragmentDefinition>,
}

/// Parses an executable document (operations and fragments).
pub fn parse_executable(source: &str) -> Result<ExecutableDocument, GraphQlError> {
    let mut parser = Parser::new(source)?;
    let mut document = ExecutableDocument::default();
    if parser.peek_kind() == Kind::Eof {
        return Err(parser.error("the document has no definitions"));
    }
    while parser.peek_kind() != Kind::Eof {
        parser.executable_definition(&mut document)?;
    }
    Ok(document)
}

/// Parses SDL into a schema.
pub fn parse_type_system(source: &str) -> Result<Schema, GraphQlError> {
    let mut parser = Parser::new(source)?;
    let mut schema = Schema::default();
    while parser.peek_kind() != Kind::Eof {
        parser.type_system_definition(&mut schema)?;
    }
    schema.finish();
    Ok(schema)
}

/// Parses a constant value literal, such as an introspection `defaultValue`.
pub fn parse_const_value(source: &str) -> Result<AstValue, GraphQlError> {
    let mut parser = Parser::new(source)?;
    let value = parser.value(true)?;
    parser.expect(Kind::Eof)?;
    Ok(value)
}

struct Parser<'a> {
    source: &'a str,
    lexer: Lexer<'a>,
    current: Token<'a>,
    depth: usize,
}

type Directives = Vec<Directive>;

impl<'a> Parser<'a> {
    fn new(source: &'a str) -> Result<Self, GraphQlError> {
        let mut lexer = Lexer::new(source);
        let current = lexer.next_token()?;
        Ok(Self {
            source,
            lexer,
            current,
            depth: 0,
        })
    }

    const fn peek_kind(&self) -> Kind {
        self.current.kind
    }

    fn peek_keyword(&self, keyword: &str) -> bool {
        self.current.kind == Kind::Name && self.current.text == keyword
    }

    fn error(&self, message: impl Into<String>) -> GraphQlError {
        syntax_error(self.source, self.current.offset, message)
    }

    fn unexpected(&self, expected: &str) -> GraphQlError {
        let found = if self.current.kind == Kind::Name {
            format!("`{}`", self.current.text)
        } else {
            self.current.kind.describe().to_owned()
        };
        self.error(format!("expected {expected}, found {found}"))
    }

    fn advance(&mut self) -> Result<Token<'a>, GraphQlError> {
        let next = self.lexer.next_token()?;
        Ok(std::mem::replace(&mut self.current, next))
    }

    fn eat(&mut self, kind: Kind) -> Result<bool, GraphQlError> {
        if self.current.kind == kind {
            self.advance()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn expect(&mut self, kind: Kind) -> Result<Token<'a>, GraphQlError> {
        if self.current.kind == kind {
            self.advance()
        } else {
            Err(self.unexpected(kind.describe()))
        }
    }

    fn expect_keyword(&mut self, keyword: &str) -> Result<(), GraphQlError> {
        if self.peek_keyword(keyword) {
            self.advance()?;
            Ok(())
        } else {
            Err(self.unexpected(&format!("`{keyword}`")))
        }
    }

    fn name(&mut self) -> Result<String, GraphQlError> {
        Ok(self.expect(Kind::Name)?.text.to_owned())
    }

    fn enter(&mut self) -> Result<(), GraphQlError> {
        self.depth += 1;
        if self.depth > MAX_NESTING {
            return Err(GraphQlError::TooLarge(format!(
                "nesting deeper than {MAX_NESTING} levels"
            )));
        }
        Ok(())
    }

    const fn leave(&mut self) {
        self.depth -= 1;
    }

    fn description(&mut self) -> Result<Option<String>, GraphQlError> {
        if self.current.kind == Kind::String {
            Ok(self.advance()?.value)
        } else {
            Ok(None)
        }
    }

    // ----- shared pieces -------------------------------------------------

    fn type_ref(&mut self) -> Result<TypeRef, GraphQlError> {
        self.enter()?;
        let inner = if self.eat(Kind::LBracket)? {
            let inner = self.type_ref()?;
            self.expect(Kind::RBracket)?;
            TypeRef::List(Box::new(inner))
        } else {
            TypeRef::Named(self.name()?)
        };
        self.leave();
        Ok(if self.eat(Kind::Bang)? {
            TypeRef::NonNull(Box::new(inner))
        } else {
            inner
        })
    }

    fn value(&mut self, constant: bool) -> Result<AstValue, GraphQlError> {
        self.enter()?;
        let value = match self.current.kind {
            Kind::Dollar if !constant => {
                self.advance()?;
                AstValue::Variable(self.name()?)
            }
            Kind::Dollar => return Err(self.error("variables are not allowed in constant values")),
            Kind::Int => AstValue::Int(self.advance()?.text.to_owned()),
            Kind::Float => AstValue::Float(self.advance()?.text.to_owned()),
            Kind::String => AstValue::String(self.advance()?.value.unwrap_or_default()),
            Kind::Name => {
                let token = self.advance()?;
                match token.text {
                    "true" => AstValue::Boolean(true),
                    "false" => AstValue::Boolean(false),
                    "null" => AstValue::Null,
                    other => AstValue::Enum(other.to_owned()),
                }
            }
            Kind::LBracket => {
                self.advance()?;
                let mut items = Vec::new();
                while !self.eat(Kind::RBracket)? {
                    items.push(self.value(constant)?);
                }
                AstValue::List(items)
            }
            Kind::LBrace => {
                self.advance()?;
                let mut fields = Vec::new();
                while !self.eat(Kind::RBrace)? {
                    let name = self.name()?;
                    self.expect(Kind::Colon)?;
                    fields.push((name, self.value(constant)?));
                }
                AstValue::Object(fields)
            }
            _ => return Err(self.unexpected("a value")),
        };
        self.leave();
        Ok(value)
    }

    fn arguments(&mut self, constant: bool) -> Result<Vec<(String, AstValue)>, GraphQlError> {
        let mut arguments = Vec::new();
        if self.eat(Kind::LParen)? {
            loop {
                let name = self.name()?;
                self.expect(Kind::Colon)?;
                arguments.push((name, self.value(constant)?));
                if self.eat(Kind::RParen)? {
                    break;
                }
            }
        }
        Ok(arguments)
    }

    fn directives(&mut self, constant: bool) -> Result<Directives, GraphQlError> {
        let mut directives = Vec::new();
        while self.eat(Kind::At)? {
            let name = self.name()?;
            let arguments = self.arguments(constant)?;
            directives.push(Directive { name, arguments });
        }
        Ok(directives)
    }

    // ----- executable documents ------------------------------------------

    fn executable_definition(
        &mut self,
        document: &mut ExecutableDocument,
    ) -> Result<(), GraphQlError> {
        if self.current.kind == Kind::LBrace {
            let selections = self.selection_set()?;
            document.operations.push(OperationDefinition {
                kind: OperationKind::Query,
                name: None,
                variables: Vec::new(),
                directives: Vec::new(),
                selections,
            });
            return Ok(());
        }
        if self.peek_keyword("fragment") {
            self.advance()?;
            let name = self.name()?;
            if name == "on" {
                return Err(self.error("a fragment cannot be named `on`"));
            }
            self.expect_keyword("on")?;
            let type_condition = self.name()?;
            let directives = self.directives(false)?;
            let selections = self.selection_set()?;
            document.fragments.push(FragmentDefinition {
                name,
                type_condition,
                directives,
                selections,
            });
            return Ok(());
        }
        let kind = (self.current.kind == Kind::Name)
            .then(|| OperationKind::parse(self.current.text))
            .flatten()
            .ok_or_else(|| {
                self.unexpected("`query`, `mutation`, `subscription`, `fragment` or `{`")
            })?;
        self.advance()?;
        let name = if self.current.kind == Kind::Name {
            Some(self.name()?)
        } else {
            None
        };
        let mut variables = Vec::new();
        if self.eat(Kind::LParen)? {
            loop {
                self.expect(Kind::Dollar)?;
                let name = self.name()?;
                self.expect(Kind::Colon)?;
                let ty = self.type_ref()?;
                let default = if self.eat(Kind::Equals)? {
                    Some(self.value(true)?)
                } else {
                    None
                };
                self.directives(true)?;
                variables.push(VariableDefinition { name, ty, default });
                if self.eat(Kind::RParen)? {
                    break;
                }
            }
        }
        let directives = self.directives(false)?;
        let selections = self.selection_set()?;
        document.operations.push(OperationDefinition {
            kind,
            name,
            variables,
            directives,
            selections,
        });
        Ok(())
    }

    fn selection_set(&mut self) -> Result<Vec<Selection>, GraphQlError> {
        self.enter()?;
        self.expect(Kind::LBrace)?;
        let mut selections = Vec::new();
        loop {
            selections.push(self.selection()?);
            if self.eat(Kind::RBrace)? {
                break;
            }
        }
        self.leave();
        Ok(selections)
    }

    fn selection(&mut self) -> Result<Selection, GraphQlError> {
        if self.eat(Kind::Spread)? {
            if self.current.kind == Kind::Name && !self.peek_keyword("on") {
                let name = self.name()?;
                let directives = self.directives(false)?;
                return Ok(Selection::Spread { name, directives });
            }
            let type_condition = if self.peek_keyword("on") {
                self.advance()?;
                Some(self.name()?)
            } else {
                None
            };
            let directives = self.directives(false)?;
            let selections = self.selection_set()?;
            return Ok(Selection::Inline {
                type_condition,
                directives,
                selections,
            });
        }
        let first = self.name()?;
        // An alias does not change what is selected; only the field name matters.
        let name = if self.eat(Kind::Colon)? {
            self.name()?
        } else {
            first
        };
        let arguments = self.arguments(false)?;
        let directives = self.directives(false)?;
        let selections = if self.current.kind == Kind::LBrace {
            Some(self.selection_set()?)
        } else {
            None
        };
        Ok(Selection::Field(FieldSelection {
            name,
            arguments,
            directives,
            selections,
        }))
    }

    // ----- type system ---------------------------------------------------

    fn type_system_definition(&mut self, schema: &mut Schema) -> Result<(), GraphQlError> {
        let description = self.description()?;
        if self.current.kind == Kind::LBrace
            || ["query", "mutation", "subscription", "fragment"]
                .iter()
                .any(|keyword| self.peek_keyword(keyword))
        {
            let offset = self.current.offset;
            self.executable_definition(&mut ExecutableDocument::default())?;
            let (line, _) = crate::lexer::line_column(self.source, offset);
            schema.warnings.push(format!(
                "line {line}: executable definition in a schema document ignored"
            ));
            return Ok(());
        }
        if self.peek_keyword("extend") {
            self.advance()?;
            return self.type_definition(schema, None, true);
        }
        self.type_definition(schema, description, false)
    }

    fn type_definition(
        &mut self,
        schema: &mut Schema,
        description: Option<String>,
        extend: bool,
    ) -> Result<(), GraphQlError> {
        if self.current.kind != Kind::Name {
            return Err(self.unexpected("a definition"));
        }
        let keyword = self.current.text;
        match keyword {
            "schema" => {
                self.advance()?;
                self.directives(true)?;
                if self.eat(Kind::LBrace)? {
                    while !self.eat(Kind::RBrace)? {
                        let operation = self.name()?;
                        let kind = OperationKind::parse(&operation).ok_or_else(|| {
                            self.error(format!("unknown operation type `{operation}`"))
                        })?;
                        self.expect(Kind::Colon)?;
                        let name = self.name()?;
                        let slot = match kind {
                            OperationKind::Query => &mut schema.query_type,
                            OperationKind::Mutation => &mut schema.mutation_type,
                            OperationKind::Subscription => &mut schema.subscription_type,
                        };
                        if slot.as_ref().is_some_and(|existing| *existing != name) {
                            schema
                                .warnings
                                .push(format!("{kind} root type redefined as `{name}`"));
                        }
                        *slot = Some(name);
                    }
                }
                Ok(())
            }
            "directive" if !extend => self.directive_definition(),
            "scalar" | "type" | "interface" | "union" | "enum" | "input" => {
                self.advance()?;
                let kind = match keyword {
                    "scalar" => TypeKind::Scalar,
                    "type" => TypeKind::Object,
                    "interface" => TypeKind::Interface,
                    "union" => TypeKind::Union,
                    "enum" => TypeKind::Enum,
                    _ => TypeKind::InputObject,
                };
                let mut ty = TypeDef::new(self.name()?, kind);
                ty.description = description;
                self.type_body(&mut ty)?;
                merge_type(schema, ty, extend);
                Ok(())
            }
            _ => Err(self.unexpected("a definition")),
        }
    }

    fn directive_definition(&mut self) -> Result<(), GraphQlError> {
        self.advance()?;
        self.expect(Kind::At)?;
        self.name()?;
        if self.current.kind == Kind::LParen {
            self.input_values(Kind::LParen, Kind::RParen)?;
        }
        if self.peek_keyword("repeatable") {
            self.advance()?;
        }
        self.expect_keyword("on")?;
        self.eat(Kind::Pipe)?;
        self.name()?;
        while self.eat(Kind::Pipe)? {
            self.name()?;
        }
        Ok(())
    }

    fn type_body(&mut self, ty: &mut TypeDef) -> Result<(), GraphQlError> {
        if matches!(ty.kind, TypeKind::Object | TypeKind::Interface)
            && self.peek_keyword("implements")
        {
            self.advance()?;
            self.eat(Kind::Amp)?;
            ty.interfaces.push(self.name()?);
            while self.eat(Kind::Amp)? {
                ty.interfaces.push(self.name()?);
            }
        }
        let directives = self.directives(true)?;
        ty.one_of = directives.iter().any(|directive| directive.name == "oneOf");
        match ty.kind {
            TypeKind::Object | TypeKind::Interface if self.current.kind == Kind::LBrace => {
                self.advance()?;
                while !self.eat(Kind::RBrace)? {
                    ty.fields.push(self.field_definition()?);
                }
            }
            TypeKind::InputObject if self.current.kind == Kind::LBrace => {
                ty.input_fields = self.input_values(Kind::LBrace, Kind::RBrace)?;
            }
            TypeKind::Enum if self.current.kind == Kind::LBrace => {
                self.advance()?;
                while !self.eat(Kind::RBrace)? {
                    let description = self.description()?;
                    let name = self.name()?;
                    if matches!(name.as_str(), "true" | "false" | "null") {
                        return Err(self.error(format!("`{name}` is not a valid enum value")));
                    }
                    let directives = self.directives(true)?;
                    ty.enum_values.push(EnumValue {
                        name,
                        description,
                        deprecated: deprecation(&directives).is_some(),
                    });
                }
            }
            TypeKind::Union if self.eat(Kind::Equals)? => {
                self.eat(Kind::Pipe)?;
                ty.members.push(self.name()?);
                while self.eat(Kind::Pipe)? {
                    ty.members.push(self.name()?);
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn field_definition(&mut self) -> Result<Field, GraphQlError> {
        let description = self.description()?;
        let name = self.name()?;
        let arguments = if self.current.kind == Kind::LParen {
            self.input_values(Kind::LParen, Kind::RParen)?
        } else {
            Vec::new()
        };
        self.expect(Kind::Colon)?;
        let ty = self.type_ref()?;
        let directives = self.directives(true)?;
        let deprecation_reason = deprecation(&directives);
        Ok(Field {
            name,
            description,
            arguments,
            ty,
            deprecated: deprecation_reason.is_some(),
            deprecation_reason,
        })
    }

    fn input_values(&mut self, open: Kind, close: Kind) -> Result<Vec<InputValue>, GraphQlError> {
        self.expect(open)?;
        let mut values = Vec::new();
        while !self.eat(close)? {
            let description = self.description()?;
            let name = self.name()?;
            self.expect(Kind::Colon)?;
            let ty = self.type_ref()?;
            let default_value = if self.eat(Kind::Equals)? {
                Some(self.value(true)?.to_json())
            } else {
                None
            };
            let directives = self.directives(true)?;
            values.push(InputValue {
                name,
                description,
                ty,
                default_value,
                deprecated: deprecation(&directives).is_some(),
            });
        }
        Ok(values)
    }
}

/// The `@deprecated` reason, if the directive is present.
fn deprecation(directives: &[Directive]) -> Option<String> {
    directives
        .iter()
        .find(|directive| directive.name == "deprecated")
        .map(|directive| {
            directive
                .arguments
                .iter()
                .find_map(|(name, value)| match (name.as_str(), value) {
                    ("reason", AstValue::String(reason)) => Some(reason.clone()),
                    _ => None,
                })
                .unwrap_or_else(|| String::from("No longer supported"))
        })
}

/// Adds a definition or extension to the schema, warning on conflicts.
fn merge_type(schema: &mut Schema, mut ty: TypeDef, extend: bool) {
    let mut seen = std::collections::BTreeSet::new();
    let mut repeated = Vec::new();
    ty.fields.retain(|field| {
        let fresh = seen.insert(field.name.clone());
        if !fresh {
            repeated.push(field.name.clone());
        }
        fresh
    });
    ty.input_fields.retain(|field| {
        let fresh = seen.insert(field.name.clone());
        if !fresh {
            repeated.push(field.name.clone());
        }
        fresh
    });
    ty.enum_values.retain(|value| {
        let fresh = seen.insert(value.name.clone());
        if !fresh {
            repeated.push(value.name.clone());
        }
        fresh
    });
    for name in repeated {
        schema.warnings.push(format!(
            "`{}.{name}` defined more than once; first kept",
            ty.name
        ));
    }
    match schema.types.entry(ty.name.clone()) {
        Entry::Vacant(slot) => {
            if extend {
                schema
                    .warnings
                    .push(format!("extension of undefined type `{}`", ty.name));
            }
            slot.insert(ty);
        }
        Entry::Occupied(mut slot) => {
            let existing = slot.get_mut();
            if existing.kind != ty.kind {
                schema.warnings.push(format!(
                    "type `{}` redefined with a different kind; ignored",
                    ty.name
                ));
                return;
            }
            if !extend && !BUILT_IN_SCALARS.contains(&ty.name.as_str()) {
                schema.warnings.push(format!(
                    "type `{}` defined more than once; definitions merged",
                    ty.name
                ));
            }
            let name = ty.name.clone();
            let mut duplicates = Vec::new();
            for field in ty.fields {
                if existing.field(&field.name).is_some() {
                    duplicates.push(field.name);
                } else {
                    existing.fields.push(field);
                }
            }
            for field in ty.input_fields {
                if existing.input_field(&field.name).is_some() {
                    duplicates.push(field.name);
                } else {
                    existing.input_fields.push(field);
                }
            }
            for value in ty.enum_values {
                if existing
                    .enum_values
                    .iter()
                    .any(|known| known.name == value.name)
                {
                    duplicates.push(value.name);
                } else {
                    existing.enum_values.push(value);
                }
            }
            for member in ty.members {
                if !existing.members.contains(&member) {
                    existing.members.push(member);
                }
            }
            for interface in ty.interfaces {
                if !existing.interfaces.contains(&interface) {
                    existing.interfaces.push(interface);
                }
            }
            existing.one_of |= ty.one_of;
            if existing.description.is_none() {
                existing.description = ty.description;
            }
            for duplicate in duplicates {
                schema.warnings.push(format!(
                    "`{name}.{duplicate}` defined more than once; first kept"
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_system() {
        let schema = parse_type_system(
            r#"
            """The root"""
            schema @link(url: "x") { query: Root mutation: Mut }
            directive @auth(role: String = "admin") repeatable on FIELD_DEFINITION | OBJECT
            type Root implements & Node & Named @key(fields: "id") {
              "the id" id: ID!
              users(first: Int = 10, order: Order = ASC, filter: Filter): [User!]! @auth
              old: String @deprecated(reason: "use new")
            }
            interface Node { id: ID! }
            interface Named implements Node { id: ID! name: String }
            type User implements Node { id: ID! }
            type Mut { noop: Boolean }
            union Result = | User | Root
            enum Order { ASC DESC @deprecated }
            input Filter @oneOf { name: String, ids: [ID!] = ["1"] }
            scalar Date @specifiedBy(url: "https://example.test")
            extend type User { email: String }
            extend union Result = Mut
            "#,
        )
        .unwrap();
        assert_eq!(schema.query_type.as_deref(), Some("Root"));
        assert_eq!(schema.mutation_type.as_deref(), Some("Mut"));
        let root = schema.get("Root").unwrap();
        assert_eq!(root.interfaces, ["Node", "Named"]);
        assert_eq!(root.fields[0].description.as_deref(), Some("the id"));
        let users = root.field("users").unwrap();
        assert_eq!(users.ty.to_string(), "[User!]!");
        assert_eq!(users.arguments[0].default_value, Some(Value::from(10)));
        assert_eq!(users.arguments[1].default_value, Some(Value::from("ASC")));
        let old = root.field("old").unwrap();
        assert_eq!(old.deprecation_reason.as_deref(), Some("use new"));
        assert_eq!(schema.get("User").unwrap().fields.len(), 2);
        assert_eq!(
            schema.get("Result").unwrap().members,
            ["User", "Root", "Mut"]
        );
        assert!(schema.get("Filter").unwrap().one_of);
        assert!(schema.get("Order").unwrap().enum_values[1].deprecated);
        assert_eq!(schema.possible_types("Node"), ["Root", "User"]);
        assert!(schema.warnings.is_empty(), "{:?}", schema.warnings);
    }

    #[test]
    fn tolerant_warnings() {
        let schema = parse_type_system(
            "type Query { a: Int a: String b: Missing } type Query { c: Int } \
             extend type Ghost { x: Int } query Q { a } enum Query { X }",
        )
        .unwrap();
        let warnings = schema.warnings.join("\n");
        for needle in [
            "`Query.a` defined more than once",
            "`Query` defined more than once",
            "extension of undefined type `Ghost`",
            "executable definition",
            "different kind",
            "undefined type `Missing`",
        ] {
            assert!(warnings.contains(needle), "{needle} not in {warnings}");
        }
        assert_eq!(schema.get("Query").unwrap().fields.len(), 3);
    }

    #[test]
    fn syntax_errors() {
        for bad in [
            "type Query {",
            "type { a: Int }",
            "type Query { a Int }",
            "enum E { true }",
            "type Query { a(x: Int = $v): Int }",
            "schema { nope: Query }",
            "banana",
            "type Query { a: [Int }",
        ] {
            assert!(parse_type_system(bad).is_err(), "{bad}");
        }
        let deep = format!("type Q {{ a: {}Int{} }}", "[".repeat(100), "]".repeat(100));
        assert_eq!(parse_type_system(&deep).unwrap_err().code(), "too_large");
    }

    #[test]
    fn executable() {
        let document = parse_executable(
            r#"
            query Q($id: ID!, $n: Int = 3) @live {
              alias: user(id: $id) { ...F ... on User @include(if: true) { name } ... { id } }
              list(input: {a: [1, 2.5, "s", ENUM, null, $n]})
            }
            fragment F on User { id }
            { __typename }
            "#,
        )
        .unwrap();
        assert_eq!(document.operations.len(), 2);
        assert_eq!(document.fragments.len(), 1);
        let operation = &document.operations[0];
        assert_eq!(
            operation.variables[1].default,
            Some(AstValue::Int(String::from("3")))
        );
        let Selection::Field(user) = &operation.selections[0] else {
            panic!("expected a field")
        };
        assert_eq!(user.name, "user");
        assert_eq!(user.selections.as_ref().unwrap().len(), 3);
        let Selection::Field(list) = &operation.selections[1] else {
            panic!("expected a field")
        };
        let mut seen = Vec::new();
        list.arguments[0].1.variables(&mut |name| seen.push(name));
        assert_eq!(seen, ["n"]);
        assert_eq!(
            list.arguments[0].1.to_json(),
            serde_json::json!({"a": [1, 2.5, "s", "ENUM", null, null]})
        );
        for bad in [
            "",
            "query { }",
            "fragment on on X { a }",
            "{ a(b: ) }",
            "query Q($a) { a }",
        ] {
            assert!(parse_executable(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn const_values() {
        assert_eq!(
            parse_const_value(r#"{a: "x", b: [RED]}"#)
                .unwrap()
                .to_json(),
            serde_json::json!({"a": "x", "b": ["RED"]})
        );
        assert!(parse_const_value("$x").is_err());
        assert!(parse_const_value("1 2").is_err());
    }
}
