//! GraphQL schema import (SDL or introspection JSON) into a type model,
//! with bounded query and mutation generation, insertion points and
//! operation validation.
//!
//! [`parse`] reads a schema, auto-detecting SDL or an introspection result,
//! and returns a [`GraphQlSpec`]:
//!
//! - the [`Schema`]: every [`TypeDef`] with its fields, arguments, input
//!   fields, enum values, interfaces and union members, deprecations and
//!   defaults;
//! - one [`Operation`] per `Query` / `Mutation` (and optionally
//!   `Subscription`) root field: every argument passed as a typed variable,
//!   nested required arguments hoisted into variables, and a selection set
//!   bounded by [`Options::max_depth`], [`Options::max_fields_per_selection`]
//!   and [`Options::max_selections`] that never re-enters a type already on
//!   its path;
//! - an example [`HttpRequest`] (from `rune-http-model`) per operation, and
//!   [`InsertionPoint`]s for every scalar and enum inside its variables;
//! - for field-level authorization testing, the types and `Type.field`
//!   coordinates each operation reads ([`GraphQlSpec::operations_for_type`],
//!   [`GraphQlSpec::operations_for_field`]).
//!
//! [`validate`] checks any executable document against a schema, and
//! [`query_depth`] measures it. The crate is sans-I/O; problems inside a
//! readable schema (undefined types, duplicates, missing roots) become
//! [`GraphQlSpec::warnings`].
//!
//! Specification: [GraphQL, October 2021](https://spec.graphql.org/October2021/),
//! plus the `@oneOf` input objects RFC.
//!
//! # Features
//!
//! - `serde`: `Serialize`/`Deserialize` for the model (with
//!   `rune-http-model/serde`).
//! - `schemars`: `JsonSchema` for the model (implies `serde`).
//!
//! # Example
//!
//! ```
//! use rune_graphql::{Options, Url, parse, query_depth, validate};
//!
//! let sdl = br#"
//!   type Query { user(id: ID!): User }
//!   type Mutation { rename(id: ID!, input: RenameInput!): User }
//!   input RenameInput { name: String! reason: String }
//!   type User { id: ID! name: String email: String @deprecated manager: User }
//! "#;
//! let options = Options::default()
//!     .with_endpoint(Url::parse("https://api.example.test/graphql").unwrap())
//!     .with_max_depth(3);
//! let spec = parse(sdl, &options)?;
//!
//! let user = spec.operation("Query.user").unwrap();
//! assert_eq!(user.document, "query User($id: ID!) { user(id: $id) { id name email } }");
//! assert_eq!(user.request.method, "POST");
//! assert!(validate(&user.document, &spec.schema).is_empty());
//! assert!(query_depth(&user.document)? <= 3);
//!
//! let rename = spec.operation("Mutation.rename").unwrap();
//! assert_eq!(rename.variables["input"]["name"], "string");
//! assert!(rename.insertion_point("/input/name").unwrap().required);
//!
//! // Which requests read `User.email`? Replay them per role.
//! assert_eq!(spec.operations_for_field("User.email").count(), 2);
//! # Ok::<(), rune_graphql::GraphQlError>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod error;
mod generate;
mod introspection;
mod lexer;
mod parser;
mod schema;
mod validate;

pub use error::GraphQlError;
pub use generate::{
    DEFAULT_ENDPOINT, ExampleStrategy, GraphQlSpec, InsertionLocation, InsertionPoint, Operation,
    Options, SchemaSource, Transport, generate,
};
pub use introspection::parse_introspection;
pub use schema::{
    BUILT_IN_SCALARS, EnumValue, Field, InputValue, OperationKind, Schema, TypeDef, TypeKind,
    TypeRef,
};
pub use validate::{ValidationError, query_depth, validate};

/// The request type operations are rendered to.
pub use rune_http_model::HttpRequest;
/// JSON values used for variables and defaults.
pub use serde_json::Value;
/// The URL type of [`Options::endpoint`].
pub use url::Url;

/// Parses SDL into a [`Schema`].
///
/// Executable definitions mixed into the document, duplicates, extensions
/// of undefined types and references to undefined types are tolerated and
/// listed in [`Schema::warnings`]. Directives other than `@deprecated` and
/// `@oneOf` are parsed and ignored.
///
/// ```
/// use rune_graphql::parse_sdl;
///
/// let schema = parse_sdl("type Query { a: Int } extend type Query { b: [String!] }")?;
/// assert_eq!(schema.get("Query").unwrap().fields.len(), 2);
/// # Ok::<(), rune_graphql::GraphQlError>(())
/// ```
pub fn parse_sdl(source: &str) -> Result<Schema, GraphQlError> {
    parser::parse_type_system(source)
}

/// Reads a schema (SDL, or an introspection result when the input starts
/// with `{`) and generates its operations.
///
/// ```
/// use rune_graphql::{Options, SchemaSource, parse};
///
/// let json = br#"{"data": {"__schema": {"queryType": {"name": "Query"}, "types": [
///   {"kind": "OBJECT", "name": "Query", "fields": [
///     {"name": "ping", "args": [], "type": {"kind": "SCALAR", "name": "String"}}]}]}}}"#;
/// let spec = parse(json, &Options::default())?;
/// assert_eq!(spec.source, SchemaSource::Introspection);
/// assert_eq!(spec.operations[0].document, "query Ping { ping }");
/// # Ok::<(), rune_graphql::GraphQlError>(())
/// ```
pub fn parse(input: &[u8], options: &Options) -> Result<GraphQlSpec, GraphQlError> {
    if input.len() > options.max_input_bytes {
        return Err(GraphQlError::TooLarge(format!(
            "{} bytes, more than the limit of {}",
            input.len(),
            options.max_input_bytes
        )));
    }
    let text = std::str::from_utf8(input).map_err(|_| GraphQlError::NotUtf8)?;
    let trimmed = text.trim_start_matches(['\u{FEFF}', ' ', '\t', '\r', '\n']);
    if trimmed.starts_with('{') && !looks_like_sdl_selection(trimmed) {
        let value: Value =
            serde_json::from_str(trimmed).map_err(|error| GraphQlError::Json(error.to_string()))?;
        let schema = parse_introspection(&value)?;
        return Ok(generate::generate_from(
            schema,
            SchemaSource::Introspection,
            options,
        ));
    }
    let schema = parse_sdl(text)?;
    Ok(generate::generate_from(schema, SchemaSource::Sdl, options))
}

/// JSON objects start with `{"` or `{}`; a GraphQL selection set at the top
/// of a document starts with `{` then a name.
fn looks_like_sdl_selection(text: &str) -> bool {
    text.get(1..)
        .unwrap_or_default()
        .trim_start()
        .starts_with(|character: char| character == '_' || character.is_ascii_alphabetic())
}

#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_input_kind() {
        assert_eq!(
            parse(b"{ \"__schema\": {\"types\": []} }", &Options::default())
                .unwrap()
                .source,
            SchemaSource::Introspection
        );
        assert_eq!(
            parse(b"{ nope", &Options::default()).unwrap_err().code(),
            "syntax_error"
        );
        assert_eq!(
            parse(b"{\"a\":", &Options::default()).unwrap_err().code(),
            "json_error"
        );
        assert_eq!(
            parse(&[0xff], &Options::default()).unwrap_err().code(),
            "not_utf8"
        );
        assert_eq!(
            parse(
                b"type Query { a: Int }",
                &Options::default().with_max_input_bytes(4)
            )
            .unwrap_err()
            .code(),
            "too_large"
        );
    }
}
