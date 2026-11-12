# rune-graphql

> GraphQL SDL and introspection import: type model, bounded query and mutation generation, insertion points and operation validation

[![crates.io](https://img.shields.io/crates/v/rune-graphql)](https://crates.io/crates/rune-graphql)
[![docs.rs](https://img.shields.io/docsrs/rune-graphql)](https://docs.rs/rune-graphql)
[![license](https://img.shields.io/crates/l/rune-graphql)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

Turns a GraphQL schema into requests a scanner or fuzzer can drive.
Schema definition language and introspection results
([GraphQL, October 2021](https://spec.graphql.org/October2021/)) both
normalize to one model:

- **`Schema`** / **`TypeDef`**: objects, interfaces (including interfaces
  that implement interfaces), unions, enums, input objects (`@oneOf`
  included) and scalars, with arguments, defaults, descriptions and
  deprecations. Type extensions are merged. `Schema::to_introspection`
  writes the standard introspection shape back out.
- **`Operation`**: one per `Query` / `Mutation` (optionally
  `Subscription`) root field. Every argument is a typed variable; required
  arguments of nested fields are hoisted into variables too. Selection sets
  are bounded by depth, fields per selection and fields per operation, and
  never re-enter a type already on their path. Unions select `__typename`
  plus an inline fragment per member.
- An example **`HttpRequest`** from
  [`rune-http-model`](../rune-http-model) (`POST` JSON, or `GET` for
  queries), with your headers.
- **`InsertionPoint`**s: every scalar and enum inside the variables, by
  JSON pointer, with its GraphQL type, nullability and enum values.
- **Field-level authorization targets**: each operation lists the types and
  `Type.field` coordinates it reads, so `operations_for_field("User.email")`
  gives the requests to replay per role.
- **`validate`**: checks any operation against the schema (fields,
  arguments, variables and their types, literals, fragments, leaf/composite
  selections), and **`query_depth`** measures it.

The crate is sans-I/O and has no GraphQL parser dependency: the lexer and
parser are bounded (nesting, size), so hostile schemas and documents stay
cheap. Problems inside a readable schema (undefined types, duplicates,
missing roots, operations mixed into SDL) become `warnings`.

## Installation

```toml
[dependencies]
rune-graphql = "0.1"
```

| Feature | Enables |
| --- | --- |
| `serde` | `Serialize`/`Deserialize` for the model |
| `schemars` | `JsonSchema` for the model (implies `serde`) |

## Usage

```rust
use rune_graphql::{Options, Url, parse, query_depth, validate};

let sdl = br#"
  type Query { order(id: ID!): Order }
  type Order { id: ID! total: Float customer: Customer lines(first: Int!): [Line] }
  type Customer { email: String orders: [Order] }
  type Line { sku: String }
"#;
let options = Options::default()
    .with_endpoint(Url::parse("http://127.0.0.1:4000/graphql").unwrap())
    .with_header("Authorization", "Bearer {{token}}")
    .with_max_depth(3);
let spec = parse(sdl, &options)?;

let order = spec.operation("Query.order").unwrap();
assert_eq!(
    order.document,
    "query Order($id: ID!, $lines_first: Int!) { order(id: $id) { id total customer { email } lines(first: $lines_first) { sku } } }"
);
assert!(validate(&order.document, &spec.schema).is_empty());
assert_eq!(query_depth(&order.document)?, 3);
assert_eq!(order.request.header("Authorization"), Some("Bearer {{token}}"));

for point in &order.insertion_points {
    println!("{} : {}", point.name, point.graphql_type); // /id : ID!, /lines_first : Int!
}

// Who can read customer emails? Replay these as each role.
let readers: Vec<_> = spec.operations_for_field("Customer.email").collect();
assert_eq!(readers.len(), 1);
# Ok::<(), rune_graphql::GraphQlError>(())
```

## Stability

The model structs and enums are `#[non_exhaustive]`: read their fields,
build options with `Options::default().with_*(…)`, and give matches a
wildcard arm.

## License

MIT
