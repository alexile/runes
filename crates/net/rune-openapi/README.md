# rune-openapi

> OpenAPI 3.x and Swagger 2.0 import: normalized endpoints, typed parameters, schemas, example requests and insertion points

[![crates.io](https://img.shields.io/crates/v/rune-openapi)](https://crates.io/crates/rune-openapi)
[![docs.rs](https://img.shields.io/docsrs/rune-openapi)](https://docs.rs/rune-openapi)
[![license](https://img.shields.io/crates/l/rune-openapi)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

Turns an API definition into something a scanner or fuzzer can drive.
[OpenAPI 3.0](https://spec.openapis.org/oas/v3.0.4),
[3.1](https://spec.openapis.org/oas/v3.1.1), 3.2 and
[Swagger 2.0](https://swagger.io/specification/v2/) documents, JSON or
YAML, all normalize to one model:

- **`Endpoint`**: method, path template, `operationId`, tags, servers,
  security requirements and declared responses.
- **`Parameter`**: path, query, header and cookie parameters with their
  `Schema`, serialization style (`form`, `simple`, `label`, `matrix`,
  `deepObject`, delimited; Swagger `collectionFormat` maps onto these) and
  examples. Operation-level entries override path-item ones.
- **`RequestBody`** / **`MediaType`**: one schema per content type,
  including Swagger 2.0 `body` and `formData` parameters.
- **`Schema`**: `$ref`s resolved, `allOf` merged, `oneOf`/`anyOf` kept as
  variants, 3.1 type arrays and numeric exclusive bounds folded in.
  Recursive references are cut off and flagged `truncated`.
- An example **`HttpRequest`** from
  [`rune-http-model`](../rune-http-model), filled with document examples or
  values synthesized from type, format, bounds and `enum`, with security
  applied (`{{scheme}}` placeholders unless you pass credentials).
- **`InsertionPoint`**s: every path/query/header/cookie parameter, form or
  multipart field, JSON pointer and XML element in that request, each with
  its schema, so payload generators can stay type-aware.

The crate is sans-I/O. External `$ref`s are never fetched; they, and other
problems inside a valid document, become `ApiSpec::warnings`. Size, depth
and `$ref` expansion are bounded, so hostile documents stay cheap.

## Installation

```toml
[dependencies]
rune-openapi = "0.1"
```

| Feature | Enables |
| --- | --- |
| `yaml` (default) | YAML 1.2 input via the safe-Rust `yaml-rust2` parser (alias expansion and nesting are bounded); JSON always works |
| `serde` | `Serialize`/`Deserialize` for the model |
| `schemars` | `JsonSchema` for the model (implies `serde`) |

## Usage

```rust
use rune_openapi::{InsertionLocation, Options, Url, parse};

let doc = br#"
openapi: 3.0.3
servers: [{url: "https://shop.example.test/v1"}]
security: [{bearer: []}]
components:
  securitySchemes:
    bearer: {type: http, scheme: bearer}
paths:
  /orders/{id}:
    get:
      operationId: getOrder
      parameters:
        - {name: id, in: path, required: true, schema: {type: integer, minimum: 1}}
        - {name: expand, in: query, schema: {type: array, items: {type: string, enum: [items]}}}
"#;

let spec = parse(doc, &Options::default())?;
let order = spec.endpoint("getOrder").unwrap();
assert_eq!(order.request.url, "https://shop.example.test/v1/orders/1?expand=items");
assert_eq!(order.request.header("Authorization"), Some("Bearer {{bearer}}"));
for point in &order.insertion_points {
    println!("{:?} {} : {:?}", point.location, point.name, point.schema_type());
}

// Render the same endpoint against a lab server with real credentials.
let lab = Options::default()
    .with_base_url(Url::parse("http://127.0.0.1:8080/").unwrap())
    .with_auth_value("bearer", "token-123");
let request = order.render(&lab).request;
assert_eq!(request.url, "http://127.0.0.1:8080/orders/1?expand=items");
assert!(order.insertion_point(InsertionLocation::Path, "id").unwrap().required);
# Ok::<(), rune_openapi::OpenApiError>(())
```

## Stability

The model structs and enums are `#[non_exhaustive]`: read their fields,
build options with `Options::default().with_*(…)`, and give matches a
wildcard arm. `Property` and `SecurityRequirement` are plain data.

## License

MIT
