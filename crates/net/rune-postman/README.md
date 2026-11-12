# rune-postman

> Postman v2.0/v2.1 collection and environment import into rune-http-model requests, with variable resolution and auth helpers

[![crates.io](https://img.shields.io/crates/v/rune-postman)](https://crates.io/crates/rune-postman)
[![docs.rs](https://img.shields.io/docsrs/rune-postman)](https://docs.rs/rune-postman)
[![license](https://img.shields.io/crates/l/rune-postman)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

Reads [Postman Collection Format](https://schema.postman.com/) v2.0 and
v2.1 exports, together with environment and globals exports, into
ready-to-send `rune-http-model` `HttpRequest`s. It has no I/O of its own:
it works on bytes, and the caller opens the files.

- **Folders**: items are walked depth first; every request keeps its folder
  path, name, id and description.
- **Variables**: `{{name}}` resolves in URLs, headers, bodies and auth
  parameters through Postman's scopes (caller overrides, script-set local
  values, environment, collection and folder variables, globals),
  recursively, with cycle detection and a size cap. URL path variables
  (`/users/:id`) are filled in. Undefined names stay as `{{name}}` and are
  listed per request.
- **Bodies**: `raw` (with a `Content-Type` from its language), `urlencoded`,
  `formdata` (multipart with a fixed boundary) and `graphql`.
- **Auth helpers**, inherited from folders and the collection: `bearer`,
  `basic`, `apikey` (header or query) and `oauth2` with an exported access
  token. Helpers that need a live exchange or a signature (`digest`,
  `oauth1`, `awsv4`, …) are reported, not applied.
- **Scripts are data**: pre-request scripts are never executed. Their source
  is kept on each request, and literal assignments such as
  `pm.environment.set("token", "abc")` are applied to the scope they target.
- **Tolerant**: a byte-order mark, the API's `{"collection": …}` wrapper,
  `null` fields and v2.0 shapes are accepted. An item with a malformed field
  is skipped with a `Warning`; the rest of the collection still reads.

## Installation

```toml
[dependencies]
rune-postman = "0.1"
rune-http-model = "0.1"
```

## Usage

```rust
use rune_postman::{ReadOptions, parse_environment};

let collection = br#"{
  "info": {"name": "Shop", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
  "auth": {"type": "bearer", "bearer": [{"key": "token", "value": "{{token}}"}]},
  "item": [{"name": "Orders", "item": [{
    "name": "Create order",
    "request": {
      "method": "POST",
      "url": "{{baseUrl}}/orders",
      "body": {"mode": "raw", "raw": "{\"sku\": \"{{sku}}\"}", "options": {"raw": {"language": "json"}}}
    }
  }]}]
}"#;
let environment = parse_environment(br#"{"name": "dev", "values": [
  {"key": "baseUrl", "value": "https://shop.test", "enabled": true},
  {"key": "token", "value": "t0k3n", "enabled": true}
]}"#)?;

let options = ReadOptions::default()
    .with_environment(environment)
    .with_variable("sku", "MUG-1");
let imported = rune_postman::read(collection, &options)?;
let order = &imported.requests[0];
assert_eq!(order.path(), "Orders/Create order");
assert_eq!(order.request.url, "https://shop.test/orders");
assert_eq!(order.request.header("Authorization"), Some("Bearer t0k3n"));
assert_eq!(order.request.content_type(), Some("application/json"));
assert_eq!(order.request.body.as_utf8(), Some(r#"{"sku": "MUG-1"}"#));
# Ok::<(), rune_postman::PostmanError>(())
```

Dynamic variables such as `{{$guid}}` and `{{$timestamp}}` are not
generated (the crate has no clock or randomness); supply them with
`ReadOptions::with_variable` or they stay unresolved. File contents
referenced by `formdata` and `file` bodies are not part of an export, so
those parts are left empty with a warning. Postman v1 collections are
rejected; export them as v2.1 first.

## Testing

The tests import collections, an environment and a globals file as the
Postman app exports them (`tests/fixtures/`): nested folders, folder and
item scripts, every body mode, inherited and overridden auth, and a v2.0
collection. Property tests check that reading never panics on arbitrary
JSON, that generated folder trees import in order, and that variable
resolution stays bounded.

## License

MIT
