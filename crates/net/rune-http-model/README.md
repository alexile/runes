# rune-http-model

> Shared HTTP model: requests, responses, byte-exact bodies, headers, timings and exchanges, sans-I/O

[![crates.io](https://img.shields.io/crates/v/rune-http-model)](https://crates.io/crates/rune-http-model)
[![docs.rs](https://img.shields.io/docsrs/rune-http-model)](https://docs.rs/rune-http-model)
[![license](https://img.shields.io/crates/l/rune-http-model)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

One HTTP model for every tool that sends, proxies, imports or analyses
traffic. Clients and proxies record with it, HAR/OpenAPI/Postman importers
produce it, and matchers, cookie jars, auth helpers and reports consume it.
The crate is sans-I/O: there is no client, only values.

- **`HttpRequest`** / **`HttpResponse`**: method, URL, version, headers,
  body and optional exact wire bytes, all kept verbatim. Malformed methods,
  URLs and headers are recorded as-is, which security tooling needs.
- **`HeaderEntry`** lists in wire order with duplicates, matched
  case-insensitively ([RFC 9110 §5.1](https://www.rfc-editor.org/rfc/rfc9110#section-5.1)):
  `header_value`, `header_values`, `has_header`, `set_header`,
  `remove_header`, `headers_from_pairs`, `headers_to_pairs`.
- **`HttpBody`**: exact bytes (`bytes::Bytes`) plus capture metadata
  (content coding still applied, truncation, full length). **`BodyKind`**
  turns text from a user or agent (text, JSON, form, base64) into bytes.
- **`HttpExchange`**: a request with its response or transport error,
  `Timings`, followed `RedirectHop`s, an `ExchangeId`, labels and tags.
- **`HttpVersion`**: HTTP/0.9 to HTTP/3, parsed from status-line and ALPN
  spellings.

## Installation

```toml
[dependencies]
rune-http-model = { version = "0.1", features = ["serde"] }
```

| Feature | Enables |
| --- | --- |
| `serde` | `Serialize`/`Deserialize` for every type, with a stable JSON shape |
| `schemars` | `JsonSchema` for every type (implies `serde`) |

No feature is on by default.

## Usage

```rust
use rune_http_model::{ExchangeId, HttpBody, HttpExchange, HttpRequest, HttpResponse, Timings};

let request = HttpRequest::post("https://shop.example.test/login")
    .with_header("Content-Type", "application/x-www-form-urlencoded")
    .with_body("user=alice&pass=hunter2");
let response = HttpResponse::new(302)
    .with_header("Location", "/account")
    .with_header("Set-Cookie", "session=abc; HttpOnly")
    .with_header("set-cookie", "theme=dark");

let exchange = HttpExchange::new(ExchangeId(1), "workbench", request)
    .with_response(response)
    .with_timings(Timings::new(42).with_time_to_headers(30));

let response = exchange.response.as_ref().unwrap();
assert!(response.is_redirect());
assert_eq!(response.header_values("SET-COOKIE").count(), 2);
assert_eq!(exchange.status(), Some(302));
```

### JSON shape (`serde`)

Bodies keep their exact bytes through JSON: valid UTF-8 is written as text,
anything else as standard base64.

```json
{ "encoding": "base64", "data": "//4AgGHD", "content_encoding": "gzip",
  "truncated": true, "total_len": 4096 }
```

On input every field is optional, and a bare string is read as a UTF-8
body. `HttpVersion` serializes as `http09`, `http10`, `http11`, `http2` or
`http3`; `BodyKind` as `empty`, `text`, `json`, `form` or `base64`.

## Stability

`HttpRequest`, `HttpResponse`, `HttpExchange`, `HttpVersion`, `BodyKind`
and `HttpModelError` are `#[non_exhaustive]`: build them with the
constructors and `with_*` methods, and give matches a wildcard arm.
`HeaderEntry`, `Timings` and `RedirectHop` are plain data with a fixed
shape that may be built with struct literals.

## License

MIT
