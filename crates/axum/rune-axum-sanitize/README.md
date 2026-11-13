# rune-axum-sanitize

> Defence-in-depth input sanitization for Axum: tokenizer-based tag stripping, HTML escaping or allowlist cleaning of query, form and JSON string values.

[![crates.io](https://img.shields.io/crates/v/rune-axum-sanitize)](https://crates.io/crates/rune-axum-sanitize)
[![docs.rs](https://img.shields.io/docsrs/rune-axum-sanitize)](https://docs.rs/rune-axum-sanitize)
[![license](https://img.shields.io/crates/l/rune-axum-sanitize)](LICENSE)

## Read this first

**Input sanitization does not prevent XSS. Output encoding does.** Whether a
string is dangerous depends on where it ends up: HTML text, an attribute, a
URL, a `<script>` block, CSS, a JSON response read by `innerHTML`. A filter
at the front door can't know that. The defences that work are:

1. **Context-aware output encoding** at render time. Templating engines that
   auto-escape (askama, maud, minijinja with autoescape, tera) do this for
   HTML; [`escape_html`](#standalone-functions) covers HTML text and quoted
   attributes when you build markup by hand.
2. **A Content-Security-Policy** without `unsafe-inline`, so injected script
   doesn't run even when encoding is missed.
3. **A real HTML sanitizer at render time** for content that must stay HTML
   (the `allowlist` mode below is one, but running it on output is better
   than on input).

This crate is a layer on top of those: it keeps obvious markup, control
characters and spoofing characters out of your database and logs, and gives
you a second chance when an output path forgets to encode. Treat it that way.

## What it does

`SanitizeLayer` rewrites requests before handlers see them:

| Input | Default | How |
|---|---|---|
| Query string | cleaned | Names and values are percent-decoded exactly as axum's `Query` does (`form_urlencoded`), so `%3Cscript%3E` is caught; changed pairs are re-encoded, others keep their bytes |
| `application/json`, `application/*+json` | cleaned | Every string, object keys included, at any depth (limit 128). Only changed literals are rewritten: key order, numbers and whitespace are kept byte for byte |
| `application/x-www-form-urlencoded` | cleaned | As the query string |
| `text/*` | cleaned | The whole body as one string; must be UTF-8 |
| Anything else (multipart, binary, no `Content-Type`) | passed through | Not buffered, not modified. Can be set to `415` instead |

Each string goes through a pipeline:

1. remove control characters: C0 except tab/LF/CR, DEL, C1 (this covers null bytes); on by default
2. optionally remove bidi controls and invisible characters (zero-width space, word joiner, BOM, soft hyphen, Hangul fillers); ZWJ/ZWNJ, variation selectors and tag characters are kept so emoji and scripts that need them survive
3. optionally normalise to NFC or NFKC (before markup handling, so NFKC folds `＜script＞` into something the next step sees)
4. apply a mode:
   - **`StripTags`** (default): tokenizer-based tag stripper. Follows the HTML tokenizer's tag, attribute, comment and bogus-comment states, so `<img alt=">" onerror=...>` is one tag. Drops the content of `script`, `style`, `iframe`, `noembed`, `noframes`, `noscript` and `xmp`. A final pass guarantees the output has no `<` followed by a letter, `/`, `!` or `?`, which defeats reassembly like `<<b>b>` or `<scr<script>ipt>`. Idempotent.
   - **`Escape`**: HTML-encodes `& < > " '` (via `rune-html-encode`). Keeps everything the user typed, but stores encoded text: anything else reading the data (emails, CSV exports, search) sees `&lt;`. Encoding twice double-encodes.
   - **`Allowlist`** (feature `allowlist`): cleans HTML with [ammonia](https://crates.io/crates/ammonia)'s html5ever-based allowlist. For rich-text fields, usually per field.

Requests the middleware can't vouch for are answered directly:

| Status | When |
|---|---|
| `413 Payload Too Large` | a body it would clean is over `max_body_bytes` (default 2 MiB, axum's default), by `Content-Length` or while reading |
| `400 Bad Request` | invalid JSON, JSON nested past `max_json_depth`, JSON object keys that become equal once cleaned (`{"a<b>": 1, "a": 2}`), a `text/*` body that isn't UTF-8, a body read error |
| `415 Unsupported Media Type` | a non-empty other body under `OtherBodies::Reject` |

Rewritten bodies get a correct `Content-Length` and lose `Transfer-Encoding`.

## Installation

```toml
[dependencies]
rune-axum-sanitize = "0.3"
# with the ammonia-backed allowlist mode:
# rune-axum-sanitize = { version = "0.3", features = ["allowlist"] }
```

## Usage

### Default layer

```rust,no_run
use axum::{routing::post, Json, Router};
use rune_axum_sanitize::SanitizeLayer;

async fn create(Json(body): Json<serde_json::Value>) -> Json<serde_json::Value> {
    Json(body)
}

#[tokio::main]
async fn main() {
    let app: Router = Router::new()
        .route("/posts", post(create))
        .layer(SanitizeLayer::default());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

`POST /posts` with `{"title": "<b>Hi</b><script>steal()</script>", "n": 1.50}`
reaches the handler as `{"title": "Hi", "n": 1.50}`.
`GET /search?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3Ehello` reaches it as `q=hello`.

### Configuration and per-route rules

```rust
use rune_axum_sanitize::{Normalization, OtherBodies, SanitizeConfig, SanitizeLayer, Sanitizer};

let config = SanitizeConfig::new()
    .sanitizer(
        Sanitizer::new()
            .normalization(Some(Normalization::Nfc))
            .strip_invisible(true),
    )
    .max_body_bytes(256 * 1024)
    .other_bodies(OtherBodies::Reject)
    // skip whole routes (exact, `/prefix/*`, or `*`)
    .exempt_route("/webhooks/*")
    // leave a field alone: JSON Pointer, `*` matches any key or index
    .exempt_field("/posts/*", "/content/*/markdown")
    // bare names match query and form fields
    .exempt_field("*", "password");

let layer = SanitizeLayer::new(config);
```

Rich text with the `allowlist` feature:

```rust,ignore
use rune_axum_sanitize::{Mode, SanitizeConfig};

let config = SanitizeConfig::new().field_mode("/posts/*", "/body", Mode::allowlist());
// `<p onclick=x()>hi</p><script>x()</script>` -> `<p>hi</p>`
```

Route patterns are matched against the path the layer sees; inside a nested
router that path excludes the nest prefix.

### Standalone functions

```rust
use rune_axum_sanitize::{escape_html, sanitize_query, strip_html, strip_null_bytes, Mode, Sanitizer};

assert_eq!(strip_html("<script>alert(1)</script>hello"), "hello");
assert_eq!(strip_html("<img alt='>' src=x onerror=alert(1)>hi"), "hi");
assert_eq!(strip_html("1 < 2"), "1 < 2");
assert_eq!(escape_html("<b>bold & bright</b>"), "&lt;b&gt;bold &amp; bright&lt;/b&gt;");
assert_eq!(strip_null_bytes(b"hel\x00lo"), b"hello");
assert_eq!(sanitize_query("q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E&page=2"), "q=&page=2");

let sanitizer = Sanitizer::new().mode(Mode::Escape);
assert_eq!(sanitizer.clean("a<b"), "a&lt;b");
let json = Sanitizer::new().clean_json(r#"{"a": ["<i>x</i>"]}"#, 32).unwrap();
assert_eq!(json, r#"{"a": ["x"]}"#);
```

## Security notes and limits

Be clear about what this does not cover:

- **Not sanitized:** path segments (`Path` extractor), headers, cookies,
  multipart fields and file uploads, bodies with other content types, and
  anything that reaches you by another route (queues, other services,
  database imports). With `OtherBodies::Passthrough` (the default), a handler
  that reads raw `Bytes` or `String` can be sent markup under
  `Content-Type: application/octet-stream`. Use `OtherBodies::Reject` on
  routes that only take JSON or forms.
- **Entities are not decoded.** `&lt;script&gt;` passes `StripTags`
  unchanged. It is harmless text unless something downstream decodes
  entities and then renders the result as HTML; no input filter can protect
  a pipeline like that. `Escape` mode turns it into `&amp;lt;...`.
- **Stripping is about markup, not context.** A value without any tag can
  still be dangerous where it lands: `javascript:alert(1)` in an `href`,
  `" onmouseover="x` in an unquoted or single-quoted attribute you build by
  hand, `';alert(1)//` inside a `<script>` string, `expression(...)` in CSS.
  Only output encoding for that context (plus URL scheme checks for links)
  handles these.
- **Unicode lookalikes** such as fullwidth `＜` are not markup to browsers and
  pass through by default. NFKC folds them to ASCII before stripping, but
  NFKC also rewrites legitimate text (ligatures, superscripts, some CJK
  compatibility forms); enable it when that's acceptable.
- **The stripper is a tokenizer, not a parser.** In odd cases (script data
  with `<!--`, `<plaintext>`, foreign content) the text it keeps differs from
  what a browser would show. It never emits something that opens a tag,
  comment or processing instruction, which the property tests check.
- **Data changes.** Users writing `a <b> c` or code snippets lose text in
  `StripTags`; `Escape` stores encoded text. Exempt the fields where that
  matters and encode them on output.
- **Bodies are buffered** (up to `max_body_bytes`) when cleaned. That cap is
  separate from axum's `DefaultBodyLimit`; keep both sensible.

Tests include a corpus of known filter-evasion vectors (nested and split
tags, unclosed tags, `>` in attributes, comment and CDATA tricks, SVG and
MathML payloads, null bytes inside tag names, entity-encoded and fullwidth
markup) and property tests for panics, UTF-8 validity, idempotence, JSON
structure preservation and agreement with `serde_json` on what is valid.

## Migrating from 0.2

0.2's query filter worked on the raw, still percent-encoded query, so
`?q=%3Cscript%3E`, which is what browsers send, passed through untouched.
`max_body_bytes` was documented but never enforced, every body (binary and
multipart included) was buffered and had its null bytes removed, and
`Content-Length` was left stale after rewriting. 0.3 fixes all of these,
which changes behaviour:

- `SanitizeConfig` fields are private. Use the builder:
  `SanitizeConfig::new().sanitize_query(..).max_body_bytes(..)`.
  `strip_html_from_query` maps to `sanitize_query`;
  `strip_null_bytes_from_body` has no direct equivalent: null bytes are now
  removed from every cleaned string as part of control-character stripping
  (`Sanitizer::strip_control_chars`), and other bodies are left alone.
- JSON, form and text bodies are now cleaned (strip tags by default), not
  just stripped of null bytes. Turn kinds off with `sanitize_json(false)`
  and friends.
- Bodies are capped at 2 MiB by default (`413` above). Malformed JSON gets
  `400`.
- `strip_html` drops `script`/`style` content (`"<script>a</script>b"` is now
  `"b"`, was `"ab"`), honours quoted `>` in attributes and drops `<` that
  would re-form a tag.
- `sanitize_query` decodes values first and re-encodes the ones it changes.

## License

MIT
