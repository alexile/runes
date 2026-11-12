# rune-mime

> MIME media types: Content-Type parsing and formatting, charset detection, and bounded multipart/form-data and multipart/mixed parsing

[![crates.io](https://img.shields.io/crates/v/rune-mime)](https://crates.io/crates/rune-mime)
[![docs.rs](https://img.shields.io/docsrs/rune-mime)](https://docs.rs/rune-mime)
[![license](https://img.shields.io/crates/l/rune-mime)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

A small, strict-but-tolerant MIME layer for HTTP tooling, sans-I/O and
panic-free on any input:

- **`MediaType`**: parse and format `Content-Type`
  ([RFC 9110 §8.3.1](https://www.rfc-editor.org/rfc/rfc9110#section-8.3.1),
  [RFC 2045 §5.1](https://www.rfc-editor.org/rfc/rfc2045#section-5.1)):
  quoted strings, [RFC 8187](https://www.rfc-editor.org/rfc/rfc8187)
  extended parameters (`name*=UTF-8''…`), `+json`/`+xml` suffixes. The
  canonical `Display` form parses back to an equal value.
- **`ContentDisposition`**: the same for `Content-Disposition`
  ([RFC 6266](https://www.rfc-editor.org/rfc/rfc6266)), with `filename*`
  taking precedence over `filename`.
- **Charsets**: `detect_charset` (BOM → declared → `<meta>` / XML
  declaration / `@charset` → UTF-8 / ASCII → Windows-1252) and
  `Charset::decode` for UTF-8, UTF-16LE/BE, US-ASCII, ISO-8859-1 and
  Windows-1252.
- **Multipart**: `parse_multipart` for `multipart/form-data`
  ([RFC 7578](https://www.rfc-editor.org/rfc/rfc7578)), `multipart/mixed`,
  `multipart/byteranges` and friends
  ([RFC 2046 §5.1](https://www.rfc-editor.org/rfc/rfc2046#section-5.1)).
  Part bodies are borrowed and carry their byte ranges in the input, so an
  insertion-point engine can splice one field. Limits on parts, header
  bytes and header count bound the work. `encode_multipart` writes parts
  back.
- **`rune-http-model` glue**: `parse_request_multipart`,
  `parse_response_multipart`, `response_charset`, `set_multipart_form`.

## Installation

```toml
[dependencies]
rune-mime = "0.1"
```

## Usage

```rust
use rune_mime::{ContentDisposition, MediaType, MultipartOptions, parse_multipart_body};

let content_type: MediaType = "multipart/form-data; boundary=XyZ".parse().unwrap();
let body = b"--XyZ\r\n\
Content-Disposition: form-data; name=\"file\"; filename*=UTF-8''%E2%82%AC.txt\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
\r\n\
hello\r\n\
--XyZ--\r\n";

let form = parse_multipart_body(&content_type, body, &MultipartOptions::default()).unwrap();
let file = form.field("file").unwrap();
assert_eq!(file.filename().as_deref(), Some("€.txt"));
assert_eq!(file.body, b"hello");
assert_eq!(&body[file.body_range.clone()], b"hello");

let cd = ContentDisposition::parse("attachment; filename=\"a b.pdf\"").unwrap();
assert_eq!(cd.filename(), Some("a b.pdf"));
```

File names are returned as sent: sanitise them before touching the file
system. Bodies with a `Content-Encoding` must be decoded before parsing.

## License

MIT
