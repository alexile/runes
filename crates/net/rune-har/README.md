# rune-har

> HAR 1.2 (HTTP Archive) reader and writer over rune-http-model, tolerant of Chrome, Firefox and Charles exports

[![crates.io](https://img.shields.io/crates/v/rune-har)](https://crates.io/crates/rune-har)
[![docs.rs](https://img.shields.io/docsrs/rune-har)](https://docs.rs/rune-har)
[![license](https://img.shields.io/crates/l/rune-har)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

Reads [HAR 1.2](http://www.softwareishard.com/blog/har-12-spec/) files from
browsers and proxies into `rune-http-model` `HttpExchange`s, and writes
exchanges back out as HAR. It has no I/O of its own: it works on bytes and
strings, and the caller opens the files.

- **Document layer**: `parse` returns a typed `Har` model with every HAR
  object. Fields the crate does not know (`_initiator`, `_charlesStatus`, …)
  are kept, so `parse` → `Har::to_json` → `parse` loses nothing.
  `HarWriter` streams entries one at a time.
- **Exchange layer**: `read` / `Har::to_exchanges` and `write` /
  `Har::from_exchanges` / `Entry::from_exchange`. Exchanges this crate
  writes read back equal. `_id`, `_tool`, `_label`, `_tags`,
  `_redirectChain`, `_contentEncoding`, `_truncated` and `_waitEstimated`
  carry the fields that HAR has no place for.
- **Tolerant**: reading accepts `null` anywhere, numbers written as strings,
  a byte-order mark, a bare `log` object, base64 with line breaks, timestamp
  offsets in any common form and HTTP/2 pseudo-headers. If one entry is
  malformed, that entry is skipped with a `Warning` and the rest of the file
  still reads.

## Installation

```toml
[dependencies]
rune-har = "0.1"
rune-http-model = "0.1"
```

## Usage

```rust
use rune_har::{ReadOptions, WriteOptions};
use rune_http_model::{ExchangeId, HttpExchange, HttpRequest, HttpResponse};

let input = br#"{"log": {"version": "1.2", "creator": {"name": "x", "version": "1"},
  "entries": [{"startedDateTime": "2024-01-02T03:04:05.678Z", "time": 12,
    "request": {"method": "GET", "url": "https://h.test/", "httpVersion": "HTTP/2",
      "headers": [], "cookies": [], "queryString": [], "headersSize": -1, "bodySize": 0},
    "response": {"status": 0, "statusText": "", "httpVersion": "", "headers": [],
      "cookies": [], "content": {"size": 0, "mimeType": ""}, "redirectURL": "",
      "headersSize": -1, "bodySize": -1, "_error": "net::ERR_CONNECTION_RESET"},
    "cache": {}, "timings": {"send": 0, "wait": 0, "receive": 0}}]}}"#;

let report = rune_har::read(input, &ReadOptions::default())?;
assert_eq!(report.exchanges[0].error.as_deref(), Some("net::ERR_CONNECTION_RESET"));

let exchange = HttpExchange::new(ExchangeId(1), "proxy", HttpRequest::get("http://h.test/"))
    .with_response(HttpResponse::new(204));
let har = rune_har::write([&exchange], &WriteOptions::default().with_pretty(true))?;
let again = rune_har::read(har.as_bytes(), &ReadOptions::default())?;
assert_eq!(again.exchanges, [exchange]);
# Ok::<(), rune_har::HarError>(())
```

The crate documentation has the full field mapping and lists the cases
where a round trip loses information. The `raw` wire bytes are not
stored. A response with status `0` reads back as no response.

## Testing

The tests round-trip export fixtures from Chrome, Firefox and Charles
(`tests/fixtures/`). Property tests write arbitrary exchanges and read them
back, and check that read → write → read is a fixpoint for arbitrary
HAR-shaped JSON.

## License

MIT
