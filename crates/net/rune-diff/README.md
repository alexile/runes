# rune-diff

[![crates.io](https://img.shields.io/crates/v/rune-diff)](https://crates.io/crates/rune-diff)
[![docs.rs](https://img.shields.io/docsrs/rune-diff)](https://docs.rs/rune-diff)
[![license](https://img.shields.io/crates/l/rune-diff)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

Response differ: Myers line/word diffs with unified output, masking of
volatile content, and a structural diff of HTTP messages built on
[`rune-http-model`](../rune-http-model). Sans-I/O.

- **Myers diff.** `diff_slices` implements Myers' O(ND) algorithm
  (*An O(ND) Difference Algorithm and Its Variations*, 1986) in its
  linear-space "middle snake" form, with prefix/suffix trimming and a cost
  cap (`DiffOptions::max_cost`) that keeps hostile inputs bounded while
  still producing a valid script.
- **Text diffs.** `TextDiff` diffs by line, word or character, gives a
  similarity ratio and renders `diff -u` style unified hunks.
- **Volatile masking.** `Masker` replaces dates, epochs, UUIDs, long
  tokens, `nonce` attributes, hidden/CSRF input and meta values, injected
  payload reflections and custom regexes with placeholders.
- **Structural HTTP diff.** `HttpDiffer` compares status, version, reason,
  headers (case-insensitive, multi-valued, volatile ones such as `Date`,
  `X-Request-Id` or `CF-Ray` skipped) and bodies: JSON structurally with
  RFC 6901 pointers (key order ignored, array elements aligned with Myers,
  ignorable pointers with `*` wildcards), text with a masked Myers diff,
  anything else by bytes. Results carry a similarity score for
  differential oracles and a readable `Display` for comparers; with the
  `serde` feature they serialize to JSON.

## Installation

```sh
cargo add rune-diff
cargo install rune-diff --features cli
```

## Library usage

```rust
use rune_diff::{Granularity, HttpDiffOptions, HttpDiffer, TextDiff};
use rune_http_model::HttpResponse;

// Line diff, unified output.
let diff = TextDiff::new("a\nb\n", "a\nc\n", Granularity::Line);
assert_eq!(diff.unified(3).to_string(), "@@ -1,2 +1,2 @@\n a\n-b\n+c\n");

// Structural response diff: volatile fields ignored, real changes reported.
let differ = HttpDiffer::new(
    &HttpDiffOptions::default().with_ignored_json_pointer("/meta/requestId"),
)?;
let a = HttpResponse::new(200)
    .with_header("Date", "Thu, 12 Nov 2026 10:00:00 GMT")
    .with_header("Content-Type", "application/json")
    .with_body(r#"{"role":"user","meta":{"requestId":"r-1"}}"#);
let b = HttpResponse::new(200)
    .with_header("Date", "Thu, 12 Nov 2026 10:00:05 GMT")
    .with_header("Content-Type", "application/json")
    .with_body(r#"{"role":"admin","meta":{"requestId":"r-2"}}"#);
let diff = differ.diff_responses(&a, &b);
assert_eq!(diff.to_string(), "body /role: \"user\" -> \"admin\"\n");
assert!(diff.similarity() < 1.0);
# Ok::<(), rune_diff::Error>(())
```

## CLI usage

```sh
rune-diff old.txt new.txt                       # unified diff; exit 1 if different
rune-diff --granularity word --mask old.html new.html
rune-diff --mode response a.json b.json         # rune-http-model HttpResponse JSON
rune-diff --mode exchange --json --ignore-pointer '/items/*/etag' a.json b.json
```

Exit status: 0 equivalent, 1 different, 2 error.
