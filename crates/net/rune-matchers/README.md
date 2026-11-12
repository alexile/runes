# rune-matchers

> Nuclei-style matcher and extractor DSL over rune-http-model exchanges: word, regex, binary, status, header, JSON and XPath rules

[![crates.io](https://img.shields.io/crates/v/rune-matchers)](https://crates.io/crates/rune-matchers)
[![docs.rs](https://img.shields.io/docsrs/rune-matchers)](https://docs.rs/rune-matchers)
[![license](https://img.shields.io/crates/l/rune-matchers)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

Decides whether an HTTP exchange "hit" and pulls values out of it, the way
[nuclei](https://docs.projectdiscovery.io/templates/reference/matchers)
templates do, over [`rune-http-model`](../rune-http-model) exchanges:

- **`Matcher`**: `word`, `regex`, `binary` (hex), `status`, `size`, `time`
  (`lt`/`le`/`gt`/`ge`/`eq`/`ne` on total milliseconds), `header` (name,
  optional value regex) and `json_pointer` (RFC 6901 pointer or jq-lite
  path, optional expected value). Each takes nuclei's `condition`
  (`and`/`or`), `negative` and `case_insensitive` flags.
- **`ResponsePart`**: body, headers, one header, status, all, raw, request
  body, request headers, URL or time.
- **`MatcherSet`**: matchers combined with `and`/`or`; `fired` reports which
  matchers hit.
- **`Extractor`**: `regex` (capture group), `kval` (header or cookie by key),
  `json` (pointer or jq-lite), `xpath` (a small subset: `/a/b`, `//b`, `*`,
  `text()`, `@attr`), `header` and `cookie`.
- **Compiled forms** (`CompiledMatcher`, `CompiledMatcherSet`,
  `CompiledExtractor`) build regexes and paths once for hot loops and never
  fail at evaluation.

Rules come from untrusted templates, so regexes are size- and
nesting-limited and run in linear time (no backreferences or lookaround),
extractors return at most `MAX_EXTRACTED_VALUES` values, and nothing panics
on any input. The crate is sans-I/O.

## Installation

```toml
[dependencies]
rune-matchers = "0.1"
```

Features:

- `serde`: (de)serialize rules in a nuclei-like JSON shape
  (`{"type": "word", "words": ["admin"], "part": "body"}`).
- `schemars`: derive `schemars::JsonSchema` for rules. Implies `serde`.

## Usage

```rust
use rune_http_model::{ExchangeId, HttpExchange, HttpRequest, HttpResponse};
use rune_matchers::{
    Extractor, ExtractorKind, MatchCondition, Matcher, MatcherKind, MatcherSet, ResponsePart,
};

let exchange = HttpExchange::new(ExchangeId(1), "scan", HttpRequest::get("http://host.test/"))
    .with_response(
        HttpResponse::new(200)
            .with_header("X-Powered-By", "PHP/8.1")
            .with_header("Set-Cookie", "session=abc123; HttpOnly")
            .with_body(r#"{"user":{"role":"admin"}}"#),
    );

let set = MatcherSet::new(
    vec![
        Matcher::status([200]),
        Matcher::word(["php"])
            .with_part(ResponsePart::Header("x-powered-by".into()))
            .ignoring_case(),
        Matcher::new(MatcherKind::JsonPointer {
            pointer: "/user/role".into(),
            value: Some("admin".into()),
        }),
    ],
    MatchCondition::And,
)
.compile()
.unwrap();
assert!(set.matches(&exchange));

let session = Extractor::new(ExtractorKind::Kval { kval: vec!["session".into()] })
    .compile()
    .unwrap();
assert_eq!(session.extract(&exchange), vec!["abc123"]);
```

## License

MIT
