# rune-subdomain-permute

> Pattern-based subdomain permutation (alterx class): deterministic, deduplicated, bounded candidate generation

[![crates.io](https://img.shields.io/crates/v/rune-subdomain-permute)](https://crates.io/crates/rune-subdomain-permute)
[![docs.rs](https://img.shields.io/docsrs/rune-subdomain-permute)](https://docs.rs/rune-subdomain-permute)
[![license](https://img.shields.io/crates/l/rune-subdomain-permute)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

Take host names you already know, apply patterns and wordlists, and get
candidate names worth resolving. Generation is pure: resolve the output
with your resolver and drop wildcard answers with
[`rune-wildcard-dns`](../rune-wildcard-dns).

- **Patterns** in alterx syntax: `{{word}}-{{sub}}.{{suffix}}`. Built-in
  variables come from the seed, split with the Public Suffix List
  (`rune-psl`) after IDNA normalization (`rune-idna`):

  | Seed `cloud.api.example.co.uk` | |
  |---|---|
  | `{{sub}}` | `cloud` |
  | `{{sub1}}`, `{{sub2}}`, … | `api` |
  | `{{suffix}}` | `api.example.co.uk` |
  | `{{root}}` | `example.co.uk` |
  | `{{sld}}` / `{{etld}}` / `{{tld}}` | `example` / `co.uk` / `uk` |

  Any other variable is a named payload list; patterns expand over every
  combination.
- **Strategies** in the defaults: prefix/suffix words with dash, dot or no
  separator, environment tokens, cloud region tokens, numeric suffixes,
  plus **number mutation** (`db07` → `db06`, `db08`, zero padding kept).
- **Enrichment** (opt-in): tokens seen in the seeds join the `word` list.
- **Output** is deterministic, deduplicated, never a seed, always a valid
  LDH host name, lazily generated and bounded by `limit`; `estimate` gives
  an upper bound up front.

## Installation

```toml
[dependencies]
rune-subdomain-permute = "0.1"
```

The command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-subdomain-permute --features cli
```

## Usage

### Library

```rust
use rune_subdomain_permute::{Options, Payloads, Permutator, Seed};

let mut payloads = Payloads::new();
payloads.insert("word", ["dev", "internal"]).unwrap();
let permutator = Permutator::new(
    ["{{word}}-{{sub}}.{{suffix}}", "{{sub}}.{{word}}.{{suffix}}"],
    payloads,
    Options::default().with_limit(10_000),
)
.unwrap();

let seeds = [Seed::parse("api.example.com").unwrap()];
let candidates: Vec<String> = permutator.permute(&seeds).collect();
assert_eq!(candidates, [
    "dev-api.example.com",
    "internal-api.example.com",
    "api.dev.example.com",
    "api.internal.example.com",
]);

// Or the alterx-style defaults over built-in wordlists:
let defaults = Permutator::default();
for name in defaults.permute(&seeds).names() {
    // `name` is a rune_dns_wire::Name, ready for a resolver.
    let _ = name;
}
```

### CLI

```bash
# seeds on stdin (or as arguments), candidates on stdout
cat known.txt | rune-subdomain-permute --limit 100000 > candidates.txt

# custom patterns and payload files
rune-subdomain-permute -p '{{word}}-{{sub}}.{{suffix}}' -P word=words.txt api.example.com

# how many would that be?
rune-subdomain-permute --estimate api.example.com
```

## License

MIT
