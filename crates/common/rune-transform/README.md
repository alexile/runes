# rune-transform

> Registry of named, chainable byte transforms (encode, decode, hash, compress) built on the rune codecs

[![crates.io](https://img.shields.io/crates/v/rune-transform)](https://crates.io/crates/rune-transform)
[![docs.rs](https://img.shields.io/docsrs/rune-transform)](https://docs.rs/rune-transform)
[![license](https://img.shields.io/crates/l/rune-transform)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

A Burp Decoder-style toolkit. A `Transform` is one named byte-to-byte
operation that always encodes and, when reversible, decodes. Transforms
live in a `TransformRegistry`, are named by id (`base64`, `gzip`, `sha256`,
…) and compose into a `TransformChain`: encode runs the steps left to
right, decode undoes them right to left. A `:decode` suffix runs a single
step backwards (`base64:decode`).

The built-in registry has 43 transforms:

| Category    | Ids |
| ----------- | --- |
| encoding    | `base64` `base64url` `base64url_nopad` `base32` `hex` `hex_upper` `hex_space` `hex_0x` `url` `url_encode_all` `double_url` `html` `html_entity_decimal` `html_entity_hex` |
| escape      | `js_hex_escape` `js_unicode_escape` `percent_u_escape` `octal_escape` `decimal_escape` |
| numeric     | `binary` `binary_spaced` `ascii_decimal` |
| compression | `gzip` `zlib` `deflate` |
| cipher      | `rot13` `rot5` `rot47` `atbash` `reverse` `nibble_swap` `bitwise_not` `swap_case` |
| hash        | `md5` `sha1` `sha224` `sha256` `sha384` `sha512` (one-way, raw digest bytes) |
| text        | `upper_case` `lower_case` `leetspeak` (one-way) |
| other       | `jwt_decode` (one-way: token to `{header, payload}` JSON, no signature check) |

The codecs are not reimplemented: they come from `rune-base64`,
`rune-base32`, `rune-hex`, `rune-url-encode`, `rune-html-encode`,
`rune-binary`, `rune-jwt`, `rune-rot13`, `rune-rot47`, `rune-atbash`,
`rune-xor`, `rune-md5`, `rune-sha1`, `rune-sha256` and `rune-sha512`
(SHA-224/384 from `sha2`, compression from `flate2`).

Parameterised transforms are built directly: `PrefixTransform`,
`SuffixTransform`, `MatchReplaceTransform`, `XorTransform`,
`UnicodeUpperCaseTransform`, `UnicodeLowerCaseTransform` and
`CompressTransform` (with its own level and output cap). Register your own
`Transform` implementations, or named chains, next to the built-ins.

`smart_decode` peels layered base64, URL and hex encodings heuristically.

The crate is sans-I/O and keeps no global state. Decompression is capped
(64 MiB by default) against decompression bombs.

## Installation

```toml
[dependencies]
rune-transform = "0.1"
```

The `rune-transform` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-transform --features cli
```

## Usage

### Library

```rust
use std::sync::Arc;
use rune_transform::{PrefixTransform, TransformRegistry, smart_decode};

let registry = TransformRegistry::builtin();

// One step, either direction.
assert_eq!(registry.encode("base64", b"hi")?, b"aGk=");
assert_eq!(registry.decode("url", b"a%20b")?, b"a b");

// A chain, encoded and decoded.
let chain = registry.parse_chain("gzip | base64")?;
let packed = chain.encode(b"hello hello hello")?;
assert_eq!(chain.decode(&packed)?, b"hello hello hello");

// Mixed directions and parameterised steps.
let chain = registry
    .parse_chain("hex:decode url")?
    .then(Arc::new(PrefixTransform::new("q=")));
assert_eq!(chain.encode(b"612062")?, b"q=a%20b");

// Hash, then print as hex.
let digest = registry.parse_chain("sha256 hex")?.encode(b"abc")?;
assert!(digest.starts_with(b"ba7816bf"));

// Peel layered encodings.
let steps = smart_decode("bmFtZSUzREpvaG4lMjBEb2U=");
assert_eq!(steps.last().map(|s| s.output.as_str()), Some("name=John Doe"));
# Ok::<(), rune_transform::Error>(())
```

### CLI

```bash
rune-transform --list                         # every built-in transform
rune-transform -i 'hello' base64              # aGVsbG8=
rune-transform -i 'aGVsbG8=' base64:decode    # hello
rune-transform -i 'abc' 'sha256|hex'          # ba7816bf…
rune-transform -r gzip base64 < blob.txt      # undo base64, then gunzip
rune-transform --smart -i 'bmFtZSUzREpvaG4lMjBEb2U='
```

## License

MIT
