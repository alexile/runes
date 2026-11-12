# rune-payload-encode

> WAF-evasion payload variants (case, encoding, comment, whitespace, concatenation) as composable rune-transform transforms

[![crates.io](https://img.shields.io/crates/v/rune-payload-encode)](https://crates.io/crates/rune-payload-encode)
[![docs.rs](https://img.shields.io/docsrs/rune-payload-encode)](https://docs.rs/rune-payload-encode)
[![license](https://img.shields.io/crates/l/rune-payload-encode)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## Installation

```toml
[dependencies]
rune-payload-encode = "0.1"
```

The `rune-payload-encode` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-payload-encode --features cli
```

Use it only against systems you are authorized to test.

## Usage

### Library

```rust
use rune_payload_encode::{Context, Encoder, Options, Technique};

let encoder = Encoder::new()?;

// The context's default techniques, original payload first.
let report = encoder.run("' OR 1=1-- -", &Options::default().with_context(Context::Sql))?;
for variant in &report.variants {
    println!("{}\t{}", variant.technique, variant.payload);
}
// original            ' OR 1=1-- -
// case_toggle         ' Or 1=1-- -
// sql_inline_comment  '/**/OR/**/1=1--/**/-
// sql_whitespace_alt  '%09OR%091=1--%09-
// sql_char_encode     CHAR(39,32,79,82,32,49,61,49,45,45,32,45)
// hex_encode          0x27204f5220313d312d2d202d
// url_encode          %27%20OR%201%3D1--%20-
// concatenation       '' OR 1'+'=1-- -'

// Pick techniques, stack them, bound the output, and reverse.
let options = Options::default()
    .with_context(Context::Xss)
    .with_techniques([Technique::HtmlEntityEncode])
    .with_stack([Technique::CaseToggle, Technique::UrlEncode])
    .with_max_variants(16)
    .with_max_variant_len(4096);
let report = encoder.run("<svg onload=x>", &options)?;
assert_eq!(report.variants[2].technique, "case_toggle+url_encode");
assert_eq!(encoder.reverse(&report.variants[1])?, "<svg onload=x>");
# Ok::<(), rune_payload_encode::Error>(())
```

Every technique is a [`rune-transform`](../../common/rune-transform)
transform. `register` adds them to a `TransformRegistry` as `evade_*` ids
(`evade_hex_encode_sql` and `evade_concatenation_sql` for the SQL forms), so
they compose with every other codec there:

```rust
use rune_transform::TransformRegistry;

let mut registry = TransformRegistry::builtin();
rune_payload_encode::register(&mut registry)?;
let chain = registry.parse_chain("evade_case_toggle | evade_sql_inline_comment | url")?;
assert_eq!(chain.encode(b"union select")?, b"UnIoN%2F%2A%2A%2FsElEcT");
# Ok::<(), rune_payload_encode::Error>(())
```

| Technique | Example (`a b<`) | Reversible | Contexts |
| --- | --- | --- | --- |
| `case_toggle` | `A b<` | no | all |
| `url_encode` | `a%20b%3C` | yes | all |
| `double_url_encode` | `a%2520b%253C` | yes | all |
| `unicode_escape` | `\u0061\u0020\u0062\u003c` | yes | all |
| `html_entity_encode` | `&#x61;&#x20;&#x62;&lt;` | yes | generic, xss, html |
| `hex_encode` | `\x61\x20\x62\x3c` / SQL `0x6120623c` | yes | all |
| `sql_inline_comment` | `a/**/b<` | no | generic, sql |
| `sql_whitespace_alt` | `a%09b<` | no | generic, sql |
| `sql_char_encode` | `CHAR(97,32,98,60)` | yes | generic, sql |
| `null_byte` | `a b<%00` | yes | all |
| `path_dot_slash_obfuscation` | `../` → `....//` | no | generic, path |
| `os_command_separator_alt` | `a${IFS}b<` | no | generic, os_command |
| `tab_newline_insertion` | `a\tb<` | no | all |
| `concatenation` | `"a ""b<"` / SQL `'a '+'b<'` | yes | generic, sql, xss, html |

`unicode_escape` writes characters outside the Basic Multilingual Plane as
UTF-16 surrogate pairs (`\ud83d\ude00`) rather than `\u1f600`.

### CLI

```bash
rune-payload-encode --context sql "' OR 1=1-- -"
# original	' OR 1=1-- -
# case_toggle	' Or 1=1-- -
# ...

rune-payload-encode -c xss -t html_entity_encode -s case_toggle+url_encode --no-original "<b>"
# html_entity_encode	&lt;&#x62;&gt;
# case_toggle+url_encode	%3CB%3E

rune-payload-encode --list
```

## License

MIT
