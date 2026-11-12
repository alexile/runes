# rune-html-encode

> HTML entity encoding and decoding — escape and unescape HTML special characters.

[![crates.io](https://img.shields.io/crates/v/rune-html-encode)](https://crates.io/crates/rune-html-encode)
[![docs.rs](https://img.shields.io/docsrs/rune-html-encode)](https://docs.rs/rune-html-encode)
[![license](https://img.shields.io/crates/l/rune-html-encode)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Escapes the five HTML special characters (`& < > " '`) to their named entities,
and decodes named entities, decimal numeric entities (`&#60;`), and hex numeric
entities (`&#x3C;`) back to text.

## Installation

```toml
[dependencies]
rune-html-encode = "0.1"
```

The `rune-html-encode` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-html-encode --features cli
```

## Usage

```rust
use rune_html_encode::{encode, decode};

let escaped = encode("<b>Hello & 'world'</b>");
assert_eq!(escaped, "&lt;b&gt;Hello &amp; &#x27;world&#x27;&lt;/b&gt;");

let back = decode("&lt;h1&gt;Hello &amp; World&lt;/h1&gt;");
assert_eq!(back, "<h1>Hello & World</h1>");
```

## CLI

```bash
rune-html-encode "<b>hello</b>"    # encode
rune-html-encode -d "&lt;b&gt;"   # decode
echo "<script>" | rune-html-encode -  # stdin
```

## Output

```
&lt;b&gt;hello&lt;/b&gt;
```

## License

MIT
