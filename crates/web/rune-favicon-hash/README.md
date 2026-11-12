# rune-favicon-hash

> Shodan-style favicon hash: signed MurmurHash3-32 over the MIME-wrapped base64 of the icon bytes

[![crates.io](https://img.shields.io/crates/v/rune-favicon-hash)](https://crates.io/crates/rune-favicon-hash)
[![docs.rs](https://img.shields.io/docsrs/rune-favicon-hash)](https://docs.rs/rune-favicon-hash)
[![license](https://img.shields.io/crates/l/rune-favicon-hash)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

The favicon hash used by Shodan (`http.favicon.hash`), FOFA (`icon_hash`)
and httpx is `mmh3.hash(codecs.encode(icon, "base64"))` in Python: the
signed 32-bit MurmurHash3 (`x86_32`, seed 0) of the icon's standard base64,
wrapped with a `\n` after every 76 characters **and** after the last line.
This crate implements exactly that, on top of
[`rune-murmur`](../../common/rune-murmur) and
[`rune-base64`](../../common/rune-base64), so tools stop re-deriving it (and
getting the wrapping wrong).

## Installation

```toml
[dependencies]
rune-favicon-hash = "0.1"
```

The `rune-favicon-hash` command-line tool is behind the opt-in `cli`
feature:

```bash
cargo install rune-favicon-hash --features cli
```

## Usage

### Library

```rust
use rune_favicon_hash::{favicon_hash, favicon_hash_base64, mime_base64, shodan_query};

let icon: &[u8] = b"hello"; // the bytes of /favicon.ico
assert_eq!(mime_base64(icon), "aGVsbG8=\n");
let hash = favicon_hash(icon);
assert_eq!(hash, 1_155_597_304);
assert_eq!(shodan_query(hash), "http.favicon.hash:1155597304");

// Icons you already hold as base64 (data: URIs, HAR bodies) hash the same,
// whatever their wrapping.
assert_eq!(favicon_hash_base64("aGVsbG8=").unwrap(), hash);
```

### CLI

```bash
rune-favicon-hash favicon.ico
# -757223386

rune-favicon-hash --shodan favicon.ico other.ico
# http.favicon.hash:-757223386  favicon.ico
# http.favicon.hash:…           other.ico

echo -n 'aGVsbG8=' | rune-favicon-hash --base64
# 1155597304
```

## License

MIT
