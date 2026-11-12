# rune-caesar

> Caesar cipher — shift-based substitution cipher with brute-force decoder.

[![crates.io](https://img.shields.io/crates/v/rune-caesar)](https://crates.io/crates/rune-caesar)
[![docs.rs](https://img.shields.io/docsrs/rune-caesar)](https://docs.rs/rune-caesar)
[![license](https://img.shields.io/crates/l/rune-caesar)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Encrypts and decrypts ASCII text by rotating each letter a fixed number of positions
through the alphabet. Non-letter characters pass through unchanged. Includes a
brute-force mode that tries all 25 non-trivial shifts — handy for CTF challenges
where the key is unknown.

## Installation

```toml
[dependencies]
rune-caesar = "0.2"
```

The `rune-caesar` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-caesar --features cli
```

## Usage

### Library

```rust
use rune_caesar::{encrypt, decrypt, brute_force};

let ciphertext = encrypt("Hello, World!", 13);
assert_eq!(ciphertext, "Uryyb, Jbeyq!");

let plaintext = decrypt(&ciphertext, 13);
assert_eq!(plaintext, "Hello, World!");

let candidates = brute_force("Khoor");
assert!(candidates.iter().any(|(shift, text)| *shift == 3 && text == "Hello"));
```

### CLI

```bash
# Encrypt
rune-caesar encrypt "Hello, World!" --shift 13
# Uryyb, Jbeyq!

# Decrypt
rune-caesar decrypt "Uryyb, Jbeyq!" --shift 13
# Hello, World!

# Brute-force all 25 shifts
rune-caesar brute "Khoor"
# shift=1: Jgnnq
# shift=2: Ifmmp
# shift=3: Hello
# ...
```

## Output

```
$ rune-caesar brute "Khoor"
shift=1: Jgnnq
shift=2: Ifmmp
shift=3: Hello
shift=4: Gdkkn
shift=5: Fcjjm
...
```

## License

MIT
