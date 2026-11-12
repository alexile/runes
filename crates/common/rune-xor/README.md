# rune-xor

> XOR cipher for byte streams and files — repeating-key, single-byte, and full repeating-key cracking.

[![crates.io](https://img.shields.io/crates/v/rune-xor)](https://crates.io/crates/rune-xor)
[![docs.rs](https://img.shields.io/docsrs/rune-xor)](https://docs.rs/rune-xor)
[![license](https://img.shields.io/crates/l/rune-xor)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

Applies XOR with a repeating key of any length. Brute-forces single-byte keys
with English frequency scoring, and cracks unknown repeating-key XOR ciphers
using Hamming distance key-size detection (Cryptopals challenge 6 technique).
Zero dependencies.

## Installation

```toml
[dependencies]
rune-xor = "0.1"
```

The `rune-xor` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-xor --features cli
```

## Usage

### Library

```rust
use rune_xor::{xor, xor_single, brute_force, break_repeating_key_xor};

// Repeating-key XOR (encrypt and decrypt are the same call)
let ct = xor(b"Attack at dawn", b"ICE");
let pt = xor(&ct, b"ICE");
assert_eq!(pt, b"Attack at dawn");

// Single-byte XOR brute-force
let ciphertext = xor_single(b"Cooking MC's like a pound of bacon", 0x58);
let best = &brute_force(&ciphertext)[0];
assert_eq!(best.key, 0x58);

// Repeating-key XOR cracker
let plaintext = b"the quick brown fox jumps over the lazy dog the quick brown fox";
let ciphertext = xor(plaintext, b"KEY");
let best = &break_repeating_key_xor(&ciphertext)[0];
assert_eq!(best.key, b"KEY");

// Custom scoring function
use rune_xor::brute_force_with;
let best = &brute_force_with(&ciphertext, |bytes| {
    bytes.iter().filter(|&&b| b.is_ascii_alphabetic()).count() as f64
})[0];

// Hamming distance (canonical Cryptopals test vector)
use rune_xor::hamming_distance;
assert_eq!(hamming_distance(b"this is a test", b"wokka wokka!!!"), 37);
```

### CLI

```bash
# Encrypt with a string key (output is raw bytes)
rune-xor file.bin -k "SECRET" > encrypted.bin

# Encrypt with a hex key
rune-xor file.bin --hex-key deadbeef > encrypted.bin

# Decrypt (XOR is its own inverse)
rune-xor encrypted.bin -k "SECRET" > decrypted.bin

# Pipe from stdin
cat file.bin | rune-xor - -k "KEY" > out.bin

# Brute-force a single-byte key
rune-xor mystery.bin --brute

# Crack an unknown repeating-key XOR cipher
rune-xor mystery.bin --break
```

## Output

**Single-byte brute-force (`--brute`)**

```
Key    Score      Plaintext (first 64 bytes)
--------------------------------------------------------------------------------
0x58   9.43       Cooking MC's like a pound of bacon
0x1a   -3.21      .....W53A.6./9".;#6"'.'.#/3"65;/9!.;/;
0x7b   -5.08      :<::>?< E?5q: "$?[J?^?Y?E< 5?:"[?: [?:
```

**Repeating-key cracker (`--break`)**

```
Key                            Score      Plaintext (first 64 bytes)
--------------------------------------------------------------------------------------------
4b4559 (KEY)                   12.34      the quick brown fox jumps over the lazy dog the q
31323334 (1234)                -2.11      ....s.../....5..t....s.../....5.
```

## License

MIT
