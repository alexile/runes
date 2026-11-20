# rune-jwt

> Decode and inspect JWT claims without signature verification.

[![crates.io](https://img.shields.io/crates/v/rune-jwt)](https://crates.io/crates/rune-jwt)
[![docs.rs](https://img.shields.io/docsrs/rune-jwt)](https://docs.rs/rune-jwt)
[![license](https://img.shields.io/crates/l/rune-jwt)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Splits and base64url-decodes a compact JWT ([RFC 7519], [RFC 7515]) —
header, payload, and signature — without verifying anything. Designed for
debugging, CTF challenges, and security research where you need to see what a
token contains.

> **Warning**: this crate does NOT verify signatures, `alg`, `exp` or any
> other claim. A token that decodes may be forged or signed with
> `alg: none`. Never use it to grant access based on token contents.

- Built for untrusted input: every function returns an error instead of
  panicking, memory is linear in the token length, and JSON nesting is
  bounded.
- Strict structure: exactly three sections (JWE is rejected), base64url
  alphabet only (correct trailing `=` padding tolerated, non-zero trailing
  bits rejected), header and claims must be JSON objects.
- `decode_raw` returns the raw bytes of all three sections, for a JWS whose
  payload is not JSON (e.g. the [RFC 8037] Ed25519 example).
- Tested against the RFC 7515, RFC 7519 and RFC 8037 example tokens, with
  property tests.

[RFC 7515]: https://www.rfc-editor.org/rfc/rfc7515
[RFC 7519]: https://www.rfc-editor.org/rfc/rfc7519
[RFC 8037]: https://www.rfc-editor.org/rfc/rfc8037

## Installation

```toml
[dependencies]
rune-jwt = "0.2"
```

The `rune-jwt` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-jwt --features cli
```

## Usage

```rust
use rune_jwt::{algorithm, claims, subject};

fn main() -> Result<(), rune_jwt::JwtError> {
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                 eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.\
                 sig";

    assert_eq!(algorithm(token)?, "HS256");
    assert_eq!(subject(token)?.as_deref(), Some("1234567890"));
    assert_eq!(claims(token)?["name"], "John Doe");
    Ok(())
}
```

## CLI

```bash
rune-jwt eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig
```

## Output

```
=== Header ===
{
  "alg": "HS256",
  "typ": "JWT"
}

=== Payload ===
{
  "sub": "1234567890"
}

=== Signature ===
sig
```

## License

MIT
