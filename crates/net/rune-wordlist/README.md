# rune-wordlist

[![crates.io](https://img.shields.io/crates/v/rune-wordlist)](https://crates.io/crates/rune-wordlist)
[![docs.rs](https://img.shields.io/docsrs/rune-wordlist)](https://docs.rs/rune-wordlist)
[![license](https://img.shields.io/crates/l/rune-wordlist)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

Versioned, Ed25519-signed wordlist and payload packs, loaded with streaming,
tamper-checked iteration and rollback-safe updates.

A **pack** is a directory of list files (one entry per line), a TOML manifest
`pack.toml` that pins each file's SHA-256 and size, and `pack.toml.sig`, a
detached [Ed25519 (RFC 8032)](https://www.rfc-editor.org/rfc/rfc8032)
signature over the manifest:

```text
web-discovery/
├── pack.toml          format, name, version, key-id, [[lists]] with sha256 + size
├── pack.toml.sig      ed25519:<128 hex digits>
├── lists/dirs.txt
└── payloads/xss.txt
```

- **Signed.** The signature is checked against a caller-supplied `Keyring`
  *before* the manifest is parsed; the manifest's `key-id` must name the key
  that signed it. Signatures are domain-separated and verified strictly.
- **Tamper-checked.** `Verify::Eager` (default) hashes every list when the pack
  is opened; every reader hashes again as it streams and fails on extra bytes
  at once and on a hash or size mismatch at the end, so a file swapped after
  opening is still caught.
- **Streaming.** Lists are read line by line through one fixed buffer; a
  64 MiB list streams with flat memory. Lines longer than a limit are an
  error, not an unbounded allocation.
- **Safe updates.** `Store::install` verifies the candidate, refuses to roll
  back to an older (validly signed) version, copies only the files the
  manifest names into staging, re-verifies the copy and switches `CURRENT`
  atomically. Fetching candidates is left to the caller.

## Installation

```sh
cargo add rune-wordlist
cargo install rune-wordlist --features cli
```

## Library usage

```rust
use rune_wordlist::{Keyring, ListKind, Options, Pack, PackBuilder, SecretKey, Version};

let dir = tempfile::tempdir()?;
std::fs::write(dir.path().join("dirs.txt"), "admin\nbackup\n.git\n")?;

// Author: hash the lists and sign the manifest.
let key = SecretKey::from_seed(&[7; 32]); // use a random seed in practice
PackBuilder::new("web", Version::new(1, 0, 0))?
    .list("dirs", "dirs.txt", ListKind::Wordlist)?
    .write(dir.path(), &key)?;

// Consumer: trust only the author's public key, then stream.
let keyring = Keyring::new().with_key(key.public_key());
let pack = Pack::open(dir.path(), &keyring, &Options::default())?;
let mut reader = pack.list("dirs")?;
let mut line = Vec::new();
while reader.read_entry(&mut line)? {
    // use `line` (bytes, without the line ending)
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

Updates go through a `Store`:

```rust,no_run
use rune_wordlist::{InstallOptions, Keyring, Options, PublicKey, Store};

let keyring = Keyring::new().with_key(PublicKey::from_hex("2152f8d1…")?);
let store = Store::new("/var/lib/myapp/packs");
let outcome = store.install("downloads/web-discovery", &keyring, &InstallOptions::default())?;
let pack = store.open("web-discovery", &keyring, &Options::default())?;
# Ok::<(), rune_wordlist::Error>(())
```

## CLI usage

```sh
rune-wordlist keygen --out signing.key            # prints the public key
rune-wordlist build packs/web --key signing.key --name web --version 1.0.0 \
    --list dirs=lists/dirs.txt --payload xss=payloads/xss.txt
rune-wordlist verify packs/web --pubkey <hex>
rune-wordlist cat packs/web dirs --pubkey <hex> | head
rune-wordlist install packs/web --store ~/.local/share/packs --pubkey <hex>
```

## Manifest format

```toml
format = 1
name = "web"                # [a-z0-9._-], 1-64 chars
version = "1.0.0"           # MAJOR.MINOR.PATCH; updates must increase it
key-id = "3097e2dee2cb4a34" # first 8 bytes of SHA-256(public key)
description = "optional"

[[lists]]
name = "dirs"
path = "lists/dirs.txt"     # relative, '/'-separated, no '..'
kind = "wordlist"           # or "payload"
sha256 = "5a9fe33b…"
size = 83
entries = 6                 # optional line count
```

The signed message is `"rune-wordlist/v1 manifest\n"` followed by the exact
bytes of `pack.toml`.
