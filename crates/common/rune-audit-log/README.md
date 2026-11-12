# rune-audit-log

> Append-only, hash-chained (optionally HMAC-signed) tamper-evident audit log with pluggable storage

[![crates.io](https://img.shields.io/crates/v/rune-audit-log)](https://crates.io/crates/rune-audit-log)
[![docs.rs](https://img.shields.io/docsrs/rune-audit-log)](https://docs.rs/rune-audit-log)
[![license](https://img.shields.io/crates/l/rune-audit-log)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

Records who did what to which target, and when. Each record carries its
sequence number, the hash of the record before it and a SHA-256 hash over
its own contents, so editing, inserting, reordering or deleting any record
breaks verification at that record.

- **Sans-I/O core.** `Chain` seals entries into records; `Verifier` checks
  a stream of records in constant memory.
- **Pluggable storage.** `MemoryStore`, `FileStore` (JSON lines, append
  mode, `0600`, optional `fsync`, bounded line length), or implement
  `Store` for your own backend.
- **Optional signing.** `HmacSha256` built in; implement `Signer` for
  Ed25519, an HSM or a KMS. A signature stops someone who can rewrite the
  whole file from re-chaining it.
- **Checkpoints.** A chain cannot show that its newest records were
  deleted. Save `head()` elsewhere and check with `verify_against`.
- **Export.** `export_jsonl` writes the log; `JsonlReader` streams it back
  for verification.

## Installation

```toml
[dependencies]
rune-audit-log = "0.1"
```

## Usage

```rust
use rune_audit_log::{AuditLog, Entry, FileStore, HmacSha256};

fn main() -> Result<(), rune_audit_log::Error> {
    let store = FileStore::open("/var/lib/myapp/audit.jsonl")?.with_sync(true);
    let mut log = AuditLog::open(store)?.with_signer(HmacSha256::new(b"key from your secret store"));

    log.append(
        Entry::new("alice", "policy.update")
            .with_target("sandbox")
            .with_field("ip", "10.0.0.7"),
    )?;

    let verified = log.verify()?;
    println!("{} records, head {}", verified.count, verified.head);
    Ok(())
}
```

A stored line looks like:

```json
{"seq":0,"ts":1700000000000,"actor":"alice","action":"policy.update","target":"sandbox","fields":{"ip":"10.0.0.7"},"prev":"0000…","hash":"9f2c…","sig":"41ab…"}
```

## License

MIT
