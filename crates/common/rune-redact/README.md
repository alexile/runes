# rune-redact

> Redact PII and secrets from text, streams, writers and tracing output with a configurable mask, hash or tokenize policy.

[![crates.io](https://img.shields.io/crates/v/rune-redact)](https://crates.io/crates/rune-redact)
[![docs.rs](https://img.shields.io/docsrs/rune-redact)](https://docs.rs/rune-redact)
[![license](https://img.shields.io/crates/l/rune-redact)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

`rune-redact` finds sensitive values in text and rewrites them: in a string, in a
stream of chunks, through a `std::io::Write` or `tokio::io::AsyncWrite` adapter, or
in `tracing` log output. It is meant as the last filter before logs, exports and
LLM calls leave the process.

Detection reuses the workspace's patterns rather than copying them:

- **Credentials**: the `rune-leak` ruleset (AWS, GitHub, Slack, Stripe, `password = "…"`, …),
  plus your own `SecretRule`s.
- **Tokens and PII**: `rune-regex-sec` for emails, IPv4/IPv6, JWTs and PEM private-key
  headers; local patterns for bearer tokens, credit cards, SSNs and US phone numbers.
- **Entropy**: `rune-entropy` flags any token above 4.5 bits/byte (API keys, random secrets).

A `Policy` picks the categories and how each is replaced:

| `Replacement` | Output                     | Use                                             |
|---------------|----------------------------|-------------------------------------------------|
| `Label`       | `[EMAIL]`                  | default                                         |
| `Mask`        | `***************1234`      | keep the last few characters for support staff  |
| `Hash`        | `[EMAIL:3f2a9c1b04d7e6a8]` | keyed HMAC-SHA256: correlate logs, no reversal  |
| `Tokenize`    | `[EMAIL_1]`                | same value, same token; restore an LLM's reply  |

## Installation

```toml
[dependencies]
rune-redact = "0.1"
# Optional: AsyncRedactingWriter, tracing-subscriber integration
# rune-redact = { version = "0.1", features = ["tokio", "tracing"] }
```

The `rune-redact` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-redact --features cli
```

## Usage

```rust
use rune_redact::redact;

let clean = redact("Email me at user@example.com or call 555-123-4567");
assert_eq!(clean, "Email me at [EMAIL] or call [PHONE]");
```

A policy, compiled once into a shareable `Redactor`:

```rust
use rune_redact::{Category, Policy, Redactor, Replacement};

let redactor = Redactor::new(
    Policy::default()
        .without_category(Category::Ipv4)
        .with_replacement(Replacement::Tokenize),
)?;
let prompt = redactor.redact("Write to amy@example.com about invoice 42");
assert_eq!(prompt, "Write to [EMAIL_1] about invoice 42");
// ... send `prompt` to the model, then:
assert_eq!(redactor.restore("Dear [EMAIL_1], ..."), "Dear amy@example.com, ...");
```

### Streams and writers

Values split across writes are still caught: the stream holds back a window
(1 KiB by default) and cuts at line boundaries or whitespace, never inside a match.

```rust
use std::io::Write;
use rune_redact::{RedactingWriter, Redactor};

let mut w = RedactingWriter::new(Vec::new(), Redactor::default());
w.write_all(b"key=AKIAIOSFOD")?;
w.write_all(b"NN7EXAMPLE\n")?;
assert_eq!(w.finish()?, b"key=[CREDENTIAL]\n");
```

`StreamRedactor` is the sans-I/O core (`push`, `push_bytes`, `finish`); with the
`tokio` feature, `AsyncRedactingWriter` wraps any `AsyncWrite`.

### Tracing

With the `tracing` feature:

```rust,ignore
use rune_redact::{RedactingFields, RedactingMakeWriter, Redactor};

// Redact whole log lines…
tracing_subscriber::fmt()
    .with_writer(RedactingMakeWriter::new(std::io::stderr, Redactor::default()))
    .init();

// …or only event and span fields.
tracing_subscriber::fmt()
    .fmt_fields(RedactingFields::new(Redactor::default()))
    .init();
```

## CLI

```bash
echo "Token: sk-abc123..." | rune-redact
rune-redact secrets.txt
tail -f app.log | rune-redact -
```

The CLI streams line by line, so it works on unbounded input.

## Categories

| Category       | Placeholder      | Source |
|----------------|------------------|--------|
| `BearerToken`  | `[BEARER]`       | `Bearer <token>` |
| `PrivateKey`   | `[PRIVATE_KEY]`  | `rune-regex-sec` |
| `Jwt`          | `[JWT]`          | `rune-regex-sec` |
| `Credential`   | `[CREDENTIAL]`   | `rune-leak` ruleset |
| `CreditCard`   | `[CC]`           | Visa / Mastercard / Amex / Discover |
| `Ssn`          | `[SSN]`          | `\d{3}-\d{2}-\d{4}` |
| `Email`        | `[EMAIL]`        | `rune-regex-sec` |
| `Ipv4`, `Ipv6` | `[IP]`           | `rune-regex-sec` |
| `Phone`        | `[PHONE]`        | US phone numbers |
| `HighEntropy`  | `[SECRET]`       | tokens ≥16 bytes above 4.5 bits/byte |

Where matches overlap, the category higher in this table wins.

## License

MIT
