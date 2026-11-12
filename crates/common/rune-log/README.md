# rune-log

> Structured tracing logging layer (text or JSON) with field-level secret and PII redaction, configured from env-style values

[![crates.io](https://img.shields.io/crates/v/rune-log)](https://crates.io/crates/rune-log)
[![docs.rs](https://img.shields.io/docsrs/rune-log)](https://docs.rs/rune-log)
[![license](https://img.shields.io/crates/l/rune-log)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

One `tracing-subscriber` layer that filters by level, writes full text,
compact text or JSON lines, and runs every logged value through a
[`rune-redact`](../rune-redact) `Redactor` first, so credentials, tokens,
emails, IPs, card numbers and the like never reach the log sink.

- **Text** formats reuse `rune-redact`'s tracing integration: field-level
  (`RedactingFields`, default) or whole-line (`RedactingMakeWriter`).
- **JSON** redacts each value before escaping it, so lines are always valid
  JSON. Integers that look like card numbers or SSNs become redacted
  strings; ordinary numbers stay numbers.
- **Configuration** comes from builder methods or env-style values
  (`RUST_LOG`, `LOG_FORMAT`, `LOG_REDACT`, or `EnvKeys::with_prefix("APP")`).
  The library never reads the environment: you pass a lookup.

It is just the logging layer; compose it with metrics or trace-export layers
on the same `Registry`.

## Installation

```bash
cargo add rune-log
```

## Usage

```rust,no_run
use rune_log::LogConfig;

fn main() -> Result<(), rune_log::Error> {
    // RUST_LOG=warn,my_app=debug LOG_FORMAT=json LOG_REDACT=fields
    LogConfig::default()
        .with_env(|k| std::env::var(k).ok())?
        .try_init(std::io::stderr)?;

    tracing::info!(user = "bob@example.com", "login from 10.0.0.7");
    // {"timestamp":"…","level":"INFO","target":"my_app",
    //  "fields":{"message":"login from [IP]","user":"[EMAIL]"}}
    Ok(())
}
```

Composing with other layers and a custom policy:

```rust,no_run
use rune_log::{LogConfig, LogFormat, Policy, Redactor, Replacement};
use tracing_subscriber::layer::SubscriberExt;

let redactor = Redactor::new(Policy::default().with_replacement(Replacement::Tokenize))?;
let logs = LogConfig::default()
    .with_format(LogFormat::Json)
    .with_filter("info,hyper=warn")?
    .with_redactor(redactor)
    .layer(std::io::stdout);

let subscriber = tracing_subscriber::registry().with(logs) /* .with(metrics_layer) */;
tracing::subscriber::set_global_default(subscriber).ok();
# Ok::<(), Box<dyn std::error::Error>>(())
```

| Variable     | Values                                   | Default |
|--------------|------------------------------------------|---------|
| `RUST_LOG`   | `level` and/or `target=level`, comma-separated | `info` |
| `LOG_FORMAT` | `full` (`text`), `compact`, `json`       | `full`  |
| `LOG_REDACT` | `fields`, `line` (text formats only)     | `fields`|

## License

MIT
