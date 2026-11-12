# rune-config

> Layered TOML configuration (defaults, files, environment, CLI) with per-key source tracking

[![crates.io](https://img.shields.io/crates/v/rune-config)](https://crates.io/crates/rune-config)
[![docs.rs](https://img.shields.io/docsrs/rune-config)](https://docs.rs/rune-config)
[![license](https://img.shields.io/crates/l/rune-config)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

One loader for the usual stack of configuration layers:

1. built-in defaults (a `Default` value of your config struct, or TOML),
2. the per-user file (`~/.config/<app>/<file>` and platform equivalents),
3. the project file (`./app.toml`, or `--config <path>`),
4. environment variables (explicit mappings and/or a prefix),
5. command-line flags (typed values or `--set key=value`).

Each layer overrides the ones before it. Tables merge deeply, other values
replace. Every leaf remembers the layer that set it, and every problem comes
back as a `ConfigIssue` naming the **layer** and the **key**:

```text
invalid configuration (2 problems):
  - project file ./app.toml: TOML syntax error at line 3, column 9: invalid string
  - environment variable APP_RPS: `scan.rate_limit`: expected an integer, got `fast`
```

Type errors found when deserializing the merged result into your struct are
attributed the same way, to the layer that set the offending key.

The library does no hidden I/O: it never reads the process environment (you
pass the variables in), and it reads files only for the file layers you add.

## Installation

```toml
[dependencies]
rune-config = "0.1"
```

## Usage

```rust
use rune_config::{
    default_user_config_path, CliOverrides, ConfigLoader, EnvMapping, ValueKind,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Config {
    #[serde(default)]
    log_level: String,
    #[serde(default)]
    rate_limit: u32,
}

fn load(config_flag: Option<&str>, rps_flag: Option<u32>, sets: &[String])
    -> Result<Config, rune_config::ConfigErrors>
{
    let user_file = default_user_config_path("myapp", "myapp.toml", |k| std::env::var(k).ok());
    let env = EnvMapping::new()
        .prefix("MYAPP_")                // MYAPP_LOG_LEVEL -> log_level
        .ignore("MYAPP_CONFIG")
        .var_as("MYAPP_RPS", "rate_limit", ValueKind::Integer);
    let mut cli = CliOverrides::new().set_opt("--rps", "rate_limit", rps_flag);
    for set in sets {
        cli = cli.assign("--set", set); // --set log_level=debug
    }

    let mut loader = ConfigLoader::new()
        .with_defaults_from(&Config::default())
        .with_user_file(user_file);
    loader = match config_flag {
        Some(path) => loader.with_project_file(path, true),
        None => loader.with_project_file("myapp.toml", false),
    };
    let loaded = loader.with_env(std::env::vars(), &env).with_cli(&cli).load()?;

    // Where did a value come from?
    if let Some(source) = loaded.source_of("rate_limit") {
        eprintln!("rate_limit set by {source}");
    }
    loaded.deserialize()
}
```

### Environment variables

- `EnvMapping::var(name, key)` / `var_as(name, key, kind)` map one variable
  to one dotted key, with an explicit `ValueKind` (`String`, `Integer`,
  `Float`, `Boolean`, `StringList`) or `Auto` (guess).
- `EnvMapping::prefix("APP_")` maps `APP_SCAN__RATE_LIMIT` to
  `scan.rate_limit` (lower-cased, `__` between segments).

### Keys

Dotted keys follow TOML: bare segments (`A-Z a-z 0-9 - _`) or quoted ones
(`servers."eu.west".host`). `parse_key` and `format_key` convert between the
text and segment forms.

## License

MIT
