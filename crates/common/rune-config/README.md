# rune-config

> Layered configuration (defaults, TOML, .env, environment, overrides) with per-key source tracking, a .env parser and env-to-struct deserialization

[![crates.io](https://img.shields.io/crates/v/rune-config)](https://crates.io/crates/rune-config)
[![docs.rs](https://img.shields.io/docsrs/rune-config)](https://docs.rs/rune-config)
[![license](https://img.shields.io/crates/l/rune-config)](LICENSE)

Three tools that work alone or together:

- **`Dotenv`**: a `.env` parser with line/column errors, line tracking per
  variable, opt-in `${VAR}` expansion and a writer that round-trips.
- **`EnvReader` / `from_env`**: environment variables straight into a
  `serde` struct, with a prefix, nested fields, lists and errors that name
  the variable.
- **`ConfigLoader`**: ordered layers (defaults < TOML files < `.env` < real
  environment < explicit overrides), merged deeply, with a report of the
  layer every final value came from.

Nothing here writes to the process environment unless you call the one
`unsafe` function that does.

## Installation

```toml
[dependencies]
rune-config = "0.2"
```

## Environment variables into a struct

```rust
use rune_config::EnvReader;
use serde::Deserialize;

#[derive(Deserialize)]
struct Config {
    debug: bool,
    db: Db,               // APP_DB__HOST, APP_DB__PORT
    #[serde(default)]
    origins: Vec<String>, // APP_ORIGINS=a,b  or  APP_ORIGINS=["a","b"]
    timeout_secs: Option<u64>,
}

#[derive(Deserialize)]
struct Db {
    host: String,
    port: u16,
}

let config: Config = EnvReader::new().prefix("APP_").from_env()?;
```

- Names are lower-cased and split on `__` (`separator` changes it).
- `case_insensitive(true)` matches the prefix and field names ignoring case,
  so `app_db__host` works and so do renamed fields like `maxConn`.
- Numbers, booleans (`true/false/1/0/yes/no/on/off`) and chars are parsed
  for the field type; `Option` is `None` when the variable is unset or
  empty; lists are comma-separated or JSON; a struct may also be one JSON
  object; enums take a variant name.
- Errors name the variable: `environment variable APP_DB__PORT: expected
  u16, got `high``, and a missing field names the variable that would set
  it: `environment variable APP_DB__HOST: not set (required by `db.host`)`.
- `from_vars` takes any `(name, value)` pairs (a test map, a `.env` file,
  several sources chained) instead of the process environment.

## `.env` files

```rust
use rune_config::{Dotenv, DotenvOptions};

let env = DotenvOptions::new()
    .expand(true)                          // ${VAR}, ${VAR:-default}, $VAR
    .expansion_env(std::env::vars())       // looked up before the file's own keys
    .reject_world_writable(true)           // Unix only
    .max_size(64 * 1024)                   // default 1 MiB
    .read(".env")?;

let host = env.get("DB_HOST");
let line = env.entry("DB_HOST").map(|e| e.line);
```

Supported syntax:

| Form | Example | Value |
| --- | --- | --- |
| plain, trimmed | `A = some value ` | `some value` |
| `export` prefix | `export A=1` | `1` |
| comment lines and inline comments | `A=1 # note` | `1` |
| `#` without whitespace before it | `URL=http://x/#top` | `http://x/#top` |
| single quotes, literal | `A='$X \n'` | `$X \n` |
| double quotes, escapes `\n \r \t \" \\ \$` | `A="a\nb"` | a, newline, b |
| multiline quoted | `KEY="-----BEGIN...\n...END-----"` | spans lines |
| expansion (opt-in) | `URL=http://${HOST:-localhost}` | expanded |

Command substitution (`$(...)`, backticks) is never run; it stays literal
text. Keys are `[A-Za-z_][A-Za-z0-9_.]*`. Errors carry the path, line and
column: `.env:2:7: expected `=` after the variable name`.

`format_dotenv` and `Dotenv::to_dotenv_string` write `.env` text that
parses back to the same pairs.

### The process environment

`Dotenv` never touches the process environment. If a program really needs
the values there (for a child process or a library that only reads
`std::env`), call:

```rust
// SAFETY: first thing in main, before any thread is spawned.
unsafe { env.load_into_process_env(false)? };
```

It is `unsafe` because `std::env::set_var` is: since Rust 2024 it is
undefined behaviour on most platforms if another thread reads or writes the
environment at the same time, and libc reads it behind your back (DNS,
time zones). Existing variables are kept unless `overwrite` is `true`.
Passing values explicitly, as the rest of this crate does, avoids the
problem entirely.

## Layered loading

```rust
use rune_config::{
    default_user_config_path, CliOverrides, ConfigLoader, DotenvOptions, EnvMapping, ValueKind,
};

let env = EnvMapping::new()
    .prefix("MYAPP_")                      // MYAPP_DB__HOST -> db.host
    .ignore("MYAPP_CONFIG")
    .var_as("MYAPP_NAME", "name", ValueKind::String);

let loaded = ConfigLoader::new()
    .with_defaults_from(&Config::default())
    .with_user_file(default_user_config_path("myapp", "myapp.toml", |k| std::env::var(k).ok()))
    .with_project_file("myapp.toml", false)
    .with_dotenv_file(".env", false, &env, &DotenvOptions::new())
    .with_process_env(&env)
    .with_cli(&CliOverrides::new().set_opt("--port", "port", port_flag))
    .load()?;

let config: Config = loaded.deserialize()?;
eprint!("{}", loaded.report());
```

The report lists every final value and its layer, hiding the values of
secret-looking keys (`password`, `token`, `secret`, `api_key`, `dsn`, ...;
see `is_secret_key`):

```text
db.host = "localhost"  # built-in default
db.password = <redacted>  # MYAPP_DB__PASSWORD in .env:4
port = 8080  # command-line flag --port
```

`Debug` for `LoadedConfig`, `Dotenv` and `DotenvEntry` uses the same
redaction, and type errors for secret keys leave the value out. Every
problem comes back as a `ConfigIssue` naming the layer and the key, all of
them at once:

```text
invalid configuration (2 problems):
  - project file ./myapp.toml: TOML syntax error at line 3, column 9: invalid string
  - environment variable MYAPP_PORT: `port`: expected an integer, got `fast`
```

Values from `EnvMapping::prefix` are typed by guessing (`ValueKind::Auto`);
map a variable explicitly with `var_as` when a string field may look like
a number, or use `ValueKind::Json` for lists and tables.

Files are read only in `load`, and each is refused above 1 MiB
(`ConfigLoader::max_file_size`, `DotenvOptions::max_size`).

## Compared with other crates

As of this release:

| | rune-config | dotenvy 0.15 | envy 0.4 | figment 0.10 |
| --- | --- | --- | --- | --- |
| `.env` parsing | yes | yes | no | no |
| Variable substitution in `.env` | opt-in | always | n/a | n/a |
| Load `.env` without changing the process env | yes (default) | yes (iterator API) | n/a | n/a |
| Env into a `serde` struct | yes | no | yes | yes (`Env` provider) |
| Nested structs from env | yes (`__`) | n/a | no | yes (`split`) |
| Lists from env | comma or JSON | n/a | comma | provider syntax |
| Layering and per-value source | yes | no | no | yes (metadata) |
| File formats | TOML, `.env` | `.env` | none | TOML, JSON, YAML (features) |
| Profiles | no | no | no | yes |
| Last release | current | 2023-03 | 2021-01 | 2024-05 |

- **dotenvy** is the most widely used `.env` loader and its default
  functions load straight into the process environment, which suits
  programs that call it at the very start of `main`. rune-config returns
  values instead and keeps the environment write behind an `unsafe` call.
- **envy** is a small, focused env-to-struct deserializer with flat field
  mapping. `EnvReader` covers the same ground and adds nesting, JSON values
  and errors that name variables.
- **figment** is a general provider framework with profiles, many formats
  and rich metadata. rune-config is narrower (TOML and `.env` only, no
  profiles) and has fewer dependencies.

## Migrating from 0.1

- File layers are now refused above 1 MiB. Raise the limit with
  `ConfigLoader::max_file_size` if you load bigger TOML files.
- `Debug` for `LoadedConfig` now prints the redacted per-key view (values,
  sources) instead of the raw table; use `table()` for the raw values.
- `Source` has two new variants, `Dotenv` and `DotenvVar`; `match`es need a
  wildcard arm (the enum was already `#[non_exhaustive]`).
- Type-error messages for secret-looking keys no longer include the value.
- The crate no longer forbids `unsafe` code: `Dotenv::load_into_process_env`
  wraps `std::env::set_var` and is itself `unsafe`.

## License

MIT
