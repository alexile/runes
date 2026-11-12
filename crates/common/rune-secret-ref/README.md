# rune-secret-ref

> Secret references (env, file, command) resolved into a redacting SecretValue

[![crates.io](https://img.shields.io/crates/v/rune-secret-ref)](https://crates.io/crates/rune-secret-ref)
[![docs.rs](https://img.shields.io/docsrs/rune-secret-ref)](https://docs.rs/rune-secret-ref)
[![license](https://img.shields.io/crates/l/rune-secret-ref)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

Configuration should never hold a credential inline, only a reference to
where it lives. `SecretRef` is that reference; resolving it yields a
`SecretValue` that prints as `<redacted>` everywhere (`Debug`, `Display`,
`Serialize`) and hands out the plain text only through `expose()`.

| Reference | Resolves to |
|---|---|
| `env:API_TOKEN` | the environment variable (looked up through a closure you pass; unset or empty is an error) |
| `file:/run/secrets/token` | the file's contents, one trailing newline stripped; relative paths join `ResolveOptions::base_dir`; on unix the file must not be readable by group or others |
| `cmd:pass show work/api` | the program's standard output, run without a shell, killed after a timeout; **off by default** (`with_allow_command(true)`) |
| `keychain:service/account`, `vault:path` | parsed here, resolved by a secret provider (`rune-secret-vault`) |

Any other text is rejected as an inline secret. No error message ever
contains secret material: parse errors do not echo the rejected text, and
resolution errors name the reference, never the value.

## Installation

```toml
[dependencies]
rune-secret-ref = { version = "0.1", features = ["serde"] }
```

Features (all off by default):

- `serde` — `Serialize`/`Deserialize` for `SecretRef` (string or one-key
  table form), redacting `Serialize` for `SecretValue`.
- `zeroize` — wipe secret buffers when they are dropped.

## Usage

```rust
use rune_secret_ref::{ResolveOptions, SecretRef};

let reference: SecretRef = "env:API_TOKEN".parse().unwrap();
let env = |name: &str| (name == "API_TOKEN").then(|| "tok-123".to_owned());
let token = reference.resolve(&ResolveOptions::default(), env).unwrap();

assert_eq!(token.expose(), "tok-123");
assert_eq!(format!("{token:?}"), "SecretValue(<redacted>)");
```

In a real program pass `|name| std::env::var(name).ok()`.

### With rune-config

With the `serde` feature a `SecretRef` field can be set from any
rune-config layer: a config file, an environment variable or a CLI flag.

```toml
[api]
token = "env:API_TOKEN"
# Table form, for arguments containing spaces:
fallback = { cmd = ["pass", "show", "work/api token"] }
```

```rust,ignore
#[derive(serde::Deserialize)]
struct Api {
    token: SecretRef,
    fallback: Option<SecretRef>,
}

let options = ResolveOptions::default().with_base_dir(config_dir);
let token = api.token.resolve(&options, |name| std::env::var(name).ok())?;
```

A pasted credential (`token = "sk-live-…"`) fails to load, attributed to
the layer and key, and the report does not repeat it.

### Command references

`cmd:` runs a program, which is code execution from configuration, so it
is refused unless `ResolveOptions::with_allow_command(true)` is set. Enable
it only for configuration the user owns, not for a project file from a
freshly cloned repository. The program runs without a shell, with standard
input closed and standard error inherited; it is killed after
`command_timeout` (10 s by default) and its output is capped at `max_len`
(64 KiB by default).

## License

MIT
