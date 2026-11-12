# rune-dirs

> Per-app config, cache, data and state directories (XDG, macOS, Windows) from a caller-supplied environment

[![crates.io](https://img.shields.io/crates/v/rune-dirs)](https://crates.io/crates/rune-dirs)
[![docs.rs](https://img.shields.io/docsrs/rune-dirs)](https://docs.rs/rune-dirs)
[![license](https://img.shields.io/crates/l/rune-dirs)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

A thin, dependency-free resolver for the per-user directories an
application needs, namespaced by its name:

| Kind     | Linux / BSD (XDG)                                     | macOS                                        | Windows                      |
| -------- | ----------------------------------------------------- | -------------------------------------------- | ---------------------------- |
| `Config` | `$XDG_CONFIG_HOME/<app>`, else `~/.config/<app>`      | `~/Library/Application Support/<app>`        | `%APPDATA%\<app>\config`     |
| `Data`   | `$XDG_DATA_HOME/<app>`, else `~/.local/share/<app>`   | `~/Library/Application Support/<app>`        | `%APPDATA%\<app>\data`       |
| `State`  | `$XDG_STATE_HOME/<app>`, else `~/.local/state/<app>`  | `~/Library/Application Support/<app>/state`  | `%LOCALAPPDATA%\<app>\state` |
| `Cache`  | `$XDG_CACHE_HOME/<app>`, else `~/.cache/<app>`        | `~/Library/Caches/<app>`                     | `%LOCALAPPDATA%\<app>\cache` |

- Unset, empty or relative variables are ignored (per the XDG spec).
- A directory the environment cannot locate is an error only when you ask
  for it, and the error names the variables to set.
- `ensure` creates a directory on demand (mode `0700` on Unix).
- `with_dir` overrides one directory, e.g. from a `--cache-dir` flag.
- The library never reads the process environment: pass a lookup function.
  Every platform's layout can be computed on any host, so tests cover all
  three.

`rune-config` uses it for its default per-user config file.

## Installation

```toml
[dependencies]
rune-dirs = "0.1"
```

## Usage

```rust
use rune_dirs::{AppDirs, DirKind};

fn main() -> Result<(), rune_dirs::Error> {
    let dirs = AppDirs::new("myapp", |name| std::env::var(name).ok())?;

    let config_file = dirs.file(DirKind::Config, "myapp.toml")?;
    let cache = dirs.ensure(DirKind::Cache)?; // created if missing
    println!("config: {}, cache: {}", config_file.display(), cache.display());
    Ok(())
}
```

## License

MIT
