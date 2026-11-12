# rune-which

> Cross-platform executable lookup on PATH or in given directories, honouring PATHEXT

[![crates.io](https://img.shields.io/crates/v/rune-which)](https://crates.io/crates/rune-which)
[![docs.rs](https://img.shields.io/docsrs/rune-which)](https://docs.rs/rune-which)
[![license](https://img.shields.io/crates/l/rune-which)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

A small `which`: find an executable by name on `PATH`, or in directories
you supply, and get its absolute path back.

- Directories are searched in order; the first match wins (`find_all`
  returns every match).
- On Windows, `PATHEXT` extensions are appended (`tool` → `tool.EXE`),
  compared case-insensitively. Extensions can be set on any platform.
- On Unix, a match must be a regular file with an execute bit.
- Names containing a path separator (`./tool`) are checked as given, not
  searched.
- Relative `PATH` entries (including the empty entry, meaning ".") are
  skipped unless you supply a working directory, which avoids `PATH=.`
  hijacks.

The library never reads the process environment: you pass a lookup
function (`|name| std::env::var(name).ok()` in a program, a map in tests).

## Installation

```toml
[dependencies]
rune-which = "0.1"
```

The `rune-which` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-which --features cli
```

## Usage

### Library

```rust
use rune_which::{which, Finder};

// The usual lookup on the real PATH (and PATHEXT on Windows).
let cargo = which("cargo", |name| std::env::var(name).ok());

// Explicit directories first, then PATH; honour relative entries.
let finder = Finder::from_env(|name| std::env::var(name).ok())
    .with_dirs(["/opt/tools/bin"])
    .with_cwd(std::env::current_dir().unwrap());
let all_pythons = finder.find_all("python3");
```

### CLI

```bash
rune-which cargo
# /home/ada/.cargo/bin/cargo

rune-which --all python3
# /usr/local/bin/python3
# /usr/bin/python3

rune-which --no-path --dir ./bin tool
# rune-which: no tool found   (exit status 1)
```

## License

MIT
