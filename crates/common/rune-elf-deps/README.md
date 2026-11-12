# rune-elf-deps

> Transitive shared-library dependency closure resolution for ELF binaries — pure-Rust ELF inspection via `rune-elf`, never executes the binaries it analyzes.

[![crates.io](https://img.shields.io/crates/v/rune-elf-deps)](https://crates.io/crates/rune-elf-deps)
[![docs.rs](https://img.shields.io/docsrs/rune-elf-deps)](https://docs.rs/rune-elf-deps)
[![license](https://img.shields.io/crates/l/rune-elf-deps)](LICENSE)

The same information `ldd` reports — every shared library a binary
transitively needs to run, plus the ELF interpreter (dynamic linker) and
glibc's NSS modules — computed without running `ldd` (whose own manual
page warns it can execute the target binary) or `readelf` (a safe
subprocess, but one per binary). ELF inspection is pure Rust via
[`rune-elf`](https://crates.io/crates/rune-elf); the one remaining
subprocess is `ldconfig -p`, a static read of glibc's own library cache.

Built for anyone assembling a minimal root filesystem, container image,
chroot, or sandbox that needs to bind in exactly the files a set of
binaries requires — nothing more.

## Usage

```rust,no_run
use rune_elf_deps::resolve_library_closure;
use std::path::PathBuf;

let closure = resolve_library_closure(&[PathBuf::from("/usr/bin/sh")]);
for path in closure {
    println!("{}", path.display());
}
```

## License

MIT
