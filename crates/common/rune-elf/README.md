# rune-elf

> Lightweight ELF binary parser — pure Rust, no unsafe, no external dependencies.

[![crates.io](https://img.shields.io/crates/v/rune-elf)](https://crates.io/crates/rune-elf)
[![docs.rs](https://img.shields.io/docsrs/rune-elf)](https://docs.rs/rune-elf)
[![license](https://img.shields.io/crates/l/rune-elf)](LICENSE)

Parses Linux/BSD ELF executables and shared libraries to extract header
fields, section and segment tables, dynamic symbol imports, `DT_NEEDED`
shared-library names, the `PT_INTERP` dynamic-linker path, and hardening
flags relevant to security analysis (PIE, NX stack, RELRO, stack canary,
FORTIFY_SOURCE, stripped).

## Installation

```toml
[dependencies]
rune-elf = "0.3"
```

The `rune-elf` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-elf --features cli
```

## Usage

```rust,no_run
use rune_elf::parse;
use std::fs;

let bytes = fs::read("/bin/ls").unwrap();
let elf = parse(&bytes).unwrap();
println!("machine:     {}", elf.header.machine);
println!("interpreter: {:?}", elf.interpreter);
println!("needed:      {:?}", elf.needed_libs);
println!("PIE:         {}", elf.security.pie);
println!("NX stack:    {}", elf.security.nx_stack);
println!("RELRO:       {}", elf.security.relro);
println!("canary:      {}", elf.security.stack_canary);
```

## CLI

```bash
rune-elf /bin/ls
rune-elf --json firmware.elf
```

## License

MIT
