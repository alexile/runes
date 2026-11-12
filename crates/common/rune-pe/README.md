# rune-pe

> Lightweight PE (Portable Executable) parser for Windows binaries.

[![crates.io](https://img.shields.io/crates/v/rune-pe)](https://crates.io/crates/rune-pe)
[![docs.rs](https://img.shields.io/docsrs/rune-pe)](https://docs.rs/rune-pe)
[![license](https://img.shields.io/crates/l/rune-pe)](LICENSE)

Parses `.exe`, `.dll`, and `.sys` files to extract headers, section
table, import and export tables, and Windows security hardening flags —
without any external C libraries or unsafe code.

- `parse` — parse a PE binary from a byte slice, returns `Pe`
- `Pe` — header, sections, imports, exports, security flags
- `PeHeader` — machine type, characteristics, PE32 vs PE32+, linker version
- `SecurityFlags` — ASLR, DEP/NX, CFG, SafeSEH, Force Integrity, High Entropy VA
- `Section` — name, virtual address, raw size, characteristics
- `Import` — DLL name and imported function names/ordinals
- `Export` — exported function names and ordinals

## Installation

```toml
[dependencies]
rune-pe = "0.1"
```

The `rune-pe` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-pe --features cli
```

## Usage

```rust,no_run
use rune_pe::parse;
use std::fs;

let bytes = fs::read("notepad.exe").unwrap();
let pe = parse(&bytes).unwrap();
println!("machine: {}", pe.header.machine);
println!("ASLR: {}", pe.security.aslr);
println!("DEP:  {}", pe.security.dep);
println!("CFG:  {}", pe.security.cfg);
for imp in &pe.imports {
    println!("  {} -> {} functions", imp.dll, imp.functions.len());
}
```

## CLI

```bash
# Header, sections and security hardening flags
rune-pe notepad.exe

# Also list imports, exports and suspicious (malware-indicator) imports
rune-pe --imports --exports --suspicious sample.dll

# Machine-readable JSON
rune-pe --json *.exe
```

## License

MIT
