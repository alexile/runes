# rune-byte-magic

> Identify file types from magic bytes — pure Rust, no libmagic dependency.

[![crates.io](https://img.shields.io/crates/v/rune-byte-magic)](https://crates.io/crates/rune-byte-magic)
[![docs.rs](https://img.shields.io/docsrs/rune-byte-magic)](https://docs.rs/rune-byte-magic)
[![license](https://img.shields.io/crates/l/rune-byte-magic)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Inspects the first bytes of any file or byte slice and returns a `FileType`
describing the format — no system `file` binary, no libmagic C library, no
`/etc/magic` database required. Security researchers and SAST engines use it to
dispatch files to the correct scanner based on content rather than extension,
catching misnamed or extensionless binaries that extension-only logic misses.

Detects 35 formats: ELF, PE, Mach-O, DEX, WASM, Java class, ZIP, GZIP, Bzip2,
XZ, Zstd, LZ4, RAR, 7-Zip, TAR, PDF, OLE2, PNG, JPEG, GIF, BMP, TIFF, ICO,
WebP, MP3, Ogg, MP4, SQLite, shell scripts, and plain text.

Built for untrusted input: only the first 512 bytes (`SAMPLE_LEN`) are read,
truncated inputs are handled, and `identify` never panics. Short magics
(`BM`, `BZh`, `ID3`) are checked together with the bytes their formats fix,
so text such as "BMW" is not misread; `Text` means valid UTF-8 without binary
control bytes. Every signature is covered by a known-answer table and property
tests.

## Installation

```toml
[dependencies]
rune-byte-magic = "0.2"
```

The `rune-byte-magic` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-byte-magic --features cli
```

## Usage

### Library

```rust
use rune_byte_magic::{identify, FileType};

let header = std::fs::read("unknown_file").unwrap();
let ft = identify(&header);

if ft.is_executable() {
    println!("binary: {} ({})", ft.name(), ft.mime_type());
}
if ft.is_archive() {
    println!("archive — extract and re-scan contents");
}

// Pattern match for fine-grained dispatch
match identify(&header) {
    FileType::Elf  => { /* Linux ELF scanner */ }
    FileType::Pe   => { /* Windows PE scanner */ }
    FileType::Zip  => { /* extract and recurse */ }
    FileType::Pdf  => { /* PDF metadata scanner */ }
    FileType::Text | FileType::Script => { /* source-level scanner */ }
    _              => {}
}
```

### CLI

```bash
rune-byte-magic file.bin                  # identify one file
rune-byte-magic file1 file2 file3         # identify many files
cat file.bin | rune-byte-magic -          # read from stdin
```

## Output

```
$ rune-byte-magic /bin/ls /etc/passwd /tmp/archive.tar.gz
/bin/ls: ELF binary (application/x-elf)
/etc/passwd: plain text (text/plain)
/tmp/archive.tar.gz: gzip compressed (application/gzip)
```

## Supported formats

| Category | Formats |
|----------|---------|
| Executables | ELF, PE/COFF, Mach-O, Mach-O fat, DEX, WASM, Java class |
| Archives | ZIP, GZIP, Bzip2, XZ, Zstandard, LZ4, RAR, 7-Zip, TAR |
| Documents | PDF, OLE2 (legacy Office) |
| Images | PNG, JPEG, GIF, BMP, TIFF, ICO, WebP |
| Audio/Video | MP3 (ID3), Ogg, MPEG-4 |
| Database | SQLite |
| Script | Shebang (`#!`) scripts |
| Text | Printable ASCII / UTF-8 |

## License

MIT
