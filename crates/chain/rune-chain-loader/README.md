# rune-chain-loader

> Hardened document loaders for rune-chain RAG: text, HTML, JSON, JSON Lines, CSV and jailed directory walks with limits.

[![crates.io](https://img.shields.io/crates/v/rune-chain-loader)](https://crates.io/crates/rune-chain-loader)
[![docs.rs](https://img.shields.io/docsrs/rune-chain-loader)](https://docs.rs/rune-chain-loader)
[![license](https://img.shields.io/crates/l/rune-chain-loader)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

`rune-chain-loader` reads content from files, directories, readers or strings and produces `Document`s — the unit of input for the `rune-chain` RAG pipeline. Documents carry their text plus string metadata and feed directly into `rune-chain-splitter` and `rune-chain-embed`.

| Loader | Input | One document per |
|---|---|---|
| `text::TextLoader`, `text::load_file`, `text::load_stdin` | UTF-8 file / reader / stdin | input |
| `html::load_file`, `html::html_to_text` | HTML (scripts, styles, comments dropped) | input |
| `DirectoryLoader` | directory tree with glob include/exclude | file |
| `jsonl::JsonlLoader` | JSON Lines, streamed | line |
| `json::JsonLoader` | JSON array/object, field selectors | record |
| `csv::CsvLoader` | CSV / TSV, streamed | row |

Every document carries `source` (when the input has a name) and `content_sha256`. Record loaders add `line` / `row` / `record` and `byte_start` / `byte_end`, so a retrieved chunk can be traced to the exact bytes it came from. Directory walks add `relative_path`, HTML adds `title`. The key names are constants in `rune_chain_loader::meta`.

Dependencies: `serde_json` and `rune-sha256`. No network code.

## Installation

```toml
[dependencies]
rune-chain-loader = "0.2"
```

## Usage

```rust,no_run
use rune_chain_loader::{DirectoryLoader, Jail, Limits, TextLoader, text, jsonl, json, csv};

// One file, with default limits (16 MiB max).
let doc = text::load_file("README.md")?;
println!("{} ({})", doc.metadata["source"], doc.metadata["content_sha256"]);

// Untrusted paths: confine them to a root.
let loader = TextLoader::new().jail(Jail::new("uploads/")?);
let doc = loader.load_file("user/notes.txt")?; // "../../etc/passwd" -> LoadError::OutsideRoot

// A documentation tree: Markdown and HTML, minus drafts, lazily.
let walk = DirectoryLoader::new("docs/")
    .include_patterns(&["*.md", "*.html"])?
    .exclude_patterns(&["drafts/**", "node_modules"])?
    .limits(Limits::default().with_max_files(5_000).with_max_depth(8));
for doc in walk.documents()? {
    let doc = doc?; // per-file errors (too large, not UTF-8) surface here
    println!("{}", doc.metadata["relative_path"]);
}

// JSON Lines with a field selector, streamed from disk.
let loader = jsonl::JsonlLoader::new()
    .fields(json::Fields::new().content("/body/text")?.metadata_only(&["id", "lang"])?)
    .strict(true);
for doc in loader.iter_file("corpus.jsonl")? {
    let doc = doc?;
    println!("line {}: {}", doc.metadata["line"], doc.content);
}

// CSV rows as documents.
let rows = csv::CsvLoader::new()
    .content_columns(&["question", "answer"])
    .metadata_columns(&["id"])
    .load_file("faq.csv")?;
# Ok::<(), rune_chain_loader::LoadError>(())
```

## Security

Loaders assume their input is hostile.

- **Limits on by default** (`Limits::DEFAULT`): 16 MiB per file, 1 MiB per JSON line / CSV row, 1,000,000 records per input, 10,000 files and depth 32 per directory walk. An over-long line is skipped without being buffered; an unterminated CSV quote stops at the row cap.
- **Jail**: `Jail::new(root)` canonicalises paths (resolving `..` and symlinks) and rejects anything outside the root. The check is path based, so it cannot stop an attacker who can swap directories for symlinks concurrently; use OS sandboxing for that.
- **Directory walks** never leave the root: symlinks are skipped unless `follow_symlinks(true)`, and then followed only to targets inside the root, each directory once (loops terminate). Hidden entries (`.git`, `.env`) are skipped by default. The walk uses an explicit stack, not recursion.
- **Special files** (FIFOs, sockets, devices) are refused or skipped before they are opened.
- **Parsers** are linear-time and property-tested against arbitrary input: HTML-to-text is a single scan without recursion, globs match in `O(pattern × path)` without backtracking, CSV is a byte-level state machine, and JSON nesting is capped at 128 levels by `serde_json`.
- **Loader metadata cannot be spoofed** by a record: `line`, `byte_*`, `record`, `row` and `content_sha256` always overwrite record fields. (`source` from a record still wins over the file path, as in 0.1.)
- There are **no URL / web loaders** in this crate; fetch remotely with a hardened client and pass the body to `html::load_str` or a loader's `iter`.

## Migrating from 0.1

0.2 is a breaking release:

- **Errors**: fallible functions return `Result<_, LoadError>` instead of `io::Result`. `LoadError` converts into `io::Error` (`?` in an `io::Result` function still works; `io::Error::from(e).kind()` keeps `NotFound` / `InvalidData`).
- **Limits on by default**: files over 16 MiB are `LoadError::TooLarge`; JSON lines over 1 MiB are skipped by `load_jsonl_str` / `load_jsonl_file`. Use the loader types with `Limits::unlimited()` for the old behaviour on trusted input.
- **New metadata**: every document gets `content_sha256`; JSONL documents also get `line`, `byte_start` and `byte_end`. Code that compares whole metadata maps must account for them.
- **`text::load_dir`** now skips symlinks, hidden files and special files (0.1 followed symlinks and read hidden `.txt` files). Use `DirectoryLoader` with `follow_symlinks(true)` / `hidden(true)` to opt back in.
- **`text::load_file`** strips a UTF-8 byte-order mark and refuses non-regular files (`LoadError::NotRegularFile`) instead of blocking on a FIFO.
- `load_jsonl_str` stops after 1,000,000 documents.

## License

MIT
