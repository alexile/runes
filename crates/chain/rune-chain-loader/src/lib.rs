//! Document loaders for the `rune-chain` RAG pipeline.
//!
//! A loader reads content from a source (file, directory, reader, string)
//! and produces [`Document`]s — the unit of input for `rune-chain-splitter`
//! and the broader retrieval-augmented generation (RAG) pipeline.
//!
//! # Loaders
//!
//! | Module / type | Input | One document per |
//! |---|---|---|
//! | [`text`] / [`TextLoader`] | UTF-8 file, reader, stdin | input |
//! | [`html`] | HTML file or string (scripts/styles dropped) | input |
//! | [`DirectoryLoader`] | directory tree, glob include/exclude | file |
//! | [`jsonl::JsonlLoader`] | JSON Lines, streamed | line |
//! | [`json::JsonLoader`] | JSON array/object, field selectors | record |
//! | [`csv::CsvLoader`] | CSV/TSV, streamed | row |
//!
//! Every document carries `source` (when the input has a name) and
//! `content_sha256`; record loaders add `line` / `row` / `record` and
//! `byte_start` / `byte_end`. The keys are constants in [`meta`].
//!
//! # Security
//!
//! Inputs are treated as untrusted. All [`Limits`] are on by default (file
//! size, record size, record count, files per walk, walk depth). File
//! loaders refuse FIFOs, sockets and devices without opening them, and can
//! be confined to a [`Jail`] root. Directory walks skip symlinks (or follow
//! them only within the root, each directory once), skip hidden entries, and
//! never recurse on the call stack. Parsers are linear-time and
//! property-tested not to panic on arbitrary input. There are no network
//! loaders in this crate.
//!
//! # Quick start
//!
//! ```rust
//! use rune_chain_loader::jsonl;
//!
//! let docs = jsonl::load_jsonl_str(
//!     r#"{"content":"hello","author":"alice"}
//!        {"content":"world","author":"bob"}"#
//! );
//! assert_eq!(docs.len(), 2);
//! assert_eq!(docs[0].metadata["author"], "alice");
//! assert_eq!(docs[0].metadata["line"], "1");
//! ```
//!
//! Files and directories:
//!
//! ```rust,no_run
//! use rune_chain_loader::{DirectoryLoader, Limits, text};
//!
//! let doc = text::load_file("README.md").unwrap();
//! println!("source: {}", doc.metadata["source"]);
//!
//! let docs = DirectoryLoader::new("docs/")
//!     .exclude_patterns(&["drafts/**"]).unwrap()
//!     .limits(Limits::default().with_max_files(500))
//!     .load()
//!     .unwrap();
//! println!("loaded {} documents", docs.len());
//! ```

/// The [`Document`] type produced by every loader.
pub mod document;
mod error;
mod glob;
pub mod html;
mod io;
mod jail;
pub mod json;
/// Loader for JSON Lines files.
pub mod jsonl;
mod limits;
pub mod meta;
#[cfg(test)]
mod tests;
/// Loader for plain-text files.
pub mod text;
mod walk;

pub mod csv;

pub use document::Document;
pub use error::LoadError;
pub use glob::Glob;
pub use jail::Jail;
pub use limits::Limits;
pub use text::TextLoader;
pub use walk::{DEFAULT_INCLUDE, DirectoryLoader, Walk, WalkEntry};
