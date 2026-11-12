use std::io::{self, Read};
use std::path::Path;

use crate::document::Document;
use crate::error::LoadError;
use crate::io::{read_file, read_limited, utf8};
use crate::jail::Jail;
use crate::limits::Limits;
use crate::meta;
use crate::walk::DirectoryLoader;

/// Loads plain-text files and readers as single [`Document`]s.
///
/// The content must be UTF-8 (a leading byte-order mark is dropped). Every
/// document gets [`meta::SOURCE`] and [`meta::CONTENT_SHA256`].
///
/// # Example
///
/// ```rust
/// use rune_chain_loader::{Jail, Limits, LoadError, text::TextLoader};
///
/// let dir = tempfile::tempdir().unwrap();
/// std::fs::write(dir.path().join("notes.txt"), "hello").unwrap();
///
/// let loader = TextLoader::new()
///     .limits(Limits::default().with_max_file_bytes(1024))
///     .jail(Jail::new(dir.path()).unwrap());
/// let doc = loader.load_file("notes.txt").unwrap();
/// assert_eq!(doc.content, "hello");
/// assert!(matches!(loader.load_file("../x"), Err(LoadError::OutsideRoot { .. } | LoadError::Io { .. })));
/// ```
#[derive(Debug, Clone, Default)]
pub struct TextLoader {
    limits: Limits,
    jail: Option<Jail>,
}

impl TextLoader {
    /// A loader with default [`Limits`] and no jail.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the limits (only [`Limits::max_file_bytes`] applies here).
    #[must_use]
    pub const fn limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Confine file paths to a [`Jail`]; relative paths resolve from its root.
    #[must_use]
    pub fn jail(mut self, jail: Jail) -> Self {
        self.jail = Some(jail);
        self
    }

    /// Load one regular file. FIFOs, devices and directories are refused with
    /// [`LoadError::NotRegularFile`]; files over the size limit with
    /// [`LoadError::TooLarge`].
    pub fn load_file(&self, path: impl AsRef<Path>) -> Result<Document, LoadError> {
        let path = path.as_ref();
        let bytes = read_file(path, self.jail.as_ref(), self.limits.max_file_bytes)?;
        let mut doc = Document::new(utf8(bytes, Some(path))?)
            .with_metadata(meta::SOURCE, path.display().to_string());
        meta::stamp_hash(&mut doc);
        Ok(doc)
    }

    /// Read everything from `reader` (up to the size limit) into one document
    /// whose `source` is `source`.
    pub fn load_reader(&self, reader: impl Read, source: &str) -> Result<Document, LoadError> {
        let bytes = read_limited(reader, self.limits.max_file_bytes, None)?;
        let mut doc = Document::new(utf8(bytes, None)?).with_metadata(meta::SOURCE, source);
        meta::stamp_hash(&mut doc);
        Ok(doc)
    }
}

/// Load a plain-text file as a single [`Document`] with default [`Limits`].
///
/// The `source` metadata key is set to the path and `content_sha256` to the
/// content's hash.
///
/// # Example
///
/// ```rust,no_run
/// use rune_chain_loader::text::load_file;
///
/// let doc = load_file("README.md").unwrap();
/// assert!(doc.metadata["source"].ends_with("README.md"));
/// ```
pub fn load_file(path: impl AsRef<Path>) -> Result<Document, LoadError> {
    TextLoader::new().load_file(path)
}

/// Load every `.txt`, `.md`, and `.rst` file directly in `dir`
/// (non-recursive) as one [`Document`] per file.
///
/// Built on [`DirectoryLoader`] with default [`Limits`]: symlinks, hidden
/// files and special files are skipped, and files that are not UTF-8 or are
/// over the size limit are skipped. Use [`DirectoryLoader`] for recursion,
/// globs and HTML.
///
/// # Example
///
/// ```rust,no_run
/// use rune_chain_loader::text::load_dir;
///
/// let docs = load_dir(".").unwrap();
/// println!("loaded {} files", docs.len());
/// ```
pub fn load_dir(dir: impl AsRef<Path>) -> Result<Vec<Document>, LoadError> {
    DirectoryLoader::new(dir)
        .recursive(false)
        .include_patterns(&["*.txt", "*.md", "*.rst"])?
        .html(false)
        .load()
}

/// Load all content from stdin (up to [`Limits::max_file_bytes`]) into a
/// single [`Document`] with `source` = `"stdin"`.
///
/// # Example
///
/// ```rust,no_run
/// use rune_chain_loader::text::load_stdin;
///
/// let doc = load_stdin().unwrap();
/// println!("loaded {} bytes from stdin", doc.content.len());
/// ```
pub fn load_stdin() -> Result<Document, LoadError> {
    TextLoader::new().load_reader(io::stdin().lock(), "stdin")
}
