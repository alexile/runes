use std::fs;
use std::path::{Path, PathBuf};

use crate::error::LoadError;

/// A root directory that loaders may not escape.
///
/// [`Jail::resolve`] joins relative paths onto the root, canonicalises the
/// result (resolving `..` and **following symlinks**) and rejects anything
/// that ends up outside the canonical root with
/// [`LoadError::OutsideRoot`]. A symlink inside the root that points
/// elsewhere is therefore refused.
///
/// The check is path based: a concurrent attacker able to swap directories
/// for symlinks between the check and the `open` can still race it. Use OS
/// sandboxing (`openat2(RESOLVE_BENEATH)`, containers) where that matters.
///
/// # Example
///
/// ```rust
/// use rune_chain_loader::{Jail, LoadError};
///
/// let dir = tempfile::tempdir().unwrap();
/// std::fs::write(dir.path().join("ok.txt"), "hi").unwrap();
/// let jail = Jail::new(dir.path()).unwrap();
///
/// assert!(jail.resolve("ok.txt").is_ok());
/// assert!(matches!(jail.resolve("../../etc/passwd"), Err(LoadError::OutsideRoot { .. }) | Err(LoadError::Io { .. })));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Jail {
    root: PathBuf,
}

impl Jail {
    /// Create a jail rooted at `root`, which must be an existing directory.
    pub fn new(root: impl AsRef<Path>) -> Result<Self, LoadError> {
        let given = root.as_ref();
        let root = fs::canonicalize(given).map_err(LoadError::io(given))?;
        let meta = fs::metadata(&root).map_err(LoadError::io(&root))?;
        if !meta.is_dir() {
            return Err(LoadError::NotRegularFile { path: root });
        }
        Ok(Self { root })
    }

    /// The canonical root directory.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Resolve `path` (relative paths are taken from the root) to a canonical
    /// path inside the root.
    pub fn resolve(&self, path: impl AsRef<Path>) -> Result<PathBuf, LoadError> {
        let given = path.as_ref();
        let joined = self.root.join(given);
        let canonical = fs::canonicalize(&joined).map_err(LoadError::io(given))?;
        if self.contains(&canonical) {
            Ok(canonical)
        } else {
            Err(LoadError::OutsideRoot {
                path: given.to_path_buf(),
            })
        }
    }

    /// `true` if the already-canonical `path` lies within the root.
    #[must_use]
    pub fn contains(&self, canonical: &Path) -> bool {
        canonical.starts_with(&self.root)
    }
}
