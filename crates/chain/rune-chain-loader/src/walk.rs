use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::document::Document;
use crate::error::LoadError;
use crate::glob::Glob;
use crate::io::{read_file, utf8};
use crate::jail::Jail;
use crate::limits::Limits;
use crate::{html, meta};

/// Patterns a [`DirectoryLoader`] includes unless told otherwise.
pub const DEFAULT_INCLUDE: &[&str] = &["*.txt", "*.md", "*.markdown", "*.rst", "*.html", "*.htm"];

/// Walks a directory tree and loads one [`Document`] per matching file.
///
/// Secure by default:
///
/// - the walk never leaves the root: symlinks are **skipped** unless
///   [`follow_symlinks`](Self::follow_symlinks) is on, and even then only
///   targets inside the canonical root are followed, each directory at most
///   once (so symlink loops terminate). The hidden and exclude rules are
///   checked against both the walk path and the target's real path, so a
///   link cannot expose an excluded or hidden entry under another name;
/// - FIFOs, sockets and devices are skipped without being opened;
/// - hidden entries (names starting with `.`, e.g. `.git`, `.env`) are
///   skipped unless [`hidden`](Self::hidden) is on;
/// - [`Limits::max_depth`], [`Limits::max_files`] and
///   [`Limits::max_file_bytes`] apply.
///
/// Files are matched with [`Glob`]s against their path relative to the
/// root; an `exclude` that matches a directory prunes it. With
/// [`html`](Self::html) on (the default), `.html`/`.htm` files are converted
/// with [`html::html_to_text`].
///
/// Loading is lazy: [`documents`](Self::documents) reads one file per `next()`.
///
/// # Example
///
/// ```rust
/// use rune_chain_loader::{DirectoryLoader, Glob};
///
/// let dir = tempfile::tempdir().unwrap();
/// std::fs::create_dir(dir.path().join("guide")).unwrap();
/// std::fs::write(dir.path().join("guide/intro.md"), "# Intro").unwrap();
/// std::fs::write(dir.path().join("guide/page.html"), "<p>Hi<script>x()</script></p>").unwrap();
/// std::fs::write(dir.path().join("draft.md"), "wip").unwrap();
///
/// let mut docs = DirectoryLoader::new(dir.path())
///     .exclude([Glob::new("draft.*").unwrap()])
///     .load()
///     .unwrap();
/// docs.sort_by(|a, b| a.metadata["relative_path"].cmp(&b.metadata["relative_path"]));
/// assert_eq!(docs.len(), 2);
/// assert_eq!(docs[0].content, "# Intro");
/// assert_eq!(docs[1].content, "Hi");
/// assert_eq!(docs[1].metadata["relative_path"], "guide/page.html");
/// ```
#[derive(Debug, Clone)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent builder switches, not a state machine"
)]
pub struct DirectoryLoader {
    root: PathBuf,
    include: Option<Vec<Glob>>,
    exclude: Vec<Glob>,
    limits: Limits,
    recursive: bool,
    follow_symlinks: bool,
    hidden: bool,
    html: bool,
}

impl DirectoryLoader {
    /// Walk `root` recursively with [`DEFAULT_INCLUDE`] and default [`Limits`].
    #[must_use]
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
            include: None,
            exclude: Vec::new(),
            limits: Limits::DEFAULT,
            recursive: true,
            follow_symlinks: false,
            hidden: false,
            html: true,
        }
    }

    /// Replace the include patterns (a file must match at least one).
    #[must_use]
    pub fn include(mut self, globs: impl IntoIterator<Item = Glob>) -> Self {
        self.include = Some(globs.into_iter().collect());
        self
    }

    /// [`include`](Self::include) from pattern strings.
    pub fn include_patterns(self, patterns: &[&str]) -> Result<Self, LoadError> {
        let globs = patterns
            .iter()
            .map(|p| Glob::new(p))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(self.include(globs))
    }

    /// Replace the exclude patterns (a matching file is skipped, a matching
    /// directory is not entered).
    #[must_use]
    pub fn exclude(mut self, globs: impl IntoIterator<Item = Glob>) -> Self {
        self.exclude = globs.into_iter().collect();
        self
    }

    /// [`exclude`](Self::exclude) from pattern strings.
    pub fn exclude_patterns(self, patterns: &[&str]) -> Result<Self, LoadError> {
        let globs = patterns
            .iter()
            .map(|p| Glob::new(p))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(self.exclude(globs))
    }

    /// Replace the limits.
    #[must_use]
    pub const fn limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Descend into subdirectories (default `true`, bounded by
    /// [`Limits::max_depth`]).
    #[must_use]
    pub const fn recursive(mut self, recursive: bool) -> Self {
        self.recursive = recursive;
        self
    }

    /// Follow symlinks whose targets stay inside the root (default `false`).
    #[must_use]
    pub const fn follow_symlinks(mut self, follow: bool) -> Self {
        self.follow_symlinks = follow;
        self
    }

    /// Include hidden (dot) files and directories (default `false`).
    #[must_use]
    pub const fn hidden(mut self, hidden: bool) -> Self {
        self.hidden = hidden;
        self
    }

    /// Convert `.html`/`.htm` files to text (default `true`).
    #[must_use]
    pub const fn html(mut self, html: bool) -> Self {
        self.html = html;
        self
    }

    /// Lazily walk the tree, yielding the matching files without reading them.
    pub fn paths(&self) -> Result<Walk, LoadError> {
        let jail = Jail::new(&self.root)?;
        let include = match &self.include {
            Some(globs) => globs.clone(),
            None => DEFAULT_INCLUDE
                .iter()
                .map(|p| Glob::new(p))
                .collect::<Result<_, _>>()?,
        };
        let entries = fs::read_dir(&self.root).map_err(LoadError::io(&self.root))?;
        let mut visited = HashSet::new();
        visited.insert(jail.root().to_path_buf());
        Ok(Walk {
            jail,
            include,
            exclude: self.exclude.clone(),
            max_depth: if self.recursive {
                self.limits.max_depth
            } else {
                0
            },
            max_files: self.limits.max_files,
            follow_symlinks: self.follow_symlinks,
            hidden: self.hidden,
            stack: vec![Frame {
                entries,
                dir: self.root.clone(),
                relative: String::new(),
                depth: 0,
            }],
            visited,
            yielded: 0,
            done: false,
        })
    }

    /// Lazily walk the tree and load each file, one per `next()`.
    ///
    /// Per-file problems (too large, not UTF-8) are yielded as errors and the
    /// walk continues; [`LoadError::TooManyFiles`] ends it.
    pub fn documents(
        &self,
    ) -> Result<impl Iterator<Item = Result<Document, LoadError>> + use<>, LoadError> {
        let walk = self.paths()?;
        let max_bytes = self.limits.max_file_bytes;
        let html = self.html;
        let jail = walk.jail.clone();
        Ok(walk.map(move |entry| load_entry(&entry?, &jail, max_bytes, html)))
    }

    /// Walk the tree and load every matching file, skipping files that fail
    /// for per-file reasons ([`LoadError::is_per_file`]). Any other error
    /// (an unreadable directory, [`LoadError::TooManyFiles`]) is returned.
    pub fn load(&self) -> Result<Vec<Document>, LoadError> {
        let mut docs = Vec::new();
        for item in self.documents()? {
            match item {
                Ok(doc) => docs.push(doc),
                Err(err) if err.is_per_file() || matches!(err, LoadError::OutsideRoot { .. }) => {}
                Err(err) => return Err(err),
            }
        }
        Ok(docs)
    }
}

fn load_entry(
    entry: &WalkEntry,
    jail: &Jail,
    max_bytes: u64,
    html: bool,
) -> Result<Document, LoadError> {
    let bytes = read_file(&entry.path, Some(jail), max_bytes)?;
    let text = utf8(bytes, Some(&entry.path))?;
    let is_html = html
        && entry
            .path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("html") || e.eq_ignore_ascii_case("htm"));
    let mut doc = if is_html {
        html::load_str(&text)
    } else {
        Document::new(text)
    };
    doc.metadata
        .insert(meta::SOURCE.to_string(), entry.path.display().to_string());
    doc.metadata
        .insert(meta::RELATIVE_PATH.to_string(), entry.relative_path.clone());
    meta::stamp_hash(&mut doc);
    Ok(doc)
}

/// A file found by a directory walk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalkEntry {
    /// The file's path: the walk root joined with [`relative_path`](Self::relative_path).
    pub path: PathBuf,
    /// The path relative to the walk root, `/`-separated.
    pub relative_path: String,
}

#[derive(Debug)]
struct Frame {
    entries: fs::ReadDir,
    dir: PathBuf,
    relative: String,
    depth: usize,
}

/// Lazy directory walk returned by [`DirectoryLoader::paths`].
#[derive(Debug)]
pub struct Walk {
    jail: Jail,
    include: Vec<Glob>,
    exclude: Vec<Glob>,
    max_depth: usize,
    max_files: usize,
    follow_symlinks: bool,
    hidden: bool,
    stack: Vec<Frame>,
    visited: HashSet<PathBuf>,
    yielded: usize,
    done: bool,
}

enum Kind {
    Dir,
    File,
    Skip,
}

impl Walk {
    /// Classify an entry, following a symlink only when allowed and only
    /// into the jail.
    fn classify(&self, path: &Path, file_type: fs::FileType) -> Kind {
        if self.follow_symlinks {
            // The walk path may run through a followed link, so the hidden
            // and exclude rules must also hold for the real location;
            // otherwise a link named `public` could expose an excluded
            // `private` directory or a hidden `.env`.
            let Ok(target) = fs::canonicalize(path) else {
                return Kind::Skip;
            };
            if !self.jail.contains(&target) || self.real_path_blocked(&target) {
                return Kind::Skip;
            }
            return match fs::metadata(&target) {
                Ok(m) if m.is_dir() => Kind::Dir,
                Ok(m) if m.is_file() => Kind::File,
                _ => Kind::Skip,
            };
        }
        if file_type.is_symlink() {
            Kind::Skip
        } else if file_type.is_dir() {
            Kind::Dir
        } else if file_type.is_file() {
            Kind::File
        } else {
            Kind::Skip
        }
    }

    /// `true` if the canonical `target`, relative to the root, is hidden
    /// (when hidden entries are off) or lies at or under an excluded path.
    fn real_path_blocked(&self, target: &Path) -> bool {
        let Ok(relative) = target.strip_prefix(self.jail.root()) else {
            return true;
        };
        let mut prefix = String::new();
        for component in relative.components() {
            let name = component.as_os_str().to_string_lossy();
            if !self.hidden && name.starts_with('.') {
                return true;
            }
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(&name);
            if self.excluded(&prefix) {
                return true;
            }
        }
        false
    }

    fn excluded(&self, relative: &str) -> bool {
        self.exclude.iter().any(|g| g.matches(relative))
    }

    /// Push `path` as a new frame if it may be entered.
    fn enter(&mut self, path: PathBuf, relative: String, depth: usize) -> Result<(), LoadError> {
        if depth > self.max_depth || self.excluded(&relative) {
            return Ok(());
        }
        if self.follow_symlinks {
            let canonical = fs::canonicalize(&path).map_err(LoadError::io(&path))?;
            if !self.jail.contains(&canonical) || !self.visited.insert(canonical) {
                return Ok(());
            }
        }
        let entries = fs::read_dir(&path).map_err(LoadError::io(&path))?;
        self.stack.push(Frame {
            entries,
            dir: path,
            relative,
            depth,
        });
        Ok(())
    }
}

impl Iterator for Walk {
    type Item = Result<WalkEntry, LoadError>;

    fn next(&mut self) -> Option<Self::Item> {
        while !self.done {
            let frame = self.stack.last_mut()?;
            let depth = frame.depth;
            let entry = match frame.entries.next() {
                None => {
                    self.stack.pop();
                    continue;
                }
                Some(Err(source)) => {
                    return Some(Err(LoadError::Io {
                        path: Some(frame.dir.clone()),
                        source,
                    }));
                }
                Some(Ok(entry)) => entry,
            };
            let name = entry.file_name().to_string_lossy().into_owned();
            if !self.hidden && name.starts_with('.') {
                continue;
            }
            let relative = if frame.relative.is_empty() {
                name
            } else {
                format!("{}/{name}", frame.relative)
            };
            let path = entry.path();
            let file_type = match entry.file_type() {
                Ok(t) => t,
                Err(err) => return Some(Err(LoadError::io(&path)(err))),
            };
            match self.classify(&path, file_type) {
                Kind::Skip => {}
                Kind::Dir => {
                    if let Err(err) = self.enter(path, relative, depth + 1) {
                        return Some(Err(err));
                    }
                }
                Kind::File => {
                    if !self.include.iter().any(|g| g.matches(&relative))
                        || self.excluded(&relative)
                    {
                        continue;
                    }
                    self.yielded += 1;
                    if self.yielded > self.max_files {
                        self.done = true;
                        return Some(Err(LoadError::TooManyFiles {
                            limit: self.max_files,
                        }));
                    }
                    return Some(Ok(WalkEntry {
                        path,
                        relative_path: relative,
                    }));
                }
            }
        }
        None
    }
}
