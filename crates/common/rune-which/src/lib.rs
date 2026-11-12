//! Cross-platform executable lookup on `PATH` or in given directories,
//! honouring `PATHEXT`.
//!
//! A [`Finder`] holds an ordered list of directories to search, the file
//! extensions to try (Windows' `PATHEXT`), and optionally the working
//! directory that relative entries resolve against. [`Finder::find`]
//! returns the first match as an absolute path; [`Finder::find_all`]
//! returns every match in search order.
//!
//! The library never reads the process environment. [`Finder::from_env`]
//! and [`which`] take a lookup function: pass
//! `|name| std::env::var(name).ok()` in a program and a fixed map in tests.
//!
//! # Rules
//!
//! - A bare name (`cargo`) is searched in every directory, in order; the
//!   first hit wins.
//! - A name with a path separator (`./tool`, `bin/tool`, `/usr/bin/env`)
//!   is not searched: it is checked as given, a relative one against
//!   [`Finder::with_cwd`].
//! - Relative search directories, including the empty `PATH` entry that
//!   means "current directory", join the working directory if one was
//!   supplied and are skipped otherwise. Skipping them by default avoids
//!   the classic `PATH=.:…` hijack.
//! - With extensions configured, a name whose extension is already in the
//!   list (`tool.exe`) is tried as-is; otherwise each extension is
//!   appended in order (`tool.COM`, `tool.EXE`, …). Comparison is
//!   ASCII-case-insensitive, as on Windows.
//! - A candidate must be a regular file (symlinks are followed) and, on
//!   Unix, have an execute bit set. [`Finder::with_check_executable`]
//!   relaxes the second check.
//!
//! The returned path is the directory joined with the matched file name;
//! symlinks are not resolved (call [`std::fs::canonicalize`] if needed).
//!
//! # Example
//!
//! ```
//! use rune_which::Finder;
//!
//! // Search explicit directories, here an empty temporary one.
//! let dir = std::env::temp_dir().join("rune-which-doc-empty");
//! # std::fs::create_dir_all(&dir).unwrap();
//! let finder = Finder::new().with_dirs([&dir]);
//! assert_eq!(finder.find("no-such-tool-xyz"), None);
//!
//! // Build the search path from an environment lookup function.
//! let env = |name: &str| (name == "PATH").then(|| "/usr/local/bin:/usr/bin".to_owned());
//! let finder = Finder::from_env(env);
//! if cfg!(unix) {
//!     assert_eq!(finder.dirs().len(), 2);
//! }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

/// The `PATHEXT` used on Windows when the variable is unset or empty.
pub const DEFAULT_PATHEXT: &str = ".COM;.EXE;.BAT;.CMD";

/// Finds the first executable called `name` on the `PATH` that `env`
/// returns, honouring `PATHEXT` on Windows.
///
/// Shorthand for [`Finder::from_env(env).find(name)`](Finder::find).
/// Relative `PATH` entries are skipped, since no working directory is
/// supplied; use a [`Finder`] with [`with_cwd`](Finder::with_cwd) to
/// honour them.
///
/// ```
/// use rune_which::which;
///
/// let env = |name: &str| (name == "PATH").then(|| String::new());
/// assert_eq!(which("sh", env), None);
/// ```
#[must_use]
pub fn which(name: impl AsRef<OsStr>, env: impl Fn(&str) -> Option<String>) -> Option<PathBuf> {
    Finder::from_env(env).find(name)
}

/// Where and how to look for executables.
///
/// Built with [`Finder::new`] or [`Finder::from_env`] and the `with_*`
/// methods; directories are searched in the order they were added.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Finder {
    dirs: Vec<PathBuf>,
    extensions: Vec<OsString>,
    cwd: Option<PathBuf>,
    check_executable: bool,
}

impl Default for Finder {
    fn default() -> Self {
        Self::new()
    }
}

impl Finder {
    /// A finder with no directories, no extensions and no working
    /// directory, that requires an execute bit on Unix.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            dirs: Vec::new(),
            extensions: Vec::new(),
            cwd: None,
            check_executable: true,
        }
    }

    /// A finder for the `PATH` (and, on Windows, `PATHEXT`) that `env`
    /// returns.
    ///
    /// `env` looks up environment variables; pass
    /// `|name| std::env::var(name).ok()` in a program and a fixed map in
    /// tests. On Windows an unset or empty `PATHEXT` falls back to
    /// [`DEFAULT_PATHEXT`]. On other platforms `PATHEXT` is ignored.
    #[must_use]
    pub fn from_env(env: impl Fn(&str) -> Option<String>) -> Self {
        let mut finder = Self::new();
        if let Some(path) = env("PATH") {
            finder = finder.with_path_var(path);
        }
        if cfg!(windows) {
            let pathext = env("PATHEXT")
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| DEFAULT_PATHEXT.to_owned());
            finder = finder.with_pathext(&pathext);
        }
        finder
    }

    /// Appends the directories of a `PATH`-style list, split with the
    /// platform's separator (`:` on Unix, `;` on Windows).
    #[must_use]
    pub fn with_path_var(mut self, path: impl AsRef<OsStr>) -> Self {
        self.dirs.extend(std::env::split_paths(path.as_ref()));
        self
    }

    /// Appends directories to search, after any already present.
    #[must_use]
    pub fn with_dirs<I>(mut self, dirs: I) -> Self
    where
        I: IntoIterator,
        I::Item: AsRef<Path>,
    {
        self.dirs
            .extend(dirs.into_iter().map(|dir| dir.as_ref().to_path_buf()));
        self
    }

    /// Appends extensions to try, such as `".exe"`. A missing leading dot
    /// is added; empty entries are ignored.
    #[must_use]
    pub fn with_extensions<I>(mut self, extensions: I) -> Self
    where
        I: IntoIterator,
        I::Item: AsRef<OsStr>,
    {
        for ext in extensions {
            let ext = ext.as_ref();
            if ext.is_empty() || ext == "." {
                continue;
            }
            let ext = if ext.as_encoded_bytes().starts_with(b".") {
                ext.to_os_string()
            } else {
                let mut dotted = OsString::from(".");
                dotted.push(ext);
                dotted
            };
            self.extensions.push(ext);
        }
        self
    }

    /// Appends the extensions of a `PATHEXT`-style list (`;`-separated,
    /// surrounding whitespace ignored), on any platform.
    #[must_use]
    pub fn with_pathext(self, pathext: &str) -> Self {
        self.with_extensions(pathext.split(';').map(str::trim))
    }

    /// Sets the directory that relative search directories and relative
    /// names with a separator resolve against. It should be absolute;
    /// a relative one is ignored.
    #[must_use]
    pub fn with_cwd(mut self, cwd: impl Into<PathBuf>) -> Self {
        let cwd = cwd.into();
        self.cwd = cwd.is_absolute().then_some(cwd);
        self
    }

    /// Whether a match must be executable (an execute bit on Unix).
    /// Default `true`. With `false`, any regular file matches. Has no
    /// effect on platforms without execute bits.
    #[must_use]
    pub const fn with_check_executable(mut self, check: bool) -> Self {
        self.check_executable = check;
        self
    }

    /// The directories searched, in order, as given (before joining the
    /// working directory).
    #[must_use]
    pub fn dirs(&self) -> &[PathBuf] {
        &self.dirs
    }

    /// The extensions tried, each with a leading dot.
    #[must_use]
    pub fn extensions(&self) -> &[OsString] {
        &self.extensions
    }

    /// The first executable called `name`, as an absolute path, or `None`.
    #[must_use]
    pub fn find(&self, name: impl AsRef<OsStr>) -> Option<PathBuf> {
        self.candidates(name.as_ref())
            .into_iter()
            .find(|candidate| self.is_match(candidate))
    }

    /// Every executable called `name`, in search order, without
    /// duplicates (a directory listed twice yields its match once).
    #[must_use]
    pub fn find_all(&self, name: impl AsRef<OsStr>) -> Vec<PathBuf> {
        let mut seen = HashSet::new();
        self.candidates(name.as_ref())
            .into_iter()
            .filter(|candidate| self.is_match(candidate))
            .filter(|candidate| seen.insert(candidate.clone()))
            .collect()
    }

    /// Every absolute path to check for `name`, in order.
    fn candidates(&self, name: &OsStr) -> Vec<PathBuf> {
        if name.is_empty() {
            return Vec::new();
        }
        if has_separator(name) {
            let Some(path) = self.absolute(Path::new(name)) else {
                return Vec::new();
            };
            let Some(base) = path.file_name() else {
                return Vec::new();
            };
            return self
                .file_names(base)
                .iter()
                .map(|file| path.with_file_name(file))
                .collect();
        }
        let file_names = self.file_names(name);
        self.dirs
            .iter()
            .filter_map(|dir| self.absolute(dir))
            .flat_map(|dir| file_names.iter().map(move |file| dir.join(file)))
            .collect()
    }

    /// The file names to try for `name`: the name itself when no
    /// extensions are configured or it already carries one of them, then
    /// the name with each extension appended.
    fn file_names(&self, name: &OsStr) -> Vec<OsString> {
        if self.extensions.is_empty() {
            return vec![name.to_os_string()];
        }
        let has_known_ext = self
            .extensions
            .iter()
            .any(|ext| ends_with_ignore_ascii_case(name, ext));
        let mut names = Vec::with_capacity(self.extensions.len() + 1);
        if has_known_ext {
            names.push(name.to_os_string());
        }
        names.extend(self.extensions.iter().map(|ext| {
            let mut with_ext = name.to_os_string();
            with_ext.push(ext);
            with_ext
        }));
        names
    }

    /// `path` if absolute, else joined to the working directory, else
    /// `None`.
    fn absolute(&self, path: &Path) -> Option<PathBuf> {
        if path.is_absolute() {
            Some(path.to_path_buf())
        } else {
            self.cwd.as_ref().map(|cwd| cwd.join(path))
        }
    }

    fn is_match(&self, path: &Path) -> bool {
        let Ok(metadata) = std::fs::metadata(path) else {
            return false;
        };
        metadata.is_file() && (!self.check_executable || is_executable(&metadata))
    }
}

fn has_separator(name: &OsStr) -> bool {
    let bytes = name.as_encoded_bytes();
    bytes.contains(&b'/') || (cfg!(windows) && bytes.contains(&b'\\'))
}

fn ends_with_ignore_ascii_case(name: &OsStr, ext: &OsStr) -> bool {
    let (name, ext) = (name.as_encoded_bytes(), ext.as_encoded_bytes());
    name.len() > ext.len() && name[name.len() - ext.len()..].eq_ignore_ascii_case(ext)
}

#[cfg(unix)]
fn is_executable(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
const fn is_executable(_metadata: &std::fs::Metadata) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Creates `dir/name` with the given Unix mode (ignored elsewhere).
    fn touch(dir: &Path, name: &str, mode: u32) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, b"#!/bin/sh\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        }
        #[cfg(not(unix))]
        let _ = mode;
        path
    }

    #[test]
    fn honours_explicit_dirs_in_order() {
        let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let in_b = touch(b.path(), "tool", 0o755);
        let finder = Finder::new().with_dirs([a.path(), b.path()]);
        assert_eq!(finder.find("tool"), Some(in_b.clone()));

        let in_a = touch(a.path(), "tool", 0o700);
        assert_eq!(finder.find("tool"), Some(in_a.clone()));
        assert_eq!(finder.find_all("tool"), vec![in_a, in_b]);
    }

    #[test]
    fn returns_none_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let finder = Finder::new().with_dirs([dir.path()]);
        assert_eq!(finder.find("absent"), None);
        assert_eq!(finder.find_all("absent"), Vec::<PathBuf>::new());
        assert_eq!(finder.find(""), None);
        assert_eq!(Finder::new().find("sh"), None);
    }

    #[test]
    fn skips_directories_and_missing_dirs() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("tool")).unwrap();
        let finder = Finder::new().with_dirs([dir.path().join("missing"), dir.path().into()]);
        assert_eq!(finder.find("tool"), None);
    }

    #[cfg(unix)]
    #[test]
    fn requires_execute_bit_unless_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let plain = touch(dir.path(), "data", 0o644);
        let finder = Finder::new().with_dirs([dir.path()]);
        assert_eq!(finder.find("data"), None);
        assert_eq!(
            finder.with_check_executable(false).find("data"),
            Some(plain)
        );
    }

    #[cfg(unix)]
    #[test]
    fn follows_symlinks_without_resolving_them() {
        let (real, bin) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let target = touch(real.path(), "tool-1.2", 0o755);
        let link = bin.path().join("tool");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert_eq!(
            Finder::new().with_dirs([bin.path()]).find("tool"),
            Some(link)
        );
        std::os::unix::fs::symlink(real.path().join("gone"), bin.path().join("dangling")).unwrap();
        assert_eq!(Finder::new().with_dirs([bin.path()]).find("dangling"), None);
    }

    #[test]
    fn relative_dirs_need_a_cwd() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("bin")).unwrap();
        let tool = touch(&dir.path().join("bin"), "tool", 0o755);
        let finder = Finder::new().with_dirs(["bin"]);
        assert_eq!(finder.find("tool"), None);
        assert_eq!(finder.clone().with_cwd("relative").find("tool"), None);
        assert_eq!(finder.with_cwd(dir.path()).find("tool"), Some(tool));
    }

    #[test]
    fn names_with_separator_are_not_searched() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("bin")).unwrap();
        let tool = touch(&dir.path().join("bin"), "tool", 0o755);
        let finder = Finder::new().with_dirs([dir.path()]);
        // `bin/tool` is relative to the cwd, not to the search dirs.
        assert_eq!(finder.find("bin/tool"), None);
        assert_eq!(
            finder.clone().with_cwd(dir.path()).find("bin/tool"),
            Some(tool.clone())
        );
        assert_eq!(finder.find(&tool), Some(tool));
    }

    #[test]
    fn pathext_appends_extensions_case_insensitively() {
        let dir = tempfile::tempdir().unwrap();
        let exe = touch(dir.path(), "tool.EXE", 0o755);
        let finder = Finder::new()
            .with_dirs([dir.path()])
            .with_pathext(" .COM ; .EXE;;.bat ");
        assert_eq!(
            finder.extensions(),
            [".COM", ".EXE", ".bat"].map(OsString::from)
        );
        assert_eq!(finder.find("tool"), Some(exe.clone()));
        // A known extension is tried as given; an unknown one gets more appended.
        assert_eq!(finder.find("tool.EXE"), Some(exe));
        assert_eq!(finder.find("tool.txt"), None);
        assert_eq!(finder.find("tool.EXE.bat"), None);
        // Without extensions, only the exact name matches.
        assert_eq!(Finder::new().with_dirs([dir.path()]).find("tool"), None);
        // Extensions apply to names with a separator, too.
        assert_eq!(
            finder.with_cwd(dir.path()).find("./tool"),
            Some(dir.path().join("./tool.EXE"))
        );
    }

    #[test]
    fn with_extensions_normalises_dots() {
        let finder = Finder::new().with_extensions(["exe", ".cmd", "", "."]);
        assert_eq!(finder.extensions(), [".exe", ".cmd"].map(OsString::from));
    }

    #[test]
    fn from_env_splits_path_and_reads_pathext_only_on_windows() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let path = std::env::join_paths([a.path(), b.path()]).unwrap();
        let path = path.into_string().unwrap();
        let env = |name: &str| match name {
            "PATH" => Some(path.clone()),
            "PATHEXT" => Some(".X".to_owned()),
            _ => None,
        };
        let finder = Finder::from_env(env);
        assert_eq!(finder.dirs(), [a.path(), b.path()]);
        if cfg!(windows) {
            assert_eq!(finder.extensions(), [OsString::from(".X")]);
        } else {
            assert_eq!(finder.extensions(), Vec::<OsString>::new());
        }
        assert_eq!(
            Finder::from_env(|_| None),
            Finder::new().with_pathext(if cfg!(windows) { DEFAULT_PATHEXT } else { "" })
        );
    }

    #[test]
    fn find_all_deduplicates_repeated_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let tool = touch(dir.path(), "tool", 0o755);
        let finder = Finder::new().with_dirs([dir.path(), dir.path()]);
        assert_eq!(finder.find_all("tool"), vec![tool]);
    }

    /// Locates a real executable through the real `PATH` (reading the
    /// environment is fine in a test; the library never does).
    #[cfg(unix)]
    #[test]
    fn locates_sh_on_the_real_path() {
        let found = which("sh", |name| std::env::var(name).ok()).unwrap();
        assert!(found.is_absolute());
        assert_eq!(found.file_name(), Some(OsStr::new("sh")));
    }
}
