//! The tool-style API: [`ScanOptions`] in, [`run`], [`ScanReport`] out.

use crate::Ruleset;
use crate::error::Error;
use crate::history::{HistoryScanner, scan_repo};
use crate::rule::{SecretRule, default_rules};
use crate::ruleset::DEFAULT_ENTROPY_THRESHOLD;
use rune_finding::Finding;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Directory names never descended into by default.
pub const DEFAULT_EXCLUDED_DIRS: &[&str] = &[".git", "node_modules", "target", "vendor", "dist"];

/// Options for [`run`] and [`scan_git_history`](crate::scan_git_history).
///
/// # Examples
///
/// ```rust
/// use rune_leak::ScanOptions;
///
/// let options = ScanOptions::new("src")
///     .with_scan_git_history(true)
///     .with_max_commits(200)
///     .with_entropy_threshold(4.5);
/// assert_eq!(options.max_commits, 200);
/// ```
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct ScanOptions {
    /// File or directory to scan; for history, the repository root.
    pub path: PathBuf,
    /// Also scan git history when `path` is a repository. Default: false.
    pub scan_git_history: bool,
    /// Commits walked back from `HEAD` in history scanning. Default: 1000.
    pub max_commits: usize,
    /// Detection rules. Default: [`default_rules`].
    pub rules: Vec<SecretRule>,
    /// Report high-entropy key-like tokens. Default: true.
    pub use_entropy: bool,
    /// Entropy threshold, bits per byte. Default: 4.3.
    pub entropy_threshold: f64,
    /// Larger files and blobs are skipped. Default: 2 MB.
    pub max_file_bytes: u64,
    /// Stop after this many findings. Default: 1000.
    pub max_findings: usize,
    /// Directory names not descended into. Default: [`DEFAULT_EXCLUDED_DIRS`].
    pub excluded_dirs: Vec<String>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            path: PathBuf::new(),
            scan_git_history: false,
            max_commits: 1000,
            rules: default_rules(),
            use_entropy: true,
            entropy_threshold: DEFAULT_ENTROPY_THRESHOLD,
            max_file_bytes: crate::DEFAULT_MAX_FILE_BYTES,
            max_findings: 1000,
            excluded_dirs: DEFAULT_EXCLUDED_DIRS
                .iter()
                .map(|d| (*d).to_owned())
                .collect(),
        }
    }
}

impl ScanOptions {
    /// Default options scanning `path`.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self::default().with_path(path)
    }

    /// Sets the path to scan.
    #[must_use]
    pub fn with_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.path = path.into();
        self
    }

    /// Enables or disables git-history scanning.
    #[must_use]
    pub const fn with_scan_git_history(mut self, enabled: bool) -> Self {
        self.scan_git_history = enabled;
        self
    }

    /// Sets how many commits history scanning walks.
    #[must_use]
    pub const fn with_max_commits(mut self, max: usize) -> Self {
        self.max_commits = max;
        self
    }

    /// Replaces the rules.
    #[must_use]
    pub fn with_rules(mut self, rules: Vec<SecretRule>) -> Self {
        self.rules = rules;
        self
    }

    /// Enables or disables entropy detection.
    #[must_use]
    pub const fn with_use_entropy(mut self, enabled: bool) -> Self {
        self.use_entropy = enabled;
        self
    }

    /// Sets the entropy threshold.
    #[must_use]
    pub const fn with_entropy_threshold(mut self, threshold: f64) -> Self {
        self.entropy_threshold = threshold;
        self
    }

    /// Sets the per-file size limit.
    #[must_use]
    pub const fn with_max_file_bytes(mut self, bytes: u64) -> Self {
        self.max_file_bytes = bytes;
        self
    }

    /// Sets the finding budget.
    #[must_use]
    pub const fn with_max_findings(mut self, max: usize) -> Self {
        self.max_findings = max;
        self
    }

    /// Replaces the excluded directory names.
    #[must_use]
    pub fn with_excluded_dirs<I, S>(mut self, dirs: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.excluded_dirs = dirs.into_iter().map(Into::into).collect();
        self
    }

    /// Compiles the options' rules and entropy setting into a [`Ruleset`].
    ///
    /// # Errors
    ///
    /// As [`Ruleset::new`].
    pub fn ruleset(&self) -> Result<Ruleset, Error> {
        let ruleset = Ruleset::new(self.rules.iter().cloned())?;
        Ok(if self.use_entropy {
            ruleset.with_entropy(self.entropy_threshold)
        } else {
            ruleset
        })
    }
}

/// The result of a scan.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct ScanReport {
    /// One finding per secret, redacted.
    pub findings: Vec<Finding>,
    /// Text files (and history blobs) inspected.
    pub files_scanned: usize,
    /// Equal to `findings.len()`.
    pub secrets_found: usize,
    /// Informational notes, e.g. that the path is not a git repository.
    pub notes: Vec<String>,
}

impl ScanReport {
    pub(crate) const fn new(
        findings: Vec<Finding>,
        files_scanned: usize,
        notes: Vec<String>,
    ) -> Self {
        let secrets_found = findings.len();
        Self {
            findings,
            files_scanned,
            secrets_found,
            notes,
        }
    }
}

/// Scans the working tree at `options.path` (a file or a directory), then its
/// git history when `options.scan_git_history` is set.
///
/// Symlinks are not followed, excluded directories are skipped, and files over
/// `max_file_bytes` or not valid UTF-8 (binaries) are ignored. Finding paths
/// are relative to `options.path`, with `/` separators.
///
/// # Errors
///
/// [`Error::EmptyPath`], [`Error::Io`] when the root cannot be read, an
/// invalid rule, or [`Error::Git`] from history scanning.
///
/// # Examples
///
/// ```rust
/// let dir = tempfile::tempdir()?;
/// std::fs::write(dir.path().join(".env"), "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")?;
///
/// let report = rune_leak::run(&rune_leak::ScanOptions::new(dir.path()))?;
/// assert_eq!(report.findings[0].check_id, "secret.aws_access_key");
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn run(options: &ScanOptions) -> Result<ScanReport, Error> {
    if options.path.as_os_str().is_empty() {
        return Err(Error::EmptyPath);
    }
    let ruleset = options.ruleset()?;
    let root = &options.path;
    let meta = fs::metadata(root).map_err(|source| Error::Io {
        path: root.clone(),
        source,
    })?;

    let mut findings = Vec::new();
    let mut files_scanned = 0usize;
    let mut notes = Vec::new();

    let walker = WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
            e.depth() == 0
                || !e.file_type().is_dir()
                || !options
                    .excluded_dirs
                    .iter()
                    .any(|d| e.file_name().to_str() == Some(d.as_str()))
        });
    'walk: for entry in walker.filter_map(Result::ok) {
        if !entry.file_type().is_file() {
            continue;
        }
        let Ok(file_meta) = entry.metadata() else {
            continue;
        };
        if file_meta.len() > options.max_file_bytes {
            continue;
        }
        let Ok(bytes) = fs::read(entry.path()) else {
            continue;
        };
        let Ok(text) = String::from_utf8(bytes) else {
            continue;
        };
        files_scanned += 1;
        let rel = relative(root, entry.path(), meta.is_dir());
        let mut full = false;
        ruleset.for_each_match(&text, |m| {
            if findings.len() < options.max_findings {
                findings.push(m.to_finding(&rel));
            } else {
                full = true;
            }
        });
        if full || findings.len() >= options.max_findings {
            break 'walk;
        }
    }

    if options.scan_git_history && findings.len() < options.max_findings && meta.is_dir() {
        let mut history = HistoryScanner::new(
            &ruleset,
            options.max_findings.saturating_sub(findings.len()),
        );
        scan_repo(options, &mut history, &mut notes)?;
        files_scanned += history.blobs_scanned();
        findings.extend(history.into_findings());
    }

    Ok(ScanReport::new(findings, files_scanned, notes))
}

/// `path` relative to `root` with `/` separators; a scanned single file keeps
/// its file name.
fn relative(root: &Path, path: &Path, root_is_dir: bool) -> String {
    let rel = if root_is_dir {
        path.strip_prefix(root).unwrap_or(path)
    } else {
        path.file_name().map_or(path, Path::new)
    };
    rel.components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}
