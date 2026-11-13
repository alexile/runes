use crate::detect::redact;
use rune_entropy::entropy;
use rune_finding::{Confidence, Evidence, Finding, Location};
use rune_regex_sec::scan as regex_scan;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Severity of a detected leak.
///
/// # Examples
///
/// ```rust
/// use rune_leak::Severity;
///
/// assert!(Severity::Critical > Severity::High);
/// assert!(Severity::High > Severity::Medium);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// Informational — unlikely to be exploited directly (IPs, emails in log messages).
    Info,
    /// Low — possible issue but requires additional context to exploit.
    Low,
    /// Medium — likely a real credential but may require additional work to exploit.
    Medium,
    /// High — probable hardcoded secret with significant exploit potential.
    High,
    /// Critical — confirmed sensitive credential type (JWT, AWS key, private key).
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => f.write_str("INFO"),
            Self::Low => f.write_str("LOW"),
            Self::Medium => f.write_str("MEDIUM"),
            Self::High => f.write_str("HIGH"),
            Self::Critical => f.write_str("CRITICAL"),
        }
    }
}

/// A single detected secret or credential leak.
///
/// # Examples
///
/// ```rust
/// use rune_leak::scan_text;
///
/// let leaks = scan_text("aws_key = \"AKIAIOSFODNN7EXAMPLE\"");
/// if let Some(leak) = leaks.first() {
///     println!("{}: {} at line {}", leak.severity, leak.category, leak.line_number);
/// }
/// ```
#[derive(Clone)]
pub struct Leak {
    /// Source file path. `None` when scanning a string with [`scan_text`].
    pub file: Option<PathBuf>,
    /// 1-based line number of the match.
    pub line_number: usize,
    /// Pattern category (e.g. `"jwt"`, `"aws_key"`, `"private_key"`).
    pub category: &'static str,
    /// The matched text extracted from the line.
    pub value: String,
    /// Shannon entropy of the matched value (bits per byte, 0.0–8.0).
    pub entropy: f64,
    /// Severity classification.
    pub severity: Severity,
    /// The full source line containing the match.
    pub line: String,
}

/// Shows the value redacted and leaves out the source line, which holds the
/// value too. Read the fields directly when you need them.
impl std::fmt::Debug for Leak {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Leak")
            .field("file", &self.file)
            .field("line_number", &self.line_number)
            .field("category", &self.category)
            .field("value", &redact(&self.value))
            .field("entropy", &self.entropy)
            .field("severity", &self.severity)
            .finish_non_exhaustive()
    }
}

impl Leak {
    /// Converts the leak into a [`rune_finding::Finding`] with check id
    /// `secret.<category>`, the file location and a CWE-798 reference. The
    /// value is redacted in the evidence; the full source line is not kept.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_leak::scan_text;
    ///
    /// let leaks = scan_text("key = \"AKIAIOSFODNN7EXAMPLE\"");
    /// let finding = leaks[0].to_finding::<()>();
    /// assert_eq!(finding.check_id, "secret.aws_key");
    /// assert!(!finding.evidence[0].snippet.contains("AKIAIOSFODNN7EXAMPLE"));
    /// ```
    #[must_use]
    pub fn to_finding<X: Default>(&self) -> Finding<X> {
        let path = self
            .file
            .as_deref()
            .map_or_else(|| "<text>".to_owned(), |p| p.display().to_string());
        let line = u32::try_from(self.line_number).unwrap_or(u32::MAX);
        let confidence = if self.severity >= Severity::High {
            Confidence::Firm
        } else {
            Confidence::Tentative
        };
        Finding::<X>::new(
            format!("secret.{}", self.category),
            format!("Possible hardcoded secret ({})", self.category),
            self.severity.into(),
            confidence,
            Location::file(path).with_lines(line, line),
        )
        .push_taxonomy(crate::rule::cwe_ref(crate::rule::CWE_HARDCODED_CREDENTIALS))
        .push_evidence(Evidence::new(
            "secret",
            format!("category={} {}", self.category, redact(&self.value)),
        ))
    }
}

impl From<Severity> for rune_finding::Severity {
    fn from(severity: Severity) -> Self {
        match severity {
            Severity::Info => Self::Informational,
            Severity::Low => Self::Low,
            Severity::Medium => Self::Medium,
            Severity::High => Self::High,
            Severity::Critical => Self::Critical,
        }
    }
}

/// Files larger than this are skipped by [`LeakScanner::scan_dir`] and
/// [`scan_dir`]: 2 MB, as [`ScanOptions`](crate::ScanOptions) does.
pub const DEFAULT_MAX_FILE_BYTES: u64 = 2_000_000;

/// Configurable secret scanner.
///
/// Use [`LeakScanner::default`] for sensible defaults, or adjust thresholds before
/// calling any of the scan methods.
///
/// # Examples
///
/// ```rust
/// use rune_leak::LeakScanner;
///
/// let scanner = LeakScanner::new().min_base64_entropy(5.0);
/// let leaks = scanner.scan_str("token = \"AKIAIOSFODNN7EXAMPLE\"");
/// assert!(!leaks.is_empty());
/// ```
#[derive(Debug, Clone)]
pub struct LeakScanner {
    /// Minimum entropy for a base64-looking match to be flagged. Default: 4.5.
    pub min_base64_entropy: f64,
    /// Minimum entropy for a hash-looking match to be flagged. Default: 3.5.
    pub min_hash_entropy: f64,
    /// Whether to report Info-severity findings (IPs, emails). Default: false.
    pub include_info: bool,
}

impl Default for LeakScanner {
    fn default() -> Self {
        Self {
            min_base64_entropy: 4.5,
            min_hash_entropy: 3.5,
            include_info: false,
        }
    }
}

impl LeakScanner {
    /// Creates a scanner with default thresholds.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the minimum entropy threshold for base64-looking matches.
    #[must_use]
    pub const fn min_base64_entropy(mut self, threshold: f64) -> Self {
        self.min_base64_entropy = threshold;
        self
    }

    /// Sets the minimum entropy threshold for hash-looking matches.
    #[must_use]
    pub const fn min_hash_entropy(mut self, threshold: f64) -> Self {
        self.min_hash_entropy = threshold;
        self
    }

    /// Enables Info-severity findings (IPv4, IPv6, email addresses).
    #[must_use]
    pub const fn with_info_findings(mut self) -> Self {
        self.include_info = true;
        self
    }

    /// Scans a string for leaks without associating a file path.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_leak::LeakScanner;
    ///
    /// let leaks = LeakScanner::new().scan_str("key = \"AKIAIOSFODNN7EXAMPLE\"");
    /// assert!(!leaks.is_empty());
    /// ```
    #[must_use]
    pub fn scan_str(&self, text: &str) -> Vec<Leak> {
        self.scan_lines(text, None)
    }

    /// Scans a file for leaks.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use rune_leak::LeakScanner;
    /// use std::path::Path;
    ///
    /// let leaks = LeakScanner::new().scan_file(Path::new("config.env")).unwrap();
    /// println!("{} leaks found", leaks.len());
    /// ```
    pub fn scan_file(&self, path: &Path) -> io::Result<Vec<Leak>> {
        let text = fs::read_to_string(path)?;
        Ok(self.scan_lines(&text, Some(path)))
    }

    /// Recursively scans a directory for leaks in all text files.
    ///
    /// Files with a binary extension (images, archives, PDFs, …), files
    /// that are not valid UTF-8 and files over [`DEFAULT_MAX_FILE_BYTES`]
    /// are skipped; [`LeakScanner::scan_dir_with_max_file_bytes`] sets
    /// another cap. Symlinks are not followed.
    ///
    /// # Errors
    ///
    /// Returns an error if the root path cannot be accessed.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use rune_leak::LeakScanner;
    /// use std::path::Path;
    ///
    /// let leaks = LeakScanner::new().scan_dir(Path::new("src/")).unwrap();
    /// for leak in &leaks {
    ///     println!("{} {}:{}", leak.severity, leak.file.as_ref().unwrap().display(), leak.line_number);
    /// }
    /// ```
    pub fn scan_dir(&self, root: &Path) -> io::Result<Vec<Leak>> {
        self.scan_dir_with_max_file_bytes(root, DEFAULT_MAX_FILE_BYTES)
    }

    /// [`LeakScanner::scan_dir`], skipping files over `max_file_bytes`
    /// instead of [`DEFAULT_MAX_FILE_BYTES`].
    ///
    /// # Errors
    ///
    /// Returns an error if the root path cannot be accessed.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_leak::LeakScanner;
    ///
    /// let dir = tempfile::tempdir()?;
    /// std::fs::write(dir.path().join(".env"), "k = \"AKIAIOSFODNN7EXAMPLE\"\n")?;
    /// let scanner = LeakScanner::new();
    /// assert_eq!(scanner.scan_dir_with_max_file_bytes(dir.path(), 1024)?.len(), 1);
    /// assert!(scanner.scan_dir_with_max_file_bytes(dir.path(), 16)?.is_empty());
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn scan_dir_with_max_file_bytes(
        &self,
        root: &Path,
        max_file_bytes: u64,
    ) -> io::Result<Vec<Leak>> {
        let mut all_leaks = Vec::new();
        for entry in WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_map(std::result::Result::ok)
            .filter(|e| e.file_type().is_file())
        {
            let path = entry.path();
            if is_binary_path(path) {
                continue;
            }
            if entry
                .metadata()
                .map_or(true, |meta| meta.len() > max_file_bytes)
            {
                continue;
            }
            if let Some(text) = read_capped(path, max_file_bytes) {
                all_leaks.extend(self.scan_lines(&text, Some(path)));
            }
        }
        Ok(all_leaks)
    }

    fn scan_lines(&self, text: &str, file: Option<&Path>) -> Vec<Leak> {
        let mut leaks = Vec::new();
        for (idx, line) in text.lines().enumerate() {
            for f in regex_scan(line) {
                let value_entropy = entropy(f.value.as_bytes());
                let Some(severity) = self.classify(f.category, value_entropy) else {
                    continue;
                };
                leaks.push(Leak {
                    file: file.map(Path::to_path_buf),
                    line_number: idx + 1,
                    category: f.category,
                    value: f.value,
                    entropy: value_entropy,
                    severity,
                    line: line.to_string(),
                });
            }
        }
        leaks
    }

    fn classify(&self, category: &str, value_entropy: f64) -> Option<Severity> {
        match category {
            "jwt" | "aws_key" | "private_key" => Some(Severity::Critical),
            "base64_secret" if value_entropy >= self.min_base64_entropy => Some(Severity::High),
            "md5" | "sha1" | "sha256" if value_entropy >= self.min_hash_entropy => {
                Some(Severity::Medium)
            }
            "email" | "url" if self.include_info => Some(Severity::Low),
            "ipv4" | "ipv6" | "uuid" | "cve" if self.include_info => Some(Severity::Info),
            _ => None,
        }
    }
}

/// Scans a string for leaks using default thresholds.
///
/// Equivalent to `LeakScanner::new().scan_str(text)`.
///
/// # Examples
///
/// ```rust
/// use rune_leak::{scan_text, Severity};
///
/// let src = "const TOKEN: &str = \"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyIn0.abc\";";
/// let leaks = scan_text(src);
/// assert!(!leaks.is_empty());
/// assert_eq!(leaks[0].severity, Severity::Critical);
/// assert_eq!(leaks[0].category, "jwt");
/// ```
#[must_use]
pub fn scan_text(text: &str) -> Vec<Leak> {
    LeakScanner::new().scan_str(text)
}

/// Scans a file for leaks using default thresholds.
///
/// # Errors
///
/// Returns an error if the file cannot be read.
///
/// # Examples
///
/// ```rust,no_run
/// use rune_leak::scan_file;
/// use std::path::Path;
///
/// let leaks = scan_file(Path::new(".env")).unwrap();
/// for leak in leaks {
///     println!("[{}] {} at line {}", leak.severity, leak.category, leak.line_number);
/// }
/// ```
pub fn scan_file(path: &Path) -> io::Result<Vec<Leak>> {
    LeakScanner::new().scan_file(path)
}

/// Recursively scans a directory for leaks using default thresholds.
///
/// # Errors
///
/// Returns an error if the directory cannot be accessed.
///
/// # Examples
///
/// ```rust,no_run
/// use rune_leak::scan_dir;
/// use std::path::Path;
///
/// let leaks = scan_dir(Path::new("src/")).unwrap();
/// println!("{} leaks found", leaks.len());
/// ```
pub fn scan_dir(root: &Path) -> io::Result<Vec<Leak>> {
    LeakScanner::new().scan_dir(root)
}

/// The file's text, or `None` if it cannot be read, is not UTF-8 or has
/// grown past `max_bytes` since it was listed.
fn read_capped(path: &Path, max_bytes: u64) -> Option<String> {
    let mut bytes = Vec::new();
    File::open(path)
        .ok()?
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .ok()?;
    if u64::try_from(bytes.len()).map_or(true, |len| len > max_bytes) {
        return None;
    }
    String::from_utf8(bytes).ok()
}

fn is_binary_path(path: &Path) -> bool {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    matches!(
        ext.as_str(),
        "png"
            | "jpg"
            | "jpeg"
            | "gif"
            | "bmp"
            | "ico"
            | "webp"
            | "tiff"
            | "pdf"
            | "zip"
            | "gz"
            | "bz2"
            | "xz"
            | "zst"
            | "tar"
            | "rar"
            | "7z"
            | "exe"
            | "dll"
            | "so"
            | "elf"
            | "dylib"
            | "class"
            | "dex"
            | "wasm"
            | "bin"
            | "dat"
            | "db"
            | "sqlite"
            | "lock"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_jwt() {
        let text = "const t = \"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyIn0.abc\";";
        let leaks = scan_text(text);
        assert!(!leaks.is_empty());
        assert!(
            leaks
                .iter()
                .any(|l| l.category == "jwt" && l.severity == Severity::Critical)
        );
    }

    #[test]
    fn detects_aws_key() {
        let text = "AWS_ACCESS_KEY_ID = \"AKIAIOSFODNN7EXAMPLE\";";
        let leaks = scan_text(text);
        assert!(
            leaks
                .iter()
                .any(|l| l.category == "aws_key" && l.severity == Severity::Critical)
        );
    }

    #[test]
    fn detects_private_key() {
        let text = "key = \"-----BEGIN RSA PRIVATE KEY-----\"";
        let leaks = scan_text(text);
        assert!(
            leaks
                .iter()
                .any(|l| l.category == "private_key" && l.severity == Severity::Critical)
        );
    }

    #[test]
    fn skips_info_by_default() {
        let text = "host = \"192.168.1.1\"";
        let leaks = scan_text(text);
        assert!(leaks.is_empty(), "IPs should be suppressed by default");
    }

    #[test]
    fn info_enabled() {
        let text = "host = \"192.168.1.1\"";
        let leaks = LeakScanner::new().with_info_findings().scan_str(text);
        assert!(leaks.iter().any(|l| l.category == "ipv4"));
    }

    #[test]
    fn data_uri_images_are_not_secrets() {
        let text = "img = \"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==\"";
        assert!(scan_text(text).is_empty());
    }

    #[test]
    fn leak_to_finding_maps_severity_and_cwe() {
        let leaks = scan_text("k = \"AKIAIOSFODNN7EXAMPLE\"");
        let finding = leaks[0].to_finding::<()>();
        assert_eq!(finding.severity, rune_finding::Severity::Critical);
        assert_eq!(finding.taxonomy[0].cwe_number(), Some(798));
    }

    #[test]
    fn scan_dir_skips_files_over_the_size_cap() {
        let dir = tempfile::tempdir().unwrap();
        let key = "k = \"AKIAIOSFODNN7EXAMPLE\"\n";
        std::fs::write(dir.path().join("small.env"), key).unwrap();
        let mut big = key.repeat(2);
        big.push_str(&"#".repeat(2_000_000));
        std::fs::write(dir.path().join("big.env"), &big).unwrap();

        let leaks = scan_dir(dir.path()).unwrap();
        assert_eq!(leaks.len(), 1, "{leaks:?}");
        assert!(leaks[0].file.as_ref().unwrap().ends_with("small.env"));

        let scanner = LeakScanner::new();
        let all = scanner
            .scan_dir_with_max_file_bytes(dir.path(), 3_000_000)
            .unwrap();
        assert_eq!(all.len(), 3);
        let none = scanner
            .scan_dir_with_max_file_bytes(dir.path(), key.len() as u64 - 1)
            .unwrap();
        assert!(none.is_empty());
    }

    #[test]
    fn severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }
}
