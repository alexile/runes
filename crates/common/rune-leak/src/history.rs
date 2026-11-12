//! Git-history scanning.
//!
//! [`HistoryScanner`] is the sans-I/O core: feed it blobs oldest commit first
//! and it reports each `(rule, path, redacted secret)` once, attributed to the
//! commit that introduced it. [`scan_git_history`] drives it from a local
//! repository through the `git` executable's plumbing commands (`rev-list`,
//! `ls-tree`, `diff-tree`, `cat-file --batch`), so no git library is linked.

use crate::Ruleset;
use crate::error::Error;
use crate::scan::{ScanOptions, ScanReport};
use rune_finding::{Evidence, Finding, Remediation};
use std::collections::HashSet;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};

const HISTORY_REMEDIATION: &str = "This secret is present in git history even if removed from \
     the working tree. Rotate the credential, then purge it from history (e.g. git filter-repo) \
     and force-push, and load secrets from a secrets manager instead.";

/// Sans-I/O history scanner: de-duplicates hits across commits.
///
/// # Examples
///
/// ```rust
/// use rune_leak::{HistoryScanner, Ruleset};
///
/// let rules = Ruleset::builtin();
/// let mut history = HistoryScanner::new(&rules, 100);
/// // Oldest commit first: the secret is attributed to the commit adding it.
/// history.push_blob("1111111111aaaa", "app.env", "KEY=AKIAIOSFODNN7EXAMPLE\n");
/// history.push_blob("2222222222bbbb", "app.env", "# moved\nKEY=AKIAIOSFODNN7EXAMPLE\n");
/// let findings = history.into_findings();
/// assert_eq!(findings.len(), 1);
/// assert!(findings[0].evidence.iter().any(|e| e.snippet.contains("1111111111")));
/// ```
#[derive(Debug)]
pub struct HistoryScanner<'r> {
    ruleset: &'r Ruleset,
    max_findings: usize,
    seen: HashSet<(String, String, String)>,
    findings: Vec<Finding>,
    blobs_scanned: usize,
}

impl<'r> HistoryScanner<'r> {
    /// A scanner that stops collecting after `max_findings` findings.
    #[must_use]
    pub fn new(ruleset: &'r Ruleset, max_findings: usize) -> Self {
        Self {
            ruleset,
            max_findings,
            seen: HashSet::new(),
            findings: Vec::new(),
            blobs_scanned: 0,
        }
    }

    /// Scans one blob of `commit` at `path`. Returns `false` once the finding
    /// budget is full, so the caller can stop early.
    pub fn push_blob(&mut self, commit: &str, path: &str, text: &str) -> bool {
        if self.is_full() {
            return false;
        }
        self.blobs_scanned += 1;
        let short = commit.get(..10).unwrap_or(commit);
        let (seen, findings, max) = (&mut self.seen, &mut self.findings, self.max_findings);
        self.ruleset.for_each_match(text, |m| {
            if findings.len() >= max {
                return;
            }
            let key = (m.rule.id.clone(), path.to_owned(), m.redacted());
            if !seen.insert(key) {
                return;
            }
            let finding = m
                .to_finding::<()>(path)
                .push_evidence(Evidence::new(
                    "git_history",
                    format!("introduced in commit {short} at {path}"),
                ))
                .with_remediation(Remediation::new(HISTORY_REMEDIATION));
            findings.push(finding);
        });
        !self.is_full()
    }

    /// Whether the finding budget is full.
    #[must_use]
    pub const fn is_full(&self) -> bool {
        self.findings.len() >= self.max_findings
    }

    /// Number of blobs scanned so far.
    #[must_use]
    pub const fn blobs_scanned(&self) -> usize {
        self.blobs_scanned
    }

    /// The findings collected so far.
    #[must_use]
    pub fn into_findings(self) -> Vec<Finding> {
        self.findings
    }
}

/// Scans only the git history of `options.path` (not its working tree),
/// walking up to `options.max_commits` commits back from `HEAD`.
///
/// The oldest commit in that window is scanned in full; every later commit
/// contributes the blobs it adds or modifies (merges against each parent).
/// Each blob object is read once, blobs over `options.max_file_bytes` and
/// non-UTF-8 blobs are skipped, and identical hits are reported once,
/// attributed to the oldest commit. The finding carries a `git_history`
/// evidence entry naming the commit's short hash.
///
/// A path that is not a git repository (discovery does not look above it),
/// a repository without commits, or a missing `git` executable is not an
/// error: the report carries a note instead.
///
/// # Errors
///
/// [`Error::EmptyPath`], an invalid rule in `options.rules`, or
/// [`Error::Git`] when a git command fails mid-scan.
///
/// # Examples
///
/// ```rust,no_run
/// use rune_leak::{scan_git_history, ScanOptions};
///
/// let report = scan_git_history(&ScanOptions::new(".").with_max_commits(200))?;
/// for finding in &report.findings {
///     println!("{} {}", finding.check_id, finding.title);
/// }
/// # Ok::<(), rune_leak::Error>(())
/// ```
pub fn scan_git_history(options: &ScanOptions) -> Result<ScanReport, Error> {
    if options.path.as_os_str().is_empty() {
        return Err(Error::EmptyPath);
    }
    let ruleset = options.ruleset()?;
    let mut scanner = HistoryScanner::new(&ruleset, options.max_findings);
    let mut notes = Vec::new();
    scan_repo(options, &mut scanner, &mut notes)?;
    let files_scanned = scanner.blobs_scanned();
    Ok(ScanReport::new(
        scanner.into_findings(),
        files_scanned,
        notes,
    ))
}

/// Drives `scanner` over the repository at `options.path`.
pub fn scan_repo(
    options: &ScanOptions,
    scanner: &mut HistoryScanner<'_>,
    notes: &mut Vec<String>,
) -> Result<(), Error> {
    let repo = options
        .path
        .canonicalize()
        .unwrap_or_else(|_| options.path.clone());
    let shown = options.path.display();

    match git(&repo, &["rev-parse", "--git-dir"]).output() {
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            notes.push("git executable not found; scanned working tree only".to_owned());
            return Ok(());
        }
        Err(err) => return Err(Error::Git(format!("rev-parse: {err}"))),
        Ok(out) if !out.status.success() => {
            notes.push(format!(
                "{shown}: not a git repository; scanned working tree only"
            ));
            return Ok(());
        }
        Ok(_) => {}
    }
    if options.max_commits == 0 {
        return Ok(());
    }
    let max = format!("--max-count={}", options.max_commits);
    let Ok(out) = run_git(&repo, &["rev-list", &max, "--reverse", "HEAD"]) else {
        notes.push("git repository has no commits; scanned working tree only".to_owned());
        return Ok(());
    };
    let commits: Vec<String> = String::from_utf8_lossy(&out)
        .split_whitespace()
        .map(str::to_owned)
        .collect();

    // (commit index, path, blob id), oldest commit first, each blob once.
    let mut blobs: Vec<(usize, String, String)> = Vec::new();
    let mut seen_oids: HashSet<String> = HashSet::new();
    for (idx, commit) in commits.iter().enumerate() {
        let entries = if idx == 0 {
            parse_ls_tree(&run_git(
                &repo,
                &["ls-tree", "-r", "-z", "--full-tree", commit],
            )?)
        } else {
            parse_diff_tree(&run_git(
                &repo,
                &[
                    "diff-tree",
                    "-r",
                    "-z",
                    "-m",
                    "--no-renames",
                    "--root",
                    "--no-commit-id",
                    commit,
                ],
            )?)
        };
        for (path, oid) in entries {
            if seen_oids.insert(oid.clone()) {
                blobs.push((idx, path, oid));
            }
        }
    }
    if blobs.is_empty() {
        return Ok(());
    }
    cat_blobs(&repo, &commits, &blobs, options.max_file_bytes, scanner)
}

/// A `git` command confined to `repo`: no discovery above it, no pager, no
/// prompts, no optional locks, and no inherited `GIT_DIR`/`GIT_WORK_TREE`.
fn git(repo: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::new("git");
    cmd.arg("--no-pager")
        .arg("--no-replace-objects")
        .arg("-C")
        .arg(repo)
        .args(["-c", "core.fsmonitor=false"])
        .args(args)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_OBJECT_DIRECTORY")
        .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .stdin(Stdio::null())
        .stderr(Stdio::null());
    if let Some(parent) = repo.parent() {
        cmd.env("GIT_CEILING_DIRECTORIES", parent);
    }
    cmd
}

fn run_git(repo: &Path, args: &[&str]) -> Result<Vec<u8>, Error> {
    let name = args.first().copied().unwrap_or("git");
    let out = git(repo, args)
        .output()
        .map_err(|err| Error::Git(format!("{name}: {err}")))?;
    if out.status.success() {
        Ok(out.stdout)
    } else {
        Err(Error::Git(format!("{name} exited with {}", out.status)))
    }
}

/// Regular-file blobs (`100644`/`100755`); symlinks and submodules are not
/// file content.
fn is_file_mode(mode: &str) -> bool {
    matches!(mode, "100644" | "100755")
}

/// Parses `git ls-tree -r -z`: `<mode> SP <type> SP <oid> TAB <path> NUL`.
fn parse_ls_tree(out: &[u8]) -> Vec<(String, String)> {
    out.split(|b| *b == 0)
        .filter_map(|record| {
            let tab = record.iter().position(|b| *b == b'\t')?;
            let head = std::str::from_utf8(&record[..tab]).ok()?;
            let mut fields = head.split(' ');
            let (mode, kind, oid) = (fields.next()?, fields.next()?, fields.next()?);
            (kind == "blob" && is_file_mode(mode)).then(|| {
                (
                    String::from_utf8_lossy(&record[tab + 1..]).into_owned(),
                    oid.to_owned(),
                )
            })
        })
        .collect()
}

/// Parses `git diff-tree -r -z --no-renames`:
/// `:<src mode> SP <dst mode> SP <src oid> SP <dst oid> SP <status> NUL <path> NUL`.
fn parse_diff_tree(out: &[u8]) -> Vec<(String, String)> {
    let mut entries = Vec::new();
    let mut fields = out.split(|b| *b == 0);
    while let Some(head) = fields.next() {
        let Some(head) = head.strip_prefix(b":") else {
            continue;
        };
        let Some(path) = fields.next() else { break };
        let Ok(head) = std::str::from_utf8(head) else {
            continue;
        };
        let parts: Vec<&str> = head.split(' ').collect();
        if let [_, dst_mode, _, dst_oid, status] = parts.as_slice()
            && is_file_mode(dst_mode)
            && !status.starts_with('D')
        {
            entries.push((
                String::from_utf8_lossy(path).into_owned(),
                (*dst_oid).to_owned(),
            ));
        }
    }
    entries
}

/// Streams `blobs` through one `git cat-file --batch` process into `scanner`.
fn cat_blobs(
    repo: &Path,
    commits: &[String],
    blobs: &[(usize, String, String)],
    max_bytes: u64,
    scanner: &mut HistoryScanner<'_>,
) -> Result<(), Error> {
    let mut child = git(repo, &["cat-file", "--batch"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|err| Error::Git(format!("cat-file: {err}")))?;
    let (Some(mut stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(Error::Git("cat-file: no pipes".to_owned()));
    };

    let result = std::thread::scope(|scope| {
        // Feed ids from a second thread so a full stdout pipe cannot deadlock.
        scope.spawn(move || {
            for (_, _, oid) in blobs {
                if writeln!(stdin, "{oid}").is_err() {
                    break;
                }
            }
        });
        let mut reader = BufReader::new(stdout);
        let read = read_batch(&mut reader, commits, blobs, max_bytes, scanner);
        // Dropping the reader closes the pipe, so the writer and git stop
        // early when the finding budget filled up.
        drop(reader);
        read
    });
    let _ = child.kill();
    let _ = child.wait();
    result
}

fn read_batch(
    reader: &mut impl BufRead,
    commits: &[String],
    blobs: &[(usize, String, String)],
    max_bytes: u64,
    scanner: &mut HistoryScanner<'_>,
) -> Result<(), Error> {
    let io_err = |err: io::Error| Error::Git(format!("cat-file: {err}"));
    let mut header = String::new();
    let mut buf = Vec::new();
    for (commit_idx, path, _) in blobs {
        header.clear();
        if reader.read_line(&mut header).map_err(io_err)? == 0 {
            return Err(Error::Git("cat-file: unexpected end of output".to_owned()));
        }
        // `<oid> <type> <size>` or `<oid> missing`.
        let mut fields = header.split_whitespace();
        let (Some(_), Some(kind), Some(size)) = (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let size: u64 = size
            .parse()
            .map_err(|_| Error::Git(format!("cat-file: bad header {header:?}")))?;
        let body = reader.by_ref().take(size);
        if kind != "blob" || size > max_bytes {
            io::copy(&mut { body }, &mut io::sink()).map_err(io_err)?;
        } else {
            buf.clear();
            { body }.read_to_end(&mut buf).map_err(io_err)?;
        }
        // Each object is followed by a newline.
        let mut newline = [0u8; 1];
        reader.read_exact(&mut newline).map_err(io_err)?;
        if kind != "blob" || size > max_bytes {
            continue;
        }
        let Ok(text) = std::str::from_utf8(&buf) else {
            continue;
        };
        let commit = commits.get(*commit_idx).map_or("", String::as_str);
        if !scanner.push_blob(commit, path, text) {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ls_tree() {
        let out = b"100644 blob aaa\tf 1.txt\x00120000 blob bbb\ts/l\x00160000 commit ccc\tsub\x00100755 blob ddd\tbin/run\x00";
        assert_eq!(
            parse_ls_tree(out),
            vec![
                ("f 1.txt".to_owned(), "aaa".to_owned()),
                ("bin/run".to_owned(), "ddd".to_owned())
            ]
        );
    }

    #[test]
    fn parses_diff_tree() {
        let out = b":100644 000000 aaa 000 D\0gone.txt\0:100644 100644 bbb ccc M\0s/x\0:000000 120000 000 ddd A\0s/l\0";
        assert_eq!(
            parse_diff_tree(out),
            vec![("s/x".to_owned(), "ccc".to_owned())]
        );
    }

    #[test]
    fn reads_batch_output() {
        let rules = Ruleset::builtin();
        let mut scanner = HistoryScanner::new(&rules, 10);
        let commits = vec!["0123456789abcdef".to_owned()];
        let blobs = vec![
            (0, "missing.txt".to_owned(), "m".to_owned()),
            (0, "a.env".to_owned(), "a".to_owned()),
        ];
        let body = "K=AKIAIOSFODNN7EXAMPLE\n";
        let stream = format!("m missing\na blob {}\n{body}\n", body.len());
        read_batch(&mut stream.as_bytes(), &commits, &blobs, 1000, &mut scanner).unwrap();
        assert_eq!(scanner.blobs_scanned(), 1);
        assert_eq!(scanner.into_findings()[0].check_id, "secret.aws_access_key");
    }

    #[test]
    fn history_scanner_respects_budget() {
        let rules = Ruleset::builtin();
        let mut scanner = HistoryScanner::new(&rules, 1);
        assert!(!scanner.push_blob("c", "a", "A=AKIAIOSFODNN7EXAMPLE\nB=AKIAIOSFODNN7EXAMPLF\n"));
        assert_eq!(scanner.into_findings().len(), 1);
    }
}
