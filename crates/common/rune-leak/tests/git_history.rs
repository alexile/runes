//! Git-history scanning against real repositories built with the `git`
//! executable. Skipped when `git` is not installed.

use rune_leak::{ScanOptions, run, scan_git_history};
use std::path::Path;
use std::process::Command;

const AWS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";

fn git(dir: &Path, args: &[&str]) -> bool {
    Command::new("git")
        .arg("-C")
        .arg(dir)
        .args([
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.com",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// A repository whose first commit adds a secret and second commit removes it.
fn repo_with_removed_secret() -> Option<tempfile::TempDir> {
    let dir = tempfile::tempdir().ok()?;
    if !git(dir.path(), &["init", "-q"]) {
        eprintln!("git not available; skipping");
        return None;
    }
    std::fs::write(
        dir.path().join("secrets.txt"),
        format!("aws_access_key_id = {AWS_KEY}\n"),
    )
    .ok()?;
    std::fs::write(dir.path().join("README"), "hello\n").ok()?;
    git(dir.path(), &["add", "-A"]).then_some(())?;
    git(dir.path(), &["commit", "-qm", "add config"]).then_some(())?;
    std::fs::write(
        dir.path().join("secrets.txt"),
        "aws_access_key_id = REDACTED\n",
    )
    .ok()?;
    std::fs::create_dir(dir.path().join("sub")).ok()?;
    std::fs::write(dir.path().join("sub/moved.env"), format!("KEY={AWS_KEY}\n")).ok()?;
    git(dir.path(), &["add", "-A"]).then_some(())?;
    git(dir.path(), &["commit", "-qm", "scrub config"]).then_some(())?;
    std::fs::remove_file(dir.path().join("sub/moved.env")).ok()?;
    Some(dir)
}

#[test]
fn finds_secret_in_history_when_working_tree_is_clean() {
    let Some(dir) = repo_with_removed_secret() else {
        return;
    };
    let head_parent = Command::new("git")
        .arg("-C")
        .arg(dir.path())
        .args(["rev-list", "--max-parents=0", "HEAD"])
        .output()
        .unwrap();
    let first = String::from_utf8(head_parent.stdout).unwrap();

    let working_tree = run(&ScanOptions::new(dir.path())).unwrap();
    assert!(
        working_tree.findings.is_empty(),
        "{:?}",
        working_tree.findings
    );

    let report = run(&ScanOptions::new(dir.path()).with_scan_git_history(true)).unwrap();
    let hits: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.check_id == "secret.aws_access_key")
        .collect();
    // Once per path: secrets.txt in the first commit, sub/moved.env in the second.
    assert_eq!(hits.len(), 2, "{hits:#?}");
    let history = hits[0]
        .evidence
        .iter()
        .find(|e| e.label == "git_history")
        .unwrap();
    assert!(history.snippet.contains(&first[..10]), "{history:?}");
    assert!(history.snippet.contains("secrets.txt"));

    let json = format!("{report:?}");
    assert!(!json.contains(AWS_KEY), "secret leaked into the report");
    assert_eq!(report.secrets_found, report.findings.len());
}

#[test]
fn history_only_and_commit_window() {
    let Some(dir) = repo_with_removed_secret() else {
        return;
    };
    let report = scan_git_history(&ScanOptions::new(dir.path())).unwrap();
    assert_eq!(report.findings.len(), 2);
    // Only HEAD: its full tree is scanned, which holds the moved secret only.
    let report = scan_git_history(&ScanOptions::new(dir.path()).with_max_commits(1)).unwrap();
    assert_eq!(report.findings.len(), 1);
    assert!(
        report.findings[0]
            .evidence
            .iter()
            .any(|e| e.snippet.contains("sub/moved.env"))
    );
    let report = scan_git_history(&ScanOptions::new(dir.path()).with_max_findings(1)).unwrap();
    assert_eq!(report.findings.len(), 1);
}

#[test]
fn non_repository_is_a_note_not_an_error() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("ok.txt"), "nothing here\n").unwrap();
    let report = run(&ScanOptions::new(dir.path()).with_scan_git_history(true)).unwrap();
    assert!(
        report
            .notes
            .iter()
            .any(|n| n.contains("not a git repository") || n.contains("git executable not found")),
        "{:?}",
        report.notes
    );
}

#[test]
fn empty_repository_is_a_note() {
    let dir = tempfile::tempdir().unwrap();
    if !git(dir.path(), &["init", "-q"]) {
        return;
    }
    let report = scan_git_history(&ScanOptions::new(dir.path())).unwrap();
    assert!(
        report.notes.iter().any(|n| n.contains("no commits")),
        "{:?}",
        report.notes
    );
}
