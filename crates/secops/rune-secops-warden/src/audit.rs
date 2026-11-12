//! Violation/audit logging — opt-in via `audit.enabled` in the policy
//! TOML. Turns "the sandboxed command failed" into "here's specifically
//! what the policy blocked," without guessing from a bare `ENOENT`/
//! `EACCES`/`EPERM` the wrapped program reports on its own, which almost
//! never says *why* (was the path just not bound? denied outright? was
//! it the command itself that isn't in `commands.allow`? a `connect()`
//! blocked by `network = "none"`?).
//!
//! Raw `strace -f` line parsing is [`rune_strace`]'s job, extracted as a
//! generic crate: nothing about splitting a trace line into
//! pid/name/args/result, or skipping `-f`'s `<unfinished>`/`<...
//! resumed>` fragments, is specific to deciding what counts as a policy
//! violation. This module owns exactly that decision — which errno
//! values mean "blocked," how to phrase the summary — on top of it.
//!
//! # Mechanism
//!
//! Wraps the entire `bwrap` invocation in a host-side `strace -f -e
//! trace=%file,connect` (see [`TRACED_SYSCALLS`] for why `%file` — every
//! filename-taking syscall — rather than a shorter, tool-specific list),
//! tracing every descendant process (tracing your own descendant tree
//! works across the nested PID namespace bwrap constructs — the tracer
//! only needs to be in an ancestor namespace, which the host process
//! spawning `strace` always is) to a log file, then parses that log after
//! the sandboxed process exits and summarizes every syscall that failed
//! as a readable line — `blocked: exec of /usr/bin/curl (ENOENT)`, not
//! just "command failed."
//!
//! This is applied inside [`crate::sandbox::build_command`] as
//! `rune-namespaces`' host-side *launcher* (see [`audit_launcher`]) so it
//! composes correctly with everything else `build_command` does — the
//! Landlock stub, resource limits, the seccomp descriptor — rather than
//! needing to re-wrap an already-built [`std::process::Command`] from the
//! outside (which would lose the seccomp descriptor's `pre_exec` setup
//! entirely). Callers just
//! need to call [`summarize_audit_log`] after the process exits, when
//! `policy.audit.enabled`.
//!
//! # What this deliberately does not do
//!
//! This is a post-hoc summary, not a real-time stream — a policy that
//! hangs waiting on input won't show anything until it eventually exits
//! (or is killed). It also doesn't try to distinguish "this ENOENT is a
//! policy violation" from "this ENOENT is an ordinary `PATH` search
//! trying several candidate directories before finding the right one" —
//! in this crate's whitelist-only model that distinction mostly
//! collapses anyway (an unlisted path categorically doesn't exist inside
//! the sandbox, by design), but it does mean a successful run can still
//! produce a handful of summary lines for candidates the wrapped
//! program's own normal search logic tried and discarded before
//! succeeding elsewhere. Read the summary as "everything the sandbox
//! said no to," not "everything that went wrong."

use std::ffi::OsString;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

/// The syscalls worth tracing: `%file` (strace's own class for every
/// syscall that takes a filename argument — `openat`, `stat`/`statx`,
/// `access`, `execve`, and more) plus `connect` for outbound network.
/// Started narrower (`openat,execve,connect` only) and had to widen:
/// confirmed live that GNU `cat` calls `statx()` on its argument first
/// and, when that alone returns `ENOENT`, never calls `openat` at all —
/// a real denial that a narrower filter would have silently missed
/// entirely, not just logged less precisely. `%file` covers that and
/// whatever the next such case turns out to be, rather than this list
/// needing to grow one tool-specific syscall at a time.
const TRACED_SYSCALLS: &str = "trace=%file,connect";

/// Deterministic per-process path `strace`'s raw trace is written to.
///
/// Shared between `audit_launcher` (which tells `strace` to
/// write here) and [`summarize_audit_log`] (which reads it back), keyed
/// on this process's own pid so concurrent, unrelated invocations of a
/// policy with `audit.enabled` don't collide.
#[must_use]
pub fn audit_log_path() -> PathBuf {
    std::env::temp_dir().join(format!(
        "rune-secops-warden-audit-{}.log",
        std::process::id()
    ))
}

/// `strace` resolved against the host's `PATH` now, while it is still
/// the caller's: the sandbox launcher runs with the scrubbed sandbox
/// environment, whose `PATH` (if any) is the sandbox's, not the host's.
fn strace_path() -> PathBuf {
    std::env::var_os("PATH")
        .iter()
        .flat_map(std::env::split_paths)
        .map(|dir| dir.join("strace"))
        .find(|candidate| candidate.is_file())
        .unwrap_or_else(|| PathBuf::from("strace"))
}

/// The host-side launcher `strace -f -yy -s 300 -e trace=... -o
/// <audit_log_path()>` that [`crate::sandbox::build_command`] runs in
/// front of `bwrap` (`rune_namespaces::Options::launcher`): `bwrap`, its
/// arguments and the sandboxed program are appended to it.
pub fn audit_launcher() -> Vec<OsString> {
    let mut launcher: Vec<OsString> = vec![strace_path().into()];
    launcher.extend(
        ["-f", "-yy", "-s", "300", "-e", TRACED_SYSCALLS, "-o"]
            .into_iter()
            .map(OsString::from),
    );
    launcher.push(audit_log_path().into());
    launcher
}

/// Summarise the trace `audit_launcher`'s `strace` wrote.
///
/// Returns one readable line per *distinct* syscall that failed — any
/// `%file`-class call (`openat`, `statx`, `access`, `execve`, ...)
/// returning `ENOENT`/`EACCES`/`EPERM`, or `connect` returning anything
/// other than success or `EINPROGRESS` (the normal return for a
/// non-blocking connect actually in progress, not a denial).
///
/// Missing or unreadable log: empty result, not an error — the sandboxed run
/// itself already happened and succeeded or failed on its own merits; a summary
/// that can't be produced shouldn't retroactively fail it.
///
/// Deduplicated (first-occurrence order preserved), not just filtered:
/// confirmed live against a real Claude Code session that its own
/// `CLAUDE.md`/`.git`-root discovery walk alone probes several
/// not-bound candidate directories two or three times over the course of
/// one session — real signal, but repeating the identical line that many
/// times buries it rather than helping find it.
pub fn summarize_audit_log(log_path: &std::path::Path) -> Vec<String> {
    let Ok(file) = std::fs::File::open(log_path) else {
        return Vec::new();
    };
    let mut seen = std::collections::HashSet::new();
    BufReader::new(file)
        .lines()
        .map_while(Result::ok)
        .filter_map(|line| summarize_line(&line))
        .filter(|summary| seen.insert(summary.clone()))
        .collect()
}

fn summarize_line(line: &str) -> Option<String> {
    // The actual line parsing — pid prefix, the `name(args) = result`
    // shape, `<unfinished ...>`/`<... resumed>` fragment handling — is
    // rune_strace's job, not this crate's: none of it is specific to
    // deciding what counts as a policy violation.
    let call = rune_strace::parse_line(line)?;
    let target = rune_strace::first_quoted_string(&call.args).unwrap_or_else(|| call.args.clone());

    if call.name == "connect" {
        if call.result.starts_with('0') || call.result.contains("EINPROGRESS") {
            return None;
        }
        let errno = call
            .result
            .split_whitespace()
            .nth(1)
            .unwrap_or_else(|| call.result.trim());
        return Some(format!("blocked: connect to {target} ({errno})"));
    }

    if !call.result.trim_start().starts_with("-1") {
        return None;
    }
    let errno = call
        .result
        .split_whitespace()
        .nth(1)
        .unwrap_or_else(|| call.result.trim());
    if !matches!(errno, "ENOENT" | "EACCES" | "EPERM") {
        return None;
    }
    let verb = if call.name.starts_with("exec") {
        "exec of"
    } else {
        "access of"
    };
    Some(format!("blocked: {verb} {target} ({errno})"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summarizes_a_blocked_openat() {
        let line = r#"12345 openat(AT_FDCWD, "/home/user/.ssh/id_rsa", O_RDONLY) = -1 ENOENT (No such file or directory)"#;
        assert_eq!(
            summarize_line(line),
            Some("blocked: access of /home/user/.ssh/id_rsa (ENOENT)".to_string())
        );
    }

    /// Regression test: confirmed live that GNU `cat` calls `statx()` on
    /// its argument first, and when that alone fails, never calls
    /// `openat` at all — a real denial the original `openat`-only
    /// syscall filter missed completely, not just logged imprecisely.
    /// See `TRACED_SYSCALLS`'s docs.
    #[test]
    fn summarizes_a_blocked_statx() {
        let line = r#"12345 statx(AT_FDCWD, "/etc/hostname", AT_STATX_SYNC_AS_STAT, STATX_ALL, 0x7ffe1df6ef10) = -1 ENOENT (No such file or directory)"#;
        assert_eq!(
            summarize_line(line),
            Some("blocked: access of /etc/hostname (ENOENT)".to_string())
        );
    }

    #[test]
    fn summarizes_a_blocked_execve() {
        let line = r#"12345 execve("/usr/bin/curl", ["curl"], 0x0 /* 0 vars */) = -1 EACCES (Permission denied)"#;
        assert_eq!(
            summarize_line(line),
            Some("blocked: exec of /usr/bin/curl (EACCES)".to_string())
        );
    }

    #[test]
    fn summarizes_a_blocked_connect() {
        let line = r#"12345 connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16) = -1 ENETUNREACH (Network is unreachable)"#;
        assert_eq!(
            summarize_line(line),
            Some("blocked: connect to 93.184.216.34 (ENETUNREACH)".to_string())
        );
    }

    #[test]
    fn ignores_successful_calls() {
        let line = r#"12345 openat(AT_FDCWD, "/usr/bin/git", O_RDONLY) = 3"#;
        assert_eq!(summarize_line(line), None);
    }

    #[test]
    fn ignores_a_connect_actually_in_progress() {
        let line = r"12345 connect(3, {sa_family=AF_INET, sin_port=htons(443)}, 16) = -1 EINPROGRESS (Operation now in progress)";
        assert_eq!(summarize_line(line), None);
    }

    #[test]
    fn ignores_unrelated_syscalls() {
        let line = r#"12345 read(3, "hello", 5) = 5"#;
        assert_eq!(summarize_line(line), None);
    }

    #[test]
    fn ignores_unfinished_and_resumed_fragments() {
        assert_eq!(
            summarize_line(r#"12345 openat(AT_FDCWD, "/etc/passwd", <unfinished ...>"#),
            None
        );
        assert_eq!(
            summarize_line(r"12345 <... openat resumed>) = -1 ENOENT (No such file)"),
            None
        );
    }

    #[test]
    fn summarize_audit_log_returns_empty_for_a_missing_file() {
        assert_eq!(
            summarize_audit_log(std::path::Path::new("/nonexistent/path/does-not-exist")),
            [] as [String; 0]
        );
    }

    #[test]
    fn summarize_audit_log_reads_a_real_file() {
        let path = std::env::temp_dir().join(format!(
            "rune-secops-warden-audit-test-{}-{:?}.log",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(
            &path,
            "12345 openat(AT_FDCWD, \"/etc/shadow\", O_RDONLY) = -1 EACCES (Permission denied)\n\
             12345 openat(AT_FDCWD, \"/usr/bin/git\", O_RDONLY) = 3\n",
        )
        .unwrap();
        let summary = summarize_audit_log(&path);
        assert_eq!(summary, vec!["blocked: access of /etc/shadow (EACCES)"]);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn summarize_audit_log_deduplicates_repeated_denials() {
        let path = std::env::temp_dir().join(format!(
            "rune-secops-warden-audit-dedup-test-{}-{:?}.log",
            std::process::id(),
            std::thread::current().id()
        ));
        let line = "12345 openat(AT_FDCWD, \"/home/user/project/.git\", O_RDONLY) = -1 ENOENT (No such file or directory)\n";
        std::fs::write(&path, line.repeat(3)).unwrap();
        let summary = summarize_audit_log(&path);
        assert_eq!(
            summary,
            vec!["blocked: access of /home/user/project/.git (ENOENT)"],
            "the same denial repeated verbatim should appear once, not three times"
        );
        std::fs::remove_file(&path).unwrap();
    }
}
