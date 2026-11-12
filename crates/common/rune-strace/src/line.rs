//! Parsing text that `strace` printed.

use std::collections::BTreeMap;

#[cfg(doc)]
use crate::Profile;
#[cfg(all(doc, target_os = "linux"))]
use crate::trace;

/// One parsed `strace -f` line: `<pid> <name>(<args>) = <result>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Syscall {
    /// The tracee's pid, if the line was prefixed with one (`strace -f`
    /// always prefixes multi-process traces; a single-process trace
    /// without `-f` might not).
    pub pid: Option<String>,
    /// Syscall name, e.g. `openat`.
    pub name: String,
    /// The raw, unparsed argument list — still containing whatever
    /// quoting/formatting `strace` itself used (`-yy` decorations,
    /// nested braces for sockaddr structs, ...). Use
    /// [`first_quoted_string`] to pull a path or address out of it.
    pub args: String,
    /// The raw result text after `= `, e.g. `"3"`, `"-1 ENOENT (No such
    /// file or directory)"`, or `"0"`.
    pub result: String,
}

/// Parse one line of `strace -f` output.
///
/// Returns `None` for a line that doesn't match the `name(args) = result` shape
/// at all, and — the one piece of `strace`-specific knowledge this function has
/// — for `<unfinished ...>`/`<... name resumed>` fragment lines. `strace -f`
/// splits a call across two such lines when another traced thread's syscall
/// interleaves mid-call; reassembling the pair by pid is a caller-level concern
/// (this crate stays line-at-a-time and stateless), so fragments are skipped
/// here rather than misparsed as a complete call.
#[must_use]
pub fn parse_line(line: &str) -> Option<Syscall> {
    let (pid, rest) = split_pid(line);
    let pid = pid.map(str::to_owned);

    if rest.contains("<unfinished") || rest.contains("<... ") {
        return None;
    }

    let (call, tail) = rest.split_once('(')?;
    // strace pads short calls so results line up in a column:
    // `getpid()                                = 42`.
    let (head, result) = tail.rsplit_once(" = ")?;
    let args = head.trim_end().strip_suffix(')')?;
    Some(Syscall {
        pid,
        name: call.trim().to_string(),
        args: args.to_string(),
        result: result.trim().to_string(),
    })
}

/// Pull the first `"..."`-quoted argument out of a raw strace argument list.
///
/// That is the path for `openat`/`execve`, or the formatted address for
/// `connect` (strace's `-yy` prints it as e.g. `"1.2.3.4:443"` for a
/// resolved socket).
#[must_use]
pub fn first_quoted_string(args: &str) -> Option<String> {
    let start = args.find('"')? + 1;
    let end = args[start..].find('"')? + start;
    Some(args[start..end].to_string())
}

/// Splits the pid prefix off a trace line: `12345 …` (`strace -f -o
/// file`) or `[pid 12345] …` (`strace -f` to a terminal).
fn split_pid(line: &str) -> (Option<&str>, &str) {
    let trimmed = line.trim();
    if let Some(after) = trimmed.strip_prefix("[pid")
        && let Some((pid, rest)) = after.split_once(']')
    {
        let pid = pid.trim();
        if !pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit()) {
            return (Some(pid), rest.trim());
        }
    }
    match trimmed.split_once(' ') {
        Some((maybe_pid, rest)) if maybe_pid.chars().all(|c| c.is_ascii_digit()) => {
            (Some(maybe_pid), rest.trim())
        }
        _ => (None, trimmed),
    }
}

/// The name of the system call a trace line starts, if it starts one.
///
/// Unlike [`parse_line`], this accepts an `<unfinished ...>` line — the
/// call was made, its result just comes later — and returns `None` for the
/// matching `<... name resumed>` line, so each call is seen exactly once.
/// Signal (`--- SIGCHLD … ---`) and exit (`+++ exited with 0 +++`) lines
/// return `None`.
///
/// ```
/// use rune_strace::call_name;
///
/// assert_eq!(call_name("42 openat(AT_FDCWD, \"/etc\", O_RDONLY <unfinished ...>"), Some("openat"));
/// assert_eq!(call_name("42 <... openat resumed>) = 3"), None);
/// assert_eq!(call_name("[pid 42] close(3) = 0"), Some("close"));
/// ```
#[must_use]
pub fn call_name(line: &str) -> Option<&str> {
    let (_, rest) = split_pid(line);
    let (name, _) = rest.split_once('(')?;
    let valid = !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    valid.then_some(name)
}

/// Counts the system calls in a whole `strace` log by name: the text-side
/// counterpart of a [`Profile`], for traces captured with `strace -f -o
/// <file>` (on a machine where [`trace`] cannot run, say).
///
/// Each call counts once, whether it was logged whole or split into
/// `<unfinished ...>`/`<... resumed>` halves.
///
/// ```
/// use rune_strace::count_calls;
///
/// let log = "\
/// 7 openat(AT_FDCWD, \"/etc/hosts\", O_RDONLY) = 3
/// 7 read(3, <unfinished ...>
/// 8 close(4) = 0
/// 7 <... read resumed>\"127.0.0.1 localhost\\n\", 4096) = 20
/// 7 read(3, \"\", 4096) = 0
/// 7 +++ exited with 0 +++
/// ";
/// let counts = count_calls(log);
/// assert_eq!(counts.get("read"), Some(&2));
/// assert_eq!(counts.len(), 3);
/// ```
#[must_use]
pub fn count_calls(log: &str) -> BTreeMap<String, u64> {
    let mut counts = BTreeMap::new();
    for name in log.lines().filter_map(call_name) {
        let count: &mut u64 = counts.entry(name.to_owned()).or_insert(0);
        *count = count.saturating_add(1);
    }
    counts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_bracketed_pid_prefix() {
        let call = parse_line("[pid  2854730] set_robust_list(0x70fa0b3cda20, 24) = 0").unwrap();
        assert_eq!(call.pid.as_deref(), Some("2854730"));
        assert_eq!(call.name, "set_robust_list");
        assert_eq!(call.result, "0");
    }

    #[test]
    fn parses_a_column_aligned_result() {
        let call = parse_line("getpid()                                = 2854727").unwrap();
        assert_eq!(call.name, "getpid");
        assert_eq!(call.args, "");
        assert_eq!(call.result, "2854727");
    }

    #[test]
    fn call_name_rejects_non_calls() {
        assert_eq!(call_name("--- SIGCHLD {si_signo=SIGCHLD} ---"), None);
        assert_eq!(call_name("1 +++ exited with 0 +++"), None);
        assert_eq!(call_name("(no name)"), None);
        assert_eq!(call_name(""), None);
    }

    /// A real `strace -f -o` capture (strace 6.x, Linux 7.0) of
    /// `sh -c 'ls / >/dev/null & wait'`, excerpted around a fork.
    const FORK_EXCERPT: &str = "\
2854716 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD <unfinished ...>
2854717 rt_sigprocmask(SIG_SETMASK, [] <unfinished ...>
2854716 <... clone resumed>, child_tidptr=0x748c33619a10) = 2854717
2854716 rt_sigprocmask(SIG_SETMASK, [] <unfinished ...>
2854717 <... rt_sigprocmask resumed>, NULL, 8) = 0
2854716 <... rt_sigprocmask resumed>, [], 8) = 0
2854717 execve(\"/usr/bin/ls\", [\"ls\", \"/\"], 0x5c4ab6f0a8 /* 30 vars */) = 0
2854717 exit_group(0)                     = ?
2854717 +++ exited with 0 +++
2854716 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=2854717, si_uid=1000, si_status=0, si_utime=0, si_stime=0} ---
2854716 wait4(-1, [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 2854717
";

    #[test]
    fn known_answer_fork_excerpt() {
        let counts = count_calls(FORK_EXCERPT);
        let expected: BTreeMap<String, u64> = [
            ("clone", 1),
            ("execve", 1),
            ("exit_group", 1),
            ("rt_sigprocmask", 2),
            ("wait4", 1),
        ]
        .into_iter()
        .map(|(name, n)| (name.to_owned(), n))
        .collect();
        assert_eq!(counts, expected);
        let complete: Vec<_> = FORK_EXCERPT.lines().filter_map(parse_line).collect();
        assert_eq!(complete.len(), 3);
        assert_eq!(complete[1].name, "exit_group");
        assert_eq!(complete[1].args, "0");
        assert_eq!(complete[1].result, "?");
        assert_eq!(complete[2].name, "wait4");
        assert_eq!(complete[2].result, "2854717");
    }

    #[test]
    fn parses_a_simple_successful_call() {
        let call = parse_line(r#"12345 openat(AT_FDCWD, "/usr/bin/git", O_RDONLY) = 3"#).unwrap();
        assert_eq!(call.pid.as_deref(), Some("12345"));
        assert_eq!(call.name, "openat");
        assert_eq!(call.args, r#"AT_FDCWD, "/usr/bin/git", O_RDONLY"#);
        assert_eq!(call.result, "3");
    }

    #[test]
    fn parses_a_failed_call_with_errno() {
        let call = parse_line(
            r#"12345 openat(AT_FDCWD, "/home/user/.ssh/id_rsa", O_RDONLY) = -1 ENOENT (No such file or directory)"#,
        )
        .unwrap();
        assert_eq!(call.result, "-1 ENOENT (No such file or directory)");
    }

    #[test]
    fn parses_a_line_with_no_pid_prefix() {
        let call = parse_line(r#"read(3, "hello", 5) = 5"#).unwrap();
        assert_eq!(call.pid, None);
        assert_eq!(call.name, "read");
    }

    #[test]
    fn skips_unfinished_fragments() {
        assert_eq!(
            parse_line(r#"12345 openat(AT_FDCWD, "/etc/passwd", <unfinished ...>"#),
            None
        );
    }

    #[test]
    fn skips_resumed_fragments() {
        assert_eq!(
            parse_line(r"12345 <... openat resumed>) = -1 ENOENT (No such file)"),
            None
        );
    }

    #[test]
    fn rejects_a_line_with_no_call_shape_at_all() {
        assert_eq!(parse_line("not a syscall line"), None);
        assert_eq!(parse_line(""), None);
    }

    #[test]
    fn first_quoted_string_extracts_a_path() {
        assert_eq!(
            first_quoted_string(r#"AT_FDCWD, "/etc/hosts", O_RDONLY"#).as_deref(),
            Some("/etc/hosts")
        );
    }

    #[test]
    fn first_quoted_string_extracts_a_formatted_address() {
        assert_eq!(
            first_quoted_string(r#"3, {sa_family=AF_INET, sin_addr=inet_addr("93.184.216.34")}"#)
                .as_deref(),
            Some("93.184.216.34")
        );
    }

    #[test]
    fn first_quoted_string_none_when_no_quotes_present() {
        assert_eq!(first_quoted_string("3, NULL, 0"), None);
    }
}
