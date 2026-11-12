//! Installing real filters.
//!
//! A filter cannot be removed, so each test installs it on a fresh thread
//! (which then exits) or in a child process: the test binary re-runs itself
//! with `RUNE_SECCOMP_CHILD` naming the test, and that run installs the
//! filter and reports through its exit status. Tests skip when the kernel
//! has no seccomp.

#![allow(clippy::unwrap_used, reason = "test helpers: a failure fails the test")]

use std::os::unix::process::ExitStatusExt;
use std::process::{Command, ExitStatus};

use rune_seccomp::{Action, Arch, Options, Report, Status, detect, install};

const CHILD: &str = "RUNE_SECCOMP_CHILD";
/// Exit status of a child that found seccomp unavailable.
const SKIP: i32 = 77;

fn seccomp_available() -> bool {
    let available = detect().is_available() && Arch::native().is_some();
    if !available {
        eprintln!("skipping: seccomp filters are not available");
    }
    available
}

/// `getppid()` as the C library returns it: `u32::MAX` is -1, a failure.
fn getppid() -> u32 {
    std::os::unix::process::parent_id()
}

const FAILED: u32 = u32::MAX;

/// Installs `options` on a new thread, runs `then` there, and returns both.
fn on_fresh_thread<T: Send + 'static>(
    options: Options,
    then: impl FnOnce() -> T + Send + 'static,
) -> (Report, T) {
    std::thread::spawn(move || {
        let report = install(&options).unwrap();
        (report, then())
    })
    .join()
    .unwrap()
}

/// Whether this process is the child run for `test`.
fn is_child(test: &str) -> bool {
    std::env::var(CHILD).is_ok_and(|name| name == test)
}

/// Re-runs this test binary for `test` only, as a child.
fn run_child(test: &str) -> Option<ExitStatus> {
    let status = Command::new(std::env::current_exe().unwrap())
        .args([test, "--exact", "--nocapture", "--test-threads=1"])
        .env(CHILD, test)
        .status()
        .unwrap();
    if status.code() == Some(SKIP) {
        eprintln!("skipping: the child found seccomp unavailable");
        return None;
    }
    Some(status)
}

/// In a child: exit with `SKIP` unless the filter is fully enforced.
fn require_enforced(report: &Report) {
    if report.status != Status::FullyEnforced {
        std::process::exit(SKIP);
    }
}

#[test]
fn denylist_blocks_listed_calls_on_its_thread_only() {
    if !seccomp_available() {
        return;
    }
    let real_parent = getppid();
    let (report, (own_pid, parent)) = on_fresh_thread(
        Options::denylist(Action::EPERM).with_syscall("getppid"),
        || (std::process::id(), getppid()),
    );
    assert_eq!(report.status, Status::FullyEnforced, "{report:?}");
    assert_eq!(report.rules, 1);
    // The allowed call passes, the blocked one fails...
    assert_eq!(own_pid, std::process::id());
    assert_eq!(parent, FAILED);
    // ...and only on the filtered thread.
    assert_eq!(getppid(), real_parent);
}

#[test]
fn log_action_lets_the_call_through() {
    if !seccomp_available() || !detect().actions().contains(Action::Log) {
        return;
    }
    let real_parent = getppid();
    let (report, ppid) = on_fresh_thread(
        Options::denylist(Action::Log).with_syscall("getppid"),
        getppid,
    );
    assert_eq!(report.status, Status::FullyEnforced, "{report:?}");
    assert_eq!(ppid, real_parent);
}

#[test]
fn errno_value_is_returned() {
    if !seccomp_available() {
        return;
    }
    let (_, result) = on_fresh_thread(
        Options::denylist(Action::ENOSYS)
            .with_syscall("mkdirat")
            .with_syscall("mkdir"),
        || std::fs::create_dir("/nonexistent-rune-seccomp/dir").unwrap_err(),
    );
    assert_eq!(result.raw_os_error(), Some(libc::ENOSYS));
}

#[test]
fn allowlist_denies_everything_else() {
    const TEST: &str = "allowlist_denies_everything_else";
    if is_child(TEST) {
        let pid = std::process::id();
        let report = install(&Options::allowlist(Action::EPERM).with_syscalls([
            "getpid",
            "exit",
            "exit_group",
        ]))
        .unwrap();
        require_enforced(&report);
        // Nothing below may allocate or print: only the three calls work.
        let allowed = std::process::id() == pid;
        let denied = getppid() == FAILED;
        std::process::exit(match (allowed, denied) {
            (true, true) => 0,
            (false, _) => 10,
            (true, false) => 11,
        });
    }
    if !seccomp_available() {
        return;
    }
    if let Some(status) = run_child(TEST) {
        assert_eq!(status.code(), Some(0), "{status:?}");
    }
}

#[test]
fn trap_action_sends_sigsys() {
    const TEST: &str = "trap_action_sends_sigsys";
    if is_child(TEST) {
        let report = install(&Options::denylist(Action::Trap).with_syscall("getppid")).unwrap();
        require_enforced(&report);
        let _ = getppid();
        std::process::exit(0);
    }
    if !seccomp_available() {
        return;
    }
    if let Some(status) = run_child(TEST) {
        assert_eq!(status.signal(), Some(libc::SIGSYS), "{status:?}");
    }
}

#[test]
fn kill_process_action_kills_the_process() {
    const TEST: &str = "kill_process_action_kills_the_process";
    if is_child(TEST) {
        let report =
            install(&Options::denylist(Action::KillProcess).with_syscall("getppid")).unwrap();
        require_enforced(&report);
        let _ = getppid();
        std::process::exit(0);
    }
    if !seccomp_available() {
        return;
    }
    if let Some(status) = run_child(TEST) {
        assert_eq!(status.signal(), Some(libc::SIGSYS), "{status:?}");
    }
}

#[test]
fn all_threads_filters_existing_threads() {
    const TEST: &str = "all_threads_filters_existing_threads";
    if is_child(TEST) {
        let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
        let other = std::thread::spawn(move || {
            go_rx.recv().unwrap();
            getppid()
        });
        let report = install(
            &Options::denylist(Action::EPERM)
                .with_syscall("getppid")
                .with_all_threads(true),
        )
        .unwrap();
        require_enforced(&report);
        go_tx.send(()).unwrap();
        let ppid = other.join().unwrap();
        std::process::exit(i32::from(!(report.all_threads && ppid == FAILED)));
    }
    if !seccomp_available() {
        return;
    }
    if let Some(status) = run_child(TEST) {
        assert_eq!(status.code(), Some(0), "{status:?}");
    }
}
