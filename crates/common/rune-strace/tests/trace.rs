//! End-to-end tests: trace real child processes with `ptrace`. Each test
//! skips (passing) when this host forbids `ptrace` or lacks the program it
//! runs.

#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    reason = "test helpers: a failed trace or a bad fixture fails the test"
)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use rune_strace::{Error, Exit, NATIVE_AUDIT_ARCH, Options, Report, SyscallId, probe, trace};

fn available() -> bool {
    if NATIVE_AUDIT_ARCH.is_none() {
        eprintln!("skipping: no AUDIT_ARCH value for this architecture");
        return false;
    }
    match probe() {
        Ok(()) => true,
        Err(err) => {
            eprintln!("skipping: {err}");
            false
        }
    }
}

fn program(name: &str) -> Option<PathBuf> {
    let found = ["/usr/bin", "/bin"]
        .iter()
        .map(|dir| Path::new(dir).join(name))
        .find(|path| path.is_file());
    if found.is_none() {
        eprintln!("skipping: no {name}");
    }
    found
}

/// Traces `name args…` with quiet standard streams; `None` (skip) when
/// tracing is unavailable or the program is not installed.
fn run(name: &str, args: &[&str], options: &Options) -> Option<Report> {
    if !available() {
        return None;
    }
    let mut command = Command::new(program(name)?);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    Some(trace(&mut command, options).unwrap())
}

fn native(nr: libc::c_long) -> SyscallId {
    SyscallId::new(NATIVE_AUDIT_ARCH.unwrap(), u64::try_from(nr).unwrap())
}

#[test]
fn produces_a_syscall_list_for_a_child() {
    let Some(report) = run("ls", &["/"], &Options::default()) else {
        return;
    };
    assert_eq!(report.exit, Some(Exit::Code(0)));
    assert_eq!(report.processes, 1);
    let profile = &report.profile;
    for nr in [libc::SYS_execve, libc::SYS_write, libc::SYS_exit_group] {
        assert!(profile.contains(native(nr)), "missing syscall {nr}");
    }
    // ls lists a directory.
    assert!(profile.contains(native(libc::SYS_getdents64)));
    let numbers = profile.numbers();
    assert!(
        numbers.windows(2).all(|w| w[0] < w[1]),
        "sorted and distinct"
    );
    assert_eq!(profile.count(native(libc::SYS_execve)), 1);
    assert!(profile.total() >= u64::try_from(numbers.len()).unwrap());
}

#[test]
fn follows_forked_children() {
    // The child writes through `cat`, a separate process.
    let script = "echo hello | cat > /dev/null; exit 3";
    let Some(report) = run("sh", &["-c", script], &Options::default()) else {
        return;
    };
    assert_eq!(report.exit, Some(Exit::Code(3)));
    assert!(report.processes >= 2, "{} processes", report.processes);
    // The forked children exec'd programs of their own.
    assert!(report.profile.count(native(libc::SYS_execve)) >= 2);
}

#[test]
fn not_following_forks_traces_only_the_child() {
    let options = Options::default().with_follow_forks(false);
    let Some(report) = run("sh", &["-c", "cat /dev/null; true"], &options) else {
        return;
    };
    assert_eq!(report.exit, Some(Exit::Code(0)));
    assert_eq!(report.processes, 1);
    // Only the shell's own initial execve, not cat's.
    assert_eq!(report.profile.count(native(libc::SYS_execve)), 1);
}

#[test]
fn reports_death_by_signal() {
    let Some(report) = run("sh", &["-c", "kill -KILL $$"], &Options::default()) else {
        return;
    };
    assert_eq!(report.exit, Some(Exit::Signal(libc::SIGKILL)));
    assert!(report.profile.contains(native(libc::SYS_kill)));
}

#[test]
fn passes_signals_through() {
    // A handled signal must reach the tracee: the trap runs and sets the
    // exit code.
    let script = "trap 'exit 7' USR1; kill -USR1 $$; sleep 5; exit 1";
    let Some(report) = run("sh", &["-c", script], &Options::default()) else {
        return;
    };
    assert_eq!(report.exit, Some(Exit::Code(7)));
}

#[test]
fn a_missing_program_is_a_spawn_error() {
    if !available() {
        return;
    }
    let mut command = Command::new("/nonexistent/program");
    assert!(matches!(
        trace(&mut command, &Options::default()),
        Err(Error::Spawn(_))
    ));
}

#[test]
fn does_not_reap_other_children() {
    // A child spawned by this thread before tracing must still be
    // waitable afterwards.
    let Some(sleep) = program("sleep") else {
        return;
    };
    let mut other = Command::new(sleep).arg("0.2").spawn().unwrap();
    if run("true", &[], &Options::default()).is_none() {
        other.wait().unwrap();
        return;
    }
    assert!(other.wait().unwrap().success());
}
