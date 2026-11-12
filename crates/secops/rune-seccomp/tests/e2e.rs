//! End-to-end tests: run real programs through the `rune-seccomp` CLI,
//! which installs the filter and then execs them, so these check that the
//! filter survives `execve` and holds for a separate program.
//!
//! The binary is built only with the `cli` feature (CI's `--all-features`
//! run). Tests that need seccomp skip when the kernel lacks it.

#![cfg(feature = "cli")]
#![allow(clippy::unwrap_used, reason = "test helpers: a failure fails the test")]

use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use rune_seccomp::{Arch, detect};

const BIN: &str = env!("CARGO_BIN_EXE_rune-seccomp");

fn find_program(name: &str) -> Option<PathBuf> {
    ["/usr/bin", "/bin"]
        .iter()
        .map(|dir| Path::new(dir).join(name))
        .find(|path| path.is_file())
}

fn seccomp_available() -> bool {
    let available = detect().is_available() && Arch::native().is_some();
    if !available {
        eprintln!("skipping: seccomp filters are not available");
    }
    available
}

fn run(command: &mut Command) -> Output {
    command.output().unwrap()
}

/// `rune-seccomp` denying directory creation.
fn no_mkdir() -> Command {
    let mut command = Command::new(BIN);
    command.args(["--deny", "mkdir", "--deny", "mkdirat"]);
    command
}

#[test]
fn detect_prints_the_kernel_support() {
    let output = run(Command::new(BIN).arg("--detect"));
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.trim(), format!("seccomp: {}", detect()));
}

#[test]
fn denied_call_fails_and_allowed_programs_run() {
    if !seccomp_available() {
        return;
    }
    let (Some(mkdir), Some(true_)) = (find_program("mkdir"), find_program("true")) else {
        eprintln!("skipping: no mkdir or true");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("made");

    let allowed = run(no_mkdir().arg("--").arg(&true_));
    assert!(allowed.status.success(), "{allowed:?}");

    let denied = run(no_mkdir().arg("--").arg(&mkdir).arg(&target));
    assert!(!denied.status.success(), "{denied:?}");
    assert!(!denied.stderr.is_empty(), "{denied:?}");
    assert!(!target.exists());

    // Without the filter the same command works.
    let plain = run(Command::new(&mkdir).arg(&target));
    assert!(plain.status.success(), "{plain:?}");
}

#[test]
fn trap_kills_the_program_with_sigsys() {
    if !seccomp_available() {
        return;
    }
    let Some(mkdir) = find_program("mkdir") else {
        eprintln!("skipping: no mkdir");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let output = run(no_mkdir()
        .args(["--action", "trap", "--"])
        .arg(&mkdir)
        .arg(dir.path().join("made")));
    assert_eq!(output.status.signal(), Some(libc::SIGSYS), "{output:?}");
}

#[test]
fn audit_mode_allowlist_runs_the_program() {
    if !seccomp_available() || !detect().actions().contains(rune_seccomp::Action::Log) {
        return;
    }
    let Some(true_) = find_program("true") else {
        eprintln!("skipping: no true");
        return;
    };
    let output = run(Command::new(BIN)
        .args(["--action", "log", "--allow", "execve", "--verbose", "--"])
        .arg(&true_));
    assert!(output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("fully enforced"),
        "{output:?}"
    );
}

#[test]
fn emit_writes_a_sock_filter_array() {
    if Arch::native().is_none() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("filter.bpf");
    let output = run(Command::new(BIN)
        .arg("--deny-dangerous")
        .arg("--emit")
        .arg(&path));
    assert!(output.status.success(), "{output:?}");
    let bytes = std::fs::read(&path).unwrap();
    assert_ne!(bytes.len(), 0);
    assert_eq!(bytes.len() % 8, 0);
}

#[test]
fn unknown_syscalls_are_rejected() {
    let output = run(Command::new(BIN).args(["--deny", "raed", "--", "true"]));
    assert_eq!(output.status.code(), Some(125), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("unknown system call `raed`"));
}
