//! End-to-end tests: run real programs through the `rune-landlock` CLI,
//! which restricts itself and then execs them, so these check that the
//! ruleset survives `execve` and holds for a separate program.
//!
//! The binary is built only with the `cli` feature (CI's `--all-features`
//! run). Tests that need Landlock skip when the kernel lacks it.

#![cfg(feature = "cli")]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use rune_landlock::{Abi, detect};

const BIN: &str = env!("CARGO_BIN_EXE_rune-landlock");

/// System directories a dynamically linked program needs to start.
const SYSTEM: &[&str] = &[
    "/usr",
    "/bin",
    "/lib",
    "/lib64",
    "/lib32",
    "/etc/ld.so.cache",
];

fn find_program(name: &str) -> Option<PathBuf> {
    ["/usr/bin", "/bin"]
        .iter()
        .map(|dir| Path::new(dir).join(name))
        .find(|path| path.is_file())
}

/// The sandbox's base arguments: read+exec on the system directories.
fn sandbox() -> Command {
    let mut command = Command::new(BIN);
    for dir in SYSTEM {
        command.arg("--read-exec").arg(dir);
    }
    command
}

fn landlock_available() -> bool {
    let available = detect().is_available();
    if !available {
        eprintln!("skipping: Landlock is not available on this kernel");
    }
    available
}

#[allow(
    clippy::unwrap_used,
    reason = "test helper: failing to spawn fails the test"
)]
fn run(command: &mut Command) -> Output {
    command.output().unwrap()
}

#[test]
fn detect_prints_the_kernel_support() {
    let output = run(Command::new(BIN).arg("--detect"));
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.trim(), format!("landlock: {}", detect()));
}

#[test]
fn allowed_paths_are_readable_and_others_are_not() {
    if !landlock_available() {
        return;
    }
    let Some(cat) = find_program("cat") else {
        eprintln!("skipping: no cat");
        return;
    };
    let allowed = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(allowed.path().join("ok.txt"), "visible").unwrap();
    std::fs::write(outside.path().join("secret.txt"), "hidden").unwrap();

    let inside = run(sandbox()
        .arg("--read")
        .arg(allowed.path())
        .arg("--")
        .arg(&cat)
        .arg(allowed.path().join("ok.txt")));
    assert!(inside.status.success(), "{inside:?}");
    assert_eq!(inside.stdout, b"visible");

    let denied = run(sandbox()
        .arg("--read")
        .arg(allowed.path())
        .arg("--")
        .arg(&cat)
        .arg(outside.path().join("secret.txt")));
    assert!(!denied.status.success(), "{denied:?}");
    assert_eq!(denied.stdout, b"");
    assert!(
        String::from_utf8_lossy(&denied.stderr).contains("Permission denied"),
        "{denied:?}"
    );
}

#[test]
fn writes_need_a_read_write_grant() {
    if !landlock_available() {
        return;
    }
    let Some(sh) = find_program("sh") else {
        eprintln!("skipping: no sh");
        return;
    };
    let read_only = tempfile::tempdir().unwrap();
    let writable = tempfile::tempdir().unwrap();
    let write = |dir: &Path| {
        run(sandbox()
            .arg("--read")
            .arg(read_only.path())
            .arg("--read-write")
            .arg(writable.path())
            .arg("--")
            .arg(&sh)
            .arg("-c")
            .arg("echo hi > \"$1\"")
            .arg("sh")
            .arg(dir.join("new.txt")))
    };

    let ok = write(writable.path());
    assert!(ok.status.success(), "{ok:?}");
    assert_eq!(
        std::fs::read_to_string(writable.path().join("new.txt")).unwrap(),
        "hi\n"
    );

    let denied = write(read_only.path());
    assert!(!denied.status.success(), "{denied:?}");
    assert!(!read_only.path().join("new.txt").exists());
}

#[test]
fn programs_outside_the_exec_allowlist_cannot_run() {
    if !landlock_available() {
        return;
    }
    let Some(cat) = find_program("cat") else {
        eprintln!("skipping: no cat");
        return;
    };
    // Read-only on the system directories: the program is visible but not
    // executable.
    let mut command = Command::new(BIN);
    for dir in SYSTEM {
        command.arg("--read").arg(dir);
    }
    let output = run(command.arg("--").arg(&cat).arg("/etc/hostname"));
    assert_eq!(output.status.code(), Some(126), "{output:?}");
}

#[test]
fn missing_paths_are_skipped_unless_asked_not_to() {
    if !landlock_available() {
        return;
    }
    let Some(cat) = find_program("cat") else {
        eprintln!("skipping: no cat");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("f"), "x").unwrap();
    let missing = dir.path().join("missing");

    let skipped = run(sandbox()
        .arg("--verbose")
        .arg("--read")
        .arg(dir.path())
        .arg("--read")
        .arg(&missing)
        .arg("--")
        .arg(&cat)
        .arg(dir.path().join("f")));
    assert!(skipped.status.success(), "{skipped:?}");
    assert!(String::from_utf8_lossy(&skipped.stderr).contains("skipped missing"));

    let strict = run(sandbox()
        .arg("--no-skip-missing")
        .arg("--read")
        .arg(&missing)
        .arg("--")
        .arg(&cat));
    assert_eq!(strict.status.code(), Some(125), "{strict:?}");
}

/// The ABI fallback: asking for more than the kernel has still sandboxes
/// with best effort, and refuses to run with `--strict`.
#[test]
fn abi_fallback() {
    let support = detect();
    let Some(cat) = find_program("cat") else {
        eprintln!("skipping: no cat");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("f"), "x").unwrap();
    let attempt = |abi: Abi, strict: bool| {
        let mut command = sandbox();
        command
            .arg("--verbose")
            .arg("--abi")
            .arg(abi.number().to_string());
        if strict {
            command.arg("--strict");
        }
        run(command
            .arg("--read")
            .arg(dir.path())
            .arg("--")
            .arg(&cat)
            .arg(dir.path().join("f")))
    };

    // Best effort always runs the program, whatever the kernel.
    let best = attempt(Abi::LATEST, false);
    assert!(best.status.success(), "{best:?}");
    let stderr = String::from_utf8_lossy(&best.stderr);
    let expected = match support.abi() {
        None => "not enforced",
        Some(abi) if abi < Abi::LATEST => "partially enforced",
        Some(_) => "fully enforced",
    };
    assert!(stderr.contains(expected), "{stderr}");

    // Strict runs only when the kernel has the ABI.
    let strict = attempt(Abi::LATEST, true);
    if support.abi() == Some(Abi::LATEST) {
        assert!(strict.status.success(), "{strict:?}");
    } else {
        assert_eq!(strict.status.code(), Some(125), "{strict:?}");
        assert!(String::from_utf8_lossy(&strict.stderr).contains("is required"));
    }

    if let Some(kernel) = support.abi() {
        let exact = attempt(kernel, true);
        assert!(exact.status.success(), "{exact:?}");
        assert!(String::from_utf8_lossy(&exact.stderr).contains("fully enforced"));
    }
}
