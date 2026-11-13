//! Applying real profiles on Linux.
//!
//! A reduction cannot be undone, so each test applies it on a fresh thread
//! (which then exits) or in a child process: the test binary re-runs
//! itself with `RUNE_PLEDGE_CHILD` naming the test. Tests skip when the
//! kernel lacks Landlock or seccomp.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, reason = "test helpers: a failure fails the test")]

use std::io::ErrorKind;
use std::os::unix::process::ExitStatusExt;
use std::process::Command;

use rune_pledge::{
    Enforcement, Permissions, Profile, Report, Status, Violation, Warning, reduce_capabilities,
};

const CHILD: &str = "RUNE_PLEDGE_CHILD";
/// Exit status of a child that found a layer unavailable.
const SKIP: i32 = 77;

/// Whether both layers can be fully enforced here.
fn available() -> bool {
    let ok = rune_landlock::detect().is_available()
        && rune_seccomp::detect().is_available()
        && rune_seccomp::Arch::native().is_some();
    if !ok {
        eprintln!("skipping: Landlock or seccomp is not available");
    }
    ok
}

/// Applies `profile` on a new thread, runs `then` there, and returns both.
fn on_fresh_thread<T: Send + 'static>(
    profile: Profile,
    then: impl FnOnce() -> T + Send + 'static,
) -> (Report, T) {
    std::thread::spawn(move || {
        let report = reduce_capabilities(&profile).unwrap();
        (report, then())
    })
    .join()
    .unwrap()
}

/// Both layers are in force; the Landlock ABI may be older than the
/// latest, which leaves some rights unenforced.
fn assert_enforced(report: &Report) {
    assert_eq!(report.syscalls, Status::FullyEnforced, "{report:?}");
    assert_ne!(report.filesystem, Status::NotEnforced, "{report:?}");
    for warning in &report.warnings {
        assert!(
            matches!(warning, Warning::FilesystemPartial { .. }),
            "{warning}"
        );
    }
}

#[test]
fn stdio_only_allows_computation_and_nothing_else() {
    if !available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("f");
    std::fs::write(&file, "data").unwrap();
    let pid = std::process::id();

    let (report, (own_pid, read, spawned)) = {
        let file = file.clone();
        on_fresh_thread(Profile::default(), move || {
            let v: Vec<u64> = (0..1000).collect();
            assert_eq!(v.iter().sum::<u64>(), 499_500);
            (
                std::process::id(),
                std::fs::read(&file).map_err(|e| e.kind()),
                Command::new("/bin/true").status().is_ok(),
            )
        })
    };
    assert_enforced(&report);
    assert_eq!(own_pid, pid);
    assert_eq!(read, Err(ErrorKind::PermissionDenied));
    assert!(!spawned, "exec and proc were not promised");
    assert!(report.landlock.is_some() && report.seccomp.is_some());

    // The harness thread was never restricted.
    assert_eq!(std::fs::read(&file).unwrap(), b"data");
}

#[test]
fn path_rules_limit_the_filesystem_promises() {
    if !available() {
        return;
    }
    let allowed = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(allowed.path().join("in"), "in").unwrap();
    std::fs::write(outside.path().join("out"), "out").unwrap();
    let missing = outside.path().join("missing");

    let profile = Profile::pledge("stdio rpath wpath")
        .unwrap()
        .with_path(allowed.path(), "rwc".parse().unwrap())
        .with_path(&missing, Permissions::READ);
    let (report, results) = {
        let (allowed, outside) = (allowed.path().to_owned(), outside.path().to_owned());
        on_fresh_thread(profile, move || {
            (
                std::fs::read_to_string(allowed.join("in")).ok(),
                std::fs::write(allowed.join("in"), "changed").is_ok(),
                // `c` without the cpath promise grants nothing.
                std::fs::write(allowed.join("new"), "x").is_err(),
                std::fs::read(outside.join("out")).is_err(),
            )
        })
    };
    assert_eq!(report.syscalls, Status::FullyEnforced, "{report:?}");
    assert_ne!(report.filesystem, Status::NotEnforced);
    assert!(report.warnings.contains(&Warning::MissingPaths {
        paths: vec![missing]
    }));
    assert_eq!(results, (Some("in".to_owned()), true, true, true));
    assert_eq!(
        std::fs::read_to_string(allowed.path().join("in")).unwrap(),
        "changed"
    );
}

#[test]
fn exec_and_proc_promises_run_programs() {
    if !available() || !std::path::Path::new("/bin/true").exists() {
        return;
    }
    let profile = Profile::pledge("stdio rpath proc exec")
        .unwrap()
        .with_enforcement(Enforcement::Required);
    let (report, status) = on_fresh_thread(profile, || {
        Command::new("/bin/true").status().map_err(|e| e.kind())
    });
    assert_enforced(&report);
    assert!(status.unwrap().success());
}

#[test]
fn kill_violation_kills_the_process() {
    const TEST: &str = "kill_violation_kills_the_process";
    if std::env::var(CHILD).is_ok_and(|name| name == TEST) {
        let report =
            reduce_capabilities(&Profile::default().with_violation(Violation::Kill)).unwrap();
        if report.syscalls != Status::FullyEnforced {
            std::process::exit(SKIP);
        }
        // `socket` was not promised: the kernel kills the process here.
        let _ = std::net::UdpSocket::bind("127.0.0.1:0");
        std::process::exit(0);
    }
    if !available() {
        return;
    }
    let status = Command::new(std::env::current_exe().unwrap())
        .args([TEST, "--exact", "--nocapture", "--test-threads=1"])
        .env(CHILD, TEST)
        .status()
        .unwrap();
    if status.code() == Some(SKIP) {
        eprintln!("skipping: the child could not enforce the filter");
        return;
    }
    assert_eq!(status.signal(), Some(libc::SIGSYS), "{status:?}");
}

/// Calls `clone` directly, as `unshare` would be used to make a namespace,
/// and `clone3`, under the stdio promise.
#[test]
#[ignore = "needs a kernel that allows unprivileged user namespaces"]
#[allow(unsafe_code, reason = "raw clone and clone3 system calls")]
fn stdio_clone_cannot_create_a_user_namespace() {
    if !available() {
        return;
    }
    let raw_clone = |flags: libc::c_long| {
        // SAFETY: with a null stack the child runs on a copy of this
        // thread's stack and exits at once without touching shared state.
        let pid = unsafe { libc::syscall(libc::SYS_clone, flags, 0, 0, 0, 0) };
        if pid == 0 {
            // SAFETY: `_exit` is async-signal-safe and never returns.
            unsafe { libc::_exit(0) };
        }
        (pid, std::io::Error::last_os_error().raw_os_error())
    };
    let user = libc::c_long::from(libc::CLONE_NEWUSER | libc::SIGCHLD);
    let plain = libc::c_long::from(libc::SIGCHLD);

    // The kernel allows it before the profile is applied.
    let (before, _) = raw_clone(user);
    if before < 0 {
        eprintln!("skipping: unprivileged user namespaces are disabled");
        return;
    }
    reap(before);

    let (report, (user, plain, clone3, thread)) = on_fresh_thread(Profile::default(), move || {
        let mut args = [0_u64; 11];
        args[0] = u64::from(libc::CLONE_NEWUSER.unsigned_abs());
        // SAFETY: `args` is a valid `struct clone_args` of the size given.
        let clone3 = unsafe {
            libc::syscall(
                libc::SYS_clone3,
                args.as_mut_ptr(),
                std::mem::size_of_val(&args),
            )
        };
        let clone3 = (clone3, std::io::Error::last_os_error().raw_os_error());
        (
            raw_clone(user),
            raw_clone(plain),
            clone3,
            // Threads still work: libc falls back from clone3 to clone.
            std::thread::spawn(|| 42).join().ok(),
        )
    });
    assert_enforced(&report);
    if plain.0 > 0 {
        reap(plain.0);
    }
    if user.0 > 0 {
        reap(user.0);
    }
    assert_eq!(user, (-1, Some(libc::EPERM)), "clone(CLONE_NEWUSER)");
    assert!(plain.0 > 0, "plain clone: {plain:?}");
    assert_eq!(clone3, (-1, Some(libc::ENOSYS)), "clone3");
    assert_eq!(thread, Some(42));
}

#[allow(unsafe_code, reason = "waitpid on a child this test made")]
fn reap(pid: libc::c_long) {
    let pid = libc::pid_t::try_from(pid).unwrap();
    // SAFETY: waits for a child of this process; the status is discarded.
    unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::__WALL) };
}
