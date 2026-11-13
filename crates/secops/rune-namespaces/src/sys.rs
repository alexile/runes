//! The crate's only `unsafe` code: `pre_exec` hooks that run between
//! `fork` and `exec`. Everything they need is prepared before the fork;
//! the hooks themselves make raw system calls only, which are
//! async-signal-safe, and never allocate.

use std::ffi::CStr;
use std::os::fd::RawFd;
use std::os::unix::process::CommandExt;
use std::process::Command;

/// Everything the `unshare` backend does in the child before `exec`.
#[derive(Debug, Default)]
pub struct ChildSetup {
    /// Call `setsid()`.
    pub new_session: bool,
    /// Set `PR_SET_PDEATHSIG` to `SIGKILL`.
    pub die_with_parent: bool,
    /// `unshare(2)` flags; zero for none.
    pub unshare_flags: libc::c_int,
    /// `(uid_map, gid_map)` contents, written after unsharing a user
    /// namespace (with `setgroups` denied first).
    pub id_maps: Option<(Vec<u8>, Vec<u8>)>,
    /// Hostname to set after unsharing the UTS namespace.
    pub hostname: Option<Vec<u8>>,
    /// A seccomp-bpf program to install last, with `no_new_privs`.
    pub seccomp: Option<Vec<libc::sock_filter>>,
}

/// The current real user and group IDs.
#[allow(
    unsafe_code,
    reason = "`getuid`/`getgid` are FFI calls; they cannot fail and take no pointers"
)]
pub fn ids() -> (libc::uid_t, libc::gid_t) {
    // SAFETY: getuid and getgid have no preconditions and always succeed.
    unsafe { (libc::getuid(), libc::getgid()) }
}

fn check(ret: libc::c_int) -> std::io::Result<()> {
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Writes `data` to the file at `path`, in the child: `open`, `write`,
/// `close`, no allocation.
#[allow(
    unsafe_code,
    reason = "raw open/write/close are the async-signal-safe way to write a file after fork"
)]
fn write_file(path: &CStr, data: &[u8]) -> std::io::Result<()> {
    // SAFETY: `path` is a valid NUL-terminated string; the flags are valid.
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
    check(fd)?;
    // SAFETY: `data` is a valid slice for the duration of the call, and a
    // write to a /proc map file is all-or-nothing.
    let written = unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
    let result = if written < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    };
    // SAFETY: `fd` was opened above and is closed exactly once.
    unsafe { libc::close(fd) };
    result
}

impl ChildSetup {
    #[allow(
        unsafe_code,
        reason = "prctl/setsid/unshare/sethostname are FFI calls made in the forked child"
    )]
    fn run(&self, parent: libc::pid_t) -> std::io::Result<()> {
        if self.new_session {
            // SAFETY: setsid takes no arguments.
            check(unsafe { libc::setsid() })?;
        }
        if self.die_with_parent {
            // SAFETY: PR_SET_PDEATHSIG takes a signal number; extra args are ignored.
            check(unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) })?;
            // If the parent died before the prctl, the signal will never
            // come and we have been reparented: give up instead.
            // SAFETY: getppid takes no arguments and cannot fail.
            if unsafe { libc::getppid() } != parent {
                return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
            }
        }
        if self.unshare_flags != 0 {
            // SAFETY: unshare takes a flag word.
            check(unsafe { libc::unshare(self.unshare_flags) })?;
        }
        if let Some((uid_map, gid_map)) = &self.id_maps {
            write_file(c"/proc/self/setgroups", b"deny")?;
            write_file(c"/proc/self/uid_map", uid_map)?;
            write_file(c"/proc/self/gid_map", gid_map)?;
        }
        if let Some(hostname) = &self.hostname {
            // SAFETY: the pointer and length describe a live byte slice.
            check(unsafe { libc::sethostname(hostname.as_ptr().cast(), hostname.len()) })?;
        }
        if let Some(filter) = &self.seccomp {
            // SAFETY: PR_SET_NO_NEW_PRIVS takes the value 1; extra args must be 0.
            check(unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) })?;
            let len = u16::try_from(filter.len())
                .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
            let prog = libc::sock_fprog {
                len,
                filter: filter.as_ptr().cast_mut(),
            };
            // SAFETY: `prog` points at `filter`, which outlives the call;
            // the kernel copies the program before returning.
            check(unsafe {
                libc::prctl(
                    libc::PR_SET_SECCOMP,
                    libc::SECCOMP_MODE_FILTER,
                    &raw const prog,
                    0,
                    0,
                )
            })?;
        }
        Ok(())
    }
}

/// Installs `setup` as a `pre_exec` hook on `command`.
#[allow(
    unsafe_code,
    reason = "`CommandExt::pre_exec` is unsafe; the hook only makes async-signal-safe system calls"
)]
pub fn install(command: &mut Command, setup: ChildSetup) {
    // Taken before the fork, for the child to check after setting its
    // death signal.
    let parent = libc::pid_t::try_from(std::process::id()).unwrap_or(libc::pid_t::MAX);
    // SAFETY: `ChildSetup::run` makes raw system calls only and touches no
    // heap state that `fork` could have left inconsistent: every buffer
    // it reads was allocated before the fork and is only borrowed.
    unsafe {
        command.pre_exec(move || setup.run(parent));
    }
}

/// Keeps `fd` open across `exec` in the child only: clears its
/// `FD_CLOEXEC` flag after the fork, so it is never leaked into processes
/// other threads spawn. `keep` owns the descriptor and lives as long as
/// `command`.
#[allow(
    unsafe_code,
    reason = "`CommandExt::pre_exec` is unsafe; the hook only calls async-signal-safe `fcntl`"
)]
pub fn inherit_fd<T: Send + Sync + 'static>(command: &mut Command, fd: RawFd, keep: T) {
    // SAFETY: the closure only calls `fcntl` on a descriptor that `keep`
    // holds open, which is async-signal-safe.
    unsafe {
        command.pre_exec(move || {
            let _owned = &keep;
            check(libc::fcntl(fd, libc::F_SETFD, 0))
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HELPER: &str = "RUNE_NAMESPACES_PDEATH_HELPER";
    const TEST: &str = "sys::tests::child_of_a_parent_that_already_died_does_not_run";

    /// The parent dies after the fork but before the child sets its death
    /// signal: the signal is never sent, so the child has to notice on its
    /// own.
    #[test]
    #[allow(unsafe_code, reason = "a test hook that sleeps, and _exit")]
    fn child_of_a_parent_that_already_died_does_not_run() {
        if let Ok(marker) = std::env::var(HELPER) {
            // The helper: spawn a child that waits in `pre_exec` long
            // enough for this process to exit first.
            std::thread::spawn(|| {
                std::thread::sleep(std::time::Duration::from_millis(200));
                // SAFETY: ends the helper at once, as a crash would.
                unsafe { libc::_exit(0) };
            });
            let mut command = Command::new("/bin/sh");
            command.args(["-c", "sleep 1; touch \"$0\"", &marker]);
            // SAFETY: the hook only sleeps.
            unsafe {
                command.pre_exec(|| {
                    std::thread::sleep(std::time::Duration::from_millis(600));
                    Ok(())
                });
            }
            install(
                &mut command,
                ChildSetup {
                    die_with_parent: true,
                    ..ChildSetup::default()
                },
            );
            let _ = command.spawn();
            std::thread::sleep(std::time::Duration::from_secs(5));
            std::process::exit(1);
        }
        if !std::path::Path::new("/bin/sh").exists() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("ran");
        let status = Command::new(std::env::current_exe().unwrap())
            .args([TEST, "--exact", "--nocapture", "--test-threads=1"])
            .env(HELPER, &marker)
            .status()
            .unwrap();
        assert!(status.success(), "{status:?}");
        // The orphan would touch the marker about 1.4 s from now.
        std::thread::sleep(std::time::Duration::from_millis(2500));
        assert!(!marker.exists(), "the orphaned child ran");
    }
}
