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
    fn run(&self) -> std::io::Result<()> {
        if self.new_session {
            // SAFETY: setsid takes no arguments.
            check(unsafe { libc::setsid() })?;
        }
        if self.die_with_parent {
            // SAFETY: PR_SET_PDEATHSIG takes a signal number; extra args are ignored.
            check(unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) })?;
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
    // SAFETY: `ChildSetup::run` makes raw system calls only and touches no
    // heap state that `fork` could have left inconsistent: every buffer
    // it reads was allocated before the fork and is only borrowed.
    unsafe {
        command.pre_exec(move || setup.run());
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
