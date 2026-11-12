//! Promises: named groups of capabilities, after OpenBSD's `pledge(2)`.

use std::fmt;
use std::str::FromStr;

use crate::Error;

/// One capability a process keeps, named after the OpenBSD `pledge(2)`
/// promise it is modelled on.
///
/// A [`Profile`](crate::Profile) lists the promises a process needs;
/// everything they do not cover is taken away. On Linux each promise opens
/// a group of system calls in the seccomp filter and, for the filesystem
/// promises, a group of Landlock rights. Seccomp cannot inspect pointer
/// arguments, so the split between promises is coarser than on OpenBSD;
/// each variant documents what it grants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Promise {
    /// Computation and I/O on file descriptors the process already holds:
    /// memory management, reading and writing, polling, pipes, signals,
    /// clocks, threads (`clone`, which seccomp cannot tell from `fork`
    /// without inspecting its flags), `ioctl`, `fstat`, sending and
    /// receiving on sockets already open, and installing further seccomp
    /// filters and Landlock rulesets (which can only narrow the
    /// restriction, as a second `pledge(2)` call may). Every useful profile
    /// needs it.
    Stdio,
    /// Read-only filesystem access: opening files (`open`, `openat`),
    /// `stat`, `readlink`, listing directories and changing directory.
    /// Landlock grants reading files and listing directories.
    Rpath,
    /// Writing to files: opening (the same calls as [`Promise::Rpath`]:
    /// seccomp cannot see open flags, so Landlock tells the two apart),
    /// `truncate` and `fallocate`. Landlock grants writing, truncating and
    /// device `ioctl`s.
    Wpath,
    /// Creating, removing, renaming and linking files, directories and
    /// symbolic links. Landlock grants the matching `Make*`, `Remove*` and
    /// `Refer` rights.
    Cpath,
    /// Creating device nodes and named pipes (`mknod`). Landlock grants
    /// making character and block devices.
    Dpath,
    /// Changing file attributes: mode, owner, timestamps and extended
    /// attributes. Landlock cannot restrict these, so only seccomp does.
    Fattr,
    /// Executing programs (`execve`, `execveat`); Landlock grants
    /// executing files. The filter is kept across `exec`, so the new
    /// program runs under the same profile: give it what it needs to start
    /// (usually [`Promise::Rpath`] for the dynamic loader).
    Exec,
    /// Managing processes: `fork`, `vfork`, `wait4`, `waitid`, `kill`,
    /// process groups and sessions, scheduling priority and pidfds.
    Proc,
    /// Changing user and group ids and capabilities (`setuid`,
    /// `setresgid`, `setgroups`, `capset` and the like).
    Id,
    /// Creating and connecting sockets: `socket`, `connect`, `bind`,
    /// `listen`, `accept` and socket options. Seccomp cannot inspect the
    /// address family, so this also allows UNIX domain sockets; on kernels
    /// with Landlock ABI 9 connecting to a pathname socket still needs
    /// [`Promise::Unix`].
    Inet,
    /// UNIX domain sockets: the same system calls as [`Promise::Inet`],
    /// and the Landlock rights to connect to and create pathname sockets.
    Unix,
}

impl Promise {
    /// Every promise, in declaration order.
    pub const ALL: [Self; 11] = [
        Self::Stdio,
        Self::Rpath,
        Self::Wpath,
        Self::Cpath,
        Self::Dpath,
        Self::Fattr,
        Self::Exec,
        Self::Proc,
        Self::Id,
        Self::Inet,
        Self::Unix,
    ];

    /// The promise's name, as `pledge(2)` spells it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Stdio => "stdio",
            Self::Rpath => "rpath",
            Self::Wpath => "wpath",
            Self::Cpath => "cpath",
            Self::Dpath => "dpath",
            Self::Fattr => "fattr",
            Self::Exec => "exec",
            Self::Proc => "proc",
            Self::Id => "id",
            Self::Inet => "inet",
            Self::Unix => "unix",
        }
    }

    /// Whether the promise grants filesystem access that Landlock
    /// restricts per path.
    #[must_use]
    pub const fn is_filesystem(self) -> bool {
        matches!(
            self,
            Self::Rpath | Self::Wpath | Self::Cpath | Self::Dpath | Self::Exec | Self::Unix
        )
    }

    /// The system calls the promise allows, by name. Names a given
    /// architecture lacks (such as `open` on `aarch64`) are skipped when
    /// the filter is built.
    #[must_use]
    pub const fn syscalls(self) -> &'static [&'static str] {
        match self {
            Self::Stdio => STDIO,
            Self::Rpath => RPATH,
            Self::Wpath => WPATH,
            Self::Cpath => CPATH,
            Self::Dpath => DPATH,
            Self::Fattr => FATTR,
            Self::Exec => EXEC,
            Self::Proc => PROC,
            Self::Id => ID,
            Self::Inet | Self::Unix => SOCKET,
        }
    }

    const fn bit(self) -> u16 {
        1 << self as u16
    }
}

impl fmt::Display for Promise {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for Promise {
    type Err = Error;

    fn from_str(name: &str) -> Result<Self, Error> {
        Self::ALL
            .into_iter()
            .find(|promise| promise.name() == name)
            .ok_or_else(|| Error::UnknownPromise { name: name.into() })
    }
}

/// A set of [`Promise`]s.
///
/// It parses from and displays as a `pledge(2)` promise string, names
/// separated by spaces:
///
/// ```
/// use rune_pledge::{Promise, PromiseSet};
///
/// let set: PromiseSet = "stdio rpath  inet".parse()?;
/// assert!(set.contains(Promise::Rpath) && !set.contains(Promise::Wpath));
/// assert_eq!(set.to_string(), "stdio rpath inet");
/// # Ok::<(), rune_pledge::Error>(())
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct PromiseSet(u16);

impl PromiseSet {
    /// No promise: the process may do nothing but exit.
    pub const EMPTY: Self = Self(0);
    /// Every promise.
    pub const ALL: Self = Self((1 << Promise::ALL.len()) - 1);

    /// Whether `promise` is in the set.
    #[must_use]
    pub const fn contains(self, promise: Promise) -> bool {
        self.0 & promise.bit() != 0
    }

    /// Whether the set is empty.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The set with `promise` added.
    #[must_use]
    pub const fn with(self, promise: Promise) -> Self {
        Self(self.0 | promise.bit())
    }

    /// The set with `promise` removed.
    #[must_use]
    pub const fn without(self, promise: Promise) -> Self {
        Self(self.0 & !promise.bit())
    }

    /// The promises in either set.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// The promises in both sets.
    #[must_use]
    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// The promises, in declaration order.
    pub fn iter(self) -> impl Iterator<Item = Promise> {
        Promise::ALL.into_iter().filter(move |p| self.contains(*p))
    }
}

impl From<Promise> for PromiseSet {
    fn from(promise: Promise) -> Self {
        Self::EMPTY.with(promise)
    }
}

impl FromIterator<Promise> for PromiseSet {
    fn from_iter<I: IntoIterator<Item = Promise>>(iter: I) -> Self {
        iter.into_iter().fold(Self::EMPTY, Self::with)
    }
}

impl Extend<Promise> for PromiseSet {
    fn extend<I: IntoIterator<Item = Promise>>(&mut self, iter: I) {
        *self = iter.into_iter().fold(*self, Self::with);
    }
}

impl FromStr for PromiseSet {
    type Err = Error;

    /// Parses promise names separated by whitespace (`pledge(2)` syntax).
    /// An empty string is the empty set.
    fn from_str(promises: &str) -> Result<Self, Error> {
        promises.split_whitespace().map(str::parse).collect()
    }
}

impl fmt::Display for PromiseSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, promise) in self.iter().enumerate() {
            if i > 0 {
                f.write_str(" ")?;
            }
            f.write_str(promise.name())?;
        }
        Ok(())
    }
}

impl fmt::Debug for PromiseSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.iter()).finish()
    }
}

const STDIO: &[&str] = &[
    // Reading and writing open descriptors.
    "read",
    "write",
    "readv",
    "writev",
    "pread64",
    "pwrite64",
    "preadv",
    "pwritev",
    "preadv2",
    "pwritev2",
    "lseek",
    "sendfile",
    "splice",
    "tee",
    "copy_file_range",
    "fsync",
    "fdatasync",
    "ftruncate",
    "flock",
    "fadvise64",
    // Descriptor management.
    "close",
    "close_range",
    "dup",
    "dup2",
    "dup3",
    "fcntl",
    "ioctl",
    // `fstat` and its modern spellings: glibc implements `fstat` with
    // `newfstatat(fd, "", AT_EMPTY_PATH)` or `statx`.
    "fstat",
    "newfstatat",
    "statx",
    "fstatfs",
    // Pipes, polling and event descriptors.
    "pipe",
    "pipe2",
    "poll",
    "ppoll",
    "select",
    "pselect6",
    "epoll_create",
    "epoll_create1",
    "epoll_ctl",
    "epoll_wait",
    "epoll_pwait",
    "epoll_pwait2",
    "eventfd",
    "eventfd2",
    "timerfd_create",
    "timerfd_settime",
    "timerfd_gettime",
    "signalfd",
    "signalfd4",
    // Sockets the process already holds.
    "sendto",
    "recvfrom",
    "sendmsg",
    "recvmsg",
    "sendmmsg",
    "recvmmsg",
    "socketpair",
    "shutdown",
    "getsockopt",
    "getsockname",
    "getpeername",
    // Memory.
    "brk",
    "mmap",
    "munmap",
    "mremap",
    "mprotect",
    "madvise",
    "mincore",
    "msync",
    "membarrier",
    // Signals.
    "rt_sigaction",
    "rt_sigprocmask",
    "rt_sigreturn",
    "rt_sigsuspend",
    "rt_sigpending",
    "rt_sigtimedwait",
    "sigaltstack",
    "tgkill",
    "tkill",
    "pause",
    "restart_syscall",
    // Clocks and timers.
    "clock_gettime",
    "clock_getres",
    "clock_nanosleep",
    "nanosleep",
    "gettimeofday",
    "time",
    "getitimer",
    "setitimer",
    "alarm",
    // Identity and limits, read-only.
    "getpid",
    "getppid",
    "gettid",
    "getuid",
    "geteuid",
    "getgid",
    "getegid",
    "getresuid",
    "getresgid",
    "getgroups",
    "getpgid",
    "getpgrp",
    "getsid",
    "getrlimit",
    "prlimit64",
    "getrusage",
    "uname",
    "sysinfo",
    "umask",
    "getcpu",
    "getrandom",
    // Threads and process lifetime.
    "clone",
    "clone3",
    "futex",
    "futex_waitv",
    "set_robust_list",
    "get_robust_list",
    "set_tid_address",
    "rseq",
    "sched_yield",
    "sched_getaffinity",
    "arch_prctl",
    "prctl",
    // Narrowing the restriction further, as a second `pledge(2)` may.
    "seccomp",
    "landlock_create_ruleset",
    "landlock_add_rule",
    "landlock_restrict_self",
    "exit",
    "exit_group",
];

const RPATH: &[&str] = &[
    "open",
    "openat",
    "openat2",
    "stat",
    "lstat",
    "access",
    "faccessat",
    "faccessat2",
    "readlink",
    "readlinkat",
    "getdents",
    "getdents64",
    "getcwd",
    "chdir",
    "fchdir",
    "statfs",
    "getxattr",
    "lgetxattr",
    "fgetxattr",
    "listxattr",
    "llistxattr",
    "flistxattr",
];

const WPATH: &[&str] = &["open", "openat", "openat2", "truncate", "fallocate"];

const CPATH: &[&str] = &[
    "open",
    "openat",
    "openat2",
    "creat",
    "mkdir",
    "mkdirat",
    "rmdir",
    "unlink",
    "unlinkat",
    "rename",
    "renameat",
    "renameat2",
    "link",
    "linkat",
    "symlink",
    "symlinkat",
];

const DPATH: &[&str] = &["mknod", "mknodat"];

const FATTR: &[&str] = &[
    "chmod",
    "fchmod",
    "fchmodat",
    "fchmodat2",
    "chown",
    "fchown",
    "fchownat",
    "lchown",
    "utime",
    "utimes",
    "utimensat",
    "futimesat",
    "setxattr",
    "lsetxattr",
    "fsetxattr",
    "removexattr",
    "lremovexattr",
    "fremovexattr",
];

const EXEC: &[&str] = &["execve", "execveat"];

const PROC: &[&str] = &[
    "fork",
    "vfork",
    "wait4",
    "waitid",
    "kill",
    "setpgid",
    "setsid",
    "getpriority",
    "setpriority",
    "sched_setaffinity",
    "sched_getparam",
    "sched_getscheduler",
    "pidfd_open",
    "pidfd_send_signal",
];

const ID: &[&str] = &[
    "setuid",
    "setgid",
    "setreuid",
    "setregid",
    "setresuid",
    "setresgid",
    "setfsuid",
    "setfsgid",
    "setgroups",
    "capget",
    "capset",
];

const SOCKET: &[&str] = &[
    "socket",
    "connect",
    "bind",
    "listen",
    "accept",
    "accept4",
    "setsockopt",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip() {
        for promise in Promise::ALL {
            assert_eq!(promise.name().parse::<Promise>().ok(), Some(promise));
        }
        assert!(matches!(
            "tty".parse::<Promise>(),
            Err(Error::UnknownPromise { name }) if name == "tty"
        ));
    }

    #[test]
    fn set_operations() {
        let set = PromiseSet::from(Promise::Stdio).with(Promise::Rpath);
        assert!(set.contains(Promise::Stdio) && set.contains(Promise::Rpath));
        assert!(!set.contains(Promise::Exec));
        assert_eq!(set.without(Promise::Rpath), Promise::Stdio.into());
        assert_eq!(
            set.intersection(Promise::Rpath.into()),
            Promise::Rpath.into()
        );
        assert_eq!(PromiseSet::ALL.iter().count(), Promise::ALL.len());
        assert!(PromiseSet::EMPTY.is_empty());
        assert_eq!(format!("{set:?}"), "{Stdio, Rpath}");
    }

    #[test]
    fn parses_pledge_strings() {
        assert_eq!("".parse::<PromiseSet>().ok(), Some(PromiseSet::EMPTY));
        let set: PromiseSet = " exec\tstdio stdio ".parse().unwrap();
        assert_eq!(set.to_string(), "stdio exec");
        assert!("stdio bogus".parse::<PromiseSet>().is_err());
    }

    #[test]
    fn syscall_lists_are_duplicate_free() {
        for promise in Promise::ALL {
            let mut names = promise.syscalls().to_vec();
            names.sort_unstable();
            let len = names.len();
            names.dedup();
            assert_eq!(names.len(), len, "{promise}");
        }
    }

    #[test]
    fn dangerous_calls_are_never_granted() {
        for promise in Promise::ALL {
            for name in [
                "ptrace",
                "mount",
                "bpf",
                "init_module",
                "kexec_load",
                "unshare",
                "setns",
                "chroot",
            ] {
                assert!(!promise.syscalls().contains(&name), "{promise}: {name}");
            }
        }
    }
}
