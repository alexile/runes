//! The resources a limit can be placed on, and the unit each is counted in.

use std::fmt;
use std::str::FromStr;

use crate::Error;

/// The integer type `getrlimit`/`setrlimit` take for a resource: an enum
/// in glibc, a plain `int` elsewhere.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub type RawResource = libc::__rlimit_resource_t;
/// The integer type `getrlimit`/`setrlimit` take for a resource: an enum
/// in glibc, a plain `int` elsewhere.
#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
pub type RawResource = libc::c_int;

/// What a resource's limit value counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Unit {
    /// Bytes.
    Bytes,
    /// Seconds of CPU time.
    Seconds,
    /// Microseconds of CPU time.
    Microseconds,
    /// A number of things: processes, file descriptors, locks, signals.
    Count,
    /// A nice-value ceiling encoded as `20 - nice`: a limit of `n` lets the
    /// process lower its nice value down to `20 - n` (so `40` allows `-20`,
    /// `0` or `1` allows nothing below `19`).
    NiceCeiling,
    /// A real-time scheduling priority (`0`–`99`).
    Priority,
}

impl fmt::Display for Unit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Bytes => "bytes",
            Self::Seconds => "seconds",
            Self::Microseconds => "microseconds",
            Self::Count => "count",
            Self::NiceCeiling => "nice ceiling (20 - nice)",
            Self::Priority => "priority",
        })
    }
}

/// A resource whose consumption the kernel can limit (`RLIMIT_*`).
///
/// Each variant documents the unit its limit is counted in; [`Resource::unit`]
/// returns it programmatically. Variants that only Linux (and Android)
/// define exist only there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Resource {
    /// `RLIMIT_AS`, in bytes: the size of the virtual address space. The
    /// usual way to cap memory; `mmap`, `brk` and stack growth fail beyond
    /// it (allocators then report out of memory).
    AddressSpace,
    /// `RLIMIT_CORE`, in bytes: the largest core dump written. `0` disables
    /// core dumps.
    Core,
    /// `RLIMIT_CPU`, in seconds of CPU time. At the soft limit the process
    /// gets `SIGXCPU` (once a second until the hard limit), at the hard
    /// limit `SIGKILL`.
    Cpu,
    /// `RLIMIT_DATA`, in bytes: the data segment, heap and (since Linux
    /// 4.7) private anonymous mappings.
    Data,
    /// `RLIMIT_FSIZE`, in bytes: the largest file the process may create
    /// or extend. Writing past it raises `SIGXFSZ`, then fails with
    /// `EFBIG`.
    FileSize,
    /// `RLIMIT_NOFILE`, a count: one more than the highest file descriptor
    /// number the process may open.
    NoFile,
    /// `RLIMIT_NPROC`, a count: processes and threads the process's *real
    /// user ID* may have, across the whole system. Not enforced for root
    /// (`CAP_SYS_RESOURCE`/`CAP_SYS_ADMIN`).
    NProc,
    /// `RLIMIT_RSS`, in bytes: the resident set size. Linux has ignored it
    /// since 2.6; it is here so it can be read and reported.
    Rss,
    /// `RLIMIT_STACK`, in bytes: the main thread's stack.
    Stack,
    /// `RLIMIT_MEMLOCK`, in bytes: memory locked into RAM with `mlock`,
    /// `mmap(MAP_LOCKED)` and friends.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    MemLock,
    /// `RLIMIT_LOCKS`, a count: `flock` and `fcntl` leases (Linux ignores
    /// it for other locks).
    #[cfg(any(target_os = "linux", target_os = "android"))]
    Locks,
    /// `RLIMIT_MSGQUEUE`, in bytes: POSIX message queue memory of the real
    /// user ID.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    MsgQueue,
    /// `RLIMIT_NICE`, a [`Unit::NiceCeiling`]: how far the process may
    /// lower its nice value.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    Nice,
    /// `RLIMIT_RTPRIO`, a [`Unit::Priority`]: the highest real-time
    /// priority the process may set.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    RtPrio,
    /// `RLIMIT_RTTIME`, in microseconds: CPU time a real-time process may
    /// use without a blocking system call (`SIGXCPU`, then `SIGKILL`).
    #[cfg(any(target_os = "linux", target_os = "android"))]
    RtTime,
    /// `RLIMIT_SIGPENDING`, a count: signals that may be queued for the
    /// real user ID.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    SigPending,
}

impl Resource {
    /// Every resource this platform defines, in `/proc/<pid>/limits` order
    /// on Linux.
    pub const ALL: &'static [Self] = &[
        Self::Cpu,
        Self::FileSize,
        Self::Data,
        Self::Stack,
        Self::Core,
        Self::Rss,
        Self::NProc,
        Self::NoFile,
        #[cfg(any(target_os = "linux", target_os = "android"))]
        Self::MemLock,
        Self::AddressSpace,
        #[cfg(any(target_os = "linux", target_os = "android"))]
        Self::Locks,
        #[cfg(any(target_os = "linux", target_os = "android"))]
        Self::SigPending,
        #[cfg(any(target_os = "linux", target_os = "android"))]
        Self::MsgQueue,
        #[cfg(any(target_os = "linux", target_os = "android"))]
        Self::Nice,
        #[cfg(any(target_os = "linux", target_os = "android"))]
        Self::RtPrio,
        #[cfg(any(target_os = "linux", target_os = "android"))]
        Self::RtTime,
    ];

    /// The C constant's name, such as `"RLIMIT_CPU"`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::AddressSpace => "RLIMIT_AS",
            Self::Core => "RLIMIT_CORE",
            Self::Cpu => "RLIMIT_CPU",
            Self::Data => "RLIMIT_DATA",
            Self::FileSize => "RLIMIT_FSIZE",
            Self::NoFile => "RLIMIT_NOFILE",
            Self::NProc => "RLIMIT_NPROC",
            Self::Rss => "RLIMIT_RSS",
            Self::Stack => "RLIMIT_STACK",
            #[cfg(any(target_os = "linux", target_os = "android"))]
            Self::MemLock => "RLIMIT_MEMLOCK",
            #[cfg(any(target_os = "linux", target_os = "android"))]
            Self::Locks => "RLIMIT_LOCKS",
            #[cfg(any(target_os = "linux", target_os = "android"))]
            Self::MsgQueue => "RLIMIT_MSGQUEUE",
            #[cfg(any(target_os = "linux", target_os = "android"))]
            Self::Nice => "RLIMIT_NICE",
            #[cfg(any(target_os = "linux", target_os = "android"))]
            Self::RtPrio => "RLIMIT_RTPRIO",
            #[cfg(any(target_os = "linux", target_os = "android"))]
            Self::RtTime => "RLIMIT_RTTIME",
            #[cfg(any(target_os = "linux", target_os = "android"))]
            Self::SigPending => "RLIMIT_SIGPENDING",
        }
    }

    /// The short name `ulimit`/`prlimit(1)` style tools use: the C name
    /// without `RLIMIT_`, lower-cased (`"cpu"`, `"as"`, `"nofile"`).
    #[must_use]
    pub const fn short_name(self) -> &'static str {
        match self {
            Self::AddressSpace => "as",
            Self::Core => "core",
            Self::Cpu => "cpu",
            Self::Data => "data",
            Self::FileSize => "fsize",
            Self::NoFile => "nofile",
            Self::NProc => "nproc",
            Self::Rss => "rss",
            Self::Stack => "stack",
            #[cfg(any(target_os = "linux", target_os = "android"))]
            Self::MemLock => "memlock",
            #[cfg(any(target_os = "linux", target_os = "android"))]
            Self::Locks => "locks",
            #[cfg(any(target_os = "linux", target_os = "android"))]
            Self::MsgQueue => "msgqueue",
            #[cfg(any(target_os = "linux", target_os = "android"))]
            Self::Nice => "nice",
            #[cfg(any(target_os = "linux", target_os = "android"))]
            Self::RtPrio => "rtprio",
            #[cfg(any(target_os = "linux", target_os = "android"))]
            Self::RtTime => "rttime",
            #[cfg(any(target_os = "linux", target_os = "android"))]
            Self::SigPending => "sigpending",
        }
    }

    /// The unit the limit value is counted in.
    #[must_use]
    pub const fn unit(self) -> Unit {
        match self {
            Self::AddressSpace | Self::Core | Self::Data | Self::FileSize | Self::Rss => {
                Unit::Bytes
            }
            Self::Stack => Unit::Bytes,
            Self::Cpu => Unit::Seconds,
            Self::NoFile | Self::NProc => Unit::Count,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            Self::MemLock | Self::MsgQueue => Unit::Bytes,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            Self::Locks | Self::SigPending => Unit::Count,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            Self::Nice => Unit::NiceCeiling,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            Self::RtPrio => Unit::Priority,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            Self::RtTime => Unit::Microseconds,
        }
    }

    /// The row label Linux prints for this resource in
    /// `/proc/<pid>/limits`, such as `"Max cpu time"`.
    #[must_use]
    pub const fn proc_label(self) -> &'static str {
        match self {
            Self::AddressSpace => "Max address space",
            Self::Core => "Max core file size",
            Self::Cpu => "Max cpu time",
            Self::Data => "Max data size",
            Self::FileSize => "Max file size",
            Self::NoFile => "Max open files",
            Self::NProc => "Max processes",
            Self::Rss => "Max resident set",
            Self::Stack => "Max stack size",
            #[cfg(any(target_os = "linux", target_os = "android"))]
            Self::MemLock => "Max locked memory",
            #[cfg(any(target_os = "linux", target_os = "android"))]
            Self::Locks => "Max file locks",
            #[cfg(any(target_os = "linux", target_os = "android"))]
            Self::MsgQueue => "Max msgqueue size",
            #[cfg(any(target_os = "linux", target_os = "android"))]
            Self::Nice => "Max nice priority",
            #[cfg(any(target_os = "linux", target_os = "android"))]
            Self::RtPrio => "Max realtime priority",
            #[cfg(any(target_os = "linux", target_os = "android"))]
            Self::RtTime => "Max realtime timeout",
            #[cfg(any(target_os = "linux", target_os = "android"))]
            Self::SigPending => "Max pending signals",
        }
    }

    /// The libc constant.
    pub(crate) const fn raw(self) -> RawResource {
        match self {
            Self::AddressSpace => libc::RLIMIT_AS,
            Self::Core => libc::RLIMIT_CORE,
            Self::Cpu => libc::RLIMIT_CPU,
            Self::Data => libc::RLIMIT_DATA,
            Self::FileSize => libc::RLIMIT_FSIZE,
            Self::NoFile => libc::RLIMIT_NOFILE,
            Self::NProc => libc::RLIMIT_NPROC,
            Self::Rss => libc::RLIMIT_RSS,
            Self::Stack => libc::RLIMIT_STACK,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            Self::MemLock => libc::RLIMIT_MEMLOCK,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            Self::Locks => libc::RLIMIT_LOCKS,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            Self::MsgQueue => libc::RLIMIT_MSGQUEUE,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            Self::Nice => libc::RLIMIT_NICE,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            Self::RtPrio => libc::RLIMIT_RTPRIO,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            Self::RtTime => libc::RLIMIT_RTTIME,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            Self::SigPending => libc::RLIMIT_SIGPENDING,
        }
    }
}

impl fmt::Display for Resource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for Resource {
    type Err = Error;

    /// Parses a C name (`"RLIMIT_NOFILE"`) or a short name (`"nofile"`),
    /// ignoring ASCII case.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let short = match (s.get(..7), s.get(7..)) {
            (Some(prefix), Some(rest)) if prefix.eq_ignore_ascii_case("RLIMIT_") => rest,
            _ => s,
        };
        Self::ALL
            .iter()
            .copied()
            .find(|r| r.short_name().eq_ignore_ascii_case(short))
            .ok_or_else(|| Error::UnknownResource { name: s.to_owned() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_prefixed_short_names() {
        for r in Resource::ALL {
            assert_eq!(
                r.name(),
                format!("RLIMIT_{}", r.short_name().to_uppercase())
            );
        }
    }

    #[test]
    fn parse_accepts_both_spellings() {
        assert_eq!(
            "RLIMIT_NOFILE".parse::<Resource>().ok(),
            Some(Resource::NoFile)
        );
        assert_eq!(
            "rlimit_as".parse::<Resource>().ok(),
            Some(Resource::AddressSpace)
        );
        assert_eq!("Cpu".parse::<Resource>().ok(), Some(Resource::Cpu));
        assert!("RLIMIT_".parse::<Resource>().is_err());
        assert!("bogus".parse::<Resource>().is_err());
        assert!("".parse::<Resource>().is_err());
    }

    #[test]
    fn raw_constants_are_distinct() {
        let mut raws: Vec<_> = Resource::ALL.iter().map(|r| r.raw()).collect();
        raws.sort_unstable();
        raws.dedup();
        assert_eq!(raws.len(), Resource::ALL.len());
    }

    #[test]
    fn units_match_kernel_documentation() {
        assert_eq!(Resource::AddressSpace.unit(), Unit::Bytes);
        assert_eq!(Resource::FileSize.unit(), Unit::Bytes);
        assert_eq!(Resource::Cpu.unit(), Unit::Seconds);
        assert_eq!(Resource::NoFile.unit(), Unit::Count);
        assert_eq!(Resource::NProc.unit(), Unit::Count);
    }
}
