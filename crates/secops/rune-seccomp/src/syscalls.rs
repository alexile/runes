//! System call names, numbers and architectures.
//!
//! Names are resolved for the architecture this crate is compiled for, from
//! the `libc` crate's `SYS_*` constants. A name that exists on another
//! supported architecture but not this one (`open` on `aarch64`, say) is
//! [known](is_known) but does not [resolve]: no program on this
//! architecture can make that call, so filters leave it out.

use std::fmt;

use crate::table;

/// A CPU architecture that seccomp filters can be built for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Arch {
    /// 64-bit x86. Filters also cover the x32 ABI, which shares the
    /// architecture tag and would otherwise slip past a denylist.
    X86_64,
    /// 64-bit Arm.
    Aarch64,
    /// 64-bit RISC-V.
    Riscv64,
}

impl Arch {
    /// The architecture this crate is compiled for, if it is supported.
    #[must_use]
    pub const fn native() -> Option<Self> {
        if cfg!(target_arch = "x86_64") {
            Some(Self::X86_64)
        } else if cfg!(target_arch = "aarch64") {
            Some(Self::Aarch64)
        } else if cfg!(target_arch = "riscv64") {
            Some(Self::Riscv64)
        } else {
            None
        }
    }

    /// The architecture's name, as Rust spells it (`std::env::consts::ARCH`).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
            Self::Riscv64 => "riscv64",
        }
    }

    /// The `AUDIT_ARCH_*` value the kernel reports to filters
    /// (`seccomp_data.arch`).
    #[must_use]
    pub const fn audit_value(self) -> u32 {
        const ARCH_64BIT_LE: u32 = 0x8000_0000 | 0x4000_0000;
        ARCH_64BIT_LE
            | match self {
                Self::X86_64 => 62,
                Self::Aarch64 => 183,
                Self::Riscv64 => 243,
            }
    }

    pub(crate) const fn target(self) -> seccompiler::TargetArch {
        match self {
            Self::X86_64 => seccompiler::TargetArch::x86_64,
            Self::Aarch64 => seccompiler::TargetArch::aarch64,
            Self::Riscv64 => seccompiler::TargetArch::riscv64,
        }
    }
}

impl fmt::Display for Arch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A system call, by name or by number.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Syscall {
    /// A name such as `"openat"`, resolved with [`resolve`].
    Name(String),
    /// A raw number for the native architecture.
    Number(i64),
}

impl From<&str> for Syscall {
    fn from(name: &str) -> Self {
        Self::Name(name.to_owned())
    }
}

impl From<String> for Syscall {
    fn from(name: String) -> Self {
        Self::Name(name)
    }
}

impl From<i64> for Syscall {
    fn from(number: i64) -> Self {
        Self::Number(number)
    }
}

impl fmt::Display for Syscall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name(name) => f.write_str(name),
            Self::Number(number) => write!(f, "#{number}"),
        }
    }
}

fn lookup(list: &[(&'static str, i64)], name: &str) -> Option<i64> {
    list.binary_search_by(|(entry, _)| (*entry).cmp(name))
        .ok()
        .and_then(|index| list.get(index))
        .map(|(_, number)| *number)
}

/// The native number of the system call `name`, if this architecture has it.
///
/// ```
/// # if rune_seccomp::Arch::native().is_none() { return; }
/// assert!(rune_seccomp::syscalls::resolve("openat").is_some());
/// assert_eq!(rune_seccomp::syscalls::resolve("no_such_call"), None);
/// ```
#[must_use]
pub fn resolve(name: &str) -> Option<i64> {
    lookup(table::COMMON, name).or_else(|| lookup(table::ARCH, name))
}

/// The name of the native system call `number`, if it is in the table.
#[must_use]
pub fn name_of(number: i64) -> Option<&'static str> {
    table::COMMON
        .iter()
        .chain(table::ARCH)
        .find(|(_, entry)| *entry == number)
        .map(|(name, _)| *name)
}

/// Every system call name and number known for the native architecture,
/// sorted by name.
pub fn native() -> impl Iterator<Item = (&'static str, i64)> {
    let mut all: Vec<_> = table::COMMON.iter().chain(table::ARCH).copied().collect();
    all.sort_unstable();
    all.into_iter()
}

/// Whether `name` is a system call on any supported architecture, even if
/// not on this one. Names that fail this check are typos.
#[must_use]
pub fn is_known(name: &str) -> bool {
    table::KNOWN.binary_search(&name).is_ok()
}

/// System calls no ordinary program needs and that widen the attack
/// surface, for a denylist; adapted from Docker's default seccomp profile.
///
/// Calls that only exist on some architectures (`_sysctl`, `ustat`,
/// `nfsservctl` on `x86_64`) are skipped elsewhere. Docker also blocks
/// `clone`/`unshare`/`setns` and `socket`; those are left out on purpose:
/// threads are made with `clone`, unprivileged namespaces are a separate
/// layer, and local sockets carry everyday IPC.
pub const DANGEROUS: &[&str] = &[
    // Kernel modules.
    "init_module",
    "finit_module",
    "delete_module",
    // Inspecting or tracing other processes.
    "ptrace",
    "process_vm_readv",
    "process_vm_writev",
    "kcmp",
    "perf_event_open",
    "lookup_dcookie",
    // The kernel keyring.
    "add_key",
    "request_key",
    "keyctl",
    // Mounts and file handles.
    "mount",
    "umount2",
    "pivot_root",
    "open_by_handle_at",
    "name_to_handle_at",
    // Host-wide state.
    "reboot",
    "kexec_load",
    "kexec_file_load",
    "swapon",
    "swapoff",
    "acct",
    "quotactl",
    "bpf",
    // Time is not namespaced.
    "clock_adjtime",
    "clock_settime",
    "settimeofday",
    // NUMA memory policy.
    "set_mempolicy",
    "get_mempolicy",
    "mbind",
    "move_pages",
    // io_uring, the source of several container escapes.
    "io_uring_setup",
    "io_uring_enter",
    "io_uring_register",
    // Legacy x86_64 calls.
    "_sysctl",
    "ustat",
    "nfsservctl",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_are_sorted_and_disjoint() {
        for list in [table::COMMON, table::ARCH] {
            assert!(list.windows(2).all(|w| w[0].0 < w[1].0));
        }
        assert!(table::KNOWN.windows(2).all(|w| w[0] < w[1]));
        for (name, _) in table::ARCH {
            assert_eq!(lookup(table::COMMON, name), None, "{name}");
        }
    }

    #[test]
    fn native_names_are_known_and_numbers_unique() {
        let all: Vec<_> = native().collect();
        let mut numbers: Vec<_> = all.iter().map(|(_, n)| *n).collect();
        numbers.sort_unstable();
        numbers.dedup();
        assert_eq!(numbers.len(), all.len());
        for (name, number) in all {
            assert!(is_known(name), "{name}");
            assert_eq!(resolve(name), Some(number));
            assert_eq!(name_of(number), Some(name));
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn x86_64_numbers() {
        assert_eq!(Arch::native(), Some(Arch::X86_64));
        assert_eq!(resolve("read"), Some(0));
        assert_eq!(resolve("openat"), Some(257));
        assert_eq!(resolve("open"), Some(2));
        assert_eq!(resolve("_sysctl"), Some(156));
        assert_eq!(name_of(39), Some("getpid"));
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn aarch64_numbers() {
        assert_eq!(resolve("openat"), Some(56));
        assert_eq!(resolve("open"), None);
        assert!(is_known("open"));
    }

    #[test]
    fn audit_values_match_the_kernel() {
        assert_eq!(Arch::X86_64.audit_value(), 0xc000_003e);
        assert_eq!(Arch::Aarch64.audit_value(), 0xc000_00b7);
        assert_eq!(Arch::Riscv64.audit_value(), 0xc000_00f3);
    }

    #[test]
    fn dangerous_names_are_known() {
        for name in DANGEROUS {
            assert!(is_known(name), "{name}");
        }
        assert!(!is_known("no_such_call"));
    }

    #[test]
    fn syscall_conversions() {
        assert_eq!(Syscall::from("read"), Syscall::Name("read".into()));
        assert_eq!(Syscall::from(7).to_string(), "#7");
    }
}
