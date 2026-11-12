//! The set of system calls a traced program made, with counts.

use std::collections::BTreeMap;

/// `AUDIT_ARCH_X86_64`: what the kernel reports for 64-bit x86 calls.
pub const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
/// `AUDIT_ARCH_I386`: 32-bit x86 calls, including those a 64-bit program
/// makes through `int 0x80`.
pub const AUDIT_ARCH_I386: u32 = 0x4000_0003;
/// `AUDIT_ARCH_AARCH64`.
pub const AUDIT_ARCH_AARCH64: u32 = 0xC000_00B7;
/// `AUDIT_ARCH_RISCV64`.
pub const AUDIT_ARCH_RISCV64: u32 = 0xC000_00F3;

/// The `AUDIT_ARCH_*` value of the architecture this crate is compiled for,
/// if it is one of the above. Seccomp filters see the same value in
/// `seccomp_data.arch`.
pub const NATIVE_AUDIT_ARCH: Option<u32> = if cfg!(target_arch = "x86_64") {
    Some(AUDIT_ARCH_X86_64)
} else if cfg!(target_arch = "aarch64") {
    Some(AUDIT_ARCH_AARCH64)
} else if cfg!(target_arch = "riscv64") {
    Some(AUDIT_ARCH_RISCV64)
} else if cfg!(target_arch = "x86") {
    Some(AUDIT_ARCH_I386)
} else {
    None
};

/// One system call as the kernel identifies it to a tracer or a seccomp
/// filter: the calling convention's `AUDIT_ARCH_*` value and the number.
///
/// The number is the raw register value, so an `x86_64` x32-ABI call keeps
/// its `0x4000_0000` bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SyscallId {
    /// The `AUDIT_ARCH_*` value.
    pub arch: u32,
    /// The system call number.
    pub nr: u64,
}

impl SyscallId {
    /// A call `nr` on `arch`.
    #[must_use]
    pub const fn new(arch: u32, nr: u64) -> Self {
        Self { arch, nr }
    }

    /// Whether this call used the native calling convention
    /// ([`NATIVE_AUDIT_ARCH`]).
    #[must_use]
    pub fn is_native(self) -> bool {
        NATIVE_AUDIT_ARCH == Some(self.arch)
    }
}

/// Which system calls a program made, and how often: the raw material for
/// a seccomp allowlist.
///
/// Build one with [`trace`](crate::trace) (from `ptrace` stops, by number)
/// or by [recording](Profile::record) calls yourself. [`Profile::numbers`]
/// lists the native numbers, ready for a filter builder such as
/// `rune-seccomp`'s `Options::allowlist(…).with_syscalls(…)`, whose
/// `syscalls::name_of` also turns them back into names.
///
/// ```
/// use rune_strace::{Profile, SyscallId};
///
/// let mut profile = Profile::new();
/// profile.record(SyscallId::new(0xC000_003E, 0));
/// profile.record(SyscallId::new(0xC000_003E, 0));
/// profile.record(SyscallId::new(0xC000_003E, 60));
/// assert_eq!(profile.count(SyscallId::new(0xC000_003E, 0)), 2);
/// assert_eq!(profile.numbers_for(0xC000_003E), vec![0, 60]);
/// assert_eq!(profile.total(), 3);
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Profile {
    counts: BTreeMap<SyscallId, u64>,
}

impl Profile {
    /// An empty profile.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            counts: BTreeMap::new(),
        }
    }

    /// Counts one call.
    pub fn record(&mut self, id: SyscallId) {
        let count = self.counts.entry(id).or_insert(0);
        *count = count.saturating_add(1);
    }

    /// Adds every count of `other` to this profile.
    pub fn merge(&mut self, other: &Self) {
        for (id, n) in &other.counts {
            let count = self.counts.entry(*id).or_insert(0);
            *count = count.saturating_add(*n);
        }
    }

    /// How many times `id` was called.
    #[must_use]
    pub fn count(&self, id: SyscallId) -> u64 {
        self.counts.get(&id).copied().unwrap_or(0)
    }

    /// Whether `id` was called at all.
    #[must_use]
    pub fn contains(&self, id: SyscallId) -> bool {
        self.counts.contains_key(&id)
    }

    /// Every distinct call and its count, ordered by architecture then
    /// number.
    pub fn iter(&self) -> impl Iterator<Item = (SyscallId, u64)> + '_ {
        self.counts.iter().map(|(id, n)| (*id, *n))
    }

    /// The architectures calls were made with.
    #[must_use]
    pub fn arches(&self) -> Vec<u32> {
        let mut arches: Vec<u32> = self.counts.keys().map(|id| id.arch).collect();
        arches.dedup();
        arches
    }

    /// The distinct numbers called with `arch`, ascending. Numbers that do
    /// not fit an `i64` (never a real system call) are left out.
    #[must_use]
    pub fn numbers_for(&self, arch: u32) -> Vec<i64> {
        self.counts
            .keys()
            .filter(|id| id.arch == arch)
            .filter_map(|id| i64::try_from(id.nr).ok())
            .collect()
    }

    /// The distinct native-architecture numbers called, ascending: an
    /// allowlist for a seccomp filter. Calls made with another convention
    /// (32-bit `int 0x80` on `x86_64`) are not included; check
    /// [`Profile::arches`] to see whether there were any.
    #[must_use]
    pub fn numbers(&self) -> Vec<i64> {
        NATIVE_AUDIT_ARCH.map_or_else(Vec::new, |arch| self.numbers_for(arch))
    }

    /// How many distinct calls were made.
    #[must_use]
    pub fn len(&self) -> usize {
        self.counts.len()
    }

    /// Whether no call was recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.counts.is_empty()
    }

    /// The total number of calls recorded.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.counts
            .values()
            .fold(0, |sum, n| sum.saturating_add(*n))
    }
}

impl Extend<SyscallId> for Profile {
    fn extend<I: IntoIterator<Item = SyscallId>>(&mut self, iter: I) {
        for id in iter {
            self.record(id);
        }
    }
}

impl FromIterator<SyscallId> for Profile {
    fn from_iter<I: IntoIterator<Item = SyscallId>>(iter: I) -> Self {
        let mut profile = Self::new();
        profile.extend(iter);
        profile
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_adds_counts() {
        let a: Profile = [SyscallId::new(1, 5), SyscallId::new(1, 6)]
            .into_iter()
            .collect();
        let mut b: Profile = std::iter::once(SyscallId::new(1, 5)).collect();
        b.merge(&a);
        assert_eq!(b.count(SyscallId::new(1, 5)), 2);
        assert_eq!(b.count(SyscallId::new(1, 6)), 1);
        assert_eq!(b.total(), 3);
    }

    #[test]
    fn numbers_filter_by_arch() {
        let profile: Profile = [
            SyscallId::new(AUDIT_ARCH_X86_64, 3),
            SyscallId::new(AUDIT_ARCH_I386, 1),
            SyscallId::new(AUDIT_ARCH_X86_64, 1),
        ]
        .into_iter()
        .collect();
        assert_eq!(profile.numbers_for(AUDIT_ARCH_X86_64), vec![1, 3]);
        assert_eq!(profile.numbers_for(AUDIT_ARCH_I386), vec![1]);
        assert_eq!(profile.arches(), vec![AUDIT_ARCH_I386, AUDIT_ARCH_X86_64]);
    }

    #[test]
    fn native_arch_matches_target() {
        if cfg!(target_arch = "x86_64") {
            assert_eq!(NATIVE_AUDIT_ARCH, Some(AUDIT_ARCH_X86_64));
            assert!(SyscallId::new(AUDIT_ARCH_X86_64, 0).is_native());
        }
    }
}
