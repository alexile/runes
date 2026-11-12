//! A set of limits applied together.

use std::process::Command;

use crate::{Error, Resource, Rlimit, Value, sys};

/// Bytes in a mebibyte, the unit of the `*_mb` fields of
/// [`Limits`](crate::Limits).
pub const MIB: u64 = 1024 * 1024;

/// Limits for any number of resources, applied together to a child
/// process ([`LimitSet::apply_to`]) or to the calling process
/// ([`LimitSet::apply_to_current`]).
///
/// Each resource appears at most once; setting it again replaces the
/// earlier limit in place. Limits are applied in insertion order.
///
/// ```
/// use rune_rlimits::{LimitSet, Resource, Rlimit};
///
/// let set = LimitSet::new()
///     .with_address_space_bytes(512 * 1024 * 1024)
///     .with_cpu_seconds(30)
///     .with(Resource::NoFile, Rlimit::new(256, 1024)?)
///     .without_core_dumps();
/// assert_eq!(set.len(), 4);
/// assert_eq!(set.get(Resource::NoFile), Some(Rlimit::new(256, 1024)?));
/// # Ok::<(), rune_rlimits::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LimitSet {
    limits: Vec<(Resource, Rlimit)>,
}

impl LimitSet {
    /// An empty set, which applies nothing.
    #[must_use]
    pub const fn new() -> Self {
        Self { limits: Vec::new() }
    }

    /// Sets `resource`'s soft and hard limits, replacing any earlier
    /// limit for it.
    #[must_use]
    pub fn with(mut self, resource: Resource, limit: Rlimit) -> Self {
        self.insert(resource, limit);
        self
    }

    /// Sets `resource`'s soft and hard limits both to `value`.
    #[must_use]
    pub fn with_fixed(self, resource: Resource, value: impl Into<Value>) -> Self {
        self.with(resource, Rlimit::fixed(value))
    }

    /// Caps the virtual address space ([`Resource::AddressSpace`]) at
    /// `bytes`.
    #[must_use]
    pub fn with_address_space_bytes(self, bytes: u64) -> Self {
        self.with_fixed(Resource::AddressSpace, bytes)
    }

    /// Caps CPU time ([`Resource::Cpu`]) at `seconds`.
    #[must_use]
    pub fn with_cpu_seconds(self, seconds: u64) -> Self {
        self.with_fixed(Resource::Cpu, seconds)
    }

    /// Caps open file descriptors ([`Resource::NoFile`]) at `count`.
    #[must_use]
    pub fn with_open_files(self, count: u64) -> Self {
        self.with_fixed(Resource::NoFile, count)
    }

    /// Caps processes and threads of the real user ID
    /// ([`Resource::NProc`]) at `count`.
    #[must_use]
    pub fn with_processes(self, count: u64) -> Self {
        self.with_fixed(Resource::NProc, count)
    }

    /// Caps the size of any file the process writes ([`Resource::FileSize`])
    /// at `bytes`.
    #[must_use]
    pub fn with_file_size_bytes(self, bytes: u64) -> Self {
        self.with_fixed(Resource::FileSize, bytes)
    }

    /// Disables core dumps ([`Resource::Core`] set to `0`).
    #[must_use]
    pub fn without_core_dumps(self) -> Self {
        self.with_fixed(Resource::Core, 0)
    }

    /// Sets `resource`'s limits in place, replacing any earlier limit.
    pub fn insert(&mut self, resource: Resource, limit: Rlimit) {
        match self.limits.iter_mut().find(|(r, _)| *r == resource) {
            Some(entry) => entry.1 = limit,
            None => self.limits.push((resource, limit)),
        }
    }

    /// The limit set for `resource`, if any.
    #[must_use]
    pub fn get(&self, resource: Resource) -> Option<Rlimit> {
        self.limits
            .iter()
            .find(|(r, _)| *r == resource)
            .map(|(_, limit)| *limit)
    }

    /// The limits, in the order they are applied.
    pub fn iter(&self) -> impl Iterator<Item = (Resource, Rlimit)> + '_ {
        self.limits.iter().copied()
    }

    /// How many resources the set limits.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.limits.len()
    }

    /// `true` if the set limits nothing.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.limits.is_empty()
    }

    /// A copy lowered to fit under `ceiling(resource)` for every resource
    /// (see [`Rlimit::clamped_to`]), keeping the order.
    #[must_use]
    pub fn clamped_by(&self, mut ceiling: impl FnMut(Resource) -> Value) -> Self {
        Self {
            limits: self
                .limits
                .iter()
                .map(|(r, limit)| (*r, limit.clamped_to(ceiling(*r))))
                .collect(),
        }
    }

    /// A copy lowered to fit under the calling process's current hard
    /// limits, so that an unprivileged process can apply it: asking for
    /// more than the current hard limit then degrades to "as much as
    /// allowed" instead of failing the spawn with `EPERM`.
    ///
    /// # Errors
    ///
    /// [`Error::Os`] if a current limit cannot be read.
    pub fn clamped_to_current(&self) -> Result<Self, Error> {
        let mut out = Self::new();
        for (resource, limit) in &self.limits {
            let hard = sys::get(*resource)?.hard();
            out.limits.push((*resource, limit.clamped_to(hard)));
        }
        Ok(out)
    }

    /// Attaches the limits to `command` via a `pre_exec` hook, so they are
    /// in effect in the child from the moment it execs. Limits survive
    /// `execve`, so a launcher the child execs into keeps them too.
    ///
    /// An empty set leaves `command` untouched (no hook is added). If the
    /// kernel rejects a limit — typically raising a hard limit without
    /// `CAP_SYS_RESOURCE` (use [`LimitSet::clamped_to_current`] to avoid
    /// that) — spawning `command` fails with that error.
    pub fn apply_to(&self, command: &mut Command) {
        if self.is_empty() {
            return;
        }
        let raw = self
            .limits
            .iter()
            .map(|(resource, limit)| (resource.raw(), limit.to_raw()))
            .collect();
        sys::pre_exec(command, raw);
    }

    /// Applies the limits to the calling process, in order, stopping at
    /// the first failure. Limits are process-wide: they affect every
    /// thread, and every child spawned afterwards inherits them.
    ///
    /// # Errors
    ///
    /// [`Error::Os`] for the first limit the kernel rejects; the limits
    /// before it stay applied.
    pub fn apply_to_current(&self) -> Result<(), Error> {
        for (resource, limit) in &self.limits {
            sys::set(*resource, *limit)?;
        }
        Ok(())
    }
}

impl FromIterator<(Resource, Rlimit)> for LimitSet {
    fn from_iter<I: IntoIterator<Item = (Resource, Rlimit)>>(iter: I) -> Self {
        let mut set = Self::new();
        for (resource, limit) in iter {
            set.insert(resource, limit);
        }
        set
    }
}

impl Extend<(Resource, Rlimit)> for LimitSet {
    fn extend<I: IntoIterator<Item = (Resource, Rlimit)>>(&mut self, iter: I) {
        for (resource, limit) in iter {
            self.insert(resource, limit);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn later_settings_replace_earlier_ones_in_place() {
        let set = LimitSet::new()
            .with_cpu_seconds(10)
            .with_open_files(64)
            .with_cpu_seconds(20);
        let order: Vec<_> = set.iter().collect();
        assert_eq!(
            order,
            [
                (Resource::Cpu, Rlimit::fixed(20)),
                (Resource::NoFile, Rlimit::fixed(64)),
            ]
        );
    }

    #[test]
    fn clamping_by_a_ceiling_function() {
        let set = LimitSet::new()
            .with(Resource::NoFile, Rlimit::UNLIMITED)
            .with_cpu_seconds(5);
        let clamped = set.clamped_by(|r| match r {
            Resource::NoFile => Value::Limited(1024),
            _ => Value::Unlimited,
        });
        assert_eq!(clamped.get(Resource::NoFile), Some(Rlimit::fixed(1024)));
        assert_eq!(clamped.get(Resource::Cpu), Some(Rlimit::fixed(5)));
    }

    #[test]
    fn collects_from_pairs() {
        let set: LimitSet = [
            (Resource::Core, Rlimit::fixed(0)),
            (Resource::Core, Rlimit::fixed(1)),
        ]
        .into_iter()
        .collect();
        assert_eq!(set.len(), 1);
        assert_eq!(set.get(Resource::Core), Some(Rlimit::fixed(1)));
    }
}
