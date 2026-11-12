//! The [`Profile`]: what a process keeps, as promises and path rules.

use std::collections::BTreeSet;
use std::path::PathBuf;

use crate::{Error, Permissions, Promise, PromiseSet};

/// System calls every profile allows.
const ALWAYS: &[&str] = &["exit", "exit_group"];

/// One `unveil(2)`-style rule: `permissions` on `path` and, for a
/// directory, everything beneath it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct PathRule {
    /// The file or directory hierarchy the rule covers.
    pub path: PathBuf,
    /// What the rule allows there, subject to the profile's promises.
    pub permissions: Permissions,
}

impl PathRule {
    /// A rule allowing `permissions` on `path`.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>, permissions: Permissions) -> Self {
        Self {
            path: path.into(),
            permissions,
        }
    }
}

/// What happens when the process makes a system call its promises do not
/// cover.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum Violation {
    /// The call fails with `EPERM`, which most programs report and survive.
    /// The default.
    #[default]
    Errno,
    /// The process is killed with an uncatchable `SIGSYS`, as OpenBSD's
    /// `pledge(2)` does. Kernels before 4.14 kill only the thread.
    Kill,
    /// The call runs and is recorded in the kernel audit log, to find out
    /// what a profile is missing before enforcing it. This only relaxes the
    /// system call filter: Landlock has no audit-only mode, so filesystem
    /// path rules are still enforced. Kernels before 4.14 cannot log, and
    /// install no filter.
    Log,
}

/// How hard [`reduce_capabilities`](crate::reduce_capabilities) tries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum Enforcement {
    /// Apply whatever the platform supports and report the rest as
    /// [`Warning`](crate::Warning)s. On a platform or kernel without the
    /// primitives, this restricts nothing and succeeds. The default: a
    /// capability reduction is a hardening layer, and a missing kernel
    /// feature should not stop the program.
    #[default]
    BestEffort,
    /// Fail with [`Error::Unsupported`], before restricting anything,
    /// unless both the filesystem layer (Landlock) and the system call
    /// layer (seccomp) are available. A kernel that supports an older
    /// Landlock ABI or lacks a seccomp action still counts: the
    /// [`Report`](crate::Report) says what is left unenforced.
    Required,
}

/// A capability-reduction profile: the [`Promise`]s the process keeps, the
/// paths it may still reach, and what happens on a violation.
///
/// With no path rule, the filesystem promises apply to the whole
/// filesystem, as `pledge(2)` without `unveil(2)` does. With path rules,
/// only the listed paths stay reachable, each with the intersection of its
/// [`Permissions`] and what the promises allow.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Profile {
    /// The promises kept.
    pub promises: PromiseSet,
    /// The path allowlist; empty means the whole filesystem.
    pub paths: Vec<PathRule>,
    /// What happens to a system call outside the promises. Default:
    /// [`Violation::Errno`].
    pub violation: Violation,
    /// What to do when the platform cannot enforce the profile. Default:
    /// [`Enforcement::BestEffort`].
    pub enforcement: Enforcement,
    /// Restrict every thread of the process, not only the calling one.
    /// Needs Linux 3.17 for seccomp and Landlock ABI 8 (Linux 6.15);
    /// older kernels restrict the calling thread only and report it.
    /// Default: `false`.
    pub all_threads: bool,
}

impl Default for Profile {
    /// [`Promise::Stdio`] only, no path: computation on the descriptors
    /// the process already holds.
    fn default() -> Self {
        Self::new(Promise::Stdio.into())
    }
}

impl Profile {
    /// A profile keeping `promises`, with no path rule.
    #[must_use]
    pub const fn new(promises: PromiseSet) -> Self {
        Self {
            promises,
            paths: Vec::new(),
            violation: Violation::Errno,
            enforcement: Enforcement::BestEffort,
            all_threads: false,
        }
    }

    /// A profile from a `pledge(2)` promise string such as
    /// `"stdio rpath inet"`.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownPromise`] for a name that is not a [`Promise`].
    pub fn pledge(promises: &str) -> Result<Self, Error> {
        Ok(Self::new(promises.parse()?))
    }

    /// Adds `promise`.
    #[must_use]
    pub const fn with_promise(mut self, promise: Promise) -> Self {
        self.promises = self.promises.with(promise);
        self
    }

    /// Adds a path rule allowing `permissions` on `path`, as `unveil(2)`
    /// does.
    #[must_use]
    pub fn with_path(mut self, path: impl Into<PathBuf>, permissions: Permissions) -> Self {
        self.paths.push(PathRule::new(path, permissions));
        self
    }

    /// Sets [`Profile::violation`].
    #[must_use]
    pub const fn with_violation(mut self, violation: Violation) -> Self {
        self.violation = violation;
        self
    }

    /// Sets [`Profile::enforcement`].
    #[must_use]
    pub const fn with_enforcement(mut self, enforcement: Enforcement) -> Self {
        self.enforcement = enforcement;
        self
    }

    /// Sets [`Profile::all_threads`].
    #[must_use]
    pub const fn with_all_threads(mut self, all_threads: bool) -> Self {
        self.all_threads = all_threads;
        self
    }

    /// The system calls the promises allow, by name, sorted. `exit` and
    /// `exit_group` are always allowed, so that even a process with no
    /// promise can end. On Linux, names the native architecture lacks are
    /// skipped when the filter is built.
    #[must_use]
    pub fn syscalls(&self) -> BTreeSet<&'static str> {
        self.promises
            .iter()
            .flat_map(|promise| promise.syscalls().iter().copied())
            .chain(ALWAYS.iter().copied())
            .collect()
    }

    /// The path rules to enforce: [`Profile::paths`], or a single rule
    /// granting everything on `/` when there is none (the promises still
    /// decide what that grants).
    #[must_use]
    pub fn path_rules(&self) -> Vec<PathRule> {
        if self.paths.is_empty() {
            vec![PathRule::new("/", Permissions::ALL)]
        } else {
            self.paths.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults() {
        let profile = Profile::default();
        assert_eq!(profile.promises, Promise::Stdio.into());
        assert_eq!(profile.paths, []);
        assert_eq!(profile.violation, Violation::Errno);
        assert_eq!(profile.enforcement, Enforcement::BestEffort);
        assert!(!profile.all_threads);
    }

    #[test]
    fn builders() {
        let profile = Profile::pledge("stdio")
            .unwrap()
            .with_promise(Promise::Rpath)
            .with_path("/usr", Permissions::READ_EXEC)
            .with_violation(Violation::Kill)
            .with_enforcement(Enforcement::Required)
            .with_all_threads(true);
        assert_eq!(profile.promises.to_string(), "stdio rpath");
        assert_eq!(
            profile.paths,
            [PathRule::new("/usr", Permissions::READ_EXEC)]
        );
        assert_eq!(profile.path_rules(), profile.paths);
        assert_eq!(profile.violation, Violation::Kill);
        assert_eq!(profile.enforcement, Enforcement::Required);
        assert!(profile.all_threads);
        assert!(Profile::pledge("stdio tty").is_err());
    }

    #[test]
    fn no_path_means_the_whole_filesystem() {
        assert_eq!(
            Profile::default().path_rules(),
            [PathRule::new("/", Permissions::ALL)]
        );
    }

    #[test]
    fn syscalls_are_the_union_of_the_promises() {
        let stdio = Profile::default().syscalls();
        assert!(stdio.contains("read") && stdio.contains("exit_group"));
        assert!(!stdio.contains("openat") && !stdio.contains("execve"));

        let rpath = Profile::pledge("stdio rpath").unwrap().syscalls();
        assert!(rpath.contains("openat") && rpath.is_superset(&stdio));
        assert!(!rpath.contains("unlinkat"));

        let net = Profile::pledge("inet").unwrap().syscalls();
        assert_eq!(net, Profile::pledge("unix").unwrap().syscalls());
        assert!(net.contains("socket") && !net.contains("read") && net.contains("exit"));

        assert_eq!(
            Profile::new(PromiseSet::EMPTY).syscalls(),
            BTreeSet::from(["exit", "exit_group"])
        );
    }
}
