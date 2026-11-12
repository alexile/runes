//! Typed POSIX resource limits: read and set them for the calling process,
//! or apply them to a [`std::process::Command`] so they are in effect in
//! the child from the moment it execs.
//!
//! Nothing here is sandboxing-specific: capping what a spawned process may
//! consume (memory, CPU time, processes, open files, file size, core
//! dumps) is useful to a build system, a CI runner or a worker pool alike.
//!
//! - [`Resource`] names a limit (`RLIMIT_*`) and knows its [`Unit`].
//! - [`Value`] is an amount or [`Value::Unlimited`]; [`Rlimit`] is a
//!   validated soft/hard pair of them.
//! - [`LimitSet`] collects limits and applies them to a child
//!   ([`LimitSet::apply_to`]) or the calling process
//!   ([`LimitSet::apply_to_current`]); [`LimitSet::clamped_to_current`]
//!   lowers requests to what an unprivileged process may set.
//! - [`get`] and [`set`] read and write one limit of the calling process;
//!   [`parse_proc_limits`] reads Linux's `/proc/<pid>/limits` table.
//! - [`Limits`] and [`apply`] are the flat, field-per-limit form for
//!   callers that configure limits from a file.
//!
//! Limits survive `execve`, so a limit set on a launcher before it execs
//! into another program stays in effect afterwards.
//!
//! # Example
//!
//! Building a set touches nothing:
//!
//! ```
//! use rune_rlimits::{LimitSet, Resource, Rlimit, Unit, Value};
//!
//! let set = LimitSet::new()
//!     .with_address_space_bytes(512 * 1024 * 1024)
//!     .with_cpu_seconds(30)
//!     .with(Resource::NoFile, "256:1024".parse::<Rlimit>()?)
//!     .without_core_dumps();
//! assert_eq!(set.get(Resource::Cpu).map(Rlimit::soft), Some(Value::Limited(30)));
//! assert_eq!(Resource::AddressSpace.unit(), Unit::Bytes);
//! assert_eq!("nofile".parse::<Resource>()?.name(), "RLIMIT_NOFILE");
//!
//! let mut command = std::process::Command::new("true");
//! set.apply_to(&mut command);
//! # Ok::<(), rune_rlimits::Error>(())
//! ```
//!
//! Reading the calling process's limits:
//!
//! ```
//! use rune_rlimits::{Resource, get};
//!
//! let files = get(Resource::NoFile)?;
//! assert!(files.soft() <= files.hard());
//! # Ok::<(), rune_rlimits::Error>(())
//! ```

// `unsafe` is confined to the `sys` module; see the README's Safety
// section.
#![warn(missing_docs)]

mod limit;
mod limit_set;
mod proc;
mod resource;
mod sys;

use std::process::Command;

pub use limit::{Rlimit, Value};
pub use limit_set::{LimitSet, MIB};
pub use proc::parse_proc_limits;
pub use resource::{Resource, Unit};
pub use sys::{get, set};

/// Errors returned by this crate.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A soft limit was asked for above its hard limit.
    #[error("soft limit {soft} exceeds hard limit {hard}")]
    SoftAboveHard {
        /// The soft limit.
        soft: Value,
        /// The hard limit.
        hard: Value,
    },
    /// A resource name is not one this platform knows.
    #[error("unknown resource {name:?}")]
    UnknownResource {
        /// The name that was given.
        name: String,
    },
    /// A limit value is neither a decimal number nor `unlimited`.
    #[error("invalid limit value {text:?}")]
    InvalidValue {
        /// The text that was given.
        text: String,
    },
    /// A `/proc/<pid>/limits` table is malformed.
    #[error("limits table line {line}: {reason}")]
    Parse {
        /// The 1-based line number.
        line: usize,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// The kernel rejected a `getrlimit`/`setrlimit` call.
    #[error("{op}({resource}): {source}")]
    Os {
        /// The call that failed.
        op: &'static str,
        /// The resource it was for.
        resource: Resource,
        /// The underlying error (`EPERM` when raising a hard limit without
        /// privilege, `EINVAL` for a soft limit above the hard one).
        source: std::io::Error,
    },
}

/// The common limits as plain fields.
///
/// This is the form for callers that load limits from a configuration
/// file. Every field is opt-in: `None`/`false` (the [`Default`]) applies
/// nothing. Each limit sets the soft and hard values alike.
///
/// [`LimitSet`] covers every resource and soft/hard pairs; convert with
/// `LimitSet::from(&limits)`.
// Not `#[non_exhaustive]`: callers build it with a struct literal, and the
// typed API (`LimitSet`) is where new resources go.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Limits {
    /// Processes and threads of the real user ID ([`Resource::NProc`]), a
    /// count.
    pub max_processes: Option<u64>,
    /// Virtual address space ([`Resource::AddressSpace`]), in mebibytes.
    pub memory_mb: Option<u64>,
    /// CPU time ([`Resource::Cpu`]), in seconds.
    pub cpu_seconds: Option<u64>,
    /// Open file descriptors ([`Resource::NoFile`]), a count.
    pub max_open_files: Option<u64>,
    /// Size of any file the process writes ([`Resource::FileSize`]), in
    /// mebibytes.
    pub max_file_size_mb: Option<u64>,
    /// Set [`Resource::Core`] to 0, disabling core dumps.
    pub disable_core_dumps: bool,
}

impl From<&Limits> for LimitSet {
    /// Converts mebibytes to bytes, saturating (a saturated value means
    /// unlimited).
    fn from(limits: &Limits) -> Self {
        let mut set = Self::new();
        if let Some(n) = limits.max_processes {
            set = set.with_processes(n);
        }
        if let Some(mb) = limits.memory_mb {
            set = set.with_address_space_bytes(mb.saturating_mul(MIB));
        }
        if let Some(secs) = limits.cpu_seconds {
            set = set.with_cpu_seconds(secs);
        }
        if let Some(n) = limits.max_open_files {
            set = set.with_open_files(n);
        }
        if let Some(mb) = limits.max_file_size_mb {
            set = set.with_file_size_bytes(mb.saturating_mul(MIB));
        }
        if limits.disable_core_dumps {
            set = set.without_core_dumps();
        }
        set
    }
}

/// Attaches `limits` to `command` via a `pre_exec` hook; see
/// [`LimitSet::apply_to`]. A no-op if no limit is set.
///
/// ```
/// use rune_rlimits::Limits;
/// use std::process::Command;
///
/// let limits = Limits {
///     memory_mb: Some(512),
///     disable_core_dumps: true,
///     ..Limits::default()
/// };
/// let mut command = Command::new("true");
/// rune_rlimits::apply(&mut command, &limits);
/// ```
pub fn apply(command: &mut Command, limits: &Limits) {
    LimitSet::from(limits).apply_to(command);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_limits_means_no_resources() {
        assert!(LimitSet::from(&Limits::default()).is_empty());
    }

    #[test]
    fn disable_core_dumps_sets_rlimit_core_to_zero() {
        let limits = Limits {
            disable_core_dumps: true,
            ..Limits::default()
        };
        let set = LimitSet::from(&limits);
        assert_eq!(set.len(), 1);
        assert_eq!(set.get(Resource::Core), Some(Rlimit::fixed(0)));
    }

    #[test]
    fn megabytes_convert_to_bytes() {
        let limits = Limits {
            memory_mb: Some(512),
            max_file_size_mb: Some(2),
            ..Limits::default()
        };
        let set = LimitSet::from(&limits);
        assert_eq!(
            set.get(Resource::AddressSpace),
            Some(Rlimit::fixed(512 * 1024 * 1024))
        );
        assert_eq!(
            set.get(Resource::FileSize),
            Some(Rlimit::fixed(2 * 1024 * 1024))
        );
    }

    #[test]
    fn huge_megabytes_saturate_to_unlimited() {
        let limits = Limits {
            memory_mb: Some(u64::MAX),
            ..Limits::default()
        };
        let set = LimitSet::from(&limits);
        let raw = set.get(Resource::AddressSpace).map(|l| l.to_raw().rlim_cur);
        assert_eq!(raw, Some(libc::RLIM_INFINITY));
    }

    #[test]
    fn every_field_maps_to_its_resource() {
        let limits = Limits {
            max_processes: Some(64),
            memory_mb: Some(1),
            cpu_seconds: Some(30),
            max_open_files: Some(256),
            max_file_size_mb: Some(1),
            disable_core_dumps: true,
        };
        let resources: Vec<_> = LimitSet::from(&limits).iter().map(|(r, _)| r).collect();
        assert_eq!(
            resources,
            [
                Resource::NProc,
                Resource::AddressSpace,
                Resource::Cpu,
                Resource::NoFile,
                Resource::FileSize,
                Resource::Core,
            ]
        );
    }
}
