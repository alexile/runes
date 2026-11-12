//! Landlock LSM filesystem sandboxing: path allowlist rulesets with ABI
//! detection and best-effort fallback on older kernels.
//!
//! [Landlock] lets an unprivileged process restrict its own filesystem
//! access, and that of everything it goes on to execute. This crate builds
//! a ruleset from an allowlist of paths and [`RightSet`]s, detects which
//! Landlock ABI the running kernel supports, and enforces the ruleset on
//! the calling thread, degrading gracefully on kernels that are older than
//! requested or lack Landlock entirely.
//!
//! The restriction is applied where it is wanted — usually in a launcher
//! just before it execs the sandboxed program — rather than from a
//! `pre_exec` hook: it survives `execve`, and building it needs
//! allocations that are not safe between `fork` and `exec`. Note that a
//! process inside a Landlock domain cannot `mount()`, so a sandbox manager
//! such as `bwrap` must finish building its namespaces before the
//! restriction is applied.
//!
//! # Example
//!
//! Building the options and working out what an old kernel would leave
//! unenforced needs no kernel support:
//!
//! ```
//! use rune_landlock::{Abi, Options, Right, Support};
//!
//! let options = Options::default()
//!     .with_read_exec("/usr")
//!     .with_read("/etc")
//!     .with_read_write("/tmp/work");
//! assert_eq!(options.rules.len(), 3);
//!
//! // On a Linux 5.19 kernel (ABI v2), truncation and device ioctls stay
//! // unrestricted; everything else is enforced.
//! let old = Support::Available { abi: Abi::V2, kernel_abi: None };
//! let lost = old.unenforced_rights(options.abi);
//! assert!(lost.contains(Right::Truncate) && lost.contains(Right::IoctlDev));
//! assert!(!lost.contains(Right::WriteFile));
//! ```
//!
//! Enforcing it restricts the calling thread for good:
//!
//! ```no_run
//! use rune_landlock::{Options, Status, restrict_self};
//! use std::os::unix::process::CommandExt;
//!
//! let report = restrict_self(
//!     &Options::default()
//!         .with_read_exec("/usr")
//!         .with_read_exec("/lib64")
//!         .with_read("/etc")
//!         .with_read_write("/tmp/work"),
//! )?;
//! if report.status != Status::FullyEnforced {
//!     eprintln!("landlock: {:?}, unenforced rights: {}", report.status, report.unenforced);
//! }
//! let err = std::process::Command::new("/usr/bin/make").exec();
//! # Ok::<(), rune_landlock::Error>(())
//! ```
//!
//! [Landlock]: https://docs.kernel.org/userspace-api/landlock.html

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod abi;
mod rights;
mod sandbox;

pub use abi::{Abi, Support, detect};
pub use rights::{Right, RightSet};
pub use sandbox::{Compatibility, Options, Report, Rule, Status, restrict_self};

/// Errors returned by this crate.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// [`Compatibility::HardRequirement`] was requested and the kernel does
    /// not support the requested ABI. Nothing was restricted.
    #[error("Landlock ABI {requested} is required, but Landlock is {support}")]
    Unsupported {
        /// The ABI that was requested.
        requested: Abi,
        /// What the kernel supports.
        support: Support,
    },
    /// A rule's path could not be opened. Nothing was restricted.
    #[error("cannot open {}: {source}", path.display())]
    Path {
        /// The rule's path.
        path: std::path::PathBuf,
        /// Why it could not be opened.
        source: std::io::Error,
    },
    /// The kernel rejected the ruleset or the restriction.
    #[error("applying the Landlock ruleset failed: {source}")]
    Landlock {
        /// The underlying error.
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}
