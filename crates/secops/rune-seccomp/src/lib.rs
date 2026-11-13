//! seccomp-bpf system call filtering: deny-by-default allowlists and
//! denylists with errno, trap, log and kill actions, kernel detection and
//! best-effort fallback.
//!
//! [seccomp] lets a process restrict which system calls it, and everything
//! it goes on to execute, may make. This crate builds a filter from a list
//! of system calls ([`Options`]), compiles it to classic BPF for the native
//! architecture with [`seccompiler`], and installs it on the calling
//! thread, falling back gracefully on kernels that lack an action or
//! seccomp altogether.
//!
//! - **Allowlist** ([`Options::allowlist`]): deny by default; listed calls
//!   run, every other call fails with an errno, traps, is logged or kills.
//! - **Denylist** ([`Options::denylist`]): listed calls are denied, for
//!   instance [`syscalls::DANGEROUS`], adapted from Docker's profile.
//! - **Architecture handling**: names resolve for the native architecture;
//!   calls through another ABI (32-bit compat) kill the process, and x32
//!   calls on `x86_64` get the deny action.
//! - **Detection** ([`detect`]) and fallback: [`Action::Log`] becomes
//!   [`Action::Allow`] and [`Action::KillProcess`] becomes
//!   [`Action::KillThread`] on kernels before 4.14, unless
//!   [`Compatibility::HardRequirement`] asks to fail instead.
//!
//! [`compile`] works without touching the kernel, and [`Program::evaluate`]
//! runs the compiled program in memory, so a filter can be checked before it
//! is installed; [`Program::to_bytes`] hands it to `bwrap --seccomp`.
//!
//! # Example
//!
//! ```
//! use rune_seccomp::{Action, Arch, Options, compile, syscalls};
//!
//! # if Arch::native().is_none() { return Ok(()); }
//! let options = Options::allowlist(Action::EPERM)
//!     .with_syscalls(["read", "write", "exit_group"]);
//! let program = compile(&options)?;
//!
//! let read = syscalls::resolve("read").unwrap_or_default();
//! let openat = syscalls::resolve("openat").unwrap_or_default();
//! assert_eq!(program.evaluate(read), Some(Action::Allow));
//! assert_eq!(program.evaluate(openat), Some(Action::EPERM));
//! # Ok::<(), rune_seccomp::Error>(())
//! ```
//!
//! Installing it restricts the calling thread for good:
//!
//! ```no_run
//! use rune_seccomp::{Action, Options, Status, install, syscalls};
//! use std::os::unix::process::CommandExt;
//!
//! let report = install(
//!     &Options::denylist(Action::EPERM).with_syscalls(syscalls::DANGEROUS.iter().copied()),
//! )?;
//! if report.status != Status::FullyEnforced {
//!     eprintln!("seccomp: {:?} ({})", report.status, report.support);
//! }
//! let err = std::process::Command::new("/usr/bin/make").exec();
//! # Ok::<(), rune_seccomp::Error>(())
//! ```
//!
//! [seccomp]: https://docs.kernel.org/userspace-api/seccomp_filter.html

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod action;
mod bpf;
mod filter;
mod support;
pub mod syscalls;
mod table;

pub use action::{Action, ActionSet, MAX_ERRNO};
pub use filter::{
    ArgMatch, Compatibility, Options, Program, Report, Status, compile, install, install_with,
};
pub use support::{Support, detect};
pub use syscalls::{Arch, Syscall};

/// Errors returned by this crate.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The crate was built for an architecture seccomp filters cannot be
    /// built for (only `x86_64`, `aarch64` and `riscv64` are supported).
    #[error("seccomp filters are not supported on {arch}")]
    UnsupportedArch {
        /// The architecture's name.
        arch: &'static str,
    },
    /// A listed name is not a system call on any supported architecture.
    #[error("unknown system call `{name}`")]
    UnknownSyscall {
        /// The name.
        name: String,
    },
    /// The options cannot make a valid filter.
    #[error("invalid seccomp filter: {reason}")]
    InvalidFilter {
        /// Why.
        reason: String,
    },
    /// [`Compatibility::HardRequirement`] was requested and the kernel has
    /// no seccomp. Nothing was installed.
    #[error("seccomp is required, but it is {support}")]
    Unsupported {
        /// What the kernel offers.
        support: Support,
    },
    /// The kernel lacks a requested action, and either
    /// [`Compatibility::HardRequirement`] was requested or it has no
    /// fallback. Nothing was installed.
    #[error("seccomp action {action} is not available (kernel offers: {available})")]
    ActionUnavailable {
        /// The requested action.
        action: Action,
        /// The actions the kernel offers.
        available: ActionSet,
    },
    /// The kernel refused `no_new_privs` or the filter.
    #[error("installing the seccomp filter failed: {source}")]
    Install {
        /// The underlying error.
        source: std::io::Error,
    },
    /// The filter could not be applied to every thread, because this
    /// thread is in an incompatible seccomp state.
    #[error("synchronising the seccomp filter failed on thread {thread}")]
    ThreadSync {
        /// The id of the thread that could not be synchronised.
        thread: i64,
    },
}
