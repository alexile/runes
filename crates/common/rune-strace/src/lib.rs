//! System-call tracing for building and tuning seccomp profiles: trace a
//! child with `ptrace(2)` and get the set of calls it made, or parse the
//! text `strace` printed.
//!
//! - [`trace`] (Linux) runs a [`Command`](std::process::Command) under
//!   `ptrace`, following its forks and threads, and returns a [`Report`]
//!   whose [`Profile`] counts every system call by architecture and
//!   number. [`Profile::numbers`] is an allowlist ready for a seccomp
//!   filter builder such as `rune-seccomp`. [`probe`] checks that tracing
//!   works on this host (Yama `ptrace_scope` and container seccomp
//!   policies can forbid it).
//! - [`parse_line`] splits one `strace -f` line into pid, name, raw
//!   arguments and result; [`first_quoted_string`] pulls a path or address
//!   out of the arguments; [`call_name`] and [`count_calls`] count calls by
//!   name in a whole log. These are sans-I/O: they never spawn `strace`.
//!
//! # Example
//!
//! Parsing captured `strace` output touches nothing:
//!
//! ```
//! use rune_strace::{count_calls, first_quoted_string, parse_line};
//!
//! let line = r#"12345 openat(AT_FDCWD, "/etc/hosts", O_RDONLY) = 3"#;
//! let call = parse_line(line).unwrap();
//! assert_eq!(call.pid.as_deref(), Some("12345"));
//! assert_eq!(call.name, "openat");
//! assert_eq!(call.result, "3");
//! assert_eq!(first_quoted_string(&call.args).as_deref(), Some("/etc/hosts"));
//!
//! let counts = count_calls("1 read(3, \"\", 1) = 0\n1 read(3, \"\", 1) = 0\n");
//! assert_eq!(counts.get("read"), Some(&2));
//! ```
//!
//! Tracing a program needs `ptrace`:
//!
//! ```no_run
//! # #[cfg(target_os = "linux")]
//! # fn main() -> Result<(), rune_strace::Error> {
//! use std::process::{Command, Stdio};
//! use rune_strace::{Options, trace};
//!
//! let mut command = Command::new("/usr/bin/ls");
//! command.arg("/").stdout(Stdio::null());
//! let report = trace(&mut command, &Options::default())?;
//! for nr in report.profile.numbers() {
//!     println!("{nr}");
//! }
//! # Ok(())
//! # }
//! # #[cfg(not(target_os = "linux"))]
//! # fn main() {}
//! ```

// `unsafe` is confined to the `sys` module; see the README's Safety
// section.
#![warn(missing_docs)]

mod line;
mod profile;
#[cfg(target_os = "linux")]
mod sys;
#[cfg(target_os = "linux")]
mod trace;

pub use line::{Syscall, call_name, count_calls, first_quoted_string, parse_line};
pub use profile::{
    AUDIT_ARCH_AARCH64, AUDIT_ARCH_I386, AUDIT_ARCH_RISCV64, AUDIT_ARCH_X86_64, NATIVE_AUDIT_ARCH,
    Profile, SyscallId,
};
#[cfg(target_os = "linux")]
pub use trace::{Exit, Options, Report, probe, trace};

/// Errors returned by [`trace`] and [`probe`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Tracing is not possible on this host.
    #[error("ptrace is unavailable here: {detail}")]
    Unavailable {
        /// What failed, with the underlying error.
        detail: String,
    },
    /// The program could not be started.
    #[error("cannot start the program: {0}")]
    Spawn(#[source] std::io::Error),
    /// A `ptrace` or `waitpid` call failed while tracing.
    #[error("{op}: {source}")]
    Ptrace {
        /// The call that failed.
        op: &'static str,
        /// The underlying error.
        source: std::io::Error,
    },
    /// The tracer thread panicked (a bug in this crate).
    #[error("the tracer thread panicked")]
    TracerPanicked,
}
