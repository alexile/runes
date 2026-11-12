//! Linux namespace process isolation: spawn children under bubblewrap or
//! `unshare(2)` with an ordered mount plan and environment allowlist.
//!
//! [`Options`] describe a sandbox — which [`Namespace`]s to unshare, the
//! [`MountPlan`] that builds its filesystem, the [`EnvPolicy`] that scrubs
//! its environment, and optionally a seccomp filter and a launcher such as
//! `rune-landlock` — and [`Options::command`] turns them into a
//! [`std::process::Command`] ready to spawn.
//!
//! Two backends build the sandbox:
//!
//! - [`Backend::Bwrap`] (the default) runs the program through
//!   [bubblewrap], which supports everything: an empty root with only the
//!   paths you bind in, masks over secrets, a PID namespace, a seccomp
//!   filter handed over in a pipe.
//! - [`Backend::Unshare`] calls `unshare(2)` in the child just before
//!   `exec`, with no helper binary, for network, IPC, UTS and user
//!   isolation of a program that keeps the host filesystem.
//!
//! Both need unprivileged user namespaces, which some distributions
//! restrict; [`probe`] checks that a backend works on this host.
//!
//! # Example
//!
//! Building the plan and inspecting what it exposes touches nothing:
//!
//! ```
//! use rune_namespaces::{EnvPolicy, Exposure, MaskKind, MountPlan, Options};
//!
//! let mounts = MountPlan::isolated()
//!     .with_system_read_only()
//!     .with_read_write("/home/me/project")
//!     .with_mask("/home/me/project/.env", MaskKind::File);
//! assert_eq!(mounts.lookup("/home/me/project/.env"), Exposure::Masked);
//! assert_eq!(mounts.lookup("/home/me/.ssh/id_ed25519"), Exposure::Private);
//!
//! let options = Options::default()
//!     .with_mounts(mounts)
//!     .with_env(EnvPolicy::default().with_allow("PATH").with_set("HOME", "/tmp"))
//!     .with_cwd("/home/me/project");
//! let args = options.bwrap_args("make", &["test"], None)?;
//! assert!(args.iter().any(|a| a == "--unshare-net"));
//! # Ok::<(), rune_namespaces::Error>(())
//! ```
//!
//! Spawning it needs `bwrap` and user namespaces:
//!
//! ```no_run
//! use rune_namespaces::{MountPlan, Options};
//!
//! let status = Options::default()
//!     .with_mounts(MountPlan::isolated().with_system_read_only())
//!     .command("/usr/bin/ls", &["/"])?
//!     .status()?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! [bubblewrap]: https://github.com/containers/bubblewrap

// `unsafe` is confined to the `sys` module's `pre_exec` hooks; see the
// README's Safety section.
#![warn(missing_docs)]

mod env;
mod mount;
mod namespace;
mod sandbox;
mod sys;

pub use env::{COMMON_VARS, EnvPolicy};
pub use mount::{Access, Exposure, MaskKind, Mount, MountPlan, Phase, SYSTEM_PATHS};
pub use namespace::{Namespace, NamespaceSet};
pub use sandbox::{BWRAP_PATHS, Backend, Options, SeccompProgram, find_bwrap, probe};

/// Errors returned by this crate.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A mount in the plan is malformed.
    #[error("invalid mount at {}: {reason}", dest.display())]
    InvalidMount {
        /// The mount's destination.
        dest: std::path::PathBuf,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// An environment variable name, pattern or value is malformed.
    #[error("invalid environment variable {}: {reason}", name.to_string_lossy())]
    InvalidEnv {
        /// The variable name or pattern.
        name: std::ffi::OsString,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// The seccomp program is malformed.
    #[error("invalid seccomp program: {reason}")]
    InvalidSeccomp {
        /// What is wrong with it.
        reason: &'static str,
    },
    /// The options contradict each other.
    #[error("invalid options: {reason}")]
    InvalidOptions {
        /// What is wrong.
        reason: &'static str,
    },
    /// The backend cannot provide what the options ask for.
    #[error("the {backend} backend cannot do this: {reason}")]
    Unsupported {
        /// The backend's name.
        backend: &'static str,
        /// What it cannot do.
        reason: &'static str,
    },
    /// The `bwrap` binary could not be found.
    #[error("bwrap not found at {}", path.display())]
    BwrapNotFound {
        /// The path or name that was tried.
        path: std::path::PathBuf,
    },
    /// The backend runs but cannot build a sandbox on this host.
    #[error("{backend} cannot create namespaces here: {detail}")]
    Unavailable {
        /// The backend's name.
        backend: &'static str,
        /// What went wrong, with a hint when it is recognized.
        detail: String,
    },
    /// An I/O operation failed.
    #[error("{context}: {source}")]
    Io {
        /// What was being done.
        context: &'static str,
        /// The underlying error.
        source: std::io::Error,
    },
}
