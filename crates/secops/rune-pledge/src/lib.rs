//! pledge-style capability reduction: map a simple promise profile to
//! Landlock and seccomp on Linux, with a documented best-effort no-op
//! elsewhere.
//!
//! OpenBSD's [`pledge(2)`] lets a program give up every capability it does
//! not name, and [`unveil(2)`] hides every path it does not list. This
//! crate offers the same shape portably: describe what the process keeps
//! as a [`Profile`] of [`Promise`]s and path rules, and
//! [`reduce_capabilities`] applies the strongest primitives the platform
//! has:
//!
//! | Platform | Filesystem layer                | System call layer                 |
//! | -------- | ------------------------------- | --------------------------------- |
//! | Linux    | Landlock (`rune-landlock`)      | seccomp-bpf (`rune-seccomp`)      |
//! | other    | none: a documented no-op        | none                              |
//!
//! On Linux the promises become a seccomp allowlist and a set of Landlock
//! rights, and each path rule grants, beneath its path, the rights both
//! its [`Permissions`] and the promises allow. Without a path rule, the
//! promises apply to the whole filesystem, as `pledge` without `unveil`
//! does. Older kernels degrade gracefully: the [`Report`] says what is in
//! force and lists a [`Warning`] for everything that is not.
//!
//! Elsewhere (macOS, the BSDs, Windows) nothing is restricted: with the
//! default [`Enforcement::BestEffort`] the call succeeds with
//! [`Status::NotEnforced`] and a [`Warning::UnsupportedPlatform`];
//! [`Enforcement::Required`] fails with [`Error::Unsupported`] instead.
//! (OpenBSD's own `pledge` and `unveil`, macOS's sandbox and Windows job
//! objects are not driven by this crate.)
//!
//! The reduction is permanent and inherited: it lasts for the rest of the
//! thread's life (the process's, with [`Profile::all_threads`]), survives
//! `execve` and passes to children. A later call can only narrow it.
//!
//! # Example
//!
//! Working out what a profile maps to needs no kernel support:
//!
//! ```
//! use rune_pledge::{Permissions, Profile, Promise};
//!
//! let profile = Profile::pledge("stdio rpath")?
//!     .with_path("/usr", Permissions::READ_EXEC)
//!     .with_path("/srv/data", "rwc".parse()?);
//! assert!(profile.promises.contains(Promise::Rpath));
//!
//! let syscalls = profile.syscalls();
//! assert!(syscalls.contains("openat"));
//! assert!(!syscalls.contains("execve"), "exec was not promised");
//! assert!(!syscalls.contains("socket"), "inet was not promised");
//! # Ok::<(), rune_pledge::Error>(())
//! ```
//!
//! Applying it restricts the calling thread for good:
//!
//! ```no_run
//! use rune_pledge::{Permissions, Profile, Status, reduce_capabilities};
//!
//! let config = std::fs::read_to_string("/etc/myapp.toml")?;
//! let report = reduce_capabilities(
//!     &Profile::pledge("stdio rpath wpath cpath")?
//!         .with_path("/var/lib/myapp", Permissions::READ_WRITE_CREATE),
//! )?;
//! if report.status != Status::FullyEnforced {
//!     for warning in &report.warnings {
//!         eprintln!("pledge: {warning}");
//!     }
//! }
//! // From here on, only /var/lib/myapp is reachable, and no program can
//! // be executed, no socket opened, no process forked.
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! [`pledge(2)`]: https://man.openbsd.org/pledge.2
//! [`unveil(2)`]: https://man.openbsd.org/unveil.2

#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(target_os = "linux")]
mod linux;
mod permissions;
mod profile;
mod promise;
mod report;

pub use permissions::Permissions;
pub use profile::{Enforcement, PathRule, Profile, Violation};
pub use promise::{Promise, PromiseSet};
pub use report::{Report, Status, Warning};

/// Errors returned by this crate.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A promise string names something that is not a [`Promise`].
    #[error("unknown promise `{name}`")]
    UnknownPromise {
        /// The unknown name.
        name: String,
    },
    /// A permission string is not a set of distinct `r`, `w`, `x` and `c`
    /// letters.
    #[error("invalid permissions `{input}`: expected letters from `rwxc`, each at most once")]
    InvalidPermissions {
        /// The rejected string.
        input: String,
    },
    /// [`Enforcement::Required`] was requested and the platform lacks a
    /// layer. Nothing was restricted.
    #[error("capability reduction is required, but {reason}")]
    Unsupported {
        /// What is missing.
        reason: String,
    },
    /// Applying the Landlock layer failed. Nothing was restricted.
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    Landlock(#[from] rune_landlock::Error),
    /// Building or installing the seccomp layer failed.
    #[cfg(target_os = "linux")]
    #[error("{source}{}", if *filesystem_restricted { " (the filesystem restriction is already in force)" } else { "" })]
    Seccomp {
        /// The underlying error.
        source: rune_seccomp::Error,
        /// `true` if the Landlock layer had already been applied, and so
        /// stays in force.
        filesystem_restricted: bool,
    },
}

/// Reduces the calling thread's capabilities to `profile`, with the
/// strongest primitives the platform has, for good.
///
/// On Linux this applies a Landlock ruleset, then a seccomp filter (see
/// `Profile::landlock_options` and `Profile::seccomp_options`); both
/// set `no_new_privs`. Unless [`Profile::all_threads`] is set, only the
/// calling thread is restricted, and threads that already exist keep their
/// capabilities. On other platforms nothing is restricted.
///
/// # Errors
///
/// - [`Error::Unsupported`] with [`Enforcement::Required`] when a layer is
///   missing; nothing has been restricted.
/// - [`Error::Landlock`] when the kernel rejects the ruleset or a path
///   rule cannot be opened; nothing has been restricted.
/// - [`Error::Seccomp`] when the filter cannot be built or installed.
pub fn reduce_capabilities(profile: &Profile) -> Result<Report, Error> {
    #[cfg(target_os = "linux")]
    {
        linux::apply(profile)
    }
    #[cfg(not(target_os = "linux"))]
    {
        unsupported_platform(profile, std::env::consts::OS)
    }
}

/// What [`reduce_capabilities`] does on a platform without primitives.
#[cfg_attr(target_os = "linux", allow(dead_code, reason = "tested on Linux"))]
fn unsupported_platform(profile: &Profile, os: &'static str) -> Result<Report, Error> {
    if profile.enforcement == Enforcement::Required {
        return Err(Error::Unsupported {
            reason: format!("{os} has no supported capability-reduction primitive"),
        });
    }
    let mut report = Report::not_enforced(Vec::new());
    report.warn(Warning::UnsupportedPlatform { os });
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn other_platforms_are_a_documented_no_op() {
        let report = unsupported_platform(&Profile::default(), "macos").unwrap();
        assert_eq!(report.status, Status::NotEnforced);
        assert_eq!(report.filesystem, Status::NotEnforced);
        assert_eq!(report.syscalls, Status::NotEnforced);
        assert_eq!(
            report.warnings,
            [Warning::UnsupportedPlatform { os: "macos" }]
        );

        let required = Profile::default().with_enforcement(Enforcement::Required);
        let err = unsupported_platform(&required, "windows").unwrap_err();
        assert!(matches!(err, Error::Unsupported { ref reason } if reason.contains("windows")));
    }

    #[test]
    fn errors_display() {
        let err = Error::UnknownPromise { name: "tty".into() };
        assert_eq!(err.to_string(), "unknown promise `tty`");
    }
}
