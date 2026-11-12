//! What [`reduce_capabilities`](crate::reduce_capabilities) did.

use std::fmt;
use std::path::PathBuf;

/// How much of a profile, or of one layer of it, is in force.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Status {
    /// Everything requested is enforced.
    FullyEnforced,
    /// Some of it is enforced; the [`Report::warnings`] say what is not.
    PartiallyEnforced,
    /// Nothing is enforced.
    NotEnforced,
}

impl Status {
    /// The status of two layers together.
    #[must_use]
    pub const fn combine(self, other: Self) -> Self {
        match (self, other) {
            (Self::FullyEnforced, Self::FullyEnforced) => Self::FullyEnforced,
            (Self::NotEnforced, Self::NotEnforced) => Self::NotEnforced,
            _ => Self::PartiallyEnforced,
        }
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::FullyEnforced => "fully enforced",
            Self::PartiallyEnforced => "partially enforced",
            Self::NotEnforced => "not enforced",
        })
    }
}

/// Something the platform could not enforce, or a rule that was left out.
///
/// With the `tracing` feature, each warning is also emitted as a
/// `tracing` warning event when it is raised.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Warning {
    /// This platform has no capability-reduction primitive this crate
    /// drives (only Linux does): nothing was restricted.
    UnsupportedPlatform {
        /// The operating system (`std::env::consts::OS`).
        os: &'static str,
    },
    /// The filesystem layer (Landlock) is not in force.
    FilesystemNotEnforced {
        /// Why.
        reason: String,
    },
    /// The filesystem layer is in force, but some of it is not.
    FilesystemPartial {
        /// What is left unenforced.
        reason: String,
    },
    /// The system call layer (seccomp) is not in force.
    SyscallsNotEnforced {
        /// Why.
        reason: String,
    },
    /// The system call layer is in force, but with a fallback action or on
    /// the calling thread only.
    SyscallsPartial {
        /// What differs from the request.
        reason: String,
    },
    /// Path rules whose path does not exist were left out (which only
    /// ever grants less).
    MissingPaths {
        /// The paths.
        paths: Vec<PathBuf>,
    },
}

impl fmt::Display for Warning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform { os } => write!(
                f,
                "capability reduction is not supported on {os}: nothing was restricted"
            ),
            Self::FilesystemNotEnforced { reason } => {
                write!(f, "filesystem restriction not enforced: {reason}")
            }
            Self::FilesystemPartial { reason } => {
                write!(f, "filesystem restriction partially enforced: {reason}")
            }
            Self::SyscallsNotEnforced { reason } => {
                write!(f, "system call filter not enforced: {reason}")
            }
            Self::SyscallsPartial { reason } => {
                write!(f, "system call filter partially enforced: {reason}")
            }
            Self::MissingPaths { paths } => {
                f.write_str("left out missing path(s):")?;
                for path in paths {
                    write!(f, " {}", path.display())?;
                }
                Ok(())
            }
        }
    }
}

/// The result of [`reduce_capabilities`](crate::reduce_capabilities).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Report {
    /// How much of the profile is in force, both layers together.
    pub status: Status,
    /// The filesystem layer (Landlock on Linux).
    pub filesystem: Status,
    /// The system call layer (seccomp on Linux).
    pub syscalls: Status,
    /// What is not enforced, and why. Empty when [`Report::status`] is
    /// [`Status::FullyEnforced`] and every path exists.
    pub warnings: Vec<Warning>,
    /// The Landlock layer's own report, if it was applied.
    #[cfg(target_os = "linux")]
    pub landlock: Option<rune_landlock::Report>,
    /// The seccomp layer's own report, if it was applied.
    #[cfg(target_os = "linux")]
    pub seccomp: Option<rune_seccomp::Report>,
}

impl Report {
    /// A report of nothing enforced.
    pub(crate) const fn not_enforced(warnings: Vec<Warning>) -> Self {
        Self {
            status: Status::NotEnforced,
            filesystem: Status::NotEnforced,
            syscalls: Status::NotEnforced,
            warnings,
            #[cfg(target_os = "linux")]
            landlock: None,
            #[cfg(target_os = "linux")]
            seccomp: None,
        }
    }

    /// Records a warning, emitting it as a `tracing` event with the
    /// `tracing` feature.
    pub(crate) fn warn(&mut self, warning: Warning) {
        #[cfg(feature = "tracing")]
        tracing::warn!(target: "rune_pledge", "{warning}");
        self.warnings.push(warning);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses_combine() {
        use Status::{FullyEnforced as F, NotEnforced as N, PartiallyEnforced as P};
        assert_eq!(F.combine(F), F);
        assert_eq!(N.combine(N), N);
        for (a, b) in [(F, N), (N, F), (P, F), (F, P), (P, P), (N, P)] {
            assert_eq!(a.combine(b), P, "{a} + {b}");
        }
    }

    #[test]
    fn warnings_display() {
        let missing = Warning::MissingPaths {
            paths: vec!["/a".into(), "/b".into()],
        };
        assert_eq!(missing.to_string(), "left out missing path(s): /a /b");
        let os = Warning::UnsupportedPlatform { os: "macos" };
        assert!(os.to_string().contains("not supported on macos"));
    }

    #[test]
    fn warn_records() {
        let mut report = Report::not_enforced(Vec::new());
        report.warn(Warning::UnsupportedPlatform { os: "windows" });
        assert_eq!(report.warnings.len(), 1);
        assert_eq!(report.status, Status::NotEnforced);
    }
}
