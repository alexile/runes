//! Detecting whether the running kernel supports seccomp filters, and
//! which actions it accepts.

use std::fmt;

use crate::ActionSet;

/// Where the kernel lists the seccomp actions it accepts (Linux 4.14).
const ACTIONS_AVAIL: &str = "/proc/sys/kernel/seccomp/actions_avail";
/// Has a `Seccomp:` line when the kernel is built with seccomp.
const SELF_STATUS: &str = "/proc/self/status";

/// What the running kernel offers for seccomp filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Support {
    /// Seccomp filters are available, with these actions.
    Available {
        /// The actions filters may return. Kernels older than 4.14 do not
        /// list them; [`ActionSet::LEGACY`] is assumed for those.
        actions: ActionSet,
    },
    /// The kernel is built without seccomp.
    NotSupported,
    /// `/proc` is not readable, so support could not be determined.
    /// Installing a filter is attempted with [`ActionSet::LEGACY`].
    Unknown,
}

impl Support {
    /// Works out support from the contents of
    /// `/proc/sys/kernel/seccomp/actions_avail` and `/proc/self/status`
    /// (`None` for a file that could not be read), without touching the
    /// kernel.
    #[must_use]
    pub fn from_proc(actions_avail: Option<&str>, self_status: Option<&str>) -> Self {
        if let Some(list) = actions_avail {
            let actions = ActionSet::parse(list);
            if !actions.is_empty() {
                return Self::Available { actions };
            }
        }
        match self_status {
            Some(status) if status.lines().any(|line| line.starts_with("Seccomp:")) => {
                Self::Available {
                    actions: ActionSet::LEGACY,
                }
            }
            Some(_) => Self::NotSupported,
            None => Self::Unknown,
        }
    }

    /// Whether seccomp filters are known to be available.
    #[must_use]
    pub const fn is_available(self) -> bool {
        matches!(self, Self::Available { .. })
    }

    /// The actions a filter may use: those listed by the kernel,
    /// [`ActionSet::LEGACY`] when support is [`Unknown`](Support::Unknown),
    /// and none when seccomp is not supported.
    #[must_use]
    pub const fn actions(self) -> ActionSet {
        match self {
            Self::Available { actions } => actions,
            Self::Unknown => ActionSet::LEGACY,
            Self::NotSupported => ActionSet::EMPTY,
        }
    }
}

impl fmt::Display for Support {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Available { actions } => write!(f, "available (actions: {actions})"),
            Self::NotSupported => f.write_str("not supported by this kernel"),
            Self::Unknown => f.write_str("unknown (/proc is not readable)"),
        }
    }
}

/// Detects the running kernel's seccomp support by reading `/proc`.
///
/// This makes no seccomp system call and changes nothing.
#[must_use]
pub fn detect() -> Support {
    let actions_avail = std::fs::read_to_string(ACTIONS_AVAIL).ok();
    let self_status = std::fs::read_to_string(SELF_STATUS).ok();
    Support::from_proc(actions_avail.as_deref(), self_status.as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Action;

    #[test]
    fn modern_kernel() {
        let support = Support::from_proc(
            Some("kill_process kill_thread trap errno user_notif trace log allow\n"),
            Some("Name:\tx\nSeccomp:\t0\nSeccomp_filters:\t0\n"),
        );
        assert_eq!(support.actions(), ActionSet::ALL);
        assert!(support.is_available());
    }

    #[test]
    fn kernel_before_4_14_lists_no_actions() {
        let support = Support::from_proc(None, Some("Name:\tx\nSeccomp:\t0\n"));
        assert_eq!(support.actions(), ActionSet::LEGACY);
        assert!(!support.actions().contains(Action::Log));
    }

    #[test]
    fn kernel_without_seccomp() {
        let support = Support::from_proc(None, Some("Name:\tx\nNoNewPrivs:\t0\n"));
        assert_eq!(support, Support::NotSupported);
        assert!(support.actions().is_empty());
    }

    #[test]
    fn no_proc() {
        assert_eq!(Support::from_proc(None, None), Support::Unknown);
        assert_eq!(Support::Unknown.actions(), ActionSet::LEGACY);
        assert!(!Support::Unknown.is_available());
    }

    #[test]
    fn detect_is_stable() {
        assert_eq!(detect(), detect());
    }

    #[test]
    fn display() {
        let support = Support::Available {
            actions: ActionSet::LEGACY,
        };
        assert_eq!(
            support.to_string(),
            "available (actions: kill_thread trap errno allow)"
        );
    }
}
