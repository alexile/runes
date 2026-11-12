//! Filter actions, and the set of actions a kernel accepts.

use std::fmt;

/// Kernel return values (`SECCOMP_RET_*`, `<linux/seccomp.h>`).
mod ret {
    pub const KILL_PROCESS: u32 = 0x8000_0000;
    pub const KILL_THREAD: u32 = 0x0000_0000;
    pub const TRAP: u32 = 0x0003_0000;
    pub const ERRNO: u32 = 0x0005_0000;
    pub const LOG: u32 = 0x7ffc_0000;
    pub const ALLOW: u32 = 0x7fff_0000;
    pub const ACTION_FULL: u32 = 0xffff_0000;
    pub const DATA: u32 = 0x0000_ffff;
}

/// The largest errno the kernel passes through ([`Action::Errno`]); larger
/// values are clamped to it by the kernel, so this crate rejects them.
pub const MAX_ERRNO: u16 = 4095;

/// What the kernel does when a system call matches (or misses) the filter.
///
/// When several filters are stacked, the kernel takes the most restrictive
/// verdict: [`KillProcess`](Action::KillProcess), then
/// [`KillThread`](Action::KillThread), [`Trap`](Action::Trap),
/// [`Errno`](Action::Errno), [`Log`](Action::Log) and finally
/// [`Allow`](Action::Allow).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Action {
    /// Run the system call.
    Allow,
    /// Run the system call and record it in the kernel audit log (Linux
    /// 4.14). Useful to find out what an allowlist is missing before
    /// enforcing it.
    Log,
    /// Skip the system call and fail it with this errno (at most
    /// [`MAX_ERRNO`]; `0` fakes success).
    Errno(u16),
    /// Skip the system call and send `SIGSYS` to the calling thread. Unless
    /// the program handles the signal, this kills the process.
    Trap,
    /// Kill the calling thread, as if by an uncatchable `SIGSYS`.
    KillThread,
    /// Kill the whole process, as if by an uncatchable `SIGSYS` (Linux
    /// 4.14).
    KillProcess,
}

impl Action {
    /// Fail with `EPERM` ("Operation not permitted"): the usual deny action.
    pub const EPERM: Self = Self::Errno(1);
    /// Fail with `EACCES` ("Permission denied").
    pub const EACCES: Self = Self::Errno(13);
    /// Fail with `ENOSYS` ("Function not implemented"), which programs
    /// usually treat as "this kernel is too old" and fall back from.
    pub const ENOSYS: Self = Self::Errno(38);

    /// The action's name, as the kernel lists it in
    /// `/proc/sys/kernel/seccomp/actions_avail`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Log => "log",
            Self::Errno(_) => "errno",
            Self::Trap => "trap",
            Self::KillThread => "kill_thread",
            Self::KillProcess => "kill_process",
        }
    }

    /// Whether the system call does not run.
    #[must_use]
    pub const fn denies(self) -> bool {
        !matches!(self, Self::Allow | Self::Log)
    }

    /// The value a seccomp filter returns for this action.
    #[must_use]
    pub const fn to_ret(self) -> u32 {
        match self {
            Self::Allow => ret::ALLOW,
            Self::Log => ret::LOG,
            Self::Errno(errno) => ret::ERRNO | (errno as u32 & ret::DATA),
            Self::Trap => ret::TRAP,
            Self::KillThread => ret::KILL_THREAD,
            Self::KillProcess => ret::KILL_PROCESS,
        }
    }

    /// The action a seccomp filter's return value stands for, if it is one
    /// this crate models (the data bits of [`Action::Trap`] are ignored).
    #[must_use]
    pub const fn from_ret(value: u32) -> Option<Self> {
        #[allow(clippy::cast_possible_truncation, reason = "masked to 16 bits")]
        let data = (value & ret::DATA) as u16;
        Some(match value & ret::ACTION_FULL {
            ret::ALLOW => Self::Allow,
            ret::LOG => Self::Log,
            ret::ERRNO => Self::Errno(data),
            ret::TRAP => Self::Trap,
            ret::KILL_THREAD => Self::KillThread,
            ret::KILL_PROCESS => Self::KillProcess,
            _ => return None,
        })
    }

    /// The closest action an older kernel offers in place of this one, if
    /// this one may be missing: [`Log`](Action::Log) becomes
    /// [`Allow`](Action::Allow) (the call still runs, only unlogged) and
    /// [`KillProcess`](Action::KillProcess) becomes
    /// [`KillThread`](Action::KillThread).
    #[must_use]
    pub const fn fallback(self) -> Option<Self> {
        match self {
            Self::Log => Some(Self::Allow),
            Self::KillProcess => Some(Self::KillThread),
            _ => None,
        }
    }

    pub(crate) const fn into_seccompiler(self) -> seccompiler::SeccompAction {
        use seccompiler::SeccompAction as S;
        match self {
            Self::Allow => S::Allow,
            Self::Log => S::Log,
            Self::Errno(errno) => S::Errno(errno as u32),
            Self::Trap => S::Trap,
            Self::KillThread => S::KillThread,
            Self::KillProcess => S::KillProcess,
        }
    }

    const fn bit(self) -> u8 {
        match self {
            Self::Allow => 1,
            Self::Log => 1 << 1,
            Self::Errno(_) => 1 << 2,
            Self::Trap => 1 << 3,
            Self::KillThread => 1 << 4,
            Self::KillProcess => 1 << 5,
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Errno(errno) => write!(f, "errno({errno})"),
            other => f.write_str(other.name()),
        }
    }
}

/// A set of action kinds, regardless of their data (all
/// [`Action::Errno`] values count as one).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct ActionSet(u8);

impl ActionSet {
    /// No actions.
    pub const EMPTY: Self = Self(0);
    /// Every action this crate models (Linux 4.14 and later).
    pub const ALL: Self = Self(0b11_1111);
    /// The actions every kernel with seccomp filters has (Linux 3.5):
    /// allow, errno, trap and kill-thread.
    pub const LEGACY: Self = Self::EMPTY
        .with(Action::Allow)
        .with(Action::Errno(0))
        .with(Action::Trap)
        .with(Action::KillThread);

    const KINDS: [Action; 6] = [
        Action::KillProcess,
        Action::KillThread,
        Action::Trap,
        Action::Errno(0),
        Action::Log,
        Action::Allow,
    ];

    /// Whether `action`'s kind is in the set.
    #[must_use]
    pub const fn contains(self, action: Action) -> bool {
        self.0 & action.bit() != 0
    }

    /// The set with `action`'s kind added.
    #[must_use]
    pub const fn with(self, action: Action) -> Self {
        Self(self.0 | action.bit())
    }

    /// Whether the set is empty.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Parses the kernel's space-separated list of action names
    /// (`/proc/sys/kernel/seccomp/actions_avail`). Names this crate does
    /// not model, such as `trace` and `user_notif`, are ignored.
    #[must_use]
    pub fn parse(list: &str) -> Self {
        list.split_whitespace()
            .filter_map(|name| Self::KINDS.into_iter().find(|kind| kind.name() == name))
            .fold(Self::EMPTY, Self::with)
    }

    /// The action kinds in the set, most restrictive first ([`Action::Errno`]
    /// appears as `Errno(0)`).
    pub fn iter(self) -> impl Iterator<Item = Action> {
        Self::KINDS
            .into_iter()
            .filter(move |kind| self.contains(*kind))
    }
}

impl fmt::Debug for ActionSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set()
            .entries(self.iter().map(Action::name))
            .finish()
    }
}

impl fmt::Display for ActionSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for kind in self.iter() {
            if !first {
                f.write_str(" ")?;
            }
            first = false;
            f.write_str(kind.name())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EVERY: [Action; 7] = [
        Action::Allow,
        Action::Log,
        Action::EPERM,
        Action::Errno(MAX_ERRNO),
        Action::Trap,
        Action::KillThread,
        Action::KillProcess,
    ];

    #[test]
    fn return_values_round_trip() {
        for action in EVERY {
            assert_eq!(Action::from_ret(action.to_ret()), Some(action), "{action}");
        }
        // SECCOMP_RET_TRACE and SECCOMP_RET_USER_NOTIF are not modelled.
        assert_eq!(Action::from_ret(0x7ff0_0000), None);
        assert_eq!(Action::from_ret(0x7fc0_0000), None);
    }

    #[test]
    fn return_values_match_the_kernel_and_seccompiler() {
        for action in EVERY {
            assert_eq!(action.to_ret(), u32::from(action.into_seccompiler()));
        }
        assert_eq!(Action::Allow.to_ret(), libc::SECCOMP_RET_ALLOW);
        assert_eq!(Action::Log.to_ret(), libc::SECCOMP_RET_LOG);
        assert_eq!(Action::EPERM.to_ret(), libc::SECCOMP_RET_ERRNO | 1);
        assert_eq!(Action::KillProcess.to_ret(), libc::SECCOMP_RET_KILL_PROCESS);
    }

    #[test]
    fn errno_constants_match_libc() {
        assert_eq!(
            Action::EPERM,
            Action::Errno(libc::EPERM.try_into().unwrap())
        );
        assert_eq!(
            Action::EACCES,
            Action::Errno(libc::EACCES.try_into().unwrap())
        );
        assert_eq!(
            Action::ENOSYS,
            Action::Errno(libc::ENOSYS.try_into().unwrap())
        );
    }

    #[test]
    fn parse_the_kernel_list() {
        let set =
            ActionSet::parse("kill_process kill_thread trap errno user_notif trace log allow\n");
        assert_eq!(set, ActionSet::ALL);
        assert_eq!(
            set.to_string(),
            "kill_process kill_thread trap errno log allow"
        );

        let legacy = ActionSet::parse("kill_thread trap errno trace allow");
        assert_eq!(legacy, ActionSet::LEGACY);
        assert!(legacy.contains(Action::Errno(5)));
        assert!(!legacy.contains(Action::Log));
        assert!(ActionSet::parse("").is_empty());
    }

    #[test]
    fn fallbacks_only_lose_logging_or_scope() {
        for action in EVERY {
            match action.fallback() {
                Some(fallback) => {
                    assert!(ActionSet::LEGACY.contains(fallback));
                    assert_eq!(action.denies(), fallback.denies());
                }
                None => assert!(ActionSet::LEGACY.contains(action)),
            }
        }
    }

    #[test]
    fn display() {
        assert_eq!(Action::EPERM.to_string(), "errno(1)");
        assert_eq!(Action::KillProcess.to_string(), "kill_process");
        assert_eq!(
            format!("{:?}", ActionSet::LEGACY),
            r#"{"kill_thread", "trap", "errno", "allow"}"#
        );
    }
}
