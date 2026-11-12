//! The Linux namespace kinds a sandbox can unshare.

use std::fmt;

/// One kind of Linux namespace (see `namespaces(7)`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Namespace {
    /// A user namespace: unprivileged processes get the capabilities they
    /// need to build the others, without gaining any on the host.
    User,
    /// A mount namespace: a private filesystem view built from the
    /// [`MountPlan`](crate::MountPlan).
    Mount,
    /// A PID namespace: the child sees only its own descendants.
    Pid,
    /// A network namespace: no interfaces but a downed loopback, so no
    /// network access at all.
    Net,
    /// An IPC namespace: private System V IPC objects and POSIX message
    /// queues.
    Ipc,
    /// A UTS namespace: a private hostname.
    Uts,
    /// A cgroup namespace: the child's cgroup appears as the root.
    Cgroup,
}

impl Namespace {
    /// Every namespace kind, in a fixed order.
    pub const ALL: [Self; 7] = [
        Self::User,
        Self::Mount,
        Self::Pid,
        Self::Net,
        Self::Ipc,
        Self::Uts,
        Self::Cgroup,
    ];

    const fn bit(self) -> u8 {
        match self {
            Self::User => 1,
            Self::Mount => 1 << 1,
            Self::Pid => 1 << 2,
            Self::Net => 1 << 3,
            Self::Ipc => 1 << 4,
            Self::Uts => 1 << 5,
            Self::Cgroup => 1 << 6,
        }
    }

    /// The short name used by `lsns(8)` and `/proc/<pid>/ns/`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Mount => "mnt",
            Self::Pid => "pid",
            Self::Net => "net",
            Self::Ipc => "ipc",
            Self::Uts => "uts",
            Self::Cgroup => "cgroup",
        }
    }

    /// The `clone(2)`/`unshare(2)` flag for this namespace.
    #[must_use]
    pub const fn clone_flag(self) -> libc::c_int {
        match self {
            Self::User => libc::CLONE_NEWUSER,
            Self::Mount => libc::CLONE_NEWNS,
            Self::Pid => libc::CLONE_NEWPID,
            Self::Net => libc::CLONE_NEWNET,
            Self::Ipc => libc::CLONE_NEWIPC,
            Self::Uts => libc::CLONE_NEWUTS,
            Self::Cgroup => libc::CLONE_NEWCGROUP,
        }
    }

    /// The `bwrap` flag that unshares this namespace. `bwrap` always
    /// creates a mount namespace, so [`Namespace::Mount`] has none.
    #[must_use]
    pub const fn bwrap_flag(self) -> Option<&'static str> {
        match self {
            Self::User => Some("--unshare-user"),
            Self::Mount => None,
            Self::Pid => Some("--unshare-pid"),
            Self::Net => Some("--unshare-net"),
            Self::Ipc => Some("--unshare-ipc"),
            Self::Uts => Some("--unshare-uts"),
            Self::Cgroup => Some("--unshare-cgroup"),
        }
    }
}

impl fmt::Display for Namespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A set of [`Namespace`]s.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct NamespaceSet(u8);

impl NamespaceSet {
    /// No namespaces.
    pub const EMPTY: Self = Self(0);
    /// Every namespace kind: the strongest isolation.
    pub const ALL: Self = Self(0x7f);

    /// Whether `namespace` is in the set.
    #[must_use]
    pub const fn contains(self, namespace: Namespace) -> bool {
        self.0 & namespace.bit() != 0
    }

    /// The set with `namespace` added.
    #[must_use]
    pub const fn with(self, namespace: Namespace) -> Self {
        Self(self.0 | namespace.bit())
    }

    /// The set with `namespace` removed.
    #[must_use]
    pub const fn without(self, namespace: Namespace) -> Self {
        Self(self.0 & !namespace.bit())
    }

    /// Whether the set is empty.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The namespaces in the set, in [`Namespace::ALL`] order.
    pub fn iter(self) -> impl Iterator<Item = Namespace> {
        Namespace::ALL
            .into_iter()
            .filter(move |ns| self.contains(*ns))
    }

    /// The combined `clone(2)`/`unshare(2)` flags.
    #[must_use]
    pub fn clone_flags(self) -> libc::c_int {
        self.iter().fold(0, |flags, ns| flags | ns.clone_flag())
    }
}

impl From<Namespace> for NamespaceSet {
    fn from(namespace: Namespace) -> Self {
        Self::EMPTY.with(namespace)
    }
}

impl FromIterator<Namespace> for NamespaceSet {
    fn from_iter<I: IntoIterator<Item = Namespace>>(iter: I) -> Self {
        iter.into_iter().fold(Self::EMPTY, Self::with)
    }
}

impl fmt::Display for NamespaceSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return f.write_str("none");
        }
        for (i, ns) in self.iter().enumerate() {
            if i > 0 {
                f.write_str(",")?;
            }
            f.write_str(ns.name())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_contains_every_kind() {
        for ns in Namespace::ALL {
            assert!(NamespaceSet::ALL.contains(ns));
            assert!(!NamespaceSet::EMPTY.contains(ns));
        }
        assert_eq!(NamespaceSet::ALL.iter().count(), Namespace::ALL.len());
        assert_eq!(
            Namespace::ALL.into_iter().collect::<NamespaceSet>(),
            NamespaceSet::ALL
        );
    }

    #[test]
    fn with_and_without() {
        let set = NamespaceSet::from(Namespace::Net).with(Namespace::User);
        assert_eq!(
            set.iter().collect::<Vec<_>>(),
            [Namespace::User, Namespace::Net]
        );
        assert_eq!(set.without(Namespace::Net), Namespace::User.into());
        assert_eq!(set.to_string(), "user,net");
        assert_eq!(NamespaceSet::EMPTY.to_string(), "none");
    }

    #[test]
    fn clone_flags_combine() {
        let set = NamespaceSet::from(Namespace::User).with(Namespace::Net);
        assert_eq!(set.clone_flags(), libc::CLONE_NEWUSER | libc::CLONE_NEWNET);
        assert_eq!(NamespaceSet::EMPTY.clone_flags(), 0);
    }

    #[test]
    fn bits_are_distinct() {
        let mut seen = 0u8;
        for ns in Namespace::ALL {
            assert_eq!(seen & ns.bit(), 0);
            seen |= ns.bit();
        }
        assert_eq!(seen, NamespaceSet::ALL.0);
    }
}
