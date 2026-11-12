//! Landlock ABI versions and detection of what the running kernel supports.

use std::fmt;

use crate::rights::RightSet;

/// A Landlock ABI version.
///
/// Each version adds features on top of the previous one. Only some of
/// them add filesystem access rights (see [`RightSet::handled_by`]); the
/// others add network rules, IPC scoping, audit logging or thread
/// synchronisation, which this crate either does not use or exposes as a
/// separate option.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Abi {
    /// Linux 5.13: the base filesystem access rights.
    V1,
    /// Linux 5.19: [`Right::Refer`](crate::Right::Refer) (link or rename
    /// across directories).
    V2,
    /// Linux 6.2: [`Right::Truncate`](crate::Right::Truncate).
    V3,
    /// Linux 6.7: TCP bind/connect rules (not used by this crate).
    V4,
    /// Linux 6.10: [`Right::IoctlDev`](crate::Right::IoctlDev).
    V5,
    /// Linux 6.12: signal and abstract UNIX socket scoping (not used by
    /// this crate).
    V6,
    /// Linux 6.15: audit logging controls (not used by this crate).
    V7,
    /// Linux 7.0: restricting every thread of the process at once (see
    /// [`Options::with_all_threads`](crate::Options::with_all_threads)).
    V8,
    /// Linux 7.1: [`Right::ResolveUnix`](crate::Right::ResolveUnix).
    V9,
}

impl Abi {
    /// The oldest ABI version.
    pub const MIN: Self = Self::V1;
    /// The newest ABI version this crate knows about.
    pub const LATEST: Self = Self::V9;
    /// Every ABI version, oldest first.
    pub const ALL: [Self; 9] = [
        Self::V1,
        Self::V2,
        Self::V3,
        Self::V4,
        Self::V5,
        Self::V6,
        Self::V7,
        Self::V8,
        Self::V9,
    ];

    /// The version number, as the kernel reports it (`1` for [`Abi::V1`]).
    #[must_use]
    pub const fn number(self) -> u32 {
        match self {
            Self::V1 => 1,
            Self::V2 => 2,
            Self::V3 => 3,
            Self::V4 => 4,
            Self::V5 => 5,
            Self::V6 => 6,
            Self::V7 => 7,
            Self::V8 => 8,
            Self::V9 => 9,
        }
    }

    /// The ABI with version number `number`, or `None` if this crate does
    /// not know it.
    #[must_use]
    pub const fn from_number(number: u32) -> Option<Self> {
        Some(match number {
            1 => Self::V1,
            2 => Self::V2,
            3 => Self::V3,
            4 => Self::V4,
            5 => Self::V5,
            6 => Self::V6,
            7 => Self::V7,
            8 => Self::V8,
            9 => Self::V9,
            _ => return None,
        })
    }

    /// The first mainline Linux release that ships this ABI.
    #[must_use]
    pub const fn linux_version(self) -> &'static str {
        match self {
            Self::V1 => "5.13",
            Self::V2 => "5.19",
            Self::V3 => "6.2",
            Self::V4 => "6.7",
            Self::V5 => "6.10",
            Self::V6 => "6.12",
            Self::V7 => "6.15",
            Self::V8 => "7.0",
            Self::V9 => "7.1",
        }
    }

    #[cfg(test)]
    pub(crate) const fn to_landlock(self) -> landlock::ABI {
        match self {
            Self::V1 => landlock::ABI::V1,
            Self::V2 => landlock::ABI::V2,
            Self::V3 => landlock::ABI::V3,
            Self::V4 => landlock::ABI::V4,
            Self::V5 => landlock::ABI::V5,
            Self::V6 => landlock::ABI::V6,
            Self::V7 => landlock::ABI::V7,
            Self::V8 => landlock::ABI::V8,
            Self::V9 => landlock::ABI::V9,
        }
    }

    const fn from_landlock(abi: landlock::ABI) -> Option<Self> {
        Some(match abi {
            landlock::ABI::V1 => Self::V1,
            landlock::ABI::V2 => Self::V2,
            landlock::ABI::V3 => Self::V3,
            landlock::ABI::V4 => Self::V4,
            landlock::ABI::V5 => Self::V5,
            landlock::ABI::V6 => Self::V6,
            landlock::ABI::V7 => Self::V7,
            landlock::ABI::V8 => Self::V8,
            landlock::ABI::V9 => Self::V9,
            _ => return None,
        })
    }
}

impl fmt::Display for Abi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}", self.number())
    }
}

/// Whether, and how far, the running kernel supports Landlock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Support {
    /// Landlock is built in and enabled.
    Available {
        /// The newest ABI both the kernel and this crate know about.
        abi: Abi,
        /// The kernel's own ABI number when it is newer than
        /// [`Abi::LATEST`]; purely informational.
        kernel_abi: Option<u32>,
    },
    /// Landlock is built into the kernel but not enabled at boot
    /// (`lsm=` does not list it).
    NotEnabled,
    /// The kernel has no Landlock support at all.
    NotImplemented,
}

impl Support {
    /// The ABI the kernel supports, or `None` if Landlock is unavailable.
    #[must_use]
    pub const fn abi(self) -> Option<Abi> {
        match self {
            Self::Available { abi, .. } => Some(abi),
            Self::NotEnabled | Self::NotImplemented => None,
        }
    }

    /// `true` if Landlock can restrict processes on this kernel.
    #[must_use]
    pub const fn is_available(self) -> bool {
        self.abi().is_some()
    }

    /// The ABI a ruleset requesting `requested` actually gets: the older of
    /// `requested` and what the kernel supports, or `None` if Landlock is
    /// unavailable.
    ///
    /// ```
    /// use rune_landlock::{Abi, Support};
    ///
    /// let old_kernel = Support::Available { abi: Abi::V2, kernel_abi: None };
    /// assert_eq!(old_kernel.effective_abi(Abi::V5), Some(Abi::V2));
    /// assert_eq!(old_kernel.effective_abi(Abi::V1), Some(Abi::V1));
    /// assert_eq!(Support::NotEnabled.effective_abi(Abi::V5), None);
    /// ```
    #[must_use]
    pub fn effective_abi(self, requested: Abi) -> Option<Abi> {
        self.abi().map(|abi| abi.min(requested))
    }

    /// The access rights a ruleset requesting `requested` would like to
    /// restrict but cannot on this kernel: the rights the kernel is too old
    /// to know about, or all of them if Landlock is unavailable. Accesses
    /// covered by these rights stay unrestricted.
    ///
    /// ```
    /// use rune_landlock::{Abi, Right, Support};
    ///
    /// let v2_kernel = Support::Available { abi: Abi::V2, kernel_abi: None };
    /// let lost = v2_kernel.unenforced_rights(Abi::V5);
    /// assert!(lost.contains(Right::Truncate) && lost.contains(Right::IoctlDev));
    /// assert!(!lost.contains(Right::ReadFile));
    /// ```
    #[must_use]
    pub fn unenforced_rights(self, requested: Abi) -> RightSet {
        let wanted = RightSet::handled_by(requested);
        self.effective_abi(requested).map_or(wanted, |effective| {
            wanted.difference(RightSet::handled_by(effective))
        })
    }
}

impl fmt::Display for Support {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Available {
                abi,
                kernel_abi: Some(kernel),
            } => write!(f, "available (ABI {abi}; kernel reports v{kernel})"),
            Self::Available { abi, .. } => write!(f, "available (ABI {abi})"),
            Self::NotEnabled => f.write_str("built in but not enabled"),
            Self::NotImplemented => f.write_str("not supported by this kernel"),
        }
    }
}

/// Probes the running kernel for Landlock support.
///
/// This only queries the kernel's ABI version; it restricts nothing and
/// does not set `no_new_privs`.
#[must_use]
pub fn detect() -> Support {
    // With no flags set and `no_new_privs` off, `apply()` makes no
    // restricting syscall: it only reports the status probed by
    // `RestrictSelf::default()` (`landlock_create_ruleset` with the
    // `VERSION` flag).
    let Ok(status) = landlock::RestrictSelf::default()
        .no_new_privs(false)
        .apply()
    else {
        return Support::NotImplemented;
    };
    match status.landlock {
        landlock::LandlockStatus::Available {
            effective_abi,
            kernel_abi,
        } => Abi::from_landlock(effective_abi).map_or(Support::NotImplemented, |abi| {
            Support::Available {
                abi,
                kernel_abi: kernel_abi.and_then(|v| u32::try_from(v).ok()),
            }
        }),
        landlock::LandlockStatus::NotEnabled => Support::NotEnabled,
        landlock::LandlockStatus::NotImplemented => Support::NotImplemented,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Right;

    #[test]
    fn numbers_round_trip() {
        for abi in Abi::ALL {
            assert_eq!(Abi::from_number(abi.number()), Some(abi));
            assert_eq!(Abi::from_landlock(abi.to_landlock()), Some(abi));
        }
        assert_eq!(Abi::from_number(0), None);
        assert_eq!(Abi::from_number(10), None);
        assert_eq!(Abi::from_landlock(landlock::ABI::Unsupported), None);
    }

    #[test]
    fn all_is_sorted_and_bounded() {
        assert!(Abi::ALL.windows(2).all(|w| w[0] < w[1]));
        assert_eq!(Abi::ALL[0], Abi::MIN);
        assert_eq!(Abi::ALL[Abi::ALL.len() - 1], Abi::LATEST);
        assert_eq!(Abi::V5.to_string(), "v5");
    }

    #[test]
    fn effective_abi_degrades_to_the_kernel() {
        let v3 = Support::Available {
            abi: Abi::V3,
            kernel_abi: None,
        };
        assert_eq!(v3.effective_abi(Abi::V9), Some(Abi::V3));
        assert_eq!(v3.effective_abi(Abi::V2), Some(Abi::V2));
        assert_eq!(Support::NotImplemented.effective_abi(Abi::V1), None);
    }

    #[test]
    fn unenforced_rights_on_old_kernels() {
        let v1 = Support::Available {
            abi: Abi::V1,
            kernel_abi: None,
        };
        let lost = v1.unenforced_rights(Abi::V5);
        assert_eq!(
            lost.iter().collect::<Vec<_>>(),
            [Right::Refer, Right::Truncate, Right::IoctlDev]
        );

        let v8 = Support::Available {
            abi: Abi::V8,
            kernel_abi: None,
        };
        assert!(v8.unenforced_rights(Abi::V5).is_empty());
        assert_eq!(
            v8.unenforced_rights(Abi::V9).iter().collect::<Vec<_>>(),
            [Right::ResolveUnix]
        );

        assert_eq!(
            Support::NotEnabled.unenforced_rights(Abi::V5),
            RightSet::handled_by(Abi::V5)
        );
    }

    #[test]
    fn detect_is_consistent_with_itself() {
        // Whatever the kernel says, asking twice gives the same answer,
        // and an available ABI is one this crate knows.
        let support = detect();
        assert_eq!(support, detect());
        if let Some(abi) = support.abi() {
            assert!(Abi::ALL.contains(&abi));
        }
    }

    #[test]
    fn support_display() {
        let s = Support::Available {
            abi: Abi::V9,
            kernel_abi: Some(11),
        };
        assert_eq!(s.to_string(), "available (ABI v9; kernel reports v11)");
        assert_eq!(Support::NotEnabled.to_string(), "built in but not enabled");
    }
}
