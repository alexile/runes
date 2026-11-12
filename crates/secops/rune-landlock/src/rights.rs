//! Filesystem access rights and sets of them.

use std::fmt;

use landlock::{AccessFs, BitFlags};

use crate::Abi;

/// One Landlock filesystem access right.
///
/// See the kernel's [access rights] documentation for the exact semantics.
///
/// [access rights]: https://docs.kernel.org/userspace-api/landlock.html#filesystem-flags
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Right {
    /// Execute a file.
    Execute,
    /// Open a file with write access.
    WriteFile,
    /// Open a file with read access.
    ReadFile,
    /// Open a directory or list its content.
    ReadDir,
    /// Remove an empty directory or rename one.
    RemoveDir,
    /// Unlink or rename a file.
    RemoveFile,
    /// Create, rename or link a character device.
    MakeChar,
    /// Create or rename a directory.
    MakeDir,
    /// Create, rename or link a regular file.
    MakeReg,
    /// Create, rename or link a UNIX domain socket.
    MakeSock,
    /// Create, rename or link a named pipe.
    MakeFifo,
    /// Create, rename or link a block device.
    MakeBlock,
    /// Create, rename or link a symbolic link.
    MakeSym,
    /// Link or rename a file from or to a different directory
    /// ([`Abi::V2`]).
    Refer,
    /// Truncate a file ([`Abi::V3`]).
    Truncate,
    /// Send `ioctl` commands to a device file ([`Abi::V5`]).
    IoctlDev,
    /// Connect to a pathname UNIX domain socket ([`Abi::V9`]).
    ResolveUnix,
}

impl Right {
    /// Every right, in declaration order.
    pub const ALL: [Self; 17] = [
        Self::Execute,
        Self::WriteFile,
        Self::ReadFile,
        Self::ReadDir,
        Self::RemoveDir,
        Self::RemoveFile,
        Self::MakeChar,
        Self::MakeDir,
        Self::MakeReg,
        Self::MakeSock,
        Self::MakeFifo,
        Self::MakeBlock,
        Self::MakeSym,
        Self::Refer,
        Self::Truncate,
        Self::IoctlDev,
        Self::ResolveUnix,
    ];

    /// The ABI version that introduced this right.
    #[must_use]
    pub const fn since(self) -> Abi {
        match self {
            Self::Refer => Abi::V2,
            Self::Truncate => Abi::V3,
            Self::IoctlDev => Abi::V5,
            Self::ResolveUnix => Abi::V9,
            _ => Abi::V1,
        }
    }

    /// `true` if the right can be granted on a single file rather than
    /// only on a directory hierarchy.
    #[must_use]
    pub const fn applies_to_files(self) -> bool {
        matches!(
            self,
            Self::Execute
                | Self::WriteFile
                | Self::ReadFile
                | Self::Truncate
                | Self::IoctlDev
                | Self::ResolveUnix
        )
    }

    /// The kernel's name for the right, without the
    /// `LANDLOCK_ACCESS_FS_` prefix and in lower case.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Execute => "execute",
            Self::WriteFile => "write_file",
            Self::ReadFile => "read_file",
            Self::ReadDir => "read_dir",
            Self::RemoveDir => "remove_dir",
            Self::RemoveFile => "remove_file",
            Self::MakeChar => "make_char",
            Self::MakeDir => "make_dir",
            Self::MakeReg => "make_reg",
            Self::MakeSock => "make_sock",
            Self::MakeFifo => "make_fifo",
            Self::MakeBlock => "make_block",
            Self::MakeSym => "make_sym",
            Self::Refer => "refer",
            Self::Truncate => "truncate",
            Self::IoctlDev => "ioctl_dev",
            Self::ResolveUnix => "resolve_unix",
        }
    }

    const fn bit(self) -> u32 {
        1 << (self as u32)
    }

    const fn to_landlock(self) -> AccessFs {
        match self {
            Self::Execute => AccessFs::Execute,
            Self::WriteFile => AccessFs::WriteFile,
            Self::ReadFile => AccessFs::ReadFile,
            Self::ReadDir => AccessFs::ReadDir,
            Self::RemoveDir => AccessFs::RemoveDir,
            Self::RemoveFile => AccessFs::RemoveFile,
            Self::MakeChar => AccessFs::MakeChar,
            Self::MakeDir => AccessFs::MakeDir,
            Self::MakeReg => AccessFs::MakeReg,
            Self::MakeSock => AccessFs::MakeSock,
            Self::MakeFifo => AccessFs::MakeFifo,
            Self::MakeBlock => AccessFs::MakeBlock,
            Self::MakeSym => AccessFs::MakeSym,
            Self::Refer => AccessFs::Refer,
            Self::Truncate => AccessFs::Truncate,
            Self::IoctlDev => AccessFs::IoctlDev,
            Self::ResolveUnix => AccessFs::ResolveUnix,
        }
    }
}

impl fmt::Display for Right {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A set of [`Right`]s.
///
/// The presets ([`RightSet::READ`], [`RightSet::EXEC`], ...) cover the
/// usual allowlist kinds. Rights a kernel is too old to know about are
/// dropped when a ruleset is applied; see [`RightSet::handled_by`].
///
/// ```
/// use rune_landlock::{Right, RightSet};
///
/// let set = RightSet::READ.union(RightSet::from(Right::Execute));
/// assert_eq!(set, RightSet::READ_EXEC);
/// assert_eq!(set.to_string(), "execute|read_file|read_dir");
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct RightSet(u32);

impl RightSet {
    /// No rights.
    pub const EMPTY: Self = Self(0);
    /// Every right this crate knows, from every ABI.
    pub const ALL: Self = Self((1 << Right::ALL.len()) - 1);
    /// Read files and list directories.
    pub const READ: Self = Self(Right::ReadFile.bit() | Right::ReadDir.bit());
    /// [`RightSet::READ`] plus executing files.
    pub const READ_EXEC: Self = Self(Self::READ.0 | Right::Execute.bit());
    /// Execute (and read, which loading a program needs) individual files.
    pub const EXEC: Self = Self(Right::Execute.bit() | Right::ReadFile.bit());
    /// Every right, including executing files: what a writable working
    /// directory needs.
    pub const READ_WRITE: Self = Self::ALL;
    /// The rights that can be granted on a non-directory file.
    pub const FILE: Self = Self(
        Right::Execute.bit()
            | Right::WriteFile.bit()
            | Right::ReadFile.bit()
            | Right::Truncate.bit()
            | Right::IoctlDev.bit()
            | Right::ResolveUnix.bit(),
    );

    /// The rights a ruleset restricts when it targets `abi`: every right
    /// introduced in `abi` or earlier.
    ///
    /// ```
    /// use rune_landlock::{Abi, Right, RightSet};
    ///
    /// assert!(!RightSet::handled_by(Abi::V1).contains(Right::Refer));
    /// assert!(RightSet::handled_by(Abi::V2).contains(Right::Refer));
    /// assert_eq!(RightSet::handled_by(Abi::LATEST), RightSet::ALL);
    /// ```
    #[must_use]
    pub fn handled_by(abi: Abi) -> Self {
        Right::ALL
            .into_iter()
            .filter(|right| right.since() <= abi)
            .collect()
    }

    /// `true` if `right` is in the set.
    #[must_use]
    pub const fn contains(self, right: Right) -> bool {
        self.0 & right.bit() != 0
    }

    /// `true` if the set has no rights.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The number of rights in the set.
    #[must_use]
    pub const fn len(self) -> usize {
        self.0.count_ones() as usize
    }

    /// The set with `right` added.
    #[must_use]
    pub const fn with(self, right: Right) -> Self {
        Self(self.0 | right.bit())
    }

    /// The set with `right` removed.
    #[must_use]
    pub const fn without(self, right: Right) -> Self {
        Self(self.0 & !right.bit())
    }

    /// Rights in either set.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Rights in both sets.
    #[must_use]
    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// Rights in `self` but not in `other`.
    #[must_use]
    pub const fn difference(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// The rights in the set, in [`Right::ALL`] order.
    pub fn iter(self) -> impl Iterator<Item = Right> {
        Right::ALL
            .into_iter()
            .filter(move |right| self.contains(*right))
    }

    pub(crate) fn to_landlock(self) -> BitFlags<AccessFs> {
        self.iter()
            .fold(BitFlags::EMPTY, |acc, right| acc | right.to_landlock())
    }
}

impl From<Right> for RightSet {
    fn from(right: Right) -> Self {
        Self(right.bit())
    }
}

impl FromIterator<Right> for RightSet {
    fn from_iter<I: IntoIterator<Item = Right>>(iter: I) -> Self {
        iter.into_iter().fold(Self::EMPTY, Self::with)
    }
}

impl fmt::Debug for RightSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.iter()).finish()
    }
}

impl fmt::Display for RightSet {
    /// The right names joined with `|`, or `none` for the empty set.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return f.write_str("none");
        }
        for (i, right) in self.iter().enumerate() {
            if i > 0 {
                f.write_str("|")?;
            }
            f.write_str(right.name())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handled_by_matches_the_landlock_crate() {
        for abi in Abi::ALL {
            assert_eq!(
                RightSet::handled_by(abi).to_landlock(),
                landlock::Access::from_all(abi.to_landlock()),
                "{abi}"
            );
        }
    }

    #[test]
    fn file_rights_match_the_landlock_crate() {
        assert_eq!(
            RightSet::FILE.to_landlock(),
            AccessFs::from_file(Abi::LATEST.to_landlock())
        );
        for right in Right::ALL {
            assert_eq!(RightSet::FILE.contains(right), right.applies_to_files());
        }
    }

    #[test]
    fn read_exec_matches_landlock_read() {
        assert_eq!(
            RightSet::READ_EXEC.to_landlock(),
            AccessFs::from_read(Abi::V1.to_landlock())
        );
    }

    #[test]
    fn handled_by_grows_monotonically() {
        for pair in Abi::ALL.windows(2) {
            let (old, new) = (RightSet::handled_by(pair[0]), RightSet::handled_by(pair[1]));
            assert!(old.difference(new).is_empty());
        }
        assert_eq!(RightSet::handled_by(Abi::V1).len(), 13);
        assert_eq!(RightSet::ALL.len(), Right::ALL.len());
    }

    #[test]
    fn set_operations() {
        let s = RightSet::EMPTY.with(Right::ReadFile).with(Right::Execute);
        assert_eq!(s, RightSet::EXEC);
        assert_eq!(s.without(Right::Execute), RightSet::from(Right::ReadFile));
        assert_eq!(
            RightSet::READ.intersection(RightSet::EXEC),
            Right::ReadFile.into()
        );
        assert_eq!(RightSet::EMPTY.to_string(), "none");
        assert_eq!(format!("{:?}", RightSet::EXEC), "{Execute, ReadFile}");
        assert_eq!(Right::IoctlDev.to_string(), "ioctl_dev");
    }
}
