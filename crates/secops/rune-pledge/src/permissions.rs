//! Per-path permissions, after OpenBSD's `unveil(2)`.

use std::fmt;
use std::str::FromStr;

use crate::Error;

/// What a [`Profile`](crate::Profile) path rule allows beneath its path,
/// spelled like `unveil(2)` permissions: any of `r`, `w`, `x` and `c`.
///
/// A permission only takes effect together with the matching promise:
/// `w` on a path does nothing without [`Promise::Wpath`](crate::Promise::Wpath).
///
/// ```
/// use rune_pledge::Permissions;
///
/// let rx: Permissions = "rx".parse()?;
/// assert!(rx.read() && rx.exec() && !rx.write());
/// assert_eq!(rx.to_string(), "rx");
/// # Ok::<(), rune_pledge::Error>(())
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Permissions(u8);

impl Permissions {
    /// No access: the path is hidden.
    pub const NONE: Self = Self(0);
    /// `r`: read files and list directories.
    pub const READ: Self = Self(1);
    /// `w`: write and truncate files, `ioctl` on devices, connect to
    /// pathname UNIX sockets.
    pub const WRITE: Self = Self(2);
    /// `x`: execute files.
    pub const EXEC: Self = Self(4);
    /// `c`: create, remove, rename and link files, directories, links,
    /// sockets, pipes and devices.
    pub const CREATE: Self = Self(8);
    /// `rx`: a system directory such as `/usr`.
    pub const READ_EXEC: Self = Self(Self::READ.0 | Self::EXEC.0);
    /// `rwc`: a working directory.
    pub const READ_WRITE_CREATE: Self = Self(Self::READ.0 | Self::WRITE.0 | Self::CREATE.0);
    /// `rwxc`: everything.
    pub const ALL: Self = Self(0b1111);

    const LETTERS: [(char, Self); 4] = [
        ('r', Self::READ),
        ('w', Self::WRITE),
        ('x', Self::EXEC),
        ('c', Self::CREATE),
    ];

    /// `r` is set.
    #[must_use]
    pub const fn read(self) -> bool {
        self.contains(Self::READ)
    }

    /// `w` is set.
    #[must_use]
    pub const fn write(self) -> bool {
        self.contains(Self::WRITE)
    }

    /// `x` is set.
    #[must_use]
    pub const fn exec(self) -> bool {
        self.contains(Self::EXEC)
    }

    /// `c` is set.
    #[must_use]
    pub const fn create(self) -> bool {
        self.contains(Self::CREATE)
    }

    /// Whether every permission in `other` is set.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Whether nothing is set.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The permissions in either.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl FromStr for Permissions {
    type Err = Error;

    /// Parses `unveil(2)` letters in any order; the empty string is
    /// [`Permissions::NONE`]. A repeated or unknown letter is an error.
    fn from_str(letters: &str) -> Result<Self, Error> {
        let invalid = || Error::InvalidPermissions {
            input: letters.into(),
        };
        let mut permissions = Self::NONE;
        for letter in letters.chars() {
            let (_, bit) = Self::LETTERS
                .into_iter()
                .find(|(l, _)| *l == letter)
                .ok_or_else(invalid)?;
            if permissions.contains(bit) {
                return Err(invalid());
            }
            permissions = permissions.union(bit);
        }
        Ok(permissions)
    }
}

impl fmt::Display for Permissions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (letter, bit) in Self::LETTERS {
            if self.contains(bit) {
                write!(f, "{letter}")?;
            }
        }
        Ok(())
    }
}

impl fmt::Debug for Permissions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Permissions(\"{self}\")")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_unveil_letters() {
        assert_eq!("".parse::<Permissions>().ok(), Some(Permissions::NONE));
        assert_eq!(
            "cwr".parse::<Permissions>().ok(),
            Some(Permissions::READ_WRITE_CREATE)
        );
        assert_eq!("rwxc".parse::<Permissions>().ok(), Some(Permissions::ALL));
        for bad in ["rr", "q", "r w", "R"] {
            assert!(
                matches!(bad.parse::<Permissions>(), Err(Error::InvalidPermissions { input }) if input == bad),
                "{bad}"
            );
        }
    }

    #[test]
    fn displays_in_canonical_order() {
        assert_eq!(Permissions::ALL.to_string(), "rwxc");
        assert_eq!(Permissions::READ_EXEC.to_string(), "rx");
        assert_eq!(format!("{:?}", Permissions::WRITE), "Permissions(\"w\")");
        assert!(Permissions::NONE.is_empty());
    }
}
