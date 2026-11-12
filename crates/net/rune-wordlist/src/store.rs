//! Installed packs and updates.

use std::fs;
use std::path::{Path, PathBuf};

use crate::author::write_atomic;
use crate::pack::{MANIFEST_FILE, SIGNATURE_FILE, read_limited};
use crate::{Error, Keyring, Options, Pack, Verify, Version};

/// Name of the file holding the active version in a pack's store directory.
const CURRENT_FILE: &str = "CURRENT";

/// What an install did, or would do; see [`plan_update`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UpdateOutcome {
    /// The pack was not installed before.
    Installed {
        /// The installed version.
        version: Version,
    },
    /// An older version was replaced.
    Upgraded {
        /// The version that was active.
        from: Version,
        /// The version now active.
        to: Version,
    },
    /// The same or an older version replaced the active one, because the
    /// caller allowed it.
    Replaced {
        /// The version that was active.
        from: Version,
        /// The version now active.
        to: Version,
    },
}

/// Settings for [`Store::install`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct InstallOptions {
    /// Accept a candidate that is not newer than the installed version
    /// (reinstall or deliberate rollback). Default `false`.
    pub allow_downgrade: bool,
}

impl InstallOptions {
    /// Sets [`allow_downgrade`](Self::allow_downgrade).
    #[must_use]
    pub const fn with_allow_downgrade(mut self, allow: bool) -> Self {
        self.allow_downgrade = allow;
        self
    }
}

/// Decides whether `candidate` may replace `installed` (sans-I/O).
///
/// Only newer versions are accepted unless `allow_downgrade` is set, so an
/// attacker who can serve an old but validly signed pack cannot roll a
/// client back to it.
///
/// ```
/// use rune_wordlist::{UpdateOutcome, Version, plan_update};
///
/// let (v1, v2) = (Version::new(1, 0, 0), Version::new(1, 1, 0));
/// assert_eq!(plan_update("p", None, v1, false)?, UpdateOutcome::Installed { version: v1 });
/// assert_eq!(plan_update("p", Some(v1), v2, false)?, UpdateOutcome::Upgraded { from: v1, to: v2 });
/// assert!(plan_update("p", Some(v2), v1, false).is_err());
/// # Ok::<(), rune_wordlist::Error>(())
/// ```
pub fn plan_update(
    name: &str,
    installed: Option<Version>,
    candidate: Version,
    allow_downgrade: bool,
) -> Result<UpdateOutcome, Error> {
    match installed {
        None => Ok(UpdateOutcome::Installed { version: candidate }),
        Some(from) if candidate > from => Ok(UpdateOutcome::Upgraded {
            from,
            to: candidate,
        }),
        Some(from) if allow_downgrade => Ok(UpdateOutcome::Replaced {
            from,
            to: candidate,
        }),
        Some(installed) => Err(Error::NotNewer {
            name: name.to_owned(),
            installed,
            candidate,
        }),
    }
}

/// A directory of installed packs, one subdirectory per pack name and one
/// per version below it, with a `CURRENT` file naming the active version:
///
/// ```text
/// <root>/web-discovery/CURRENT        "1.4.0"
/// <root>/web-discovery/1.4.0/pack.toml
/// <root>/web-discovery/1.4.0/pack.toml.sig
/// <root>/web-discovery/1.4.0/lists/dirs.txt
/// ```
///
/// [`install`](Self::install) is the update command: it verifies a candidate
/// pack fully, refuses rollbacks, copies only the files the manifest names
/// into a staging directory, verifies the copy, moves it into place and then
/// switches `CURRENT` with an atomic rename. A failed or interrupted update
/// leaves the previous version active. Fetching the candidate (HTTP, git,
/// an archive) is left to the caller.
#[derive(Debug, Clone)]
pub struct Store {
    root: PathBuf,
}

impl Store {
    /// A store rooted at `root` (created on first install).
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The store's root directory.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The active version of pack `name`, if installed.
    pub fn installed(&self, name: &str) -> Result<Option<Version>, Error> {
        crate::validate_name(name)?;
        let path = self.root.join(name).join(CURRENT_FILE);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = read_limited(&path, 64)?
            .ok_or_else(|| Error::InvalidVersion("<CURRENT file too large>".to_owned()))?;
        let text = String::from_utf8_lossy(&bytes);
        text.trim().parse().map(Some)
    }

    /// Opens the active version of pack `name`.
    pub fn open(&self, name: &str, keyring: &Keyring, options: &Options) -> Result<Pack, Error> {
        let version = self
            .installed(name)?
            .ok_or_else(|| Error::NotInstalled(name.to_owned()))?;
        let pack = Pack::open(
            self.root.join(name).join(version.to_string()),
            keyring,
            options,
        )?;
        // The directory name is not signed; the manifest is.
        if pack.manifest().name != name || pack.manifest().version != version {
            return Err(Error::Manifest(format!(
                "installed directory {name}/{version} holds {} {}",
                pack.manifest().name,
                pack.manifest().version
            )));
        }
        Ok(pack)
    }

    /// Verifies the pack in `source` and makes it the active version.
    pub fn install(
        &self,
        source: impl AsRef<Path>,
        keyring: &Keyring,
        options: &InstallOptions,
    ) -> Result<UpdateOutcome, Error> {
        let eager = Options::default().with_verify(Verify::Eager);
        let candidate = Pack::open(source.as_ref(), keyring, &eager)?;
        let manifest = candidate.manifest();
        let name = manifest.name.as_str();
        let version = manifest.version;
        let outcome = plan_update(
            name,
            self.installed(name)?,
            version,
            options.allow_downgrade,
        )?;

        let pack_dir = self.root.join(name);
        let staging = pack_dir.join(format!(".staging-{version}"));
        let target = pack_dir.join(version.to_string());
        remove_dir_if_exists(&staging)?;
        mkdir(&staging)?;

        let staged = stage(&candidate, &staging, keyring);
        if let Err(e) = staged {
            let _ = fs::remove_dir_all(&staging);
            return Err(e);
        }

        if target.exists() {
            // Reinstalling a version: move the old copy aside first so the
            // rename below cannot fail on a non-empty directory.
            let trash = pack_dir.join(format!(".old-{version}"));
            remove_dir_if_exists(&trash)?;
            fs::rename(&target, &trash).map_err(|e| Error::io(&target, e))?;
            fs::rename(&staging, &target).map_err(|e| Error::io(&target, e))?;
            let _ = fs::remove_dir_all(&trash);
        } else {
            fs::rename(&staging, &target).map_err(|e| Error::io(&target, e))?;
        }
        write_atomic(
            &pack_dir.join(CURRENT_FILE),
            format!("{version}\n").as_bytes(),
        )?;
        Ok(outcome)
    }

    /// Removes every installed version of `name` except the active one.
    /// Returns the versions removed.
    pub fn prune(&self, name: &str) -> Result<Vec<Version>, Error> {
        let current = self
            .installed(name)?
            .ok_or_else(|| Error::NotInstalled(name.to_owned()))?;
        let dir = self.root.join(name);
        let mut removed = Vec::new();
        for entry in fs::read_dir(&dir).map_err(|e| Error::io(&dir, e))? {
            let entry = entry.map_err(|e| Error::io(&dir, e))?;
            let Some(file_name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if let Ok(v) = file_name.parse::<Version>()
                && v != current
                && entry.path().is_dir()
            {
                fs::remove_dir_all(entry.path()).map_err(|e| Error::io(entry.path(), e))?;
                removed.push(v);
            }
        }
        removed.sort_unstable();
        Ok(removed)
    }
}

fn stage(candidate: &Pack, staging: &Path, keyring: &Keyring) -> Result<(), Error> {
    let src = candidate.root();
    for file in [MANIFEST_FILE, SIGNATURE_FILE] {
        copy(&src.join(file), &staging.join(file))?;
    }
    for list in &candidate.manifest().lists {
        let to = list.file_in(staging);
        if let Some(parent) = to.parent() {
            mkdir(parent)?;
        }
        copy(&list.file_in(src), &to)?;
    }
    // Verify what landed on disk, not what was read from the source.
    let staged = Pack::open(
        staging,
        keyring,
        &Options::default().with_verify(Verify::Eager),
    )?;
    if staged.manifest() != candidate.manifest() {
        return Err(Error::Manifest(
            "pack changed while it was being installed".to_owned(),
        ));
    }
    Ok(())
}

fn mkdir(path: &Path) -> Result<(), Error> {
    fs::create_dir_all(path).map_err(|e| Error::io(path, e))
}

fn copy(from: &Path, to: &Path) -> Result<(), Error> {
    fs::copy(from, to).map(drop).map_err(|e| Error::io(from, e))
}

fn remove_dir_if_exists(path: &Path) -> Result<(), Error> {
    match fs::remove_dir_all(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(Error::io(path, e)),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan() {
        let v = |s: &str| s.parse::<Version>().unwrap();
        assert!(matches!(
            plan_update("p", Some(v("1.0.0")), v("1.0.0"), false),
            Err(Error::NotNewer { .. })
        ));
        assert_eq!(
            plan_update("p", Some(v("1.0.0")), v("1.0.0"), true).unwrap(),
            UpdateOutcome::Replaced {
                from: v("1.0.0"),
                to: v("1.0.0")
            }
        );
    }
}
