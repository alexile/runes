//! The mount plan: the ordered list of mounts that builds the sandbox's
//! filesystem view, and a pure model of what that view exposes.
//!
//! Mount order matters. Mounts are applied one after another, and a mount
//! at a path hides everything mounted earlier at or below it. Mounting the
//! root tmpfs *after* `/proc` and `/dev`, for instance, silently leaves the
//! sandbox with an empty `/proc` and a `/dev` without `/dev/urandom` —
//! a real crash `rune-secops-warden` once shipped. A [`MountPlan`] therefore
//! applies mounts by [`Phase`] (root, then `/proc` and `/dev`, then binds,
//! then masks) and only keeps insertion order within a phase, so a plan
//! cannot be built in an order that shadows its own system mounts or lets a
//! bind uncover a masked path.

use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use crate::Error;

/// Whether a bind mount is writable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum Access {
    /// Read-only: writes fail with `EROFS`.
    #[default]
    ReadOnly,
    /// Read-write: writes reach the host.
    ReadWrite,
}

/// What a [`Mount::Mask`] hides.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MaskKind {
    /// A directory: replaced by an empty, read-only tmpfs.
    Dir,
    /// A file: replaced by a read-only bind of the host's `/dev/null`.
    /// `bwrap` binds are `nodev`, so opening it fails with `EACCES`;
    /// either way its content is gone.
    File,
}

/// When a mount is applied. Mounts apply phase by phase, and in insertion
/// order within a phase, so a plan cannot shadow its own system mounts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Phase {
    /// The tmpfs at `/`.
    Root,
    /// `/proc` and `/dev`.
    System,
    /// Binds, tmpfs directories, plain directories and symlinks, in
    /// insertion order — so a later bind of a sub-path overrides an earlier
    /// bind of its parent.
    Binds,
    /// Masks, last, so no bind can uncover what they hide.
    Masks,
}

/// One mount in a [`MountPlan`]. Destinations are paths inside the
/// sandbox; sources are host paths.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Mount {
    /// An empty, writable, sandbox-private tmpfs at `dest`.
    Tmpfs {
        /// Where to mount it.
        dest: PathBuf,
    },
    /// A fresh `procfs` for the sandbox's PID namespace.
    Proc {
        /// Where to mount it, normally `/proc`.
        dest: PathBuf,
    },
    /// A minimal `/dev`: `null`, `zero`, `full`, `random`, `urandom`,
    /// `tty`, `pts` and `shm`.
    Dev {
        /// Where to mount it, normally `/dev`.
        dest: PathBuf,
    },
    /// The host path `src` made visible at `dest`.
    Bind {
        /// Host source path.
        src: PathBuf,
        /// Where it appears in the sandbox.
        dest: PathBuf,
        /// Read-only or read-write.
        access: Access,
        /// Skip the mount, rather than failing, if `src` does not exist.
        optional: bool,
    },
    /// The host device node or directory `src` at `dest`, with device
    /// access allowed.
    DevBind {
        /// Host source path.
        src: PathBuf,
        /// Where it appears in the sandbox.
        dest: PathBuf,
        /// Skip the mount if `src` does not exist.
        optional: bool,
    },
    /// An empty directory at `dest` (created in whatever is mounted there).
    Dir {
        /// The directory to create.
        dest: PathBuf,
    },
    /// A symlink at `link` pointing to `target`.
    Symlink {
        /// The symlink's content; may be relative.
        target: PathBuf,
        /// Where to create it.
        link: PathBuf,
    },
    /// Hides whatever binds put at `dest`.
    Mask {
        /// The path to hide.
        dest: PathBuf,
        /// Whether it is a directory or a file.
        kind: MaskKind,
    },
}

impl Mount {
    /// A mask for `path`, choosing [`MaskKind`] from what is on the host.
    /// Returns `Ok(None)` if `path` does not exist, so there is nothing to
    /// hide.
    ///
    /// # Errors
    ///
    /// If `path` exists but its metadata cannot be read.
    pub fn mask(path: impl Into<PathBuf>) -> std::io::Result<Option<Self>> {
        let dest = path.into();
        match std::fs::metadata(&dest) {
            Ok(meta) => Ok(Some(Self::Mask {
                kind: if meta.is_dir() {
                    MaskKind::Dir
                } else {
                    MaskKind::File
                },
                dest,
            })),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err),
        }
    }

    /// The path inside the sandbox this mount creates or covers.
    #[must_use]
    pub fn dest(&self) -> &Path {
        match self {
            Self::Tmpfs { dest }
            | Self::Proc { dest }
            | Self::Dev { dest }
            | Self::Bind { dest, .. }
            | Self::DevBind { dest, .. }
            | Self::Dir { dest }
            | Self::Mask { dest, .. } => dest,
            Self::Symlink { link, .. } => link,
        }
    }

    /// When this mount is applied.
    #[must_use]
    pub fn phase(&self) -> Phase {
        match self {
            Self::Tmpfs { dest } if is_root(dest) => Phase::Root,
            Self::Proc { .. } | Self::Dev { .. } => Phase::System,
            Self::Mask { .. } => Phase::Masks,
            _ => Phase::Binds,
        }
    }

    /// Appends this mount's `bwrap` arguments to `out`.
    pub fn push_bwrap_args(&self, out: &mut Vec<OsString>) {
        let mut push = |flag: &str, paths: &[&Path]| {
            out.push(flag.into());
            out.extend(paths.iter().map(|p| p.as_os_str().to_owned()));
        };
        match self {
            Self::Tmpfs { dest } => push("--tmpfs", &[dest]),
            Self::Proc { dest } => push("--proc", &[dest]),
            Self::Dev { dest } => push("--dev", &[dest]),
            Self::Bind {
                src,
                dest,
                access,
                optional,
            } => {
                let flag = match (access, optional) {
                    (Access::ReadOnly, false) => "--ro-bind",
                    (Access::ReadOnly, true) => "--ro-bind-try",
                    (Access::ReadWrite, false) => "--bind",
                    (Access::ReadWrite, true) => "--bind-try",
                };
                push(flag, &[src, dest]);
            }
            Self::DevBind {
                src,
                dest,
                optional,
            } => push(
                if *optional {
                    "--dev-bind-try"
                } else {
                    "--dev-bind"
                },
                &[src, dest],
            ),
            Self::Dir { dest } => push("--dir", &[dest]),
            Self::Symlink { target, link } => push("--symlink", &[target, link]),
            Self::Mask {
                dest,
                kind: MaskKind::Dir,
            } => {
                push("--tmpfs", &[dest]);
                push("--remount-ro", &[dest]);
            }
            Self::Mask {
                dest,
                kind: MaskKind::File,
            } => push("--ro-bind", &[Path::new("/dev/null"), dest]),
        }
    }

    fn validate(&self) -> Result<(), Error> {
        let invalid = |reason: &'static str| Error::InvalidMount {
            dest: self.dest().to_path_buf(),
            reason,
        };
        check_sandbox_path(self.dest()).map_err(invalid)?;
        match self {
            Self::Bind { src, .. } | Self::DevBind { src, .. } => check_sandbox_path(src)
                .map_err(|_| invalid("source must be a normalized absolute path")),
            Self::Symlink { target, .. } => {
                if target.as_os_str().is_empty() || has_nul(target) {
                    Err(invalid(
                        "symlink target must be non-empty and contain no NUL",
                    ))
                } else {
                    Ok(())
                }
            }
            Self::Proc { dest } | Self::Dev { dest } | Self::Mask { dest, .. } if is_root(dest) => {
                Err(invalid("cannot be mounted at /"))
            }
            _ => Ok(()),
        }
    }
}

fn is_root(path: &Path) -> bool {
    path.components().eq([Component::RootDir])
}

fn has_nul(path: &Path) -> bool {
    path.as_os_str().as_bytes().contains(&0)
}

fn check_sandbox_path(path: &Path) -> Result<(), &'static str> {
    if !path.is_absolute() {
        return Err("path must be absolute");
    }
    if path.components().any(|c| c == Component::ParentDir) {
        return Err("path must not contain `..`");
    }
    if has_nul(path) {
        return Err("path must not contain NUL");
    }
    Ok(())
}

/// Lexically normalizes an absolute path: drops `.` and resolves `..`
/// without touching the filesystem. Returns `None` for a relative path.
fn normalize(path: &Path) -> Option<PathBuf> {
    if !path.is_absolute() {
        return None;
    }
    let mut out = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::Normal(part) => out.push(part),
            Component::ParentDir => {
                out.pop();
            }
            Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
        }
    }
    Some(out)
}

/// What a path inside the sandbox resolves to, according to
/// [`MountPlan::lookup`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Exposure {
    /// Nothing is mounted there: the path does not exist in the sandbox.
    Absent,
    /// The host path `source`, with `access`.
    Host {
        /// The host path it shows.
        source: PathBuf,
        /// Read-only or read-write.
        access: Access,
    },
    /// The host device path `source`.
    Device {
        /// The host path it shows.
        source: PathBuf,
    },
    /// Inside a sandbox-private tmpfs or directory: nothing from the host.
    Private,
    /// Inside the sandbox's own `procfs`.
    Proc,
    /// Inside the sandbox's minimal `/dev`.
    Dev,
    /// Hidden by a [`Mount::Mask`].
    Masked,
    /// Reached through a symlink: `target` with the rest of the path
    /// appended. Lookup does not follow it.
    Symlink {
        /// Where it leads.
        target: PathBuf,
    },
}

impl Exposure {
    /// Whether the path shows any host content.
    #[must_use]
    pub const fn is_host(&self) -> bool {
        matches!(self, Self::Host { .. } | Self::Device { .. })
    }
}

/// An ordered list of [`Mount`]s describing the sandbox's filesystem.
///
/// Build it with [`MountPlan::isolated`] (an empty root with `/proc`,
/// `/dev`, `/tmp` and `/run`) and the `with_*` methods; inspect the result
/// without spawning anything with [`MountPlan::lookup`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MountPlan {
    mounts: Vec<Mount>,
}

/// Host paths [`MountPlan::with_system_read_only`] binds: what a
/// dynamically linked program needs to start. Missing ones are skipped.
pub const SYSTEM_PATHS: &[&str] = &[
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib32",
    "/lib64",
    "/etc/ld.so.cache",
    "/etc/ld.so.conf",
    "/etc/ld.so.conf.d",
    "/etc/alternatives",
];

impl MountPlan {
    /// An empty plan. Under `bwrap` the root is still a fresh, empty
    /// tmpfs; with no mounts at all, the `unshare` backend leaves the host
    /// filesystem in place.
    #[must_use]
    pub const fn new() -> Self {
        Self { mounts: Vec::new() }
    }

    /// An isolated base: an empty tmpfs root, a fresh `/proc`, a minimal
    /// `/dev`, and empty private `/tmp` and `/run`. Nothing from the host
    /// is visible until bound in.
    #[must_use]
    pub fn isolated() -> Self {
        Self::new()
            .with_tmpfs("/")
            .with(Mount::Proc {
                dest: "/proc".into(),
            })
            .with(Mount::Dev {
                dest: "/dev".into(),
            })
            .with_tmpfs("/tmp")
            .with_tmpfs("/run")
    }

    /// Adds `mount`.
    #[must_use]
    pub fn with(mut self, mount: Mount) -> Self {
        self.push(mount);
        self
    }

    /// Adds `mount`.
    pub fn push(&mut self, mount: Mount) {
        self.mounts.push(mount);
    }

    /// Binds the host path `src` at `dest`.
    #[must_use]
    pub fn with_bind(
        self,
        src: impl Into<PathBuf>,
        dest: impl Into<PathBuf>,
        access: Access,
        optional: bool,
    ) -> Self {
        self.with(Mount::Bind {
            src: src.into(),
            dest: dest.into(),
            access,
            optional,
        })
    }

    /// Binds the host path `path` read-only at the same path.
    #[must_use]
    pub fn with_read_only(self, path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        self.with_bind(path.clone(), path, Access::ReadOnly, false)
    }

    /// Binds the host path `path` read-write at the same path.
    #[must_use]
    pub fn with_read_write(self, path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        self.with_bind(path.clone(), path, Access::ReadWrite, false)
    }

    /// Binds every existing path in [`SYSTEM_PATHS`] read-only.
    #[must_use]
    pub fn with_system_read_only(self) -> Self {
        SYSTEM_PATHS.iter().fold(self, |plan, path| {
            plan.with_bind(path, path, Access::ReadOnly, true)
        })
    }

    /// Mounts an empty, writable, private tmpfs at `dest`.
    #[must_use]
    pub fn with_tmpfs(self, dest: impl Into<PathBuf>) -> Self {
        self.with(Mount::Tmpfs { dest: dest.into() })
    }

    /// Creates a symlink at `link` pointing to `target`.
    #[must_use]
    pub fn with_symlink(self, target: impl Into<PathBuf>, link: impl Into<PathBuf>) -> Self {
        self.with(Mount::Symlink {
            target: target.into(),
            link: link.into(),
        })
    }

    /// Binds the host device `path` at the same path.
    #[must_use]
    pub fn with_dev_bind(self, path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        self.with(Mount::DevBind {
            src: path.clone(),
            dest: path,
            optional: false,
        })
    }

    /// Hides `dest`, of the given kind, from whatever binds expose it.
    #[must_use]
    pub fn with_mask(self, dest: impl Into<PathBuf>, kind: MaskKind) -> Self {
        self.with(Mount::Mask {
            dest: dest.into(),
            kind,
        })
    }

    /// The mounts in insertion order.
    #[must_use]
    pub fn mounts(&self) -> &[Mount] {
        &self.mounts
    }

    /// Whether the plan has no mounts.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.mounts.is_empty()
    }

    /// The mounts in the order they are applied: by [`Phase`], then by
    /// insertion order.
    pub fn ordered(&self) -> impl Iterator<Item = &Mount> {
        let mut ordered: Vec<&Mount> = self.mounts.iter().collect();
        ordered.sort_by_key(|mount| mount.phase());
        ordered.into_iter()
    }

    /// Checks every mount: destinations and bind sources must be absolute,
    /// without `..` or NUL; `/proc`, `/dev` and masks cannot go at `/`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidMount`] for the first invalid mount.
    pub fn validate(&self) -> Result<(), Error> {
        self.mounts.iter().try_for_each(Mount::validate)
    }

    /// The `bwrap` arguments for the plan, in application order.
    #[must_use]
    pub fn bwrap_args(&self) -> Vec<OsString> {
        let mut out = Vec::new();
        for mount in self.ordered() {
            mount.push_bwrap_args(&mut out);
        }
        out
    }

    /// What the absolute sandbox path `path` resolves to, without touching
    /// the filesystem: the last applied mount at or above it decides.
    ///
    /// `..` is resolved lexically and symlinks are not followed. A
    /// relative path is [`Exposure::Absent`]. With an empty plan, under
    /// `bwrap`, everything is absent.
    #[must_use]
    pub fn lookup(&self, path: impl AsRef<Path>) -> Exposure {
        let Some(path) = normalize(path.as_ref()) else {
            return Exposure::Absent;
        };
        let covering = self
            .ordered()
            .filter_map(|mount| {
                let dest = normalize(mount.dest())?;
                let rest = path.strip_prefix(&dest).ok()?.to_path_buf();
                Some((mount, rest))
            })
            .last();
        let Some((mount, rest)) = covering else {
            return Exposure::Absent;
        };
        let join = |base: &Path| {
            if rest.as_os_str().is_empty() {
                base.to_path_buf()
            } else {
                base.join(&rest)
            }
        };
        match mount {
            Mount::Tmpfs { .. } => Exposure::Private,
            Mount::Dir { .. } if rest.as_os_str().is_empty() => Exposure::Private,
            // A plain directory is created in whatever is mounted around
            // it; what lies below it is still empty.
            Mount::Dir { .. } => Exposure::Absent,
            Mount::Proc { .. } => Exposure::Proc,
            Mount::Dev { .. } => Exposure::Dev,
            Mount::Bind { src, access, .. } => Exposure::Host {
                source: join(src),
                access: *access,
            },
            Mount::DevBind { src, .. } => Exposure::Device { source: join(src) },
            Mount::Symlink { target, .. } => Exposure::Symlink {
                target: join(target),
            },
            Mount::Mask { .. } => Exposure::Masked,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(plan: &MountPlan) -> Vec<String> {
        plan.bwrap_args()
            .into_iter()
            .map(|a| a.into_string().unwrap())
            .collect()
    }

    #[test]
    fn isolated_root_comes_before_proc_and_dev_whatever_the_insertion_order() {
        // Regression: warden once emitted `--tmpfs /` after `--proc` and
        // `--dev`, which shadowed both.
        let plan = MountPlan::new()
            .with(Mount::Proc {
                dest: "/proc".into(),
            })
            .with(Mount::Dev {
                dest: "/dev".into(),
            })
            .with_tmpfs("/");
        assert_eq!(
            args(&plan),
            ["--tmpfs", "/", "--proc", "/proc", "--dev", "/dev"]
        );
        assert_eq!(plan.lookup("/dev/urandom"), Exposure::Dev);
        assert_eq!(plan.lookup("/proc/self"), Exposure::Proc);
    }

    #[test]
    fn masks_apply_after_binds() {
        let plan = MountPlan::isolated()
            .with_mask("/home/u/.ssh", MaskKind::Dir)
            .with_read_only("/home/u");
        let a = args(&plan);
        let bind = a.iter().position(|x| x == "--ro-bind").unwrap();
        let mask = a.iter().position(|x| x == "/home/u/.ssh").unwrap();
        assert!(bind < mask);
        assert_eq!(
            &a[mask - 1..],
            ["--tmpfs", "/home/u/.ssh", "--remount-ro", "/home/u/.ssh"]
        );
        assert_eq!(plan.lookup("/home/u/.ssh/id_ed25519"), Exposure::Masked);
        assert_eq!(
            plan.lookup("/home/u/src/main.rs"),
            Exposure::Host {
                source: "/home/u/src/main.rs".into(),
                access: Access::ReadOnly
            }
        );
    }

    #[test]
    fn later_bind_of_subpath_overrides_parent() {
        let plan = MountPlan::isolated()
            .with_read_write("/work")
            .with_read_only("/work/.git/hooks");
        assert_eq!(
            plan.lookup("/work/.git/hooks/pre-commit"),
            Exposure::Host {
                source: "/work/.git/hooks/pre-commit".into(),
                access: Access::ReadOnly
            }
        );
        assert_eq!(
            plan.lookup("/work/src"),
            Exposure::Host {
                source: "/work/src".into(),
                access: Access::ReadWrite
            }
        );
    }

    #[test]
    fn bind_flags() {
        let plan = MountPlan::new()
            .with_bind("/a", "/x", Access::ReadOnly, true)
            .with_bind("/b", "/y", Access::ReadWrite, false)
            .with_bind("/c", "/z", Access::ReadWrite, true)
            .with_dev_bind("/dev/kvm")
            .with_symlink("usr/bin", "/bin")
            .with(Mount::Dir { dest: "/d".into() })
            .with_mask("/x/.env", MaskKind::File);
        assert_eq!(
            args(&plan),
            [
                "--ro-bind-try",
                "/a",
                "/x",
                "--bind",
                "/b",
                "/y",
                "--bind-try",
                "/c",
                "/z",
                "--dev-bind",
                "/dev/kvm",
                "/dev/kvm",
                "--symlink",
                "usr/bin",
                "/bin",
                "--dir",
                "/d",
                "--ro-bind",
                "/dev/null",
                "/x/.env",
            ]
        );
        assert_eq!(plan.lookup("/x/.env"), Exposure::Masked);
        assert_eq!(
            plan.lookup("/bin/sh"),
            Exposure::Symlink {
                target: "usr/bin/sh".into()
            }
        );
        assert_eq!(
            plan.lookup("/dev/kvm"),
            Exposure::Device {
                source: "/dev/kvm".into()
            }
        );
        assert_eq!(plan.lookup("/d"), Exposure::Private);
        assert_eq!(plan.lookup("/d/x"), Exposure::Absent);
    }

    #[test]
    fn mount_at_bind_dest_maps_to_source() {
        let plan =
            MountPlan::isolated().with_bind("/home/u/proj", "/work", Access::ReadWrite, false);
        assert_eq!(
            plan.lookup("/work/a/../b"),
            Exposure::Host {
                source: "/home/u/proj/b".into(),
                access: Access::ReadWrite
            }
        );
        // The source is not visible at its own host path: only the root
        // tmpfs is there.
        assert_eq!(plan.lookup("/home/u/proj"), Exposure::Private);
        assert_eq!(plan.lookup("relative"), Exposure::Absent);
        assert_eq!(plan.lookup("/tmp/x"), Exposure::Private);
    }

    #[test]
    fn empty_plan_exposes_nothing() {
        assert_eq!(MountPlan::new().lookup("/etc/passwd"), Exposure::Absent);
        assert_eq!(MountPlan::new().bwrap_args(), [] as [OsString; 0]);
    }

    #[test]
    fn validate_rejects_bad_paths() {
        let cases = [
            (MountPlan::new().with_tmpfs("tmp"), "path must be absolute"),
            (
                MountPlan::new().with_read_only("/a/../b"),
                "path must not contain `..`",
            ),
            (
                MountPlan::new().with_bind("rel", "/x", Access::ReadOnly, false),
                "source must be a normalized absolute path",
            ),
            (
                MountPlan::new().with_mask("/", MaskKind::Dir),
                "cannot be mounted at /",
            ),
            (
                MountPlan::new().with(Mount::Proc { dest: "/".into() }),
                "cannot be mounted at /",
            ),
            (
                MountPlan::new().with_symlink("", "/l"),
                "symlink target must be non-empty and contain no NUL",
            ),
        ];
        for (plan, expected) in cases {
            match plan.validate() {
                Err(Error::InvalidMount { reason, .. }) => assert_eq!(reason, expected),
                other => panic!("expected {expected:?}, got {other:?}"),
            }
        }
        MountPlan::isolated()
            .with_system_read_only()
            .with_read_write("/work")
            .validate()
            .unwrap();
    }

    #[test]
    fn nul_is_rejected() {
        use std::os::unix::ffi::OsStringExt;
        let path = PathBuf::from(OsString::from_vec(b"/a\0b".to_vec()));
        assert!(MountPlan::new().with_tmpfs(path).validate().is_err());
    }

    #[test]
    fn mask_detects_kind() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        std::fs::write(&file, "x").unwrap();
        assert!(matches!(
            Mount::mask(dir.path()).unwrap(),
            Some(Mount::Mask {
                kind: MaskKind::Dir,
                ..
            })
        ));
        assert!(matches!(
            Mount::mask(&file).unwrap(),
            Some(Mount::Mask {
                kind: MaskKind::File,
                ..
            })
        ));
        assert_eq!(Mount::mask(dir.path().join("none")).unwrap(), None);
    }
}
