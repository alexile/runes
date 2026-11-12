//! [`Preset`]: one sandbox description that compiles to every mechanism.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::Command;

use rune_landlock::RightSet;
use rune_namespaces::{
    Access, EnvPolicy, Exposure, MaskKind, Mount, MountPlan, Namespace, NamespaceSet, Phase,
    SeccompProgram,
};
use rune_seccomp::{Action, syscalls};

use crate::Error;
use crate::paths::PROXY_SOCKET;

/// What a [`Grant`] allows on its path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum GrantAccess {
    /// Read files and list directories. Bound read-only; Landlock grants
    /// [`RightSet::READ`].
    Read,
    /// Read and execute. Bound read-only; Landlock grants
    /// [`RightSet::READ_EXEC`]. For system directories with programs and
    /// libraries in them.
    ReadExec,
    /// Everything. Bound read-write; Landlock grants
    /// [`RightSet::READ_WRITE`].
    ReadWrite,
}

impl GrantAccess {
    /// The bind mount access for this grant.
    #[must_use]
    pub const fn mount_access(self) -> Access {
        match self {
            Self::Read | Self::ReadExec => Access::ReadOnly,
            Self::ReadWrite => Access::ReadWrite,
        }
    }

    /// The Landlock rights for this grant.
    #[must_use]
    pub const fn rights(self) -> RightSet {
        match self {
            Self::Read => RightSet::READ,
            Self::ReadExec => RightSet::READ_EXEC,
            Self::ReadWrite => RightSet::READ_WRITE,
        }
    }
}

/// One host path made visible in the sandbox, at the same path.
///
/// A preset's grants are the single source of truth for its filesystem:
/// [`Preset::mount_plan`] binds them and [`Preset::landlock_options`]
/// allows exactly them, so the two layers cannot drift apart.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Grant {
    /// The absolute host path.
    pub path: PathBuf,
    /// What is allowed on it.
    pub access: GrantAccess,
    /// Skip it, rather than failing, if the path does not exist on the
    /// host. System files differ between distributions; a project
    /// directory should not be optional.
    pub optional: bool,
}

impl Grant {
    /// A grant of `access` on `path` that must exist.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>, access: GrantAccess) -> Self {
        Self {
            path: path.into(),
            access,
            optional: false,
        }
    }

    /// A grant of `access` on `path`, skipped if `path` does not exist.
    #[must_use]
    pub fn optional(path: impl Into<PathBuf>, access: GrantAccess) -> Self {
        Self {
            optional: true,
            ..Self::new(path, access)
        }
    }
}

/// Network access for a [`Preset`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Network {
    /// No network at all: a private network namespace with only a downed
    /// loopback. The default.
    #[default]
    None,
    /// The host's network, unfiltered.
    Host,
    /// No network but one Unix socket: a private network namespace, with
    /// the host socket of a [`rune_egress_proxy::Proxy`] serving
    /// [`Egress::policy`] bound in at [`PROXY_SOCKET`]. The proxy, not the
    /// preset, enforces the allowlist; run it with
    /// [`Proxy::serve_unix`](rune_egress_proxy::Proxy::serve_unix) on
    /// [`Egress::socket`].
    Proxied(Egress),
}

/// The egress proxy behind [`Network::Proxied`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Egress {
    /// What the proxy allows.
    pub policy: rune_egress_proxy::Policy,
    /// The absolute host path of the proxy's Unix socket.
    pub socket: PathBuf,
}

impl Egress {
    /// An egress proxy serving `policy` on the host socket `socket`.
    #[must_use]
    pub fn new(policy: rune_egress_proxy::Policy, socket: impl Into<PathBuf>) -> Self {
        Self {
            policy,
            socket: socket.into(),
        }
    }
}

/// The paths every `bwrap` sandbox built from [`MountPlan::isolated`] has
/// and Landlock must allow, or ordinary programs abort: `/dev` needs
/// read-write (and device `ioctl`s, which Bun's runtime makes on startup),
/// `/proc` read, and the private `/tmp` and `/run` read-write.
const BASE_GRANTS: &[(&str, GrantAccess)] = &[
    ("/dev", GrantAccess::ReadWrite),
    ("/proc", GrantAccess::Read),
    ("/tmp", GrantAccess::ReadWrite),
    ("/run", GrantAccess::ReadWrite),
];

/// The default seccomp filter.
///
/// It denies, with `EPERM`, every call in [`syscalls::DANGEROUS`] (adapted from Docker's profile: module loading,
/// `ptrace`, the kernel keyring, `mount`, `io_uring` and more) that exists
/// on this architecture.
#[must_use]
pub fn default_seccomp() -> rune_seccomp::Options {
    rune_seccomp::Options::denylist(Action::EPERM).with_syscalls(
        syscalls::DANGEROUS
            .iter()
            .copied()
            .filter(|name| syscalls::resolve(name).is_some()),
    )
}

/// A complete, declarative sandbox: what the program sees, which variables
/// it gets, whether it reaches the network, and which system calls it may
/// make.
///
/// A preset is plain data, built by [`dev_tool`](crate::dev_tool),
/// [`network_tool`](crate::network_tool) or by hand, and widened with the
/// `with_*` methods. Nothing touches the system until
/// [`Preset::command`]; the other methods compile it for each mechanism:
///
/// - [`Preset::namespace_options`] for `rune-namespaces` (namespaces, mount
///   plan, environment, seccomp program);
/// - [`Preset::landlock_options`] for `rune-landlock`, a second, in-kernel
///   check of the same grants;
/// - [`Preset::seccomp`] for `rune-seccomp`;
/// - [`Network::Proxied`] for `rune-egress-proxy`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Preset {
    /// A short name, for messages.
    pub name: String,
    /// The host paths made visible, in order: a later grant of a sub-path
    /// overrides an earlier grant of its parent in the mount plan.
    pub grants: Vec<Grant>,
    /// Paths hidden even though a grant covers them. Masks are applied
    /// after every bind, so no grant can uncover them. Landlock rules are
    /// additive and cannot express a mask; the mount layer alone hides
    /// these.
    pub masks: Vec<(PathBuf, MaskKind)>,
    /// The environment.
    pub env: EnvPolicy,
    /// The working directory inside the sandbox.
    pub cwd: Option<PathBuf>,
    /// Network access.
    pub network: Network,
    /// The system call filter, or `None` for none.
    pub seccomp: Option<rune_seccomp::Options>,
    /// The hostname inside the UTS namespace.
    pub hostname: Option<String>,
}

impl Preset {
    /// An empty preset named `name`: nothing visible but the private base
    /// (`/proc`, `/dev`, `/tmp`, `/run`), no variables, no network, and the
    /// [`default_seccomp`] filter.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            grants: Vec::new(),
            masks: Vec::new(),
            env: EnvPolicy::default(),
            cwd: None,
            network: Network::None,
            seccomp: Some(default_seccomp()),
            hostname: None,
        }
    }

    /// Adds `grant`.
    #[must_use]
    pub fn with_grant(mut self, grant: Grant) -> Self {
        self.grants.push(grant);
        self
    }

    /// Makes `path` readable.
    #[must_use]
    pub fn with_read_only(self, path: impl Into<PathBuf>) -> Self {
        self.with_grant(Grant::new(path, GrantAccess::Read))
    }

    /// Makes `path` readable and executable.
    #[must_use]
    pub fn with_read_exec(self, path: impl Into<PathBuf>) -> Self {
        self.with_grant(Grant::new(path, GrantAccess::ReadExec))
    }

    /// Makes `path` readable and writable.
    #[must_use]
    pub fn with_read_write(self, path: impl Into<PathBuf>) -> Self {
        self.with_grant(Grant::new(path, GrantAccess::ReadWrite))
    }

    /// Hides `path`, of the given kind. The path must exist on the host if
    /// a read-write grant covers it; see [`crate::secret_masks`].
    #[must_use]
    pub fn with_mask(mut self, path: impl Into<PathBuf>, kind: MaskKind) -> Self {
        self.masks.push((path.into(), kind));
        self
    }

    /// Adds every mask in `masks`.
    #[must_use]
    pub fn with_masks<I>(mut self, masks: I) -> Self
    where
        I: IntoIterator<Item = (PathBuf, MaskKind)>,
    {
        self.masks.extend(masks);
        self
    }

    /// Passes the host variable `name` (or `PREFIX*` pattern) through.
    #[must_use]
    pub fn with_env_allow(mut self, name: impl Into<OsString>) -> Self {
        self.env = self.env.with_allow(name);
        self
    }

    /// Sets the variable `name` to `value`.
    #[must_use]
    pub fn with_env_set(mut self, name: impl Into<OsString>, value: impl Into<OsString>) -> Self {
        self.env = self.env.with_set(name, value);
        self
    }

    /// Sets the working directory.
    #[must_use]
    pub fn with_cwd(mut self, cwd: impl Into<PathBuf>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }

    /// Sets the network access.
    #[must_use]
    pub fn with_network(mut self, network: Network) -> Self {
        self.network = network;
        self
    }

    /// Sets the hostname.
    #[must_use]
    pub fn with_hostname(mut self, hostname: impl Into<String>) -> Self {
        self.hostname = Some(hostname.into());
        self
    }

    /// Sets the seccomp filter; `None` turns it off.
    #[must_use]
    pub fn with_seccomp(mut self, seccomp: Option<rune_seccomp::Options>) -> Self {
        self.seccomp = seccomp;
        self
    }

    /// Lets the program make the system call `name` although the seccomp
    /// filter lists it, for a tool that genuinely needs one.
    #[must_use]
    pub fn with_allowed_syscall(mut self, name: &str) -> Self {
        let number = syscalls::resolve(name);
        if let Some(options) = self.seccomp.as_mut() {
            options.syscalls.retain(|syscall| match syscall {
                rune_seccomp::Syscall::Name(listed) => listed != name,
                rune_seccomp::Syscall::Number(listed) => Some(*listed) != number,
                _ => true,
            });
        }
        self
    }

    /// The namespaces to unshare: all of them, except the network
    /// namespace with [`Network::Host`].
    #[must_use]
    pub const fn namespaces(&self) -> NamespaceSet {
        match self.network {
            Network::Host => NamespaceSet::ALL.without(Namespace::Net),
            Network::None | Network::Proxied(_) => NamespaceSet::ALL,
        }
    }

    /// The `bwrap` mount plan: the isolated base, every grant in order,
    /// the egress proxy socket, then the masks.
    #[must_use]
    pub fn mount_plan(&self) -> MountPlan {
        let mut plan = MountPlan::isolated();
        for grant in &self.grants {
            plan.push(Mount::Bind {
                src: grant.path.clone(),
                dest: grant.path.clone(),
                access: grant.access.mount_access(),
                optional: grant.optional,
            });
        }
        if let Network::Proxied(egress) = &self.network {
            plan.push(Mount::Bind {
                src: egress.socket.clone(),
                dest: PROXY_SOCKET.into(),
                access: Access::ReadWrite,
                optional: false,
            });
        }
        for (path, kind) in &self.masks {
            plan.push(Mount::Mask {
                dest: path.clone(),
                kind: *kind,
            });
        }
        plan
    }

    /// What the sandbox path `path` resolves to under
    /// [`Preset::mount_plan`], without touching the filesystem. A path no
    /// grant covers is [`Exposure::Private`]: it falls in the empty tmpfs
    /// root, where nothing exists. [`Preset::is_visible`] tells the two
    /// apart.
    #[must_use]
    pub fn exposure(&self, path: impl AsRef<Path>) -> Exposure {
        self.mount_plan().lookup(path)
    }

    /// Whether the sandbox path `path` can exist in the sandbox: a grant,
    /// the proxy socket or the private base (`/proc`, `/dev`, `/tmp`,
    /// `/run`) covers it, and no mask hides it. Everything else lands in
    /// the empty root and does not exist. Pure, like
    /// [`Preset::exposure`]; whether a granted host path really exists is
    /// not checked.
    #[must_use]
    pub fn is_visible(&self, path: impl AsRef<Path>) -> bool {
        visible(&self.mount_plan(), path.as_ref())
    }

    /// The Landlock ruleset for the same grants, to apply inside the
    /// sandbox (see [`Preset::landlock_wrapper`]): the base paths every
    /// `bwrap` sandbox has, then each grant with its
    /// [`GrantAccess::rights`]. Missing paths are skipped and older
    /// kernels get best effort.
    #[must_use]
    pub fn landlock_options(&self) -> rune_landlock::Options {
        let base = BASE_GRANTS
            .iter()
            .map(|(path, access)| (PathBuf::from(path), *access));
        let grants = self
            .grants
            .iter()
            .map(|grant| (grant.path.clone(), grant.access));
        base.chain(grants).fold(
            rune_landlock::Options::default().with_skip_missing(true),
            |options, (path, access)| options.with_rule(path, access.rights()),
        )
    }

    /// The arguments that run the `rune-landlock` binary at `launcher` in
    /// front of the program, enforcing [`Preset::landlock_options`]; set
    /// them as [`rune_namespaces::Options::wrapper`]. `launcher` must be
    /// visible and executable inside the sandbox (under a
    /// [`GrantAccess::ReadExec`] grant such as `/usr`).
    #[must_use]
    pub fn landlock_wrapper(&self, launcher: impl Into<OsString>) -> Vec<OsString> {
        let mut args = vec![launcher.into()];
        for rule in self.landlock_options().rules {
            let flag = if rule.rights == RightSet::READ_WRITE {
                "--read-write"
            } else if rule.rights == RightSet::READ_EXEC {
                "--read-exec"
            } else {
                "--read"
            };
            args.push(flag.into());
            args.push(rule.path.into_os_string());
        }
        args.push("--".into());
        args
    }

    /// Checks that the preset is well formed and self-consistent:
    ///
    /// - every grant, mask and the proxy socket path is absolute;
    /// - the working directory and a pinned `$HOME` are visible in the
    ///   sandbox. A `$HOME` that points at nothing makes many programs
    ///   abort early instead of failing gracefully;
    /// - the namespace options are valid (see
    ///   [`rune_namespaces::Options::validate`]).
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] or [`Error::Namespaces`] for the first problem.
    pub fn validate(&self) -> Result<(), Error> {
        for path in self
            .grants
            .iter()
            .map(|grant| &grant.path)
            .chain(self.masks.iter().map(|(path, _)| path))
        {
            if !path.is_absolute() {
                return Err(Error::Invalid {
                    reason: format!("path {} must be absolute", path.display()),
                });
            }
        }
        if let Network::Proxied(egress) = &self.network
            && !egress.socket.is_absolute()
        {
            return Err(Error::Invalid {
                reason: format!(
                    "egress proxy socket {} must be absolute",
                    egress.socket.display()
                ),
            });
        }
        let plan = self.mount_plan();
        if let Some(cwd) = &self.cwd
            && !visible(&plan, cwd)
        {
            return Err(Error::Invalid {
                reason: format!("working directory {} is not visible", cwd.display()),
            });
        }
        if let Some(home) = self.env.set.get(OsStr::new("HOME"))
            && !visible(&plan, Path::new(home))
        {
            return Err(Error::Invalid {
                reason: format!("HOME {} is not visible", Path::new(home).display()),
            });
        }
        self.base_options().validate().map_err(Error::Namespaces)
    }

    /// The compiled seccomp program, or `None` if the filter is off or
    /// empty.
    ///
    /// # Errors
    ///
    /// [`Error::Seccomp`] if the filter cannot be compiled, for instance on
    /// an unsupported architecture.
    pub fn seccomp_program(&self) -> Result<Option<rune_seccomp::Program>, Error> {
        match &self.seccomp {
            Some(options) if !options.syscalls.is_empty() => rune_seccomp::compile(options)
                .map(Some)
                .map_err(Error::Seccomp),
            _ => Ok(None),
        }
    }

    /// The [`rune_namespaces::Options`] for this preset, seccomp program
    /// included. Add [`Preset::landlock_wrapper`] with
    /// [`rune_namespaces::Options::with_wrapper`] to layer Landlock.
    ///
    /// # Errors
    ///
    /// As [`Preset::validate`] and [`Preset::seccomp_program`].
    pub fn namespace_options(&self) -> Result<rune_namespaces::Options, Error> {
        self.validate()?;
        let options = self.base_options();
        Ok(match self.seccomp_program()? {
            Some(program) => options.with_seccomp(
                SeccompProgram::from_bytes(program.to_bytes()).map_err(Error::Namespaces)?,
            ),
            None => options,
        })
    }

    /// A [`Command`] that runs `program` with `args` in this sandbox,
    /// passing through host variables as [`Preset::env`] allows. Spawn it
    /// once (see [`rune_namespaces::Options::command`]).
    ///
    /// # Errors
    ///
    /// As [`Preset::namespace_options`], plus [`Error::Namespaces`] if the
    /// seccomp pipe cannot be set up.
    pub fn command<S: AsRef<OsStr>>(
        &self,
        program: impl AsRef<OsStr>,
        args: &[S],
    ) -> Result<Command, Error> {
        self.namespace_options()?
            .command(program, args)
            .map_err(Error::Namespaces)
    }

    fn base_options(&self) -> rune_namespaces::Options {
        let mut options = rune_namespaces::Options::default()
            .with_namespaces(self.namespaces())
            .with_mounts(self.mount_plan())
            .with_env(self.env.clone());
        if let Some(cwd) = &self.cwd {
            options = options.with_cwd(cwd);
        }
        if let Some(hostname) = &self.hostname {
            options = options.with_hostname(hostname);
        }
        options
    }
}

/// Whether `path` is covered by something in `plan` other than the empty
/// root tmpfs, and not masked.
fn visible(plan: &MountPlan, path: &Path) -> bool {
    let without_root = plan
        .mounts()
        .iter()
        .filter(|mount| mount.phase() != Phase::Root)
        .cloned()
        .fold(MountPlan::new(), MountPlan::with);
    !matches!(
        without_root.lookup(path),
        Exposure::Absent | Exposure::Masked
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_preset_is_valid_and_isolated() {
        let preset = Preset::new("empty");
        assert!(preset.validate().is_ok());
        assert_eq!(preset.namespaces(), NamespaceSet::ALL);
        assert!(!preset.is_visible("/etc/passwd"));
        assert!(preset.is_visible("/tmp/x"));
        assert_eq!(preset.exposure("/tmp/x"), Exposure::Private);
    }

    #[test]
    fn grants_drive_both_mounts_and_landlock() {
        let preset = Preset::new("t")
            .with_read_exec("/usr")
            .with_read_write("/work");
        assert_eq!(
            preset.exposure("/work/a"),
            Exposure::Host {
                source: "/work/a".into(),
                access: Access::ReadWrite
            }
        );
        let rules = preset.landlock_options().rules;
        assert!(
            rules
                .iter()
                .any(|r| r.path == Path::new("/usr") && r.rights == RightSet::READ_EXEC)
        );
        assert!(
            rules
                .iter()
                .any(|r| r.path == Path::new("/work") && r.rights == RightSet::READ_WRITE)
        );
    }

    #[test]
    fn masks_win_over_grants() {
        let preset = Preset::new("t")
            .with_read_write("/work")
            .with_mask("/work/.env", MaskKind::File);
        assert_eq!(preset.exposure("/work/.env"), Exposure::Masked);
    }

    #[test]
    fn relative_paths_are_rejected() {
        let err = Preset::new("t").with_read_only("etc").validate();
        assert!(matches!(err, Err(Error::Invalid { .. })));
    }

    #[test]
    fn invisible_home_and_cwd_are_rejected() {
        let home = Preset::new("t").with_env_set("HOME", "/home/me");
        assert!(matches!(home.validate(), Err(Error::Invalid { .. })));
        let cwd = Preset::new("t").with_cwd("/srv/app");
        assert!(matches!(cwd.validate(), Err(Error::Invalid { .. })));
        let masked = Preset::new("t")
            .with_read_write("/srv")
            .with_mask("/srv/app", MaskKind::Dir)
            .with_cwd("/srv/app");
        assert!(matches!(masked.validate(), Err(Error::Invalid { .. })));
    }

    #[test]
    fn host_network_drops_only_the_net_namespace() {
        let preset = Preset::new("t").with_network(Network::Host);
        let namespaces = preset.namespaces();
        assert!(!namespaces.contains(Namespace::Net));
        assert!(namespaces.contains(Namespace::Pid));
        assert!(namespaces.contains(Namespace::Mount));
    }

    #[test]
    fn proxied_network_binds_only_the_socket() {
        let egress = Egress::new(
            rune_egress_proxy::Policy::new()
                .allow_host("crates.io")
                .unwrap(),
            "/run/user/1000/egress.sock",
        );
        let preset = Preset::new("t").with_network(Network::Proxied(egress));
        assert!(preset.namespaces().contains(Namespace::Net));
        assert_eq!(
            preset.exposure(PROXY_SOCKET),
            Exposure::Host {
                source: "/run/user/1000/egress.sock".into(),
                access: Access::ReadWrite
            }
        );
        assert!(preset.validate().is_ok());
        let relative = Preset::new("t").with_network(Network::Proxied(Egress::new(
            rune_egress_proxy::Policy::new(),
            "egress.sock",
        )));
        assert!(matches!(relative.validate(), Err(Error::Invalid { .. })));
    }

    #[test]
    fn allowed_syscall_is_removed_from_the_filter() {
        if rune_seccomp::Arch::native().is_none() {
            return;
        }
        let ptrace = syscalls::resolve("ptrace").unwrap();
        let preset = Preset::new("t");
        let program = preset.seccomp_program().unwrap().unwrap();
        assert_eq!(program.evaluate(ptrace), Some(Action::EPERM));
        let widened = preset.with_allowed_syscall("ptrace");
        let program = widened.seccomp_program().unwrap().unwrap();
        assert_eq!(program.evaluate(ptrace), Some(Action::Allow));
    }

    #[test]
    fn seccomp_can_be_turned_off() {
        let preset = Preset::new("t").with_seccomp(None);
        assert!(preset.seccomp_program().unwrap().is_none());
        assert!(preset.namespace_options().unwrap().seccomp.is_none());
    }

    #[test]
    fn landlock_wrapper_lists_every_rule() {
        let preset = Preset::new("t")
            .with_read_exec("/usr")
            .with_read_only("/etc/hosts")
            .with_read_write("/work");
        let args = preset.landlock_wrapper("/usr/bin/rune-landlock");
        let args: Vec<_> = args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            args.first().map(String::as_str),
            Some("/usr/bin/rune-landlock")
        );
        assert_eq!(args.last().map(String::as_str), Some("--"));
        for pair in [
            ["--read-exec", "/usr"],
            ["--read", "/etc/hosts"],
            ["--read-write", "/work"],
            ["--read-write", "/dev"],
            ["--read", "/proc"],
        ] {
            assert!(args.windows(2).any(|w| w == pair), "{pair:?} in {args:?}");
        }
    }
}
