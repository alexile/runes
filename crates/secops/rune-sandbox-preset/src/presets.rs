//! The ready-made presets: [`dev_tool`] and [`network_tool`].

use std::path::PathBuf;

use rune_namespaces::{MaskKind, SYSTEM_PATHS};

use crate::paths::{
    DEFAULT_HOME, DNS_FILES, HOST_IDENTITY_FILES, PASSTHROUGH_VARS, SAFE_PATH, TLS_PATHS,
    USER_DB_FILES,
};
use crate::preset::{Grant, GrantAccess, Network, Preset};

/// Inputs to [`dev_tool`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct DevToolOptions {
    /// The project directory: read-write, and the working directory.
    pub project_dir: PathBuf,
    /// `$HOME` inside the sandbox. Default: [`DEFAULT_HOME`], the private
    /// `/tmp`. Whatever it is, it must be visible: grant it (or a parent)
    /// through `read_only` or `read_write`, or [`Preset::validate`] fails.
    pub home: Option<PathBuf>,
    /// Extra host paths to make readable, such as a toolchain outside
    /// `/usr` (`~/.rustup`).
    pub read_only: Vec<PathBuf>,
    /// Extra host paths to make writable, such as a build cache
    /// (`~/.cargo/registry`, `~/.npm`).
    pub read_write: Vec<PathBuf>,
    /// Paths to hide, typically from [`crate::secret_masks`] on the
    /// project directory.
    pub masks: Vec<(PathBuf, MaskKind)>,
}

impl DevToolOptions {
    /// Options for the project at `project_dir`, everything else default.
    #[must_use]
    pub fn new(project_dir: impl Into<PathBuf>) -> Self {
        Self {
            project_dir: project_dir.into(),
            ..Self::default()
        }
    }

    /// Sets [`DevToolOptions::home`].
    #[must_use]
    pub fn with_home(mut self, home: impl Into<PathBuf>) -> Self {
        self.home = Some(home.into());
        self
    }

    /// Adds a readable path.
    #[must_use]
    pub fn with_read_only(mut self, path: impl Into<PathBuf>) -> Self {
        self.read_only.push(path.into());
        self
    }

    /// Adds a writable path.
    #[must_use]
    pub fn with_read_write(mut self, path: impl Into<PathBuf>) -> Self {
        self.read_write.push(path.into());
        self
    }

    /// Adds masks.
    #[must_use]
    pub fn with_masks<I>(mut self, masks: I) -> Self
    where
        I: IntoIterator<Item = (PathBuf, MaskKind)>,
    {
        self.masks.extend(masks);
        self
    }
}

/// Inputs to [`network_tool`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NetworkToolOptions {
    /// A directory to make read-write and the working directory, for
    /// downloads or output. Default: none; the tool works in the private
    /// `/tmp`.
    pub work_dir: Option<PathBuf>,
    /// `$HOME` inside the sandbox, as for [`DevToolOptions::home`].
    pub home: Option<PathBuf>,
    /// Network access. Default: [`Network::Host`]. Prefer
    /// [`Network::Proxied`] when the hosts the tool needs are known.
    pub network: Network,
    /// Extra host paths to make readable.
    pub read_only: Vec<PathBuf>,
    /// Extra host paths to make writable.
    pub read_write: Vec<PathBuf>,
}

impl Default for NetworkToolOptions {
    fn default() -> Self {
        Self {
            work_dir: None,
            home: None,
            network: Network::Host,
            read_only: Vec::new(),
            read_write: Vec::new(),
        }
    }
}

impl NetworkToolOptions {
    /// Sets [`NetworkToolOptions::work_dir`].
    #[must_use]
    pub fn with_work_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.work_dir = Some(dir.into());
        self
    }

    /// Sets [`NetworkToolOptions::home`].
    #[must_use]
    pub fn with_home(mut self, home: impl Into<PathBuf>) -> Self {
        self.home = Some(home.into());
        self
    }

    /// Sets [`NetworkToolOptions::network`].
    #[must_use]
    pub fn with_network(mut self, network: Network) -> Self {
        self.network = network;
        self
    }

    /// Adds a readable path.
    #[must_use]
    pub fn with_read_only(mut self, path: impl Into<PathBuf>) -> Self {
        self.read_only.push(path.into());
        self
    }

    /// Adds a writable path.
    #[must_use]
    pub fn with_read_write(mut self, path: impl Into<PathBuf>) -> Self {
        self.read_write.push(path.into());
        self
    }
}

/// The part both presets share: the system directories programs and
/// libraries live in (read and execute, missing ones skipped), the user
/// database, a pinned `$PATH` and `$HOME`, and the harmless variables in
/// [`PASSTHROUGH_VARS`].
fn base(name: &str, home: Option<&PathBuf>) -> Preset {
    let preset = SYSTEM_PATHS.iter().fold(Preset::new(name), |preset, path| {
        preset.with_grant(Grant::optional(*path, GrantAccess::ReadExec))
    });
    let preset = USER_DB_FILES.iter().fold(preset, |preset, path| {
        preset.with_grant(Grant::optional(*path, GrantAccess::Read))
    });
    let home = home.map_or_else(|| PathBuf::from(DEFAULT_HOME), Clone::clone);
    PASSTHROUGH_VARS
        .iter()
        .fold(preset, |preset, name| preset.with_env_allow(*name))
        .with_env_set("PATH", SAFE_PATH)
        .with_env_set("HOME", home)
}

fn with_paths(preset: Preset, read_only: &[PathBuf], read_write: &[PathBuf]) -> Preset {
    let preset = read_only
        .iter()
        .fold(preset, |preset, path| preset.with_read_only(path.clone()));
    read_write
        .iter()
        .fold(preset, |preset, path| preset.with_read_write(path.clone()))
}

/// A sandbox for an offline developer tool: a compiler, build system, test
/// runner, linter or formatter working on one project.
///
/// - **Filesystem**: the system directories read and execute
///   ([`SYSTEM_PATHS`]), `/etc/passwd`, `/etc/group` and `/etc/localtime`
///   read-only, the project read-write, plus the extra paths in
///   `options`. Nothing else of the host, home directory included.
/// - **Network**: none ([`Network::None`]). Fetch dependencies before, or
///   use [`network_tool`] for the fetch step.
/// - **Environment**: [`PASSTHROUGH_VARS`] from the host; `PATH` pinned to
///   [`SAFE_PATH`] and `HOME` to `options.home`.
/// - **Working directory**: the project.
/// - **System calls**: [`default_seccomp`](crate::default_seccomp).
#[must_use]
pub fn dev_tool(options: &DevToolOptions) -> Preset {
    let preset = base("dev-tool", options.home.as_ref())
        .with_grant(Grant::optional("/etc/localtime", GrantAccess::Read));
    with_paths(preset, &options.read_only, &options.read_write)
        .with_read_write(options.project_dir.clone())
        .with_cwd(options.project_dir.clone())
        .with_masks(options.masks.iter().cloned())
}

/// A sandbox for a tool that talks to the network: a downloader, package
/// fetcher, API client or crawler.
///
/// - **Filesystem**: as [`dev_tool`], plus what name resolution and TLS
///   need ([`DNS_FILES`], [`TLS_PATHS`], [`HOST_IDENTITY_FILES`]), all
///   read-only, and `options.work_dir` read-write.
/// - **Network**: `options.network`, by default the host's. With
///   [`Network::Proxied`] the tool has no network but the egress proxy's
///   socket.
/// - **Environment**, **system calls**: as [`dev_tool`].
/// - **Working directory**: `options.work_dir`, or `/tmp`.
#[must_use]
pub fn network_tool(options: &NetworkToolOptions) -> Preset {
    let preset = DNS_FILES.iter().chain(HOST_IDENTITY_FILES).fold(
        base("network-tool", options.home.as_ref()),
        |preset, path| preset.with_grant(Grant::optional(*path, GrantAccess::Read)),
    );
    let preset = TLS_PATHS.iter().fold(preset, |preset, path| {
        preset.with_grant(Grant::optional(*path, GrantAccess::Read))
    });
    let preset = with_paths(preset, &options.read_only, &options.read_write)
        .with_network(options.network.clone());
    match &options.work_dir {
        Some(dir) => preset.with_read_write(dir.clone()).with_cwd(dir.clone()),
        None => preset.with_cwd(DEFAULT_HOME),
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::path::Path;

    use rune_namespaces::{Access, Exposure, Namespace};

    use super::*;
    use crate::paths::PROXY_SOCKET;
    use crate::preset::Egress;

    fn host(path: &str, access: Access) -> Exposure {
        Exposure::Host {
            source: path.into(),
            access,
        }
    }

    fn env_set<'a>(preset: &'a Preset, name: &str) -> Option<&'a OsStr> {
        preset
            .env
            .set
            .get(OsStr::new(name))
            .map(std::ffi::OsString::as_os_str)
    }

    #[test]
    fn dev_tool_rules() {
        let preset = dev_tool(&DevToolOptions::new("/home/me/project"));
        assert!(preset.validate().is_ok());
        // Isolated from the network.
        assert_eq!(preset.network, Network::None);
        assert!(preset.namespaces().contains(Namespace::Net));
        // The project is writable and the working directory.
        assert_eq!(
            preset.exposure("/home/me/project/src/main.rs"),
            host("/home/me/project/src/main.rs", Access::ReadWrite)
        );
        assert_eq!(preset.cwd.as_deref(), Some(Path::new("/home/me/project")));
        // System programs are read-only; secrets in the home are absent.
        assert_eq!(
            preset.exposure("/usr/bin/cc"),
            host("/usr/bin/cc", Access::ReadOnly)
        );
        assert!(!preset.is_visible("/home/me/.ssh/id_ed25519"));
        assert!(!preset.is_visible("/etc/shadow"));
        // No DNS or TLS configuration: an offline tool needs neither.
        assert!(!preset.is_visible("/etc/resolv.conf"));
        assert!(!preset.is_visible("/etc/ssl/certs"));
        // PATH and HOME are pinned, never passed through.
        assert_eq!(env_set(&preset, "PATH"), Some(OsStr::new(SAFE_PATH)));
        assert_eq!(env_set(&preset, "HOME"), Some(OsStr::new(DEFAULT_HOME)));
        assert!(!preset.env.allows(OsStr::new("PATH")));
        assert!(!preset.env.allows(OsStr::new("HOME")));
        assert!(!preset.env.allows(OsStr::new("AWS_SECRET_ACCESS_KEY")));
        assert!(preset.env.allows(OsStr::new("LC_CTYPE")));
        // The dangerous system calls are filtered.
        assert!(preset.seccomp.is_some());
    }

    #[test]
    fn dev_tool_landlock_matches_its_mounts() {
        let preset = dev_tool(&DevToolOptions::new("/srv/p").with_read_write("/var/cache/p"));
        let rules = preset.landlock_options().rules;
        for grant in &preset.grants {
            assert!(
                rules
                    .iter()
                    .any(|r| r.path == grant.path && r.rights == grant.access.rights()),
                "{}",
                grant.path.display()
            );
        }
        // Nothing in the Landlock ruleset is invisible to the mount plan.
        for rule in &rules {
            assert!(preset.is_visible(&rule.path), "{}", rule.path.display());
        }
    }

    #[test]
    fn dev_tool_masks_secrets_and_widens_on_request() {
        let preset = dev_tool(
            &DevToolOptions::new("/srv/p")
                .with_home("/home/me")
                .with_read_only("/home/me/.rustup")
                .with_read_write("/home/me/.cargo/registry")
                .with_masks([("/srv/p/.env".into(), MaskKind::File)]),
        );
        assert!(preset.validate().is_err(), "/home/me itself is not granted");
        let preset = dev_tool(
            &DevToolOptions::new("/srv/p")
                .with_home("/home/me/.cargo")
                .with_read_only("/home/me/.rustup")
                .with_read_write("/home/me/.cargo")
                .with_masks([("/srv/p/.env".into(), MaskKind::File)]),
        );
        assert!(preset.validate().is_ok());
        assert_eq!(preset.exposure("/srv/p/.env"), Exposure::Masked);
        assert_eq!(
            preset.exposure("/home/me/.rustup/toolchains"),
            host("/home/me/.rustup/toolchains", Access::ReadOnly)
        );
        assert!(!preset.is_visible("/home/me/.ssh"));
    }

    #[test]
    fn network_tool_rules() {
        let preset = network_tool(&NetworkToolOptions::default().with_work_dir("/srv/dl"));
        assert!(preset.validate().is_ok());
        assert_eq!(preset.network, Network::Host);
        assert!(!preset.namespaces().contains(Namespace::Net));
        assert!(preset.namespaces().contains(Namespace::Pid));
        for path in DNS_FILES.iter().chain(TLS_PATHS).chain(HOST_IDENTITY_FILES) {
            assert_eq!(
                preset.exposure(path),
                host(path, Access::ReadOnly),
                "{path}"
            );
        }
        assert_eq!(
            preset.exposure("/srv/dl/f"),
            host("/srv/dl/f", Access::ReadWrite)
        );
        assert_eq!(preset.cwd.as_deref(), Some(Path::new("/srv/dl")));
        assert!(!preset.is_visible("/home"));
        assert_eq!(env_set(&preset, "PATH"), Some(OsStr::new(SAFE_PATH)));
    }

    #[test]
    fn network_tool_without_work_dir_runs_in_private_tmp() {
        let preset = network_tool(&NetworkToolOptions::default());
        assert!(preset.validate().is_ok());
        assert_eq!(preset.cwd.as_deref(), Some(Path::new("/tmp")));
        assert_eq!(preset.exposure("/tmp"), Exposure::Private);
    }

    #[test]
    fn network_tool_proxied_keeps_the_network_namespace() {
        let egress = Egress::new(
            rune_egress_proxy::Policy::new()
                .allow_hosts(["*.crates.io", "static.rust-lang.org"])
                .unwrap(),
            "/run/user/1000/egress.sock",
        );
        let preset = network_tool(
            &NetworkToolOptions::default().with_network(Network::Proxied(egress.clone())),
        );
        assert!(preset.validate().is_ok());
        assert!(preset.namespaces().contains(Namespace::Net));
        assert_eq!(
            preset.exposure(PROXY_SOCKET),
            host("/run/user/1000/egress.sock", Access::ReadWrite)
        );
        assert_eq!(preset.network, Network::Proxied(egress));
    }

    #[test]
    fn presets_compile_to_namespace_options() {
        for preset in [
            dev_tool(&DevToolOptions::new("/srv/p")),
            network_tool(&NetworkToolOptions::default()),
        ] {
            let options = preset.namespace_options().unwrap();
            let args = options
                .bwrap_args("/usr/bin/true", &[] as &[&str], None)
                .unwrap();
            assert!(args.iter().any(|a| a == "--unshare-pid"), "{}", preset.name);
            if rune_seccomp::Arch::native().is_some() {
                assert!(options.seccomp.is_some(), "{}", preset.name);
            }
        }
    }
}
