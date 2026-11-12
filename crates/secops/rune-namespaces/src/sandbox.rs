//! [`Options`] and turning them into a ready-to-spawn [`Command`].

use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::sys::{self, ChildSetup};
use crate::{EnvPolicy, Error, MountPlan, Namespace, NamespaceSet};

/// Well-known `bwrap` install locations, checked before a `PATH` search so
/// a hostile or reordered `PATH` cannot substitute another binary.
pub const BWRAP_PATHS: &[&str] = &["/usr/bin/bwrap", "/usr/local/bin/bwrap", "/bin/bwrap"];

/// How the sandbox is built.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum Backend {
    /// Launch through bubblewrap, which supports every feature, found with
    /// [`find_bwrap`] (or by `PATH` search if it is in none of
    /// [`BWRAP_PATHS`]).
    #[default]
    Bwrap,
    /// Launch through the `bwrap` binary at this path.
    BwrapAt(PathBuf),
    /// Call `unshare(2)` in the child just before `exec`, with no helper
    /// binary. It cannot build a mount plan or a PID namespace (both need
    /// a process that stays behind to set them up); use it for network,
    /// IPC, UTS and user isolation of a program that keeps the host
    /// filesystem view.
    Unshare,
}

impl Backend {
    /// A short name: `bwrap` or `unshare`.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Bwrap | Self::BwrapAt(_) => "bwrap",
            Self::Unshare => "unshare",
        }
    }
}

/// Finds `bwrap`: the first existing [`BWRAP_PATHS`] entry, or `None` if
/// it is in none of them (a `PATH` search is still possible by spawning
/// the bare name).
#[must_use]
pub fn find_bwrap() -> Option<PathBuf> {
    BWRAP_PATHS
        .iter()
        .map(Path::new)
        .find(|path| path.is_file())
        .map(Path::to_path_buf)
}

/// A compiled classic-BPF seccomp filter: the raw bytes of a
/// `struct sock_filter` array in native byte order, as produced by a
/// seccomp compiler such as `seccompiler` or `rune-seccomp`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SeccompProgram(Vec<u8>);

impl SeccompProgram {
    /// The kernel's limit on instructions per filter (`BPF_MAXINSNS`).
    pub const MAX_INSTRUCTIONS: usize = 4096;
    const INSTRUCTION_LEN: usize = 8;

    /// Wraps a compiled program.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidSeccomp`] if `bytes` is empty, not a whole number of
    /// 8-byte instructions, or longer than [`Self::MAX_INSTRUCTIONS`].
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Result<Self, Error> {
        let bytes = bytes.into();
        if bytes.is_empty() || bytes.len() % Self::INSTRUCTION_LEN != 0 {
            return Err(Error::InvalidSeccomp {
                reason: "program must be a non-empty array of 8-byte instructions",
            });
        }
        if bytes.len() / Self::INSTRUCTION_LEN > Self::MAX_INSTRUCTIONS {
            return Err(Error::InvalidSeccomp {
                reason: "program exceeds 4096 instructions",
            });
        }
        Ok(Self(bytes))
    }

    /// The raw program bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The number of instructions.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len() / Self::INSTRUCTION_LEN
    }

    /// Always `false`: an empty program cannot be constructed.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }

    fn filters(&self) -> Vec<libc::sock_filter> {
        self.0
            .as_chunks::<{ Self::INSTRUCTION_LEN }>()
            .0
            .iter()
            .map(|insn| libc::sock_filter {
                code: u16::from_ne_bytes([insn[0], insn[1]]),
                jt: insn[2],
                jf: insn[3],
                k: u32::from_ne_bytes([insn[4], insn[5], insn[6], insn[7]]),
            })
            .collect()
    }
}

/// How to isolate a child process.
///
/// The defaults are the strictest: every namespace, an empty root with
/// only `/proc`, `/dev`, `/tmp` and `/run`, an empty environment, a new
/// session, and death with the parent. Loosen them with the `with_*`
/// methods.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Options {
    /// The namespaces to unshare. Default: [`NamespaceSet::ALL`].
    pub namespaces: NamespaceSet,
    /// The filesystem view. Default: [`MountPlan::isolated`].
    pub mounts: MountPlan,
    /// The environment. Default: empty.
    pub env: EnvPolicy,
    /// The hostname inside the UTS namespace. Default: none.
    pub hostname: Option<String>,
    /// The working directory inside the sandbox. Default: none (`/` under
    /// `bwrap`, unchanged under `unshare`).
    pub cwd: Option<PathBuf>,
    /// Kill the child when the parent dies. Default: `true`.
    pub die_with_parent: bool,
    /// Start a new session, detaching the child from the controlling
    /// terminal so it cannot inject keystrokes with `TIOCSTI`. Default:
    /// `true`.
    pub new_session: bool,
    /// A seccomp filter for the sandboxed program. Default: none.
    pub seccomp: Option<SeccompProgram>,
    /// A launcher run inside the sandbox in front of the program, such as
    /// `["rune-landlock", "--read-exec", "/usr", "--"]`: it is executed
    /// with the program and its arguments appended. This is how to layer
    /// Landlock, which cannot be applied to `bwrap` itself. Default: none.
    pub wrapper: Vec<OsString>,
    /// A host-side launcher run *outside* the sandbox in front of `bwrap`,
    /// such as `["/usr/bin/strace", "-f", "-o", "trace.log"]`: it is
    /// executed with the `bwrap` binary and its arguments appended, keeps
    /// the seccomp descriptor and receives the sandbox environment. Only
    /// for [`Backend::Bwrap`] and [`Backend::BwrapAt`]. Default: none.
    pub launcher: Vec<OsString>,
    /// How the sandbox is built. Default: [`Backend::Bwrap`].
    pub backend: Backend,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            namespaces: NamespaceSet::ALL,
            mounts: MountPlan::isolated(),
            env: EnvPolicy::default(),
            hostname: None,
            cwd: None,
            die_with_parent: true,
            new_session: true,
            seccomp: None,
            wrapper: Vec::new(),
            launcher: Vec::new(),
            backend: Backend::Bwrap,
        }
    }
}

impl Options {
    /// Sets [`Options::namespaces`].
    #[must_use]
    pub const fn with_namespaces(mut self, namespaces: NamespaceSet) -> Self {
        self.namespaces = namespaces;
        self
    }

    /// Keeps the host's network: removes [`Namespace::Net`].
    #[must_use]
    pub const fn with_host_network(mut self) -> Self {
        self.namespaces = self.namespaces.without(Namespace::Net);
        self
    }

    /// Sets [`Options::mounts`].
    #[must_use]
    pub fn with_mounts(mut self, mounts: MountPlan) -> Self {
        self.mounts = mounts;
        self
    }

    /// Sets [`Options::env`].
    #[must_use]
    pub fn with_env(mut self, env: EnvPolicy) -> Self {
        self.env = env;
        self
    }

    /// Sets [`Options::hostname`].
    #[must_use]
    pub fn with_hostname(mut self, hostname: impl Into<String>) -> Self {
        self.hostname = Some(hostname.into());
        self
    }

    /// Sets [`Options::cwd`].
    #[must_use]
    pub fn with_cwd(mut self, cwd: impl Into<PathBuf>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }

    /// Sets [`Options::die_with_parent`].
    #[must_use]
    pub const fn with_die_with_parent(mut self, die_with_parent: bool) -> Self {
        self.die_with_parent = die_with_parent;
        self
    }

    /// Sets [`Options::new_session`].
    #[must_use]
    pub const fn with_new_session(mut self, new_session: bool) -> Self {
        self.new_session = new_session;
        self
    }

    /// Sets [`Options::seccomp`].
    #[must_use]
    pub fn with_seccomp(mut self, program: SeccompProgram) -> Self {
        self.seccomp = Some(program);
        self
    }

    /// Sets [`Options::wrapper`].
    #[must_use]
    pub fn with_wrapper<I, S>(mut self, wrapper: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.wrapper = wrapper.into_iter().map(Into::into).collect();
        self
    }

    /// Sets [`Options::launcher`].
    #[must_use]
    pub fn with_launcher<I, S>(mut self, launcher: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.launcher = launcher.into_iter().map(Into::into).collect();
        self
    }

    /// Sets [`Options::backend`].
    #[must_use]
    pub fn with_backend(mut self, backend: Backend) -> Self {
        self.backend = backend;
        self
    }

    /// Checks the options for the chosen backend.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidMount`], [`Error::InvalidEnv`] for a bad mount or
    ///   variable.
    /// - [`Error::InvalidOptions`] for a hostname without a UTS namespace,
    ///   or a relative working directory.
    /// - [`Error::Unsupported`] for a mount plan, PID namespace or
    ///   [`Options::launcher`] with [`Backend::Unshare`].
    pub fn validate(&self) -> Result<(), Error> {
        self.mounts.validate()?;
        self.env.validate()?;
        if self.hostname.is_some() && !self.namespaces.contains(Namespace::Uts) {
            return Err(Error::InvalidOptions {
                reason: "a hostname needs the UTS namespace",
            });
        }
        if self
            .hostname
            .as_deref()
            .is_some_and(|h| h.is_empty() || h.len() > 64 || h.contains('\0'))
        {
            return Err(Error::InvalidOptions {
                reason: "hostname must be 1 to 64 bytes without NUL",
            });
        }
        if self.cwd.as_deref().is_some_and(Path::is_relative) {
            return Err(Error::InvalidOptions {
                reason: "working directory must be absolute",
            });
        }
        if self.backend == Backend::Unshare {
            if !self.mounts.is_empty() {
                return Err(Error::Unsupported {
                    backend: "unshare",
                    reason: "mount plans need the bwrap backend; use an empty MountPlan",
                });
            }
            if self.namespaces.contains(Namespace::Pid) {
                return Err(Error::Unsupported {
                    backend: "unshare",
                    reason: "a PID namespace needs the bwrap backend",
                });
            }
            if !self.launcher.is_empty() {
                return Err(Error::Unsupported {
                    backend: "unshare",
                    reason: "a launcher needs the bwrap backend",
                });
            }
        }
        Ok(())
    }

    /// The `bwrap` arguments that run `program` with `args`, without the
    /// `bwrap` binary itself. Pure: nothing is read or spawned.
    /// `seccomp_fd` is the descriptor number `bwrap` will read the
    /// [`Options::seccomp`] program from.
    ///
    /// # Errors
    ///
    /// As [`Options::validate`].
    pub fn bwrap_args<S: AsRef<OsStr>>(
        &self,
        program: impl AsRef<OsStr>,
        args: &[S],
        seccomp_fd: Option<i32>,
    ) -> Result<Vec<OsString>, Error> {
        self.validate()?;
        let mut out: Vec<OsString> = Vec::new();
        if self.new_session {
            out.push("--new-session".into());
        }
        if self.die_with_parent {
            out.push("--die-with-parent".into());
        }
        out.extend(
            self.namespaces
                .iter()
                .filter_map(Namespace::bwrap_flag)
                .map(OsString::from),
        );
        if let Some(hostname) = &self.hostname {
            out.extend(["--hostname".into(), hostname.into()]);
        }
        out.extend(self.mounts.bwrap_args());
        if let Some(cwd) = &self.cwd {
            out.extend(["--chdir".into(), cwd.clone().into_os_string()]);
        }
        if let Some(fd) = seccomp_fd {
            out.extend(["--seccomp".into(), fd.to_string().into()]);
        }
        out.push("--".into());
        out.extend(self.wrapper.iter().cloned());
        out.push(program.as_ref().to_owned());
        out.extend(args.iter().map(|a| a.as_ref().to_owned()));
        Ok(out)
    }

    /// A [`Command`] that runs `program` with `args` in the sandbox, with
    /// the environment resolved from the current process's environment
    /// through [`Options::env`].
    ///
    /// Spawn it once: a seccomp program is handed over in a pipe that the
    /// first `bwrap` consumes.
    ///
    /// # Errors
    ///
    /// As [`Options::validate`], plus [`Error::Io`] if the seccomp pipe
    /// cannot be set up.
    pub fn command<S: AsRef<OsStr>>(
        &self,
        program: impl AsRef<OsStr>,
        args: &[S],
    ) -> Result<Command, Error> {
        self.command_with_env(program, args, self.env.resolve(std::env::vars_os()))
    }

    /// As [`Options::command`], with the sandbox environment given
    /// directly (typically from [`EnvPolicy::resolve`]) instead of resolved
    /// from the current process.
    ///
    /// # Errors
    ///
    /// As [`Options::command`].
    pub fn command_with_env<S: AsRef<OsStr>>(
        &self,
        program: impl AsRef<OsStr>,
        args: &[S],
        env: Vec<(OsString, OsString)>,
    ) -> Result<Command, Error> {
        let mut command = match &self.backend {
            Backend::Bwrap | Backend::BwrapAt(_) => self.bwrap_command(program, args)?,
            Backend::Unshare => self.unshare_command(program, args)?,
        };
        command.env_clear().envs(env);
        Ok(command)
    }

    fn bwrap_command<S: AsRef<OsStr>>(
        &self,
        program: impl AsRef<OsStr>,
        args: &[S],
    ) -> Result<Command, Error> {
        let bwrap = match &self.backend {
            Backend::BwrapAt(path) => path.clone(),
            _ => find_bwrap().unwrap_or_else(|| PathBuf::from("bwrap")),
        };
        let seccomp = self
            .seccomp
            .as_ref()
            .map(|program| -> Result<_, Error> {
                let (reader, mut writer) =
                    std::io::pipe().map_err(io("creating the seccomp pipe"))?;
                // The program is at most 32 KiB, within a pipe's 64 KiB
                // buffer, so this cannot block.
                writer
                    .write_all(program.as_bytes())
                    .map_err(io("writing the seccomp program"))?;
                Ok(reader)
            })
            .transpose()?;
        let fd = seccomp.as_ref().map(AsRawFd::as_raw_fd);
        let mut command = match self.launcher.split_first() {
            Some((launcher, launcher_args)) => {
                let mut command = Command::new(launcher);
                command.args(launcher_args).arg(bwrap);
                command
            }
            None => Command::new(bwrap),
        };
        command.args(self.bwrap_args(program, args, fd)?);
        if let (Some(fd), Some(reader)) = (fd, seccomp) {
            sys::inherit_fd(&mut command, fd, reader);
        }
        Ok(command)
    }

    fn unshare_command<S: AsRef<OsStr>>(
        &self,
        program: impl AsRef<OsStr>,
        args: &[S],
    ) -> Result<Command, Error> {
        self.validate()?;
        let mut command_line = self
            .wrapper
            .iter()
            .map(OsString::as_os_str)
            .chain([program.as_ref()])
            .chain(args.iter().map(AsRef::as_ref));
        let Some(first) = command_line.next() else {
            return Err(Error::InvalidOptions {
                reason: "no program to run",
            });
        };
        let mut command = Command::new(first);
        command.args(command_line);
        if let Some(cwd) = &self.cwd {
            command.current_dir(cwd);
        }
        let id_maps = self.namespaces.contains(Namespace::User).then(|| {
            let (uid, gid) = sys::ids();
            (
                format!("{uid} {uid} 1").into_bytes(),
                format!("{gid} {gid} 1").into_bytes(),
            )
        });
        sys::install(
            &mut command,
            ChildSetup {
                new_session: self.new_session,
                die_with_parent: self.die_with_parent,
                unshare_flags: self.namespaces.clone_flags(),
                id_maps,
                hostname: self.hostname.clone().map(String::into_bytes),
                seccomp: self.seccomp.as_ref().map(SeccompProgram::filters),
            },
        );
        Ok(command)
    }
}

fn io(context: &'static str) -> impl FnOnce(std::io::Error) -> Error {
    move |source| Error::Io { context, source }
}

/// Checks that `backend` can actually build a sandbox on this host, by
/// spawning a throwaway one.
///
/// Unprivileged user namespaces are often restricted (Debian's
/// `kernel.unprivileged_userns_clone`, Ubuntu's `AppArmor` policy), in
/// which case the binary runs but every sandbox fails. The probe asks for
/// every namespace the backend supports and a program that does not
/// exist: if the failure is the missing program, namespace setup worked.
///
/// # Errors
///
/// [`Error::BwrapNotFound`] when `bwrap` is missing, or
/// [`Error::Unavailable`] with the reason sandboxing does not work.
pub fn probe(backend: &Backend) -> Result<(), Error> {
    const PROGRAM: &str = "/nonexistent/rune-namespaces-probe";
    let options = Options::default().with_backend(backend.clone());
    let options = match backend {
        Backend::Unshare => options
            .with_mounts(MountPlan::new())
            .with_namespaces(NamespaceSet::ALL.without(Namespace::Pid)),
        _ => options,
    };
    let mut command = options.command_with_env::<&str>(PROGRAM, &[], Vec::new())?;
    match backend {
        Backend::Unshare => match command.output() {
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(Error::Unavailable {
                backend: "unshare",
                detail: format!("{err}{}", userns_hint(&err.to_string())),
            }),
            Ok(_) => Err(Error::Unavailable {
                backend: "unshare",
                detail: "the probe program unexpectedly ran".into(),
            }),
        },
        Backend::Bwrap | Backend::BwrapAt(_) => {
            let output = command.output().map_err(|err| {
                if err.kind() == std::io::ErrorKind::NotFound {
                    Error::BwrapNotFound {
                        path: PathBuf::from(command.get_program()),
                    }
                } else {
                    Error::Io {
                        context: "running bwrap",
                        source: err,
                    }
                }
            })?;
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains(PROGRAM) {
                // bwrap got as far as exec'ing the probe: setup worked.
                Ok(())
            } else {
                let detail = stderr.trim();
                Err(Error::Unavailable {
                    backend: "bwrap",
                    detail: format!("{detail}{}", userns_hint(detail)),
                })
            }
        }
    }
}

fn userns_hint(message: &str) -> &'static str {
    if message.contains("user namespace")
        || message.contains("Operation not permitted")
        || message.contains("Permission denied")
    {
        " (unprivileged user namespaces look restricted: check \
         kernel.unprivileged_userns_clone, kernel.apparmor_restrict_unprivileged_userns, \
         or use a setuid bwrap)"
    } else {
        ""
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Access, MaskKind};

    fn strings(args: Vec<OsString>) -> Vec<String> {
        args.into_iter().map(|a| a.into_string().unwrap()).collect()
    }

    #[test]
    fn default_bwrap_args_are_maximally_strict() {
        let args = strings(Options::default().bwrap_args("prog", &["a"], None).unwrap());
        assert_eq!(
            args,
            [
                "--new-session",
                "--die-with-parent",
                "--unshare-user",
                "--unshare-pid",
                "--unshare-net",
                "--unshare-ipc",
                "--unshare-uts",
                "--unshare-cgroup",
                "--tmpfs",
                "/",
                "--proc",
                "/proc",
                "--dev",
                "/dev",
                "--tmpfs",
                "/tmp",
                "--tmpfs",
                "/run",
                "--",
                "prog",
                "a",
            ]
        );
    }

    #[test]
    fn host_network_drops_unshare_net() {
        let args = strings(
            Options::default()
                .with_host_network()
                .bwrap_args::<&str>("p", &[], None)
                .unwrap(),
        );
        assert!(!args.iter().any(|a| a == "--unshare-net"));
        assert!(args.iter().any(|a| a == "--unshare-pid"));
    }

    #[test]
    fn hostname_cwd_seccomp_and_wrapper() {
        let options = Options::default()
            .with_hostname("box")
            .with_cwd("/work")
            .with_mounts(MountPlan::isolated().with_bind("/h/p", "/work", Access::ReadWrite, false))
            .with_wrapper(["rune-landlock", "--read-write", "/work", "--"]);
        let args = strings(options.bwrap_args("make", &["test"], Some(7)).unwrap());
        let at = |flag: &str| args.iter().position(|a| a == flag).unwrap();
        assert_eq!(args[at("--hostname") + 1], "box");
        assert_eq!(args[at("--chdir") + 1], "/work");
        assert_eq!(args[at("--seccomp") + 1], "7");
        assert!(at("--bind") < at("--chdir"));
        let tail = &args[at("--") + 1..];
        assert_eq!(
            tail,
            [
                "rune-landlock",
                "--read-write",
                "/work",
                "--",
                "make",
                "test"
            ]
        );
    }

    #[test]
    fn invalid_options() {
        let no_uts = Options::default()
            .with_namespaces(NamespaceSet::ALL.without(Namespace::Uts))
            .with_hostname("x");
        assert!(matches!(
            no_uts.validate(),
            Err(Error::InvalidOptions { .. })
        ));
        let rel = Options::default().with_cwd("rel");
        assert!(matches!(rel.validate(), Err(Error::InvalidOptions { .. })));
        let bad_mount =
            Options::default().with_mounts(MountPlan::new().with_mask("/", MaskKind::Dir));
        assert!(matches!(
            bad_mount.validate(),
            Err(Error::InvalidMount { .. })
        ));
        let unshare = Options::default().with_backend(Backend::Unshare);
        assert!(matches!(unshare.validate(), Err(Error::Unsupported { .. })));
        let unshare_pid = unshare.with_mounts(MountPlan::new());
        assert!(matches!(
            unshare_pid.validate(),
            Err(Error::Unsupported { .. })
        ));
        unshare_pid
            .with_namespaces(NamespaceSet::ALL.without(Namespace::Pid))
            .validate()
            .unwrap();
    }

    #[test]
    fn seccomp_program_validation_and_decoding() {
        assert!(SeccompProgram::from_bytes(vec![]).is_err());
        assert!(SeccompProgram::from_bytes(vec![0; 9]).is_err());
        assert!(SeccompProgram::from_bytes(vec![0; 8 * 4097]).is_err());
        // BPF_RET | BPF_K, SECCOMP_RET_ALLOW
        let mut insn = Vec::new();
        insn.extend(0x06u16.to_ne_bytes());
        insn.extend([0, 0]);
        insn.extend(0x7fff_0000u32.to_ne_bytes());
        let program = SeccompProgram::from_bytes(insn.clone()).unwrap();
        assert_eq!(program.len(), 1);
        assert_eq!(program.as_bytes(), insn);
        let filters = program.filters();
        assert_eq!((filters[0].code, filters[0].k), (0x06, 0x7fff_0000));
    }

    #[test]
    fn command_scrubs_the_environment() {
        let command = Options::default()
            .with_env(EnvPolicy::default().with_set("A", "1"))
            .command_with_env::<&str>("p", &[], vec![("A".into(), "1".into())])
            .unwrap();
        let envs: Vec<_> = command.get_envs().collect();
        assert_eq!(envs, [(OsStr::new("A"), Some(OsStr::new("1")))]);
        // Values never go on the command line.
        assert!(!command.get_args().any(|a| a == "1"));
    }

    #[test]
    fn launcher_runs_in_front_of_bwrap() {
        let command = Options::default()
            .with_backend(Backend::BwrapAt("/opt/bwrap".into()))
            .with_launcher(["/usr/bin/strace", "-f"])
            .command_with_env::<&str>("/bin/prog", &["x"], Vec::new())
            .unwrap();
        assert_eq!(command.get_program(), "/usr/bin/strace");
        let args: Vec<_> = command.get_args().collect();
        assert_eq!(&args[..2], ["-f", "/opt/bwrap"]);
        assert_eq!(&args[args.len() - 3..], ["--", "/bin/prog", "x"]);

        let unshare = Options::default()
            .with_backend(Backend::Unshare)
            .with_mounts(MountPlan::new())
            .with_namespaces(NamespaceSet::ALL.without(Namespace::Pid))
            .with_launcher(["/usr/bin/strace"]);
        assert!(matches!(unshare.validate(), Err(Error::Unsupported { .. })));
    }

    #[test]
    fn unshare_command_runs_program_directly() {
        let command = Options::default()
            .with_backend(Backend::Unshare)
            .with_mounts(MountPlan::new())
            .with_namespaces(Namespace::Net.into())
            .with_wrapper(["/usr/bin/env"])
            .command_with_env("true", &["x"], Vec::new())
            .unwrap();
        assert_eq!(command.get_program(), "/usr/bin/env");
        assert_eq!(command.get_args().collect::<Vec<_>>(), ["true", "x"]);
    }
}
