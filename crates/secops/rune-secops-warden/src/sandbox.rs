//! Turning a validated [`Policy`] into a sandboxed [`Command`]: the
//! policy-to-mechanism mapping onto [`rune_namespaces`] (namespaces, the
//! mount plan, the environment), [`rune_seccomp`] (the syscall filter),
//! [`rune_landlock`] (through the in-sandbox stub) and
//! [`rune_egress_proxy`] (domain/IP egress), plus preflight diagnostics.
//!
//! The mechanisms live in those crates; this module decides what the
//! policy asks of each. Two behaviours changed when the mechanisms moved
//! there, both deliberately:
//!
//! - The sandbox environment reaches `bwrap` through its own environment
//!   instead of `--clearenv`/`--setenv` arguments, so forwarded values
//!   (tokens in `env.allow`) no longer show up in `/proc/<pid>/cmdline`.
//! - A `filesystem.deny` directory is masked with an empty *read-only*
//!   tmpfs (it used to be writable), and the seccomp program reaches
//!   `bwrap` through a pipe whose descriptor is inherited by `bwrap`
//!   alone.

use std::path::{Path, PathBuf};
use std::process::Command;

use rune_namespaces::{
    Access, Backend, EnvPolicy, MaskKind, MountPlan, Namespace, NamespaceSet, Options,
    SeccompProgram,
};

use crate::deps::resolve_library_closure;
use crate::limits::apply_limits;
use crate::policy::{FilesystemSection, Network, PathKind, Policy, WardenError};
use crate::resolve::{ResolvedCommand, ResolvedDeny, resolve_allowed_binaries, resolve_deny_paths};
use crate::seccomp::compiled_seccomp_program;

/// Create the host-side target of every `read_only`/`read_write` entry
/// that opted into `create` and doesn't exist yet — e.g. a config file a
/// tool writes on first run. bwrap refuses to bind a nonexistent source,
/// so without this a policy pointing at not-yet-created state would fail
/// outright on a genuinely first-ever run.
fn ensure_paths_exist(filesystem: &FilesystemSection) -> Result<(), WardenError> {
    for entry in filesystem
        .read_only
        .iter()
        .chain(filesystem.read_write.iter())
        .chain(filesystem.read_only_override.iter())
    {
        let Some(kind) = entry.create else { continue };
        if entry.path.exists() {
            continue;
        }
        if let Some(parent) = entry.path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|err| WardenError::Io(format!("creating {}: {err}", parent.display())))?;
        }
        match kind {
            PathKind::Directory => std::fs::create_dir_all(&entry.path).map_err(|err| {
                WardenError::Io(format!("creating {}: {err}", entry.path.display()))
            })?,
            PathKind::File => {
                let content = entry.create_content.as_deref().unwrap_or("");
                std::fs::write(&entry.path, content).map_err(|err| {
                    WardenError::Io(format!("creating {}: {err}", entry.path.display()))
                })?;
            }
        }
    }
    Ok(())
}

/// Resolve `bwrap` to a single canonical path: a well-known install
/// location ([`rune_namespaces::BWRAP_PATHS`]) if one exists, otherwise a
/// `PATH` search. Checking those first, rather than always doing a
/// bare-name `PATH` lookup, means a hostile or merely reordered `PATH` at
/// spawn time can't substitute a different binary for the one every other
/// call in this module resolves to — [`check_bwrap_available`],
/// [`preflight`], and [`build_command`] all resolve `bwrap` through this
/// same function.
fn resolve_bwrap_path() -> PathBuf {
    rune_namespaces::find_bwrap().unwrap_or_else(|| PathBuf::from("bwrap"))
}

/// Check that the `bwrap` (bubblewrap) binary is available.
pub fn check_bwrap_available() -> Result<(), WardenError> {
    Command::new(resolve_bwrap_path())
        .arg("--version")
        .output()
        .map(|_| ())
        .map_err(|_| WardenError::BwrapNotFound)
}

/// Verify that `bwrap` can actually construct a sandbox on this host, not
/// just that the binary runs.
///
/// Unprivileged namespace creation can be disabled system-wide (e.g.
/// Debian/Ubuntu's `kernel.unprivileged_userns_clone` sysctl, or a hardened
/// `AppArmor` profile restricting unprivileged user namespaces on newer
/// kernels), in which case `bwrap --version` still succeeds but every real
/// sandbox invocation fails. This runs [`rune_namespaces::probe`]: a
/// namespace-creation probe with a deliberately nonexistent program, so it
/// never needs to find or execute anything real.
///
/// This is a real subprocess spawn — call it once at startup, not on
/// every [`build_command`].
pub fn preflight() -> Result<(), WardenError> {
    check_bwrap_available()?;
    rune_namespaces::probe(&Backend::BwrapAt(resolve_bwrap_path())).map_err(|err| match err {
        rune_namespaces::Error::BwrapNotFound { .. } => WardenError::BwrapNotFound,
        other => WardenError::Preflight(other.to_string()),
    })
}

/// Map a [`rune_namespaces`] error: a malformed path, hostname or
/// variable means the policy is unusable as written.
fn namespace_error(err: rune_namespaces::Error) -> WardenError {
    match err {
        rune_namespaces::Error::Io { .. } => WardenError::Io(err.to_string()),
        other => WardenError::Invalid(vec![other.to_string()]),
    }
}

/// Whether `network.allowed_domains`/`allowed_ips` route egress through
/// the filtering proxy.
const fn egress_proxy_enabled(policy: &Policy) -> bool {
    !policy.network.allowed_domains.is_empty() || !policy.network.allowed_ips.is_empty()
}

/// The namespaces `policy` unshares (`bwrap` always adds a mount
/// namespace).
fn namespaces(policy: &Policy) -> NamespaceSet {
    let sandbox = &policy.sandbox;
    let mut set = NamespaceSet::EMPTY;
    // Domain/IP-scoped egress (`network.allowed_domains`/`allowed_ips`)
    // forces full isolation regardless of `sandbox.network` — the whole
    // point is that the *only* path out is the bind-mounted proxy socket,
    // not "isolated except when the policy also happens to say full." See
    // `network_proxy`'s module docs for why a shared namespace +
    // cooperating-only proxy isn't good enough.
    if sandbox.network == Network::None || egress_proxy_enabled(policy) {
        set = set.with(Namespace::Net);
    }
    if sandbox.unshare_pid {
        set = set.with(Namespace::Pid);
    }
    if sandbox.unshare_ipc {
        set = set.with(Namespace::Ipc);
    }
    if sandbox.unshare_uts || sandbox.hostname.is_some() {
        set = set.with(Namespace::Uts);
    }
    set
}

/// The filesystem view `policy` describes.
///
/// [`MountPlan`] applies mounts by phase — the empty root tmpfs, then
/// `/proc` and `/dev`, then binds in insertion order, then masks — so the
/// ordering bugs this crate once shipped cannot come back: a `--tmpfs /`
/// issued *after* `/proc`/`/dev` shadows them (reproduced end to end: a
/// Bun-based agent aborted on the missing `/dev/urandom`), and a mask
/// issued before a bind can be uncovered by it.
fn mount_plan(
    policy: &Policy,
    allowed_commands: &[ResolvedCommand],
    library_closure: &[PathBuf],
    denied_paths: &[ResolvedDeny],
) -> MountPlan {
    let fs = &policy.filesystem;
    // `MountPlan::isolated`: everything is invisible until explicitly
    // bound in, plus fresh `/proc` and `/dev` and empty private `/tmp`
    // and `/run`. FHS-compliant tooling assumes `/run` exists (runtime
    // state, PID files, `XDG_RUNTIME_DIR`); nothing from the host's real
    // `/tmp` or `/run` (D-Bus, ssh-agent/gpg-agent sockets, ...) is
    // exposed unless the policy binds it explicitly.
    let mut plan = MountPlan::isolated();
    for entry in &fs.read_only {
        plan = plan.with_bind(&entry.path, entry.target(), Access::ReadOnly, false);
    }
    for entry in &fs.read_write {
        plan = plan.with_bind(&entry.path, entry.target(), Access::ReadWrite, false);
    }
    // Bound after every read_write entry above, specifically so it wins: a
    // later read-only bind on a path already covered by an earlier
    // read-write one shadows just that path. See
    // `FilesystemSection::read_only_override` for why this exists (a real
    // disclosed sandbox-escape class, not a hypothetical one).
    for entry in &fs.read_only_override {
        plan = plan.with_bind(&entry.path, entry.target(), Access::ReadOnly, false);
    }
    for entry in &fs.symlink {
        plan = plan.with_symlink(&entry.target, &entry.link);
    }
    for entry in &fs.device {
        plan = plan.with_dev_bind(&entry.path);
    }
    // Individually bind each allowed binary at its own host path — the
    // containing directory is never bound wholesale, so anything not
    // listed here simply does not exist inside the sandbox. Likewise for
    // the shared libraries those binaries need: binding a whole
    // `/usr/lib`-style directory makes every executable under it runnable
    // by absolute path regardless of `commands.allow` — confirmed
    // directly with `/usr/lib/openssh/ssh-keysign`. See
    // `crate::resolve_library_closure`.
    for path in allowed_commands
        .iter()
        .map(|resolved| &resolved.path)
        .chain(library_closure)
    {
        plan = plan.with_read_only(path);
    }
    // Masks always apply last, so they hide any ancestor bind above.
    for entry in denied_paths {
        let kind = if entry.is_dir {
            MaskKind::Dir
        } else {
            MaskKind::File
        };
        plan = plan.with_mask(&entry.path, kind);
    }
    plan
}

/// The environment `policy` passes through: `env.allow` from the host,
/// overlaid with `env.set`. Nothing else.
fn env_policy(policy: &Policy) -> EnvPolicy {
    let env = policy
        .env
        .allow
        .iter()
        .fold(EnvPolicy::default(), EnvPolicy::with_allow);
    policy
        .env
        .set
        .iter()
        .fold(env, |env, (name, value)| env.with_set(name, value))
}

/// The [`rune_namespaces`] options for `policy`, without the seccomp
/// program, launcher, Landlock/network stub, or proxy socket that
/// [`build_command`] adds.
fn sandbox_options(policy: &Policy, mounts: MountPlan, cwd: Option<&Path>) -> Options {
    let namespaces = namespaces(policy);
    let mut options = Options::default()
        .with_namespaces(namespaces)
        .with_mounts(mounts)
        .with_env(env_policy(policy))
        .with_die_with_parent(policy.sandbox.die_with_parent)
        .with_new_session(policy.sandbox.new_session);
    if namespaces.contains(Namespace::Uts)
        && let Some(hostname) = &policy.sandbox.hostname
    {
        options = options.with_hostname(hostname.clone());
    }
    if let Some(dir) = cwd {
        options = options.with_cwd(dir);
    }
    options
}

/// Build the `bwrap` argument vector for a policy, without the `--`
/// and the program to run.
///
/// Side-effect free: `allowed_commands`, `library_closure`, and
/// `denied_paths` are precomputed by the caller so this function stays
/// unit-testable without touching the filesystem. `seccomp_fd`, if given, is
/// the file descriptor number (as it will exist in the spawned `bwrap` process)
/// holding a compiled seccomp-bpf program.
///
/// The environment is not part of the arguments: [`build_command`] hands
/// it to `bwrap` through its own environment, so values never appear on
/// a command line.
///
/// # Errors
///
/// [`WardenError::Invalid`] when a path, hostname or working directory
/// cannot be expressed (a relative path, `..`, NUL, a hostname longer
/// than 64 bytes).
pub fn build_bwrap_args(
    policy: &Policy,
    allowed_commands: &[ResolvedCommand],
    library_closure: &[PathBuf],
    denied_paths: &[ResolvedDeny],
    seccomp_fd: Option<i32>,
    cwd: Option<&Path>,
) -> Result<Vec<String>, WardenError> {
    let mounts = mount_plan(policy, allowed_commands, library_closure, denied_paths);
    let mut args = sandbox_options(policy, mounts, cwd)
        .bwrap_args("", &[] as &[&str], seccomp_fd)
        .map_err(namespace_error)?;
    // Drop the trailing `--` and the empty program name.
    args.truncate(args.len().saturating_sub(2));
    Ok(args
        .into_iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect())
}

/// Build a ready-to-spawn sandboxed [`Command`] for `program` under
/// `policy`.
///
/// Requires `bwrap` (bubblewrap) to be installed, and runs [`Policy::validate`]
/// first, refusing to build a command for a policy that doesn't actually
/// provide the isolation it appears to.
///
/// `program` is the process you're deliberately choosing to launch, but
/// like anything else it must still be reachable inside the sandbox's
/// filesystem view — typically by listing it in `commands.allow` (or an
/// absolute path under one of the bound `filesystem` paths) — nothing is
/// exempt from the whitelist. `commands.allow` then also governs what
/// `program` can go on to execute itself.
///
/// Spawn the returned command once: the seccomp program is handed to
/// `bwrap` through a pipe the first spawn consumes.
pub fn build_command(
    policy: &Policy,
    program: &str,
    program_args: &[String],
) -> Result<Command, WardenError> {
    check_bwrap_available()?;
    policy.validate().map_err(WardenError::Invalid)?;
    ensure_paths_exist(&policy.filesystem)?;

    let allowed_commands = resolve_allowed_binaries(&policy.commands);
    let library_closure = resolve_library_closure(
        &allowed_commands
            .iter()
            .map(|c| c.path.clone())
            .collect::<Vec<_>>(),
    );
    let denied_paths = resolve_deny_paths(&policy.filesystem);
    let mut mounts = mount_plan(policy, &allowed_commands, &library_closure, &denied_paths);
    let mut env = env_policy(policy);

    // Started here, before bwrap even exists, so it's already accepting
    // connections by the time the sandboxed program could possibly try
    // to reach it. See `network_proxy`'s module docs for the full
    // mechanism and, importantly, what it doesn't guarantee.
    let network_proxy_socket = if egress_proxy_enabled(policy) {
        let egress = crate::network_proxy::egress_policy(&policy.network)
            .map_err(|err| WardenError::Invalid(vec![format!("network: {err}")]))?;
        Some(
            crate::network_proxy::spawn_proxy(egress)
                .map_err(|err| WardenError::Io(format!("starting network egress proxy: {err}")))?,
        )
    } else {
        None
    };

    if let Some(proxy_socket) = &network_proxy_socket {
        // The one thing reachable inside the isolated network namespace,
        // network-wise: a bind mount, not a Landlock rule or anything
        // conditional — visible regardless of whether Landlock ends up
        // applying at all.
        mounts = mounts.with_bind(
            proxy_socket,
            crate::network_proxy::IN_SANDBOX_PROXY_SOCKET,
            Access::ReadWrite,
            false,
        );
        // Point every common convention at the in-sandbox relay so the
        // sandboxed program doesn't need its own policy-specific
        // configuration to find it — both cases exist in the wild
        // (curl honors the lowercase form; many other tools only check
        // uppercase).
        let proxy_url = format!("http://127.0.0.1:{}", crate::network_proxy::RELAY_PORT);
        for var in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
            env = env.with_set(var, &proxy_url);
        }
    }

    let mut wrapper = Vec::new();
    if policy.sandbox.landlock || network_proxy_socket.is_some() {
        // Run the stub inside the sandbox in front of `program` — see
        // `landlock_layer`'s module docs for why Landlock in particular
        // can't be a `pre_exec` hook on `bwrap` itself (bwrap's own
        // mount-namespace construction is fundamentally incompatible with
        // being Landlock-restricted while it happens), and
        // `network_proxy`'s docs for why the relay has to run as a forked
        // process inside the sandbox.
        let self_exe = std::env::current_exe().map_err(|err| {
            WardenError::Io(format!(
                "sandbox.landlock = true and/or network.allowed_domains/allowed_ips being non-empty require locating this program's own executable: {err}"
            ))
        })?;
        // The stub binary itself needs to be reachable inside the
        // sandbox, like any other binary bwrap execs — a normal bind,
        // not a Landlock rule; the ruleset isn't active yet at this
        // point, bwrap hasn't even started.
        mounts = mounts.with_read_only(&self_exe);
        for lib in resolve_library_closure(std::slice::from_ref(&self_exe)) {
            mounts = mounts.with_read_only(lib);
        }

        let stub = crate::landlock_layer::build_stub_program(
            self_exe,
            policy,
            &allowed_commands,
            &library_closure,
        );
        for (name, value) in &stub.env {
            env = env.with_set(name, value);
        }
        wrapper.push(stub.program);
    }

    let seccomp = compiled_seccomp_program(&policy.seccomp)?
        .map(|program| SeccompProgram::from_bytes(program.to_bytes()))
        .transpose()
        .map_err(namespace_error)?;

    let cwd = policy
        .sandbox
        .cwd
        .clone()
        .or_else(|| std::env::current_dir().ok());
    let mut options = sandbox_options(policy, mounts, cwd.as_deref())
        .with_env(env)
        .with_wrapper(wrapper)
        .with_backend(Backend::BwrapAt(resolve_bwrap_path()));
    if let Some(program) = seccomp {
        options = options.with_seccomp(program);
    }
    if policy.audit.enabled {
        // `strace` runs on the host in front of `bwrap`, tracing the whole
        // tree; see `audit.rs`'s module docs.
        options = options.with_launcher(crate::audit::audit_launcher());
    }

    let mut command = options
        .command(program, program_args)
        .map_err(namespace_error)?;
    apply_limits(&mut command, &policy.limits);
    Ok(command)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{FilesystemSection, PathEntry, PathKind};
    use std::path::PathBuf;

    #[test]
    fn resolve_bwrap_path_returns_an_absolute_path_when_well_known_location_exists() {
        let resolved = resolve_bwrap_path();
        if rune_namespaces::BWRAP_PATHS
            .iter()
            .any(|candidate| Path::new(candidate).is_file())
        {
            assert!(
                resolved.is_absolute(),
                "expected an absolute path when a well-known bwrap location exists, got {resolved:?}"
            );
        }
    }

    #[test]
    fn ensure_paths_exist_creates_missing_file_and_directory() {
        let dir = std::env::temp_dir().join(format!(
            "rune-secops-warden-ensure-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let missing_file = dir.join("state/config.json");
        let missing_dir = dir.join("cache/data");

        let filesystem = FilesystemSection {
            read_write: vec![
                PathEntry {
                    path: missing_file.clone(),
                    mount_as: None,
                    create: Some(PathKind::File),
                    create_content: None,
                    acknowledge_executable_content: false,
                },
                PathEntry {
                    path: missing_dir.clone(),
                    mount_as: None,
                    create: Some(PathKind::Directory),
                    create_content: None,
                    acknowledge_executable_content: false,
                },
            ],
            ..Default::default()
        };

        ensure_paths_exist(&filesystem).unwrap();
        assert!(missing_file.is_file());
        assert_eq!(std::fs::read_to_string(&missing_file).unwrap(), "");
        assert!(missing_dir.is_dir());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn ensure_paths_exist_writes_create_content() {
        let dir = std::env::temp_dir().join(format!(
            "rune-secops-warden-ensure-content-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let config = dir.join("config.json");

        let filesystem = FilesystemSection {
            read_write: vec![PathEntry {
                path: config.clone(),
                mount_as: None,
                create: Some(PathKind::File),
                create_content: Some("{}".to_string()),
                acknowledge_executable_content: false,
            }],
            ..Default::default()
        };

        ensure_paths_exist(&filesystem).unwrap();
        assert_eq!(std::fs::read_to_string(&config).unwrap(), "{}");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn ensure_paths_exist_does_not_overwrite_existing_file() {
        let dir = std::env::temp_dir().join(format!(
            "rune-secops-warden-ensure-existing-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let config = dir.join("config.json");
        std::fs::write(&config, r#"{"real":"state"}"#).unwrap();

        let filesystem = FilesystemSection {
            read_write: vec![PathEntry {
                path: config.clone(),
                mount_as: None,
                create: Some(PathKind::File),
                create_content: Some("{}".to_string()),
                acknowledge_executable_content: false,
            }],
            ..Default::default()
        };

        ensure_paths_exist(&filesystem).unwrap();
        assert_eq!(
            std::fs::read_to_string(&config).unwrap(),
            r#"{"real":"state"}"#
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn ensure_paths_exist_leaves_uncreate_entries_alone() {
        let filesystem = FilesystemSection {
            read_write: vec![PathEntry {
                path: PathBuf::from("/definitely/does/not/exist/on/this/host"),
                mount_as: None,
                create: None,
                create_content: None,
                acknowledge_executable_content: false,
            }],
            ..Default::default()
        };
        // No `create` set, so this must not attempt (and fail on) creation.
        ensure_paths_exist(&filesystem).unwrap();
    }

    #[test]
    fn empty_policy_is_maximally_strict() {
        let policy = Policy::default();
        let args = build_bwrap_args(&policy, &[], &[], &[], None, None).unwrap();
        assert!(args.iter().any(|a| a == "--unshare-net"));
        assert!(args.iter().any(|a| a == "--unshare-pid"));
        assert!(args.iter().any(|a| a == "--unshare-ipc"));
        assert!(args.iter().any(|a| a == "--unshare-uts"));
        assert!(args.iter().any(|a| a == "--new-session"));
        assert!(!args.iter().any(|a| a == "--ro-bind"));
        assert!(!args.iter().any(|a| a == "--bind"));
    }

    #[test]
    fn tmpfs_root_is_mounted_before_proc_and_dev() {
        // Regression test for a real, reproduced crash: bwrap applies
        // mount operations in argument order, so `--tmpfs /` issued
        // *after* `--proc`/`--dev` shadows them — the sandboxed process
        // ends up with a /dev containing no /dev/urandom and an empty
        // /proc, which is enough to hard-crash real programs (observed
        // with a Bun-based CLI agent calling abort() on a missing
        // /dev/urandom rather than falling back to getrandom()).
        let policy = Policy::default();
        let args = build_bwrap_args(&policy, &[], &[], &[], None, None).unwrap();
        let tmpfs_root = args
            .iter()
            .position(|a| a == "/")
            .expect("--tmpfs / should be present");
        let proc_idx = args
            .iter()
            .position(|a| a == "--proc")
            .expect("--proc should be present");
        let dev_idx = args
            .iter()
            .position(|a| a == "--dev")
            .expect("--dev should be present");
        assert!(
            tmpfs_root < proc_idx,
            "tmpfs root must be mounted before --proc"
        );
        assert!(
            tmpfs_root < dev_idx,
            "tmpfs root must be mounted before --dev"
        );
    }

    #[test]
    fn network_full_shares_net() {
        let mut policy = Policy::default();
        policy.sandbox.network = Network::Full;
        let args = build_bwrap_args(&policy, &[], &[], &[], None, None).unwrap();
        assert!(!args.iter().any(|a| a == "--unshare-net"));
    }

    #[test]
    fn hostname_forces_uts_namespace() {
        let mut policy = Policy::default();
        policy.sandbox.unshare_uts = false;
        policy.sandbox.hostname = Some("sandbox".to_string());
        let args = build_bwrap_args(&policy, &[], &[], &[], None, None).unwrap();
        assert!(args.iter().any(|a| a == "--unshare-uts"));
        let idx = args.iter().position(|a| a == "--hostname").unwrap();
        assert_eq!(args[idx + 1], "sandbox");
    }

    #[test]
    fn seccomp_fd_emits_flag() {
        let policy = Policy::default();
        let args = build_bwrap_args(&policy, &[], &[], &[], Some(200), None).unwrap();
        let idx = args.iter().position(|a| a == "--seccomp").unwrap();
        assert_eq!(args[idx + 1], "200");
    }

    #[test]
    fn no_seccomp_fd_omits_flag() {
        let policy = Policy::default();
        let args = build_bwrap_args(&policy, &[], &[], &[], None, None).unwrap();
        assert!(!args.iter().any(|a| a == "--seccomp"));
    }

    #[test]
    fn read_write_bind_uses_mount_as() {
        let mut policy = Policy::default();
        policy.filesystem.read_write.push(PathEntry {
            path: PathBuf::from("/home/user/project"),
            mount_as: Some(PathBuf::from("/workspace")),
            create: None,
            create_content: None,
            acknowledge_executable_content: false,
        });
        let args = build_bwrap_args(&policy, &[], &[], &[], None, None).unwrap();
        let idx = args.iter().position(|a| a == "--bind").unwrap();
        assert_eq!(args[idx + 1], "/home/user/project");
        assert_eq!(args[idx + 2], "/workspace");
    }

    #[allow(clippy::similar_names, reason = "parallel names for parallel fixtures")]
    #[test]
    fn read_only_override_is_bound_after_read_write_so_it_wins() {
        let mut policy = Policy::default();
        policy.filesystem.read_write.push(PathEntry {
            path: PathBuf::from("/home/user/.claude"),
            mount_as: None,
            create: None,
            create_content: None,
            acknowledge_executable_content: false,
        });
        policy.filesystem.read_only_override.push(PathEntry {
            path: PathBuf::from("/home/user/.claude/settings.json"),
            mount_as: None,
            create: None,
            create_content: None,
            acknowledge_executable_content: false,
        });
        let args = build_bwrap_args(&policy, &[], &[], &[], None, None).unwrap();

        let rw_idx = args
            .iter()
            .position(|a| a == "/home/user/.claude")
            .expect("read_write parent should be bound");
        let ro_idx = args
            .iter()
            .position(|a| a == "/home/user/.claude/settings.json")
            .expect("read_only_override entry should be bound");
        assert!(
            ro_idx > rw_idx,
            "read_only_override must be bound after its read_write ancestor so it shadows it, got args: {args:?}"
        );
        assert_eq!(args[ro_idx - 1], "--ro-bind");
    }

    #[test]
    fn deny_directory_masks_with_tmpfs() {
        let denied_paths = vec![ResolvedDeny {
            path: PathBuf::from("/home/user/.ssh"),
            is_dir: true,
        }];
        let policy = Policy::default();
        let args = build_bwrap_args(&policy, &[], &[], &denied_paths, None, None).unwrap();
        let idx = args.iter().rposition(|a| a == "--tmpfs").unwrap();
        assert_eq!(args[idx + 1], "/home/user/.ssh");
    }

    #[test]
    fn deny_file_masks_with_dev_null_bind() {
        let denied_paths = vec![ResolvedDeny {
            path: PathBuf::from("/home/user/project/.env"),
            is_dir: false,
        }];
        let policy = Policy::default();
        let args = build_bwrap_args(&policy, &[], &[], &denied_paths, None, None).unwrap();
        let idx = args
            .iter()
            .position(|a| a == "/home/user/project/.env")
            .unwrap();
        assert_eq!(args[idx - 2], "--ro-bind");
        assert_eq!(args[idx - 1], "/dev/null");
    }

    #[test]
    fn allowed_command_bound_at_its_own_path_only() {
        let policy = Policy::default();
        let allowed = vec![ResolvedCommand {
            name: "rm".to_string(),
            path: PathBuf::from("/usr/bin/rm"),
        }];
        let args = build_bwrap_args(&policy, &allowed, &[], &[], None, None).unwrap();
        // source and target are the same path, so the first occurrence is
        // the source half of the `--ro-bind SRC DEST` triple.
        let idx = args.iter().position(|a| a == "/usr/bin/rm").unwrap();
        assert_eq!(args[idx - 1], "--ro-bind");
        assert_eq!(args[idx + 1], "/usr/bin/rm");
    }

    #[test]
    fn library_closure_bound_individually_not_as_a_directory() {
        let policy = Policy::default();
        let closure = vec![PathBuf::from("/usr/lib/x86_64-linux-gnu/libc.so.6")];
        let args = build_bwrap_args(&policy, &[], &closure, &[], None, None).unwrap();
        let idx = args
            .iter()
            .position(|a| a == "/usr/lib/x86_64-linux-gnu/libc.so.6")
            .unwrap();
        assert_eq!(args[idx - 1], "--ro-bind");
        // Never the containing directory — that's the whole point.
        assert!(!args.iter().any(|a| a == "/usr/lib/x86_64-linux-gnu"));
    }

    #[test]
    fn no_allowed_commands_means_nothing_bound() {
        let policy = Policy::default();
        let args = build_bwrap_args(&policy, &[], &[], &[], None, None).unwrap();
        assert!(!args.iter().any(|a| a == "--ro-bind"));
    }

    #[test]
    fn env_set_overrides_and_extends_allowlist() {
        let mut policy = Policy::default();
        policy.env.allow = vec!["CI".to_string()];
        policy.env.set.insert("CI".to_string(), "true".to_string());
        let env = env_policy(&policy).resolve([("CI", "false"), ("OTHER", "x")]);
        assert_eq!(env, [("CI".into(), "true".into())]);
        // The environment never goes on bwrap's command line.
        let args = build_bwrap_args(&policy, &[], &[], &[], None, None).unwrap();
        assert!(!args.iter().any(|a| a == "--setenv" || a == "true"));
    }

    #[test]
    fn env_allowlist_only_passes_present_vars() {
        let mut policy = Policy::default();
        policy.env.allow = vec![
            "RUNE_WARDEN_TEST_VAR".to_string(),
            "RUNE_WARDEN_TEST_VAR_UNSET".to_string(),
        ];
        let env = env_policy(&policy).resolve([
            ("RUNE_WARDEN_TEST_VAR", "secret"),
            ("AWS_SECRET_ACCESS_KEY", "s3cr3t"),
        ]);
        assert_eq!(env, [("RUNE_WARDEN_TEST_VAR".into(), "secret".into())]);
    }

    #[test]
    fn build_command_passes_env_through_the_environment_not_argv() {
        if check_bwrap_available().is_err() {
            return;
        }
        let mut policy = Policy::default();
        policy.sandbox.landlock = false;
        policy
            .env
            .set
            .insert("RUNE_WARDEN_TOKEN".to_string(), "hunter2".to_string());
        let command = build_command(&policy, "/bin/true", &[]).unwrap();
        assert!(
            command
                .get_envs()
                .any(|(k, v)| k == "RUNE_WARDEN_TOKEN" && v == Some("hunter2".as_ref()))
        );
        assert!(!command.get_args().any(|a| a == "hunter2"));
        let args: Vec<_> = command.get_args().collect();
        let sep = args.iter().position(|a| *a == "--").unwrap();
        assert_eq!(args[sep + 1], "/bin/true");
        assert!(args.iter().any(|a| *a == "--seccomp"));
    }

    #[test]
    fn audit_runs_strace_in_front_of_bwrap() {
        if check_bwrap_available().is_err() {
            return;
        }
        let mut policy = Policy::default();
        policy.sandbox.landlock = false;
        policy.audit.enabled = true;
        let command = build_command(&policy, "/bin/true", &[]).unwrap();
        assert!(Path::new(command.get_program()).ends_with("strace"));
        assert!(
            command
                .get_args()
                .any(|a| Path::new(a) == resolve_bwrap_path())
        );
    }

    #[test]
    fn relative_cwd_is_rejected() {
        let policy = Policy::default();
        let err =
            build_bwrap_args(&policy, &[], &[], &[], None, Some(Path::new("rel"))).unwrap_err();
        assert!(matches!(err, WardenError::Invalid(_)));
    }

    #[test]
    fn deny_directory_mask_is_read_only() {
        let denied_paths = vec![ResolvedDeny {
            path: PathBuf::from("/home/user/.ssh"),
            is_dir: true,
        }];
        let args =
            build_bwrap_args(&Policy::default(), &[], &[], &denied_paths, None, None).unwrap();
        let idx = args.iter().position(|a| a == "--remount-ro").unwrap();
        assert_eq!(args[idx + 1], "/home/user/.ssh");
    }

    #[test]
    fn denies_are_applied_after_every_bind() {
        let mut policy = Policy::default();
        policy.filesystem.read_write.push(PathEntry {
            path: PathBuf::from("/home/user"),
            mount_as: None,
            create: None,
            create_content: None,
            acknowledge_executable_content: false,
        });
        let denied_paths = vec![ResolvedDeny {
            path: PathBuf::from("/home/user/.ssh"),
            is_dir: true,
        }];
        let allowed = vec![ResolvedCommand {
            name: "rm".to_string(),
            path: PathBuf::from("/usr/bin/rm"),
        }];
        let args = build_bwrap_args(&policy, &allowed, &[], &denied_paths, None, None).unwrap();
        let mask = args.iter().position(|a| a == "/home/user/.ssh").unwrap();
        let last_bind = args
            .iter()
            .rposition(|a| a == "--ro-bind" || a == "--bind")
            .unwrap();
        assert!(mask > last_bind, "{args:?}");
    }

    #[test]
    fn build_command_rejects_invalid_policy() {
        let policy = Policy {
            filesystem: crate::policy::FilesystemSection {
                read_only: vec![PathEntry {
                    path: PathBuf::from("/"),
                    mount_as: None,
                    create: None,
                    create_content: None,
                    acknowledge_executable_content: false,
                }],
                ..Default::default()
            },
            ..Default::default()
        };
        let err = build_command(&policy, "true", &[]).unwrap_err();
        assert!(matches!(err, WardenError::Invalid(_)));
    }
}
