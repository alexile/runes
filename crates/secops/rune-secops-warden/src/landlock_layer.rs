//! Landlock as a second, independent filesystem enforcement layer —
//! opt-in via `sandbox.landlock` in the policy TOML (on by default, like
//! `seccomp.enabled`: pure hardening with a graceful best-effort fallback
//! on kernels that don't support it, so there's no workflow downside to
//! leaving it on).
//!
//! # Why this exists
//!
//! The mount-namespace whitelist ([`crate::sandbox::build_bwrap_args`]) is
//! the primary enforcement mechanism, but it's *one* mechanism: a bug in
//! bwrap itself, in the kernel's namespace code, or in how this crate
//! constructs the bwrap argument vector would compromise it entirely.
//! Landlock is a second, independent gate at the VFS/inode layer,
//! restricting the sandboxed program (and, since Landlock restrictions
//! survive `exec()` and can only be narrowed further — never widened — by
//! a descendant, everything it goes on to spawn) to exactly the same
//! paths the policy already whitelists.
//!
//! # Where this is applied, and why — a real dead end documented here on
//! purpose
//!
//! The obvious-looking design is to apply the ruleset to the process
//! *about to exec `bwrap`*, via `pre_exec` on the `bwrap`
//! [`std::process::Command`] — Landlock restrictions inherit through
//! `exec()`, so in theory that would cover `bwrap` and everything it goes
//! on to spawn with one call. **This does not work, and the failure is
//! worth recording so nobody rediscovers it the hard way**: confirmed
//! directly (a minimal reproduction restricting only to `/`, the
//! broadest possible grant) that once *any* Landlock ruleset is active,
//! bwrap's own `mount(NULL, "/", MS_SLAVE)` — the first step of
//! constructing its mount namespace — fails outright with `EPERM`,
//! regardless of what paths are granted. This matches a limitation the
//! `landlock` crate's own docs name directly: *"arbitrary mounts are
//! always denied"* for a process inside an active Landlock domain. A
//! sandbox manager that needs to `mount()` (which bwrap fundamentally
//! does, repeatedly, to construct the sandbox at all) cannot itself be
//! Landlock-restricted while doing so.
//!
//! The working design instead applies Landlock *after* bwrap has
//! finished constructing the sandbox — from a tiny stub process that
//! bwrap execs in place of the real target program, which restricts
//! itself and then execs the real program as its very last act. Bwrap's
//! own mount-namespace construction is complete by the time this stub
//! runs, so the `EPERM` above never triggers; the ruleset then applies to
//! exactly the process that matters (the sandboxed program itself), using
//! paths as they appear *inside* the already-constructed sandbox — which
//! is arguably more correct than the pre-exec design would have been
//! anyway, since it doesn't need to separately account for bwrap's own
//! binary, libraries, or `/proc` setup needs.
//!
//! [`build_stub_program`] and [`run_stub_if_invoked`] are the two halves
//! of this: [`crate::sandbox::build_command`] arranges for the stub to be
//! bwrap's exec target (see its use of [`build_stub_program`]), and any
//! CLI built on this library must call [`run_stub_if_invoked`] as the
//! very first thing in `main()`, before any argument parsing — see that
//! function's docs.
//!
//! # What this deliberately does NOT do
//!
//! Landlock rules are purely additive grants: a path is permitted if *any*
//! rule covers it, with no concept of "this narrower rule overrides that
//! broader one." That means this layer cannot reproduce
//! [`FilesystemSection::deny`][crate::policy::FilesystemSection] or
//! [`FilesystemSection::read_only_override`][crate::policy::FilesystemSection]'s
//! narrowing semantics — if `~/.claude` is granted full read-write access
//! here, a *separate* read-only rule for `~/.claude/settings.json` adds
//! nothing on top of that broader grant; Landlock has no way to express
//! "except this one file, which must be read-only." `deny` and
//! `read_only_override` remain solely bwrap's job (mount-order layering,
//! covered by their own e2e tests); this layer's real, honest guarantee
//! is coarser and different in kind: *nothing outside the whitelisted
//! roots — the exact set of paths in `commands.allow`'s resolved
//! binaries, their shared-library closure, and `filesystem.read_only`/
//! `read_write`/`read_only_override`/`device` — is reachable at all*,
//! even if the mount-namespace boundary that would normally hide
//! everything else is somehow bypassed or misconfigured.
//!
//! It also means the top-level sandboxed program itself needs to be
//! covered by one of those grants (in practice: listed in
//! `commands.allow`, the same as every other exec inside the sandbox) —
//! with `sandbox.landlock = true`, a `program` reachable only via an
//! ad-hoc bwrap filesystem bind and never added to `commands.allow` would
//! fail to start, where it would have worked with Landlock off. This is
//! the intended effect, not a bug: allowing that would mean Landlock, the
//! layer specifically meant to survive a mistake in the filesystem
//! whitelist, trusted that same whitelist as an unconditional escape
//! hatch.
//!
//! # Mechanism
//!
//! The ruleset itself is built and enforced by [`rune_landlock`]; this
//! module only decides *which* paths get *which* rights and carries them
//! into the sandbox. One intentional difference from the hand-rolled
//! ruleset this crate used to build: a granted path that does not exist
//! inside the sandbox is now skipped (fewer grants), where it used to
//! abort the whole ruleset and silently leave Landlock off for the run.

use std::path::PathBuf;

use rune_landlock::{Abi, Compatibility, Options, Report};

use crate::policy::{FilesystemSection, Policy};
use crate::resolve::ResolvedCommand;

/// The Landlock ABI version to request. Best-effort mode means requesting
/// a version newer than the running kernel supports degrades gracefully
/// to whatever subset it does support, rather than failing outright — so
/// this is safe to bump forward as newer kernels become common; it
/// doesn't need to track the exact minimum kernel this project supports.
const REQUESTED_ABI: Abi = Abi::V5;

/// Marks a process as the Landlock stub rather than a normal invocation —
/// see [`run_stub_if_invoked`]. Not meant to ever be set by a human. Not
/// landlock-specific despite living in this module — it's the general
/// "route through the stub at all" marker, since `sandbox::build_command`
/// routes through the exact same stub for `network.allowed_domains`/
/// `network.allowed_ips` too (see [`run_stub_if_invoked`]'s handling of
/// [`network::NETWORK_UDS_ENV`]).
const STUB_MARKER_ENV: &str = "RUNE_WARDEN_STUB";
/// Presence (not just content) matters for these three: unset entirely
/// means "don't apply Landlock at all" (network-only stub invocation),
/// whereas set-but-empty means a genuinely empty grant list — see
/// [`run_stub_if_invoked`].
const READ_ONLY_ENV: &str = "RUNE_WARDEN_LANDLOCK_RO";
const READ_WRITE_ENV: &str = "RUNE_WARDEN_LANDLOCK_RW";
const EXEC_ENV: &str = "RUNE_WARDEN_LANDLOCK_EXEC";
/// Environment variables can't contain a NUL byte, so it can't appear in
/// any of the paths being joined — safe as a delimiter for exactly that
/// reason. `:` (the obvious choice) can legally appear inside a path
/// component and is rejected here on purpose to avoid a false sense of
/// safety.
const PATH_LIST_SEP: char = '\u{1f}';

fn encode_paths(paths: &[PathBuf]) -> String {
    paths
        .iter()
        .map(|p| p.to_string_lossy())
        .collect::<Vec<_>>()
        .join(&PATH_LIST_SEP.to_string())
}

fn decode_paths(value: &str) -> Vec<PathBuf> {
    if value.is_empty() {
        return Vec::new();
    }
    value.split(PATH_LIST_SEP).map(PathBuf::from).collect()
}

/// The stub [`crate::sandbox::build_command`] runs inside the sandbox in
/// front of the real target (`rune_namespaces::Options::wrapper`; the real
/// program and its arguments are appended to `program`), plus the
/// environment variables it must add to the sandbox environment for the
/// stub to reconstruct the same ruleset once it's running inside the
/// fully-constructed sandbox. `self_exe` is `std::env::current_exe()` —
/// resolved by the caller, not this function, since a library shouldn't
/// guess how its host CLI is invoked — and still needs to be bound into
/// the sandbox like any other binary (including its own shared-library
/// closure); this function only prepares the stub *invocation*, not the
/// bind.
pub struct StubProgram {
    pub program: PathBuf,
    pub env: Vec<(String, String)>,
}

/// Build the stub invocation for whichever of `sandbox.landlock` /
/// `network.allowed_domains` / `network.allowed_ips` are active
/// (`sandbox::build_command` only calls this when at least one is) —
/// applying Landlock's ruleset and/or forking the network relay from
/// *inside* the sandbox, then exec'ing the real program. See the module
/// docs for why Landlock in particular has to work this way rather than
/// restricting `bwrap` itself, and [`crate::network_proxy`]'s docs for
/// the relay.
pub fn build_stub_program(
    self_exe: PathBuf,
    policy: &Policy,
    allowed_commands: &[ResolvedCommand],
    library_closure: &[PathBuf],
) -> StubProgram {
    let mut env = vec![(STUB_MARKER_ENV.to_string(), "1".to_string())];

    if policy.sandbox.landlock {
        let read_only = landlock_read_only_targets(&policy.filesystem);
        let read_write = landlock_read_write_targets(&policy.filesystem);
        let exec = landlock_exec_targets(allowed_commands, library_closure);
        env.push((READ_ONLY_ENV.to_string(), encode_paths(&read_only)));
        env.push((READ_WRITE_ENV.to_string(), encode_paths(&read_write)));
        env.push((EXEC_ENV.to_string(), encode_paths(&exec)));
    }

    if !policy.network.allowed_domains.is_empty() || !policy.network.allowed_ips.is_empty() {
        env.push((
            crate::network_proxy::NETWORK_UDS_ENV.to_string(),
            crate::network_proxy::IN_SANDBOX_PROXY_SOCKET.to_string(),
        ));
    }

    StubProgram {
        program: self_exe,
        env,
    }
}

fn landlock_read_only_targets(filesystem: &FilesystemSection) -> Vec<PathBuf> {
    filesystem
        .read_only
        .iter()
        .chain(filesystem.read_only_override.iter())
        .map(|entry| entry.target().to_path_buf())
        .collect()
}

/// `bwrap` always mounts these fresh — `--proc /proc`, `--dev /dev`, and
/// a `tmpfs` at `/tmp` and `/run` — regardless of what `policy.filesystem`
/// says, since they're not user-configurable at all (see
/// `sandbox::build_bwrap_args`). Confirmed live: without granting these,
/// a real Claude Code session under `sandbox.landlock = true` aborted
/// outright (Bun's runtime hit a denied `ioctl()` on a device file) —
/// Landlock ABI V5 added `IoctlDev`, gating `ioctl()` on device nodes,
/// and `/dev` was never covered by anything in `policy.filesystem` for
/// it to inherit a grant from.
const BWRAP_MANAGED_PATHS: &[&str] = &["/proc", "/dev", "/tmp", "/run"];

fn landlock_read_write_targets(filesystem: &FilesystemSection) -> Vec<PathBuf> {
    filesystem
        .read_write
        .iter()
        .map(|entry| entry.target().to_path_buf())
        .chain(filesystem.device.iter().map(|entry| entry.path.clone()))
        .chain(BWRAP_MANAGED_PATHS.iter().map(PathBuf::from))
        .collect()
}

fn landlock_exec_targets(
    allowed_commands: &[ResolvedCommand],
    library_closure: &[PathBuf],
) -> Vec<PathBuf> {
    allowed_commands
        .iter()
        .map(|command| command.path.clone())
        .chain(library_closure.iter().cloned())
        .collect()
}

/// Call this as the very first thing in your CLI's `main()`, before any
/// argument parsing (real target-program arguments, e.g. `claude -p
/// "..."`, would otherwise be misparsed as this CLI's own flags).
///
/// If this process was launched as the stub (see `build_stub_program` and the
/// module docs for why Landlock in particular has to be a separate exec rather
/// than a `pre_exec` hook), this does whichever of two things
/// `sandbox::build_command` asked for and does not return:
///
/// - If `RUNE_WARDEN_NETWORK_UDS` is set
///   (`network.allowed_domains` and/or `network.allowed_ips` was
///   non-empty): `fork()`s first. The
///   parent runs the relay (`network_proxy::serve_relay`) forever,
///   bridging the sandbox's own private loopback to the bind-mounted
///   proxy socket — see that module's docs for why this has to be a
///   separate process rather than a background thread (threads don't
///   survive the `exec()` below). The child continues on to the next
///   step.
/// - If Landlock's env vars are present (`sandbox.landlock` was `true`):
///   restricts the process (the fork's child, if both are active) to the
///   ruleset they encode.
///
/// Finally execs the real target program. Otherwise — the overwhelming
/// majority of invocations, since this only fires when the marker env
/// var is set — it's a no-op and returns immediately.
pub fn run_stub_if_invoked() {
    use std::os::unix::process::CommandExt;

    if std::env::var_os(STUB_MARKER_ENV).is_none() {
        return;
    }

    // `None` (var never set) vs `Some(_)` (possibly empty, but present)
    // is the signal for whether Landlock is active at all — an empty
    // grant list is a real, if unusual, policy; the *absence* of these
    // vars means `sandbox.landlock` was `false` and nothing here should
    // touch Landlock at all. See these consts' own doc comments.
    let landlock_active = std::env::var_os(READ_ONLY_ENV).is_some();
    let read_only = decode_paths(&std::env::var(READ_ONLY_ENV).unwrap_or_default());
    let read_write = decode_paths(&std::env::var(READ_WRITE_ENV).unwrap_or_default());
    let exec = decode_paths(&std::env::var(EXEC_ENV).unwrap_or_default());
    let network_uds = std::env::var(crate::network_proxy::NETWORK_UDS_ENV).ok();

    // Never propagate the stub's own marker/spec env vars into the real
    // program — they're this mechanism's internal plumbing, not
    // something a sandboxed `claude` or `cargo` should ever see.
    for var in [
        STUB_MARKER_ENV,
        READ_ONLY_ENV,
        READ_WRITE_ENV,
        EXEC_ENV,
        crate::network_proxy::NETWORK_UDS_ENV,
    ] {
        // SAFETY: single-threaded at this point (the very first thing
        // `main()` does, before any work that could spawn a thread, and
        // before the fork below).
        unsafe { std::env::remove_var(var) };
    }

    // Bind the relay's port before forking, so it is listening before the
    // real program can try to reach it (see `network_proxy::bind_relay`).
    let relay = network_uds.and_then(|uds| match crate::network_proxy::bind_relay() {
        Ok(listener) => Some((listener, uds)),
        Err(err) => {
            eprintln!(
                "rune-secops-warden: warning: binding the network relay failed ({err}), network.allowed_domains/allowed_ips has no effect this run"
            );
            None
        }
    });

    if let Some((listener, uds)) = relay {
        // SAFETY: still single-threaded (nothing above spawns threads);
        // the fork()-in-a-library caveats that matter are about signal
        // handlers and locks held by *other* threads, neither of which
        // apply here.
        match unsafe { libc::fork() } {
            -1 => {
                // Nobody will serve it: close it so clients fail fast
                // instead of hanging in the listen backlog.
                drop(listener);
                eprintln!(
                    "rune-secops-warden: warning: fork() failed, network.allowed_domains/allowed_ips has no effect this run"
                );
            }
            0 => {
                // Child: falls through to the Landlock/exec steps below.
            }
            child => {
                // The relay's own accept loop blocks forever waiting for
                // new connections — it has no way to notice on its own
                // that the child (the real program) has exited. Run it
                // on a background thread instead of inline, so the main
                // thread here is free to `wait()` for the child and then
                // `exit()` the whole process — tearing the relay thread
                // down with it — the moment there's nothing left for it
                // to serve, rather than leaking a process that runs
                // forever after the sandboxed program is long done.
                std::thread::spawn(move || {
                    if let Err(err) =
                        crate::network_proxy::serve_relay(&listener, std::path::Path::new(&uds))
                    {
                        eprintln!("rune-secops-warden: network relay failed: {err}");
                    }
                });
                let mut status = 0i32;
                // SAFETY: plain waitpid on our own child; retried on EINTR.
                while unsafe { libc::waitpid(child, &raw mut status, 0) } == -1 {
                    if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                        std::process::exit(1);
                    }
                }
                std::process::exit(exit_code(status));
            }
        }
    }

    if landlock_active {
        // Best-effort, same as everywhere else in this module: a kernel
        // without Landlock support, or any other failure applying the
        // ruleset, must never prevent the real program from running —
        // see the module docs on this being a second layer, never the
        // sole one.
        let _ = restrict_self_to_paths(&read_only, &read_write, &exec);
    }

    let mut args = std::env::args_os();
    args.next(); // argv[0]: this stub invocation's own path, discard.
    let Some(real_program) = args.next() else {
        eprintln!(
            "rune-secops-warden: internal error: landlock stub invoked with no target program"
        );
        std::process::exit(127);
    };
    let real_args: Vec<_> = args.collect();

    let err = std::process::Command::new(&real_program)
        .args(&real_args)
        .exec();
    eprintln!(
        "rune-secops-warden: failed to exec {}: {err}",
        real_program.to_string_lossy()
    );
    std::process::exit(126);
}

/// The exit code that reports the sandboxed program's wait `status` to our
/// own parent: its exit code, or `128 + signal` (as a shell does) when a
/// signal killed it, so a crash or a seccomp kill never looks like success.
const fn exit_code(status: libc::c_int) -> i32 {
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        1
    }
}

/// The [`rune_landlock`] options for exactly `read_only`/`read_write`/
/// `exec`: read (and execute) access under `read_only`, everything under
/// `read_write`, and execute + read on the individual binaries and shared
/// libraries in `exec` — not directories a process should be creating or
/// deleting files under.
fn landlock_options(read_only: &[PathBuf], read_write: &[PathBuf], exec: &[PathBuf]) -> Options {
    let options = Options::default()
        .with_abi(REQUESTED_ABI)
        .with_compatibility(Compatibility::BestEffort)
        .with_skip_missing(true);
    let options = read_only.iter().fold(options, Options::with_read_exec);
    let options = read_write.iter().fold(options, Options::with_read_write);
    exec.iter().fold(options, Options::with_exec)
}

/// Build a Landlock ruleset from exactly `read_only`/`read_write`/`exec`
/// and apply it to the calling process (and everything it execs from
/// here on) — the primitive [`run_stub_if_invoked`] calls once it's
/// running inside the constructed sandbox. Exposed separately because
/// it's also the natural unit to test directly: applying it to a plain
/// process (no bwrap, no mount namespace at all) and confirming it still
/// blocks what it should is the sharpest possible check of the
/// defense-in-depth claim — namespace enforcement doesn't even need to
/// exist, let alone fail, for this layer to hold on its own.
///
/// Returns the enforcement report rather than treating a weaker-than-
/// requested result as an error: [`rune_landlock::Status::PartiallyEnforced`]
/// or even [`rune_landlock::Status::NotEnforced`] (Landlock unavailable on
/// this kernel entirely) both leave the mount-namespace whitelist as the
/// sole enforcement layer, exactly as if `sandbox.landlock` were `false` —
/// never worse than that.
pub fn restrict_self_to_paths(
    read_only: &[PathBuf],
    read_write: &[PathBuf],
    exec: &[PathBuf],
) -> Result<Report, rune_landlock::Error> {
    rune_landlock::restrict_self(&landlock_options(read_only, read_write, exec))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Regression: the relay parent exited with `WEXITSTATUS`, which is 0
    // for a child killed by a signal, so a crashed or seccomp-killed
    // program looked like a success to whoever ran the sandbox.
    #[test]
    fn exit_code_reports_signal_deaths() {
        use std::os::unix::process::ExitStatusExt;
        let raw = |script: &str| {
            std::process::Command::new("sh")
                .args(["-c", script])
                .status()
                .unwrap()
                .into_raw()
        };
        let killed = raw("kill -KILL $$");
        assert_eq!(libc::WEXITSTATUS(killed), 0, "what the old code reported");
        assert_eq!(exit_code(killed), 128 + libc::SIGKILL);
        assert_eq!(exit_code(raw("exit 3")), 3);
        assert_eq!(exit_code(raw("true")), 0);
    }

    fn scratch_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "rune-secops-warden-landlock-test-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn encode_decode_paths_round_trips() {
        let paths = vec![PathBuf::from("/a/b"), PathBuf::from("/c/d e")];
        assert_eq!(decode_paths(&encode_paths(&paths)), paths);
    }

    #[test]
    fn options_map_each_list_to_its_rights() {
        use rune_landlock::RightSet;
        let options = landlock_options(
            &[PathBuf::from("/ro")],
            &[PathBuf::from("/rw")],
            &[PathBuf::from("/bin/x")],
        );
        let rights: Vec<_> = options
            .rules
            .iter()
            .map(|rule| (rule.path.clone(), rule.rights))
            .collect();
        assert_eq!(
            rights,
            [
                (PathBuf::from("/ro"), RightSet::READ_EXEC),
                (PathBuf::from("/rw"), RightSet::READ_WRITE),
                (PathBuf::from("/bin/x"), RightSet::EXEC),
            ]
        );
        assert_eq!(options.abi, REQUESTED_ABI);
        assert!(options.skip_missing);
    }

    #[test]
    fn decode_empty_string_is_empty_list() {
        assert_eq!(decode_paths(""), [] as [PathBuf; 0]);
    }

    /// The sharpest possible test of the defense-in-depth claim: apply the
    /// ruleset directly to *this test process* (standing in for "bwrap's
    /// mount-namespace enforcement doesn't exist / has been bypassed") and
    /// confirm Landlock alone — with no mount namespace involved at all —
    /// still blocks access outside the granted paths and still allows it
    /// inside them. Run in a forked child so restricting the test
    /// process's own filesystem access doesn't affect the rest of the
    /// test suite.
    #[test]
    fn landlock_alone_blocks_paths_outside_the_policy_even_without_a_mount_namespace() {
        let allowed_dir = scratch_dir("allowed");
        let outside_dir = scratch_dir("outside");
        let allowed_file = allowed_dir.join("readable.txt");
        let outside_file = outside_dir.join("secret.txt");
        std::fs::write(&allowed_file, "ok").unwrap();
        std::fs::write(&outside_file, "should not be reachable").unwrap();

        // SAFETY: fork() in a single-threaded test process; the child
        // only performs syscalls (open, read) and libc calls
        // (exit/_exit) before terminating, then exits — it never returns
        // out of this test function into the rest of the harness.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            let status = restrict_self_to_paths(&[], std::slice::from_ref(&allowed_dir), &[]);
            let enforced = matches!(
                status.map(|report| report.status),
                Ok(rune_landlock::Status::FullyEnforced | rune_landlock::Status::PartiallyEnforced)
            );
            if !enforced {
                // No Landlock support on this kernel at all — nothing to
                // test; exit distinctly so the parent can skip cleanly.
                unsafe { libc::_exit(2) };
            }
            let inside_ok = std::fs::read_to_string(&allowed_file).is_ok();
            let outside_blocked = std::fs::read_to_string(&outside_file).is_err();
            unsafe { libc::_exit(i32::from(!(inside_ok && outside_blocked))) };
        }

        let mut wait_status = 0i32;
        unsafe { libc::waitpid(pid, &raw mut wait_status, 0) };
        let exit_code = libc::WEXITSTATUS(wait_status);
        if exit_code == 2 {
            eprintln!("skipping: this kernel does not support Landlock at all");
            return;
        }
        assert_eq!(
            exit_code, 0,
            "Landlock must allow the granted path and block the ungranted one, with no mount namespace involved"
        );

        std::fs::remove_dir_all(&allowed_dir).unwrap();
        std::fs::remove_dir_all(&outside_dir).unwrap();
    }

    #[test]
    fn restrict_self_to_paths_reports_a_status_rather_than_erroring_on_partial_support() {
        let dir = scratch_dir("status");
        let exec = vec![PathBuf::from("/bin/true")];
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let result = restrict_self_to_paths(&[], std::slice::from_ref(&dir), &exec);
            unsafe { libc::_exit(i32::from(result.is_err())) };
        }
        let mut wait_status = 0i32;
        unsafe { libc::waitpid(pid, &raw mut wait_status, 0) };
        assert_eq!(libc::WEXITSTATUS(wait_status), 0);

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
