//! A library for turning a declarative TOML policy into a hard, OS-level
//! sandbox boundary around a process — built for locking down AI coding
//! agents (Claude Code and similar tools) that otherwise run with the full
//! privileges of the user that launched them.
//!
//! An AI agent with a shell can read any file the user can read
//! (`.ssh/id_rsa`, `.aws/credentials`, browser cookie stores — and once
//! read, that content may end up in a prompt, a log, or a provider's
//! servers), write or delete any file the user can write (a project's
//! database, `.git`, unrelated home directories), and run any command on
//! `PATH`. This crate expresses what an agent *should* be able to touch as
//! a TOML policy and compiles it into two independent, layered kernel
//! boundaries:
//!
//! - [bubblewrap](https://github.com/containers/bubblewrap) (`bwrap`) Linux
//!   namespaces — mount, network, PID, IPC, and UTS — for *scope*: which
//!   paths, network, and commands exist at all.
//! - A compiled seccomp-bpf filter (see [`compiled_seccomp_program`]) for *defense in
//!   depth* beneath that: even a process that somehow reaches a file it
//!   shouldn't can't `ptrace` a sibling, load a kernel module, or remount
//!   something to get around the sandbox.
//!
//! Both boundaries apply to the *entire process tree* the agent spawns:
//! every subprocess it launches (a shell, `npm`, `psql`, ...) inherits the
//! same namespaces and the same syscall filter, so there is no
//! privilege-escalation path through "just shell out".
//!
//! This crate is a library only — it turns a [`Policy`] into a ready-to-run
//! `bwrap` [`std::process::Command`]. Building an actual
//! `rune-secops-warden` CLI on top of it is left to a separate binary.
//! **Linux only** — bubblewrap, seccomp-bpf, and the namespaces this crate
//! relies on don't exist elsewhere. See [`presets`] for a policy verified
//! against a real agent (Claude Code) end to end, not just unit-tested.
//!
//! # Whitelist, not blacklist
//!
//! Every axis of this policy is default-deny. An empty [`Policy`] (an
//! empty TOML file) produces the strictest possible sandbox: no
//! filesystem paths visible beyond an empty root, no network, no
//! environment variables, and no executable commands at all. Nothing is
//! reachable unless a rule explicitly names it:
//!
//! - **Filesystem** — nothing is visible by default (an empty tmpfs
//!   root). Only paths listed under `read_only` or `read_write` are bound
//!   in, optionally remounted at a different path (`mount_as`). `deny`
//!   entries are a narrowing tool *within* an already-allowed path — e.g.
//!   allow `$HOME` broadly but carve `$HOME/.ssh` back out of it — not a
//!   general blacklist gate.
//! - **Commands** — nothing is executable by default. Binaries named
//!   under `commands.allow` are individually bind-mounted at their exact
//!   host path, along with the exact shared-library files they need to
//!   actually run (see [`resolve_library_closure`]) — never a whole
//!   directory. Anything not listed simply does not exist inside the
//!   sandbox (`ENOENT`), even if a parent directory happens to be
//!   readable for other reasons. Binding a whole directory that contains
//!   executable files (`/usr/bin`, `/usr/lib`, ...) via
//!   `filesystem.read_only`/`read_write` would defeat this, so
//!   [`Policy::validate`] refuses that combination outright unless you
//!   explicitly acknowledge it on that entry via
//!   [`PathEntry::acknowledge_executable_content`].
//! - **Network** — off by default (`sandbox.network = "none"`, a fully
//!   unshared network namespace); opt into `"full"` explicitly. There is
//!   no partial, domain-allowlisted mode — see the note at the end of
//!   this section.
//! - **Environment variables** — nothing passes through by default.
//!   `env.allow` names host variables to forward if present; `env.set`
//!   injects fixed values regardless of the host environment. Everything
//!   else (API keys, cloud credentials sitting in the shell environment)
//!   is stripped before the agent ever sees it.
//! - **Syscalls** — a curated, Docker-profile-derived deny list (see
//!   [`denied_syscall_names`]) blocks kernel module loading, `ptrace`/cross-process
//!   memory access, the kernel keyring, `mount`, `io_uring`, and other
//!   syscalls no ordinary CLI tool has a legitimate reason to call.
//! - **Namespaces** — PID, IPC, and UTS (hostname) isolation, and
//!   terminal-injection protection (`new_session`, blocking
//!   `TIOCSTI`/`TIOCLINUX`), all default to the strictest setting (on).
//!
//! **What this crate cannot do:** domain-level network allowlisting
//! (`"only api.anthropic.com"`) needs either a privileged veth+firewall
//! setup or a forced-proxy convention the sandboxed process could just
//! ignore — a soft control that would look like a hard one. Rather than
//! ship something that looks secure but isn't, `sandbox.network` stays
//! binary (`none`/`full`, both real kernel guarantees); if you need
//! domain-level egress control, put the whole sandbox behind a
//! host-level firewall or run it inside a container/VM that owns its own
//! network stack.
//!
//! Resource limits (`[limits]`) are the one section that is **not**
//! strict-by-default — see [`LimitsSection`] for why.
//!
//! # Policy layer over the `rune-*` sandbox crates
//!
//! This crate is the policy layer: the TOML language, [`presets`], and the
//! mapping onto the crates that implement each mechanism —
//! [`rune_namespaces`] (the `bwrap` namespaces, mount plan and
//! environment), [`rune_seccomp`] (the syscall filter), [`rune_landlock`]
//! (the in-sandbox Landlock ruleset) and [`rune_egress_proxy`]
//! (`network.allowed_domains`/`allowed_ips`).
//!
//! //! # Example
//!
//! ```rust,no_run
//! use rune_secops_warden::{build_command, preflight, Policy};
//! use std::path::Path;
//!
//! preflight().unwrap(); // once, e.g. at startup
//!
//! let policy = Policy::load(Path::new("warden.toml")).unwrap();
//! for warning in policy.warnings() {
//!     eprintln!("warning: {warning}");
//! }
//!
//! let mut command = build_command(&policy, "claude", &[]).unwrap();
//! let status = command.status().unwrap();
//! std::process::exit(status.code().unwrap_or(1));
//! ```
//!
//! A [`Policy`] is plain data. Every section is deny-by-default, so the
//! empty policy grants nothing and is valid as it stands:
//!
//! ```rust
//! use rune_secops_warden::Policy;
//!
//! let policy = Policy::default();
//! assert!(policy.validate().is_ok());
//! ```
//!
//! # Policy file
//!
//! ```toml
//! [sandbox]
//! network = "none"          # "none" | "full"
//! die_with_parent = true
//! new_session = true        # block TIOCSTI terminal injection
//! unshare_pid = true
//! unshare_ipc = true
//! unshare_uts = true
//! hostname = "sandbox"      # optional; implies unshare_uts
//!
//! [filesystem]
//! # A bare string is shorthand for "just bind this path" — read_only/
//! # read_write/read_only_override entries can also be a table
//! # ({ path = "...", create = "directory", ... }) when you need mount_as,
//! # create/create_content, or acknowledge_executable_content (see the
//! # "Whitelist, not blacklist" caveat above). deny/device are always a
//! # bare string, since they only ever have one field.
//! read_only = ["/lib", "/usr/lib"]
//! read_write = ["/home/user/project"]
//! deny = ["/home/user/project/.env"]
//!
//! [env]
//! allow = ["PATH", "HOME"]
//!
//! [env.set]
//! CI = "true"
//!
//! [commands]
//! # Bare names are resolved against PATH; entries may also pin an exact
//! # path: { name = "git", path = "/usr/bin/git" }
//! allow = ["cat", "ls", "git", "node"]
//!
//! [seccomp]
//! enabled = true             # hardened default-deny syscall filter
//! allow = []                 # remove specific syscalls if a tool needs one
//!
//! [limits]
//! # Opt-in only — see LimitsSection docs. All unset here means no caps.
//! disable_core_dumps = true  # the one default-on limit; prevents secrets
//!                             # in memory from landing in a crash dump
//! ```

mod audit;
mod deps;
// Landlock enforcement forks a probe child and scrubs the environment before
// any thread exists; both need libc FFI. Every block carries a SAFETY note.
#[allow(
    unsafe_code,
    reason = "fork/wait/_exit FFI and pre-thread env scrubbing"
)]
mod landlock_layer;
mod limits;
mod network_proxy;
mod policy;
pub mod presets;
mod resolve;
mod sandbox;
mod seccomp;

pub use audit::{audit_log_path, summarize_audit_log};
pub use deps::resolve_library_closure;
pub use landlock_layer::run_stub_if_invoked;
pub use policy::{
    AuditSection, CommandRef, CommandsSection, DenyEntry, DeviceEntry, EnvSection,
    FilesystemSection, LimitsSection, Network, NetworkSection, PathEntry, PathKind, Policy,
    SandboxSection, SeccompSection, SymlinkEntry, WardenError,
};
pub use resolve::{
    ResolvedCommand, ResolvedDeny, STANDARD_BIN_DIRS, resolve_allowed_binaries,
    resolve_allowed_binaries_in, resolve_deny_paths,
};
pub use sandbox::{build_bwrap_args, build_command, check_bwrap_available, preflight};
pub use seccomp::{compiled_seccomp_program, denied_syscall_names};
