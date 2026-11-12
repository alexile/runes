# rune-secops-warden

> Whitelist-only TOML policy engine for sandboxing AI coding agents (Claude Code and such) via bubblewrap Linux namespaces and a seccomp-bpf syscall filter — filesystem, network, env vars, commands, and syscalls all deny-by-default.

[![crates.io](https://img.shields.io/crates/v/rune-secops-warden)](https://crates.io/crates/rune-secops-warden)
[![docs.rs](https://img.shields.io/docsrs/rune-secops-warden)](https://docs.rs/rune-secops-warden)
[![license](https://img.shields.io/crates/l/rune-secops-warden)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

An AI coding agent with a shell runs with the full privileges of the user
that launched it: it can read `.ssh/id_rsa` or `.aws/credentials`, write or
delete a project's database, and run any command on `PATH`. This crate
turns a declarative TOML policy into two layered kernel-enforced
boundaries:

- [bubblewrap](https://github.com/containers/bubblewrap) (`bwrap`) Linux
  namespaces — mount, network, PID, IPC, UTS — for *scope*: which paths,
  network, and commands exist at all.
- A compiled seccomp-bpf filter for *defense in depth* beneath that: even
  a process that somehow reaches a file it shouldn't can't `ptrace` a
  sibling, load a kernel module, or remount something to get around the
  sandbox.

Both boundaries cover the whole process tree the agent spawns — every
subprocess inherits the same namespaces and the same syscall filter, so
there's no escape hatch through "just shell out".

It's a library, not a CLI — it compiles a [`Policy`](src/policy.rs) into a
ready-to-spawn `bwrap` `std::process::Command`. Wire it up to a `-c
policy.toml -- <program>`-style binary as needed.

## Built on generic, independently reusable crates

Everything in this crate that isn't actually specific to sandboxing has
been pulled out into its own small crate — each usable on its own for
something that has nothing to do with AI agents or security:

- `rune-namespaces` — the `bwrap` invocation: namespaces, a phase-ordered
  mount plan (so a mask can never be uncovered and the root tmpfs can never
  shadow `/proc`/`/dev`), environment scrubbing through the launcher's own
  environment rather than its command line, and the seccomp handoff.
- `rune-seccomp` — the Docker-derived syscall deny list and its BPF
  compilation (including the x32-ABI guard on `x86_64`).
- `rune-landlock` — the Landlock ruleset the in-sandbox stub enforces.
- `rune-egress-proxy` — the host-side allowlisting `CONNECT` proxy behind
  `network.allowed_domains`/`allowed_ips`: host patterns, CIDR ranges, the
  SSRF guard and DNS pinning.
- [`rune-elf-deps`](https://crates.io/crates/rune-elf-deps) (built on
  [`rune-elf`](https://crates.io/crates/rune-elf)) — transitive
  shared-library dependency closure resolution, backing the exact-file
  binds `commands.allow` needs.
- [`rune-rlimits`](https://crates.io/crates/rune-rlimits) — POSIX
  resource limits on a `std::process::Command`, backing `[limits]`.
- [`rune-strace`](https://crates.io/crates/rune-strace) — `strace -f`
  output-line parsing, backing `audit.enabled`'s violation summaries.
- [`rune-relay`](https://crates.io/crates/rune-relay) — bidirectional
  stream relaying, backing the in-sandbox TCP↔Unix-socket bridge to the
  egress proxy.

What's left in this crate is the policy layer: the TOML policy language,
the presets, and the decisions that map them onto the mechanisms above
(which paths get which Landlock rights, which syscalls are denied, which
errno counts as "blocked," ...), plus the stub protocol that carries
Landlock and the relay into the sandbox.

Moving the mechanisms out changed a few behaviours on purpose: the sandbox
environment no longer appears on `bwrap`'s command line; a
`filesystem.deny` directory is masked read-only; the seccomp descriptor is
inherited by `bwrap` alone; a Landlock grant for a path missing inside the
sandbox is skipped instead of disabling Landlock for the run; x32 system
calls are denied on `x86_64`; malformed `network.allowed_domains` entries
are rejected by `Policy::validate`; and `build_bwrap_args` returns a
`Result` and `compiled_seccomp_program` a `rune_seccomp::Program`.

## Verified against a real agent, not just unit tests

[`presets::claude_code`](src/presets.rs) builds a working policy for the
native Claude Code CLI, and it earned that by being run for real — repeatedly,
with fresh cold-start home directories, end to end through `build_command`
and real `bwrap` — not by guessing from documentation. That process
surfaced (and fixed) three real bugs along the way, in decreasing order of
how much they'll bite anyone else using this crate:

1. **A mount-ordering bug in `build_bwrap_args` itself.** `--proc`/`--dev`
   were emitted *before* `--tmpfs /`. bwrap applies mount operations in
   argument order, so the later root tmpfs silently shadowed both —
   handing the sandboxed process a `/dev` with no `/dev/urandom` and an
   empty `/proc`. Real-world impact: Bun (Claude Code's runtime) reads
   `/dev/urandom` during startup and calls `abort()` rather than falling
   back to `getrandom()` when it's missing — a full, reproducible crash,
   for every policy built with this crate before the fix, regardless of
   what the policy itself said. Fixed; regression-tested.
2. **`env.allow = ["HOME"]` passes through the calling process's own
   `$HOME`**, not whatever path a policy actually bound state under. Easy
   to not notice when your ambient `$HOME` happens to match, and a
   straightforward source of "why can't it find its config" bugs
   otherwise. `presets::claude_code` pins `HOME` via `env.set` instead.
3. **`build_command` defaulted `--chdir` to the calling process's own
   `cwd`.** Fine for a shell wrapper run from the right directory,
   surprising as a library default. `SandboxSection.cwd` now lets you set
   it explicitly, and the preset does.

None of this showed up in unit tests, because unit tests don't run bwrap.
If you're hand-writing a policy for a different tool, expect to need the
same process: `strace -f -e trace=openat,connect,execve` a real,
successful run of it, and check `policy.warnings()` plus `Policy::validate`
before trusting a policy that merely *looks* right.

## Whitelist, not blacklist

Every axis is default-deny. An empty policy is the strictest possible
sandbox: no filesystem paths, no network, no environment variables, no
executable commands, and a hardened syscall filter. Nothing is reachable
unless a rule names it — including individual commands, which are
bind-mounted in one at a time rather than being carved out of an
otherwise-open `/usr/bin`. [`Policy::validate`](src/policy.rs) hard-refuses
policies that look strict but silently aren't (binding a whole executable
directory alongside `commands.allow`, binding `/`, ...).

`sandbox.network` itself stays binary (`none`/`full`, both real kernel
guarantees) — but `[network]` layers domain- and IP/CIDR-level egress
filtering on top without needing a privileged veth+firewall setup or a
forced-proxy convention the sandboxed process could just ignore. See
[Domain/IP network egress](#domainip-network-egress) below for the
mechanism and its one honest limitation (raw, proxy-unaware TCP/UDP has
no path out regardless of the allowlist).

## Domain/IP network egress

`network.allowed_domains` (exact hostnames or `*.`-prefixed wildcards) and
`network.allowed_ips` (bare addresses or CIDR ranges, IPv4 or IPv6) are
both opt-in and additive — either one non-empty forces full
`--unshare-net` isolation regardless of `sandbox.network`, and the *only*
path out is a host-side CONNECT-only proxy reachable exclusively via a
bind-mounted Unix domain socket. A process that ignores
`HTTP_PROXY`/`HTTPS_PROXY` gets no network at all, not silently
unfiltered access — see [`network_proxy.rs`](src/network_proxy.rs)'s
module docs for the full mechanism.

A bare-IP `CONNECT` target is only ever reachable via `allowed_ips` — a
literal never goes through domain allowlisting, so there's no "it's
public, so allow it" fallback for one. A hostname allowed via
`allowed_domains` is resolved once, and refused if every resulting
address falls in a private/loopback/link-local/reserved range (the same
default-block list close competitors in this space — `agentjail`,
`jailoc` — ship) unless `allowed_ips` separately covers it. This is the
standard defense against a DNS-rebinding attack using an allowed domain
to reach an internal service or a cloud metadata endpoint
(`169.254.169.254`) that was never meant to be reachable; `allowed_ips`
is the explicit override for a domain that legitimately needs to resolve
there (an internal registry, a private CI runner, ...).

The honest limit either way: this is an HTTP CONNECT tunnel, not a
transparent firewall, so it only covers TCP traffic a client actually
routes through an HTTP-style proxy. A program speaking raw, proxy-unaware
TCP/UDP has no path out at all, allowed domain/IP or not.

## Installation

```toml
[dependencies]
rune-secops-warden = "0.2"
```

## Usage

```rust,no_run
use rune_secops_warden::{build_command, preflight, Policy};
use std::path::Path;

preflight().unwrap(); // once, e.g. at startup — see below

let policy = Policy::load(Path::new("warden.toml")).unwrap();
for warning in policy.warnings() {
    eprintln!("warning: {warning}");
}

let mut command = build_command(&policy, "claude", &[]).unwrap();
let status = command.status().unwrap();
std::process::exit(status.code().unwrap_or(1));
```

`preflight()` actually attempts to construct a namespace, rather than just
checking that `bwrap` runs — on hosts where unprivileged user namespaces
are disabled (a common hardening setting, e.g. Debian/Ubuntu's
`kernel.unprivileged_userns_clone` sysctl), `bwrap --version` still
succeeds but every real sandbox invocation fails; `preflight()` catches
that upfront with an actionable error instead of a cryptic one later.

To sandbox Claude Code specifically, start from the verified preset
instead of writing a policy by hand:

```rust,no_run
use rune_secops_warden::presets::{ClaudeCodeOptions, claude_code};
use rune_secops_warden::build_command;
use std::path::PathBuf;

let claude_binary = PathBuf::from("/home/user/.local/share/claude/versions/2.1.233");
let policy = claude_code(&ClaudeCodeOptions {
    claude_binary: claude_binary.clone(),
    home: PathBuf::from("/home/user"),
    project_dirs: vec![PathBuf::from("/home/user/project")],
    ..Default::default()
});
let mut command = build_command(&policy, claude_binary.to_str().unwrap(), &["-p".into(), "hi".into()]).unwrap();
let status = command.status().unwrap();
```

## Policy file

```toml
[sandbox]
network = "none"          # "none" | "full"
die_with_parent = true
new_session = true        # block TIOCSTI terminal injection
unshare_pid = true
unshare_ipc = true
unshare_uts = true
hostname = "sandbox"      # optional; implies unshare_uts

[network]
# Opt-in — see "Domain/IP network egress" below. Either field non-empty
# forces full network-namespace isolation regardless of sandbox.network
# above; the only path out is a filtering proxy.
allowed_domains = ["api.anthropic.com", "*.anthropic.com"]
allowed_ips = ["10.0.0.0/24"]   # bare IPs or CIDR ranges, IPv4 or IPv6

[filesystem]
# A bare string binds the path with no special handling; use a table
# ({ path = "...", create = "directory", ... }) when you need mount_as,
# create/create_content, or acknowledge_executable_content.
read_write = ["/home/user/project"]
deny = ["/home/user/project/.env"]

[env]
# Don't put PATH or HOME here — see the caveat below.
allow = ["USER", "LANG", "LC_ALL", "TERM"]

[env.set]
PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
HOME = "/home/user/project"
CI = "true"

[commands]
# Bare names are resolved against PATH; entries may also pin an exact path.
allow = ["cat", "ls", "git", "node"]

[seccomp]
# Hardened default-deny syscall filter (ptrace, mount, kernel module
# loading, kernel keyring, io_uring, ...), adapted from Docker's default
# seccomp profile. On by default; remove specific entries if a wrapped
# tool genuinely needs one.
enabled = true
allow = []

[limits]
# Opt-in only (see LimitsSection docs for why) — all unset here means no
# caps beyond disable_core_dumps, which is on by default.
max_processes = 512
memory_mb = 4096
disable_core_dumps = true
```

**Caveat:** don't defeat the command whitelist by bind-mounting a whole
directory that contains executable files (`/usr/bin`, `/bin`, `/usr/lib`,
`/lib`, ...) via `filesystem.read_only`/`read_write` — that grants
execution of everything in it regardless of `commands.allow` (confirmed
directly: `bash -c '/usr/lib/openssh/ssh-keysign'` ran under a policy
that never allowed it, purely because `/usr/lib` was bound for dynamic
linking). You shouldn't need to bind library directories at all:
`build_command` resolves the exact shared-library files each allowed
binary needs and binds those individually, automatically — see
[`resolve_library_closure`](src/deps.rs). `Policy::validate()` — which
`build_command` calls automatically — refuses any `filesystem` entry
that still contains executable files while `commands.allow` is set,
unless that specific entry sets `acknowledge_executable_content = true`.

Same reasoning for `env`: don't put `PATH` or `HOME` in `env.allow` — that
passes through *this process's* own ambient values, not something scoped
to the sandbox. For `PATH` specifically it's a real privilege escalation:
a dev shell's `$PATH` often has writable, project-local directories ahead
of `/usr/bin` (`node_modules/.bin`, a venv, direnv shims), and a sandboxed
process can shadow an allowed command's bare name with its own script
placed there. Pin both explicitly via `env.set` instead, as in the
example above.

Requires the `bwrap` (bubblewrap) binary on `PATH` — e.g. `apt install
bubblewrap`. Linux only.

## Safety

The workspace denies `unsafe` code. This crate allows it in one module
only, with a `reason` on the `#[allow]` and a `SAFETY` comment on every
`unsafe` block:

- `landlock_layer`: Landlock enforcement forks a probe child
  (`fork`, `waitpid`, `_exit`) and scrubs the environment before any
  thread exists. Both need libc FFI.

Everything else, including policy parsing and the network proxy, is safe
Rust.

## License

MIT
