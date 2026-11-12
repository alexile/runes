# rune-namespaces

> Linux namespace process isolation: spawn children under bubblewrap or unshare(2) with an ordered mount plan and environment allowlist

[![crates.io](https://img.shields.io/crates/v/rune-namespaces)](https://crates.io/crates/rune-namespaces)
[![docs.rs](https://img.shields.io/docsrs/rune-namespaces)](https://docs.rs/rune-namespaces)
[![license](https://img.shields.io/crates/l/rune-namespaces)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

`rune-namespaces` runs a program in fresh Linux namespaces with only the
filesystem, network and environment you allow:

- **Namespaces**: user, mount, PID, network, IPC, UTS and cgroup, all on by
  default. A new network namespace has only a downed loopback: no network.
- **Mount plan**: an empty root with `/proc`, `/dev`, `/tmp` and `/run`,
  plus read-only or read-write binds, tmpfs directories, symlinks, device
  binds and masks over secrets. Mounts are applied by phase (root, system,
  binds, masks), so a plan can never shadow its own `/proc` and `/dev` or
  let a bind uncover a masked path. `MountPlan::lookup` answers what any
  path resolves to without spawning anything.
- **Environment allowlist**: the child starts empty; allow names or
  `PREFIX*` patterns through, or set values. The environment is handed to
  the launcher's own environment, never its command line, so passed-through
  secrets do not show up in `ps`.
- **Two backends**: [bubblewrap](https://github.com/containers/bubblewrap)
  (the default, every feature), or `unshare(2)` in the child just before
  `exec`, with no helper binary, for a program that keeps the host
  filesystem.
- **Layering**: a compiled seccomp-bpf program (for example from
  `rune-seccomp`) is installed on the sandboxed program, and a `wrapper`
  such as `rune-landlock` runs inside the sandbox in front of it. A
  host-side `launcher` (such as `strace -f`) can run in front of `bwrap`.
- **Probe**: `probe` checks that a backend actually works here, since
  unprivileged user namespaces are often restricted.

## Installation

```toml
[dependencies]
rune-namespaces = "0.1"
```

The `rune-namespaces` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-namespaces --features cli
```

## Usage

### Library

```rust,no_run
use rune_namespaces::{EnvPolicy, MaskKind, MountPlan, Options, probe, Backend};

probe(&Backend::Bwrap)?;
let options = Options::default()
    .with_mounts(
        MountPlan::isolated()
            .with_system_read_only()
            .with_read_write("/home/me/project")
            .with_mask("/home/me/project/.env", MaskKind::File),
    )
    .with_env(EnvPolicy::default().with_common().with_set("CI", "1"))
    .with_cwd("/home/me/project")
    // Landlock cannot restrict bwrap itself (it would block mount()), so it
    // runs inside the sandbox in front of the program.
    .with_wrapper(["/usr/bin/rune-landlock", "--read-exec", "/usr", "--read-write", ".", "--"]);
let status = options.command("make", &["test"])?.status()?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

The plan is a plain value you can inspect and test:

```rust
use rune_namespaces::{Access, Exposure, MountPlan};

let plan = MountPlan::isolated().with_bind("/home/me/project", "/work", Access::ReadWrite, false);
assert_eq!(
    plan.lookup("/work/src/main.rs"),
    Exposure::Host { source: "/home/me/project/src/main.rs".into(), access: Access::ReadWrite },
);
assert!(!plan.lookup("/home/me/.ssh/id_ed25519").is_host());
```

### CLI

```bash
rune-namespaces --probe
# namespaces: available

rune-namespaces --system --rw "$PWD" --mask "$PWD/.env" --chdir "$PWD" \
    --env PATH --setenv HOME=/tmp -- make test

# Network, IPC, UTS and user isolation only, keeping the host filesystem.
rune-namespaces --backend unshare -- ./fetch-nothing.sh

# Show the bwrap invocation without running it.
rune-namespaces --system --ro /data --print-args -- ls /data
```

Exit status: the program's own, 125 if the sandbox cannot be set up, 126 if
the program (or `bwrap`) cannot be executed, 127 if it does not exist.

## Requirements

Both backends rely on unprivileged user namespaces. Debian's
`kernel.unprivileged_userns_clone=0` and Ubuntu's
`kernel.apparmor_restrict_unprivileged_userns=1` restrict them; Ubuntu
ships an AppArmor profile that still lets `/usr/bin/bwrap` use them, so the
bwrap backend often works where `unshare` does not. `probe` tells you which.

## Safety

The crate needs `unsafe` for `pre_exec` hooks, which run in the child
between `fork` and `exec`; all of it lives in `src/sys.rs`, each item
allows `unsafe_code` with a reason and each block carries a `SAFETY`
comment:

- The `unshare` backend calls `setsid`, `prctl(PR_SET_PDEATHSIG)`,
  `unshare`, writes the `/proc/self/{setgroups,uid_map,gid_map}` files with
  raw `open`/`write`/`close`, calls `sethostname`, and installs a seccomp
  filter with `prctl`. Every buffer is prepared before the fork and only
  borrowed in the child; the hook makes async-signal-safe system calls
  only and never allocates.
- The bwrap backend hands the seccomp program over in a pipe; a hook
  clears `FD_CLOEXEC` on the read end in the child only, so the descriptor
  never leaks into processes other threads spawn.
- `getuid`/`getgid` are called through `libc` to build the ID maps.

## License

MIT
