# rune-pledge

> pledge-style capability reduction: map a simple promise profile to Landlock and seccomp on Linux, with a documented best-effort no-op elsewhere

[![crates.io](https://img.shields.io/crates/v/rune-pledge)](https://crates.io/crates/rune-pledge)
[![docs.rs](https://img.shields.io/docsrs/rune-pledge)](https://docs.rs/rune-pledge)
[![license](https://img.shields.io/crates/l/rune-pledge)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

[OpenBSD's `pledge(2)`](https://man.openbsd.org/pledge.2) lets a program
give up every capability it does not name, and
[`unveil(2)`](https://man.openbsd.org/unveil.2) hides every path it does
not list. `rune-pledge` offers the same shape portably: describe what the
process keeps as a `Profile` of promises and path rules, and
`reduce_capabilities` applies the strongest primitives the platform has.

| Platform | Filesystem layer                                    | System call layer                                 |
| -------- | --------------------------------------------------- | ------------------------------------------------- |
| Linux    | Landlock ([`rune-landlock`](../rune-landlock))      | seccomp-bpf ([`rune-seccomp`](../rune-seccomp))   |
| other    | none: a documented no-op with a warning             | none                                              |

- **Promises**: `stdio`, `rpath`, `wpath`, `cpath`, `dpath`, `fattr`,
  `exec`, `proc`, `id`, `inet` and `unix`, parsed from a pledge string
  such as `"stdio rpath inet"`. Each opens a group of system calls in a
  deny-by-default seccomp allowlist and, for the filesystem promises, a
  group of Landlock rights. `exit` and `exit_group` are always allowed.
- **Path rules**: `unveil`-style `r`, `w`, `x` and `c` permissions per
  path. A path gets the rights both its permissions and the promises
  allow; without a path rule the promises apply to the whole filesystem,
  as `pledge` without `unveil` does. Missing paths are skipped.
- **Violations**: a denied call fails with `EPERM` (default), kills the
  process with `SIGSYS` as on OpenBSD, or is only logged to the audit
  log, to find what a profile is missing.
- **Best effort, honestly reported**: older kernels degrade gracefully
  (an older Landlock ABI, a missing seccomp action), and the `Report`
  lists a `Warning` for everything not in force. `Enforcement::Required`
  fails up front, before restricting anything, when a layer is missing.
  With the `tracing` feature, warnings are also emitted as `tracing`
  events.
- **Inspectable**: `Profile::syscalls`, `Profile::landlock_options` and
  `Profile::seccomp_options` show exactly what will be applied, without
  touching the kernel.

Seccomp cannot inspect pointer arguments, so the promises are coarser than
OpenBSD's: `rpath` and `wpath` both allow `openat` (Landlock then tells
reads from writes apart per path), `inet` and `unix` both allow `socket`,
and `stdio` allows `clone` for threads, which also permits a raw `fork`.
`clone` is only allowed without `CLONE_NEW*` flags, so it cannot create
namespaces as `unshare` would, and `clone3` fails with `ENOSYS` (its flags
live in memory seccomp cannot read); libc then falls back to `clone`, as
under Docker's default profile.
Landlock does not cover `chmod`/`chown`, so `fattr` is enforced by
seccomp alone.

## Installation

```toml
[dependencies]
rune-pledge = "0.1"
```

The `rune-pledge` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-pledge --features cli
```

## Usage

### Library

```rust,no_run
use rune_pledge::{Permissions, Profile, Status, reduce_capabilities};

// Setup that needs wider access happens first.
let config = std::fs::read_to_string("/etc/myapp.toml")?;

let report = reduce_capabilities(
    &Profile::pledge("stdio rpath wpath cpath")?
        .with_path("/var/lib/myapp", Permissions::READ_WRITE_CREATE),
)?;
if report.status != Status::FullyEnforced {
    for warning in &report.warnings {
        eprintln!("pledge: {warning}");
    }
}
// Only /var/lib/myapp is reachable now; exec, sockets and fork are gone.
# Ok::<(), Box<dyn std::error::Error>>(())
```

What a profile maps to can be checked without applying it:

```rust
use rune_pledge::Profile;

let profile = Profile::pledge("stdio rpath")?;
assert!(profile.syscalls().contains("openat"));
assert!(!profile.syscalls().contains("execve"));
# Ok::<(), rune_pledge::Error>(())
```

The reduction is permanent: it lasts for the rest of the thread's life
(the process's, with `Profile::all_threads`), survives `execve` and is
inherited by children. A later call can only narrow it. Only the calling
thread is restricted by default, so threads that already exist keep their
capabilities.

### CLI

```bash
# Print what a profile maps to.
rune-pledge --print 'stdio inet'

# Run a program with only read access to a few paths.
rune-pledge -v -p rx:/usr -p rx:/lib -p rx:/lib64 -p r:/etc 'stdio rpath' -- cat /etc/hostname
# rune-pledge: partially enforced
# rune-pledge: filesystem restriction partially enforced: the kernel's Landlock ABI v8 leaves unrestricted: resolve_unix
# myhost

# Kill the program on the first call it did not promise.
rune-pledge --violation kill 'stdio rpath' -- ./tool
```

The `exec` promise is always added, since the program itself has to be
executed, and the filter carries over into it: give it what its dynamic
loader needs (`rpath` and `rx` on the library directories). Exit status:
the program's own, 125 if the profile is invalid or cannot be applied, 126
if the program cannot be executed and 127 if it does not exist.

## License

MIT
