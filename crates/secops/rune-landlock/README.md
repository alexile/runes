# rune-landlock

> Landlock LSM filesystem sandboxing: path allowlist rulesets with ABI detection and best-effort fallback on older kernels

[![crates.io](https://img.shields.io/crates/v/rune-landlock)](https://crates.io/crates/rune-landlock)
[![docs.rs](https://img.shields.io/docsrs/rune-landlock)](https://docs.rs/rune-landlock)
[![license](https://img.shields.io/crates/l/rune-landlock)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

[Landlock](https://docs.kernel.org/userspace-api/landlock.html) lets an
unprivileged Linux process restrict its own filesystem access, and that of
everything it goes on to execute. `rune-landlock` turns a path allowlist
into a Landlock ruleset and enforces it:

- **Allowlist builder**: grant read, read+exec, exec or read-write on files
  and directory hierarchies, or any custom `RightSet`.
- **ABI detection**: `detect()` reports which Landlock ABI (v1 to v9) the
  kernel supports, or that Landlock is missing or disabled.
- **Graceful degrade**: by default, a kernel older than the requested ABI
  enforces what it can, and the `Report` lists the rights left
  unrestricted. `Compatibility::HardRequirement` refuses to run instead.
- **Enforce on self**: `restrict_self` restricts the calling thread (or all
  threads, on ABI v8) and everything it execs. Missing paths are skipped
  and reported, which only ever grants less.

Everything not granted is denied, for every right the requested ABI
handles. Rules are additive: a narrower rule cannot take back what a
broader one grants.

## Installation

```toml
[dependencies]
rune-landlock = "0.1"
```

The `rune-landlock` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-landlock --features cli
```

## Usage

### Library

```rust,no_run
use rune_landlock::{Options, Status, restrict_self};
use std::os::unix::process::CommandExt;

let report = restrict_self(
    &Options::default()
        .with_read_exec("/usr")
        .with_read_exec("/lib64")
        .with_read("/etc")
        .with_read_write("/tmp/work"),
)?;
if report.status != Status::FullyEnforced {
    eprintln!("landlock {:?}; unenforced: {}", report.status, report.unenforced);
}
// The restriction survives exec: the program inherits it.
let err = std::process::Command::new("/usr/bin/make").exec();
# Ok::<(), rune_landlock::Error>(())
```

What an older kernel would leave unrestricted can be worked out without
touching the kernel:

```rust
use rune_landlock::{Abi, Right, Support};

let linux_5_19 = Support::Available { abi: Abi::V2, kernel_abi: None };
let lost = linux_5_19.unenforced_rights(Abi::V5);
assert!(lost.contains(Right::Truncate) && lost.contains(Right::IoctlDev));
```

Apply the restriction after any setup that needs wider access. A process
inside a Landlock domain cannot `mount()`, so with a namespace sandbox such
as `bwrap`, restrict a stub that bwrap execs, not bwrap itself.

### CLI

```bash
rune-landlock --detect
# landlock: available (ABI v8)

rune-landlock --read-exec /usr --read-exec /lib64 --read /etc --read-write . -- make test

# Require ABI v9 (Linux 7.1) rather than degrade; report what is enforced.
rune-landlock --abi 9 --strict --verbose --read-exec /usr -- /usr/bin/ls /
```

Exit status: the program's own, 125 if the sandbox cannot be set up, 126 if
the program cannot be executed (including when the allowlist denies it),
127 if it does not exist.

## Safety

The crate itself contains no `unsafe` code (`#![forbid(unsafe_code)]`). The
Landlock system calls (`landlock_create_ruleset`, `landlock_add_rule`,
`landlock_restrict_self`) and `prctl(PR_SET_NO_NEW_PRIVS)` have no safe
wrapper in `std`, so they are made through the
[`landlock`](https://crates.io/crates/landlock) crate, maintained by the
Landlock kernel developers. That FFI is confined to the dependency, which
keeps its file descriptors owned and checks every return value.

The restriction is deliberately not offered as a `pre_exec` hook: building
a ruleset allocates, which is not async-signal-safe between `fork` and
`exec`. Restrict the launcher itself and then `exec` the program, as the
CLI does.

## License

MIT
