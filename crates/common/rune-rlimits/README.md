# rune-rlimits

> Typed POSIX resource limits: read and set them for the current process, or apply them to a `std::process::Command` via `pre_exec`.

[![crates.io](https://img.shields.io/crates/v/rune-rlimits)](https://crates.io/crates/rune-rlimits)
[![docs.rs](https://img.shields.io/docsrs/rune-rlimits)](https://docs.rs/rune-rlimits)
[![license](https://img.shields.io/crates/l/rune-rlimits)](LICENSE)

Caps what a process may consume: memory, CPU time, processes, open files,
file size, core dumps and the rest of the `RLIMIT_*` family. Nothing here
is sandboxing-specific; a build system, a CI runner or a worker pool can
use it as well as a sandbox. Limits survive `execve`, so a limit set on a
launcher before it execs into another program stays in effect afterwards.

## Installation

```sh
cargo add rune-rlimits
```

## Usage

Build a `LimitSet` and attach it to a `Command`; the limits are set in the
child between `fork` and `exec`:

```rust
use rune_rlimits::{LimitSet, Resource, Rlimit};
use std::process::Command;

let limits = LimitSet::new()
    .with_address_space_bytes(512 * 1024 * 1024)
    .with_cpu_seconds(30)
    .with(Resource::NoFile, Rlimit::new(256, 1024)?)
    .without_core_dumps()
    // Ask for at most what this process may set without privilege.
    .clamped_to_current()?;

let mut command = Command::new("some-program");
limits.apply_to(&mut command);
let status = command.status()?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Read or change the calling process's own limits:

```rust
use rune_rlimits::{Resource, Rlimit, get, set};

let files = get(Resource::NoFile)?;
println!("open files: soft {} hard {}", files.soft(), files.hard());
set(Resource::Core, Rlimit::new(0, files.hard())?)?;
# Ok::<(), rune_rlimits::Error>(())
```

`parse_proc_limits` reads Linux's `/proc/<pid>/limits` table, which is how
the tests check what a child actually received. The flat `Limits` struct
(one optional field per common limit, sizes in MiB) and `apply` remain for
callers that load limits from a configuration file.

Run `cargo run -p rune-rlimits --example show_limits` to print the current
process's limits.

## Resources and units

| `Resource`     | Constant            | Unit                              |
|----------------|---------------------|-----------------------------------|
| `AddressSpace` | `RLIMIT_AS`         | bytes of virtual memory           |
| `Core`         | `RLIMIT_CORE`       | bytes (`0` disables core dumps)   |
| `Cpu`          | `RLIMIT_CPU`        | seconds of CPU time               |
| `Data`         | `RLIMIT_DATA`       | bytes                             |
| `FileSize`     | `RLIMIT_FSIZE`      | bytes per file                    |
| `NoFile`       | `RLIMIT_NOFILE`     | file descriptors                  |
| `NProc`        | `RLIMIT_NPROC`      | processes/threads of the real UID |
| `Rss`          | `RLIMIT_RSS`        | bytes (ignored by Linux)          |
| `Stack`        | `RLIMIT_STACK`      | bytes                             |
| `MemLock`      | `RLIMIT_MEMLOCK`    | bytes (Linux)                     |
| `Locks`        | `RLIMIT_LOCKS`      | file leases (Linux)               |
| `MsgQueue`     | `RLIMIT_MSGQUEUE`   | bytes (Linux)                     |
| `Nice`         | `RLIMIT_NICE`       | `20 - nice` ceiling (Linux)       |
| `RtPrio`       | `RLIMIT_RTPRIO`     | real-time priority (Linux)        |
| `RtTime`       | `RLIMIT_RTTIME`     | microseconds (Linux)              |
| `SigPending`   | `RLIMIT_SIGPENDING` | queued signals (Linux)            |

The kernel enforces the soft limit. An unprivileged process may lower
either limit and raise the soft one up to the hard one; raising a hard
limit needs `CAP_SYS_RESOURCE`, and a spawn asking for it fails with
`EPERM`. `LimitSet::clamped_to_current` lowers a request to fit.

## Safety

The workspace denies `unsafe` code. This crate allows it in one module,
`src/sys.rs`, on three items, each with a `reason` and a `SAFETY` comment
on every block:

- `get` and `set` call `getrlimit`/`setrlimit` with a pointer to a local
  `struct rlimit` that outlives the call.
- `pre_exec` installs the hook behind `LimitSet::apply_to`, because
  `std::os::unix::process::CommandExt::pre_exec` is an `unsafe fn`: the
  hook runs in the forked child before `execve`, where only
  async-signal-safe calls are sound. The resource/value pairs are built
  before the fork; the hook only reads them and calls `setrlimit`, which is
  async-signal-safe, and neither allocates nor takes locks.

## License

MIT
