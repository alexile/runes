# rune-seccomp

> seccomp-bpf system call filtering: deny-by-default allowlists and denylists with errno, trap, log and kill actions, kernel detection and best-effort fallback

[![crates.io](https://img.shields.io/crates/v/rune-seccomp)](https://crates.io/crates/rune-seccomp)
[![docs.rs](https://img.shields.io/docsrs/rune-seccomp)](https://docs.rs/rune-seccomp)
[![license](https://img.shields.io/crates/l/rune-seccomp)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

[seccomp](https://docs.kernel.org/userspace-api/seccomp_filter.html) lets
a Linux process restrict which system calls it, and everything it goes on
to execute, may make. `rune-seccomp` turns a list of system calls into a
seccomp-bpf filter and installs it:

- **Allowlist builder**: deny by default and allow the listed calls, or
  deny only the listed ones (`syscalls::DANGEROUS` is a starting list
  adapted from Docker's default profile). Calls are named or numbered.
- **Actions**: fail with an errno, `trap` (`SIGSYS`), `log` (allow and
  audit, to find out what an allowlist misses), or kill the thread or
  process.
- **Architecture handling**: names resolve for `x86_64`, `aarch64` or
  `riscv64`. Calls through another ABI (32-bit compat) kill the process,
  and x32 calls on `x86_64` get the deny action, so they cannot bypass a
  denylist.
- **Detection and graceful degrade**: `detect()` reads `/proc` to report
  whether seccomp is available and which actions the kernel accepts. On
  kernels before 4.14, `log` falls back to `allow` and `kill_process` to
  `kill_thread`; a kernel without seccomp installs nothing. The `Report`
  says what happened. `Compatibility::HardRequirement` refuses instead.
- **Check without installing**: `compile` builds the BPF program without
  touching the kernel, `Program::evaluate` runs it in memory, and
  `Program::to_bytes` hands it to `bwrap --seccomp`.

## Installation

```toml
[dependencies]
rune-seccomp = "0.1"
```

The `rune-seccomp` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-seccomp --features cli
```

## Usage

### Library

```rust,no_run
use rune_seccomp::{Action, Options, Status, install, syscalls};
use std::os::unix::process::CommandExt;

let report = install(
    &Options::denylist(Action::EPERM)
        .with_syscalls(syscalls::DANGEROUS.iter().copied()),
)?;
if report.status != Status::FullyEnforced {
    eprintln!("seccomp {:?}: {}", report.status, report.support);
}
// The filter survives exec: the program inherits it.
let err = std::process::Command::new("/usr/bin/make").exec();
# Ok::<(), rune_seccomp::Error>(())
```

A filter can be checked in memory before it is installed:

```rust
use rune_seccomp::{Action, Options, compile, syscalls};

let program = compile(
    &Options::allowlist(Action::EPERM).with_syscalls(["read", "write", "exit_group"]),
)?;
let read = syscalls::resolve("read").unwrap_or_default();
let openat = syscalls::resolve("openat").unwrap_or_default();
assert_eq!(program.evaluate(read), Some(Action::Allow));
assert_eq!(program.evaluate(openat), Some(Action::EPERM));
# Ok::<(), rune_seccomp::Error>(())
```

Install the filter after any setup that needs wider access: an allowlist
only has to cover what the program does next. Installing also sets
`no_new_privs`, so setuid programs run afterwards gain no privileges.

### CLI

```bash
rune-seccomp --detect
# seccomp: available (actions: kill_process kill_thread trap errno log allow)

rune-seccomp --deny-dangerous -- make test
rune-seccomp --deny mount --deny ptrace --action trap -- ./tool

# Audit mode: log every call an allowlist would deny, without denying it.
rune-seccomp --action log --allow read --allow write --verbose -- ./tool

# Compile a filter for bwrap.
rune-seccomp --deny-dangerous --emit filter.bpf
bwrap --seccomp 3 3<filter.bpf ... -- ./tool
```

Exit status: the program's own, 125 if the filter cannot be set up, 126 if
the program cannot be executed (including when the filter denies it), 127
if it does not exist.

## Safety

The crate itself contains no `unsafe` code (`#![forbid(unsafe_code)]`).
`prctl(PR_SET_NO_NEW_PRIVS)` and `seccomp(SECCOMP_SET_MODE_FILTER)` have no
safe wrapper in `std`, so they are made through
[`seccompiler`](https://crates.io/crates/seccompiler), the filter compiler
maintained by the Firecracker project. That FFI is confined to the
dependency, which passes the program by reference and checks every return
value. Detection only reads `/proc`.

The filter is deliberately not offered as a `pre_exec` hook: compiling it
allocates, which is not async-signal-safe between `fork` and `exec`.
Install it in the launcher itself and then `exec` the program, as the CLI
does, or pass the compiled program to `bwrap --seccomp`.

## License

MIT
