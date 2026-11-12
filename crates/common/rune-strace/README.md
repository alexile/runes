# rune-strace

> Syscall tracing for seccomp profiles: ptrace a child to collect the system calls it makes, and parse `strace -f` output.

[![crates.io](https://img.shields.io/crates/v/rune-strace)](https://crates.io/crates/rune-strace)
[![docs.rs](https://img.shields.io/docsrs/rune-strace)](https://docs.rs/rune-strace)
[![license](https://img.shields.io/crates/l/rune-strace)](LICENSE)

A seccomp allowlist starts from the system calls a program actually makes.
This crate collects them two ways:

- **`trace`** (Linux) runs a `std::process::Command` under `ptrace(2)`,
  following its forks and threads like `strace -f`, and returns a
  `Profile`: every call by architecture (`AUDIT_ARCH_*`) and number, with
  counts. `Profile::numbers` is the native allowlist, sorted. `probe`
  checks that tracing works on this host first.
- **`parse_line`**, **`call_name`** and **`count_calls`** read text that
  `strace -f` already printed (pid prefixes, column-aligned results,
  `<unfinished ...>`/`<... resumed>` halves), and `first_quoted_string`
  pulls a path or address out of the arguments. These are sans-I/O.

The crate does not decide what a call means or which calls to allow.

## Installation

```sh
cargo add rune-strace
```

## Usage

Trace a program and build an allowlist from what it did:

```rust,no_run
use std::process::{Command, Stdio};
use rune_strace::{Options, trace};

let mut command = Command::new("/usr/bin/ls");
command.arg("/").stdout(Stdio::null());
let report = trace(&mut command, &Options::default())?;
println!("exit {:?}, {} processes", report.exit, report.processes);

// Native system call numbers, ascending; with rune-seccomp:
//   Options::allowlist(Action::Errno(1)).with_syscalls(numbers)
// and rune_seccomp::syscalls::name_of(nr) for display.
let numbers: Vec<i64> = report.profile.numbers();
# Ok::<(), rune_strace::Error>(())
```

`report.profile.arches()` shows whether the program also made calls
through another convention (32-bit `int 0x80` on `x86_64`), which a filter
has to handle too. The profile includes the `execve` that started the
program, because a filter installed before `exec` must allow it.

Parse captured `strace` output:

```rust
use rune_strace::{count_calls, first_quoted_string, parse_line};

let line = r#"12345 openat(AT_FDCWD, "/etc/hosts", O_RDONLY) = 3"#;
let call = parse_line(line).unwrap();
assert_eq!(call.pid.as_deref(), Some("12345"));
assert_eq!(call.name, "openat");
assert_eq!(call.result, "3");
assert_eq!(first_quoted_string(&call.args).as_deref(), Some("/etc/hosts"));

let counts = count_calls("7 read(3, <unfinished ...>\n7 <... read resumed>\"\", 1) = 0\n");
assert_eq!(counts.get("read"), Some(&1));
```

Run `cargo run -p rune-strace --example syscall_profile -- ls /` to print
a program's profile.

## Requirements and limits

- Linux 5.3 or newer (`PTRACE_GET_SYSCALL_INFO`, which reports the
  architecture and number the same way on every CPU).
- `ptrace` must be allowed: Yama `kernel.yama.ptrace_scope` 3 and many
  container seccomp profiles forbid it. `trace` then fails with
  `Error::Unavailable`, and the tests skip.
- Tracing runs on a dedicated thread that waits only for its own child
  and tracees, so other children of the process are never reaped. The
  child's handle is internal: send its output to files or `Stdio::null`.
- Signals pass through to the tracees; job-control stops (`SIGSTOP`,
  `SIGTSTP`) are not honoured while tracing.

## Safety

The workspace denies `unsafe` code. This crate allows it only in
`src/sys.rs`, item by item, each with a `reason` and a `SAFETY` comment on
every block:

- `ptrace(2)` is a variadic C function. Each wrapper passes either plain
  integers (pid, option bits, a signal number) or a pointer to a local
  that outlives the call and has the size the request writes
  (`PTRACE_GETEVENTMSG` writes an `unsigned long`, `PTRACE_GET_SYSCALL_INFO`
  at most the buffer size it is given; a test checks the struct layout).
- `waitpid` writes the status to a local `int`; `kill` takes integers.
- `CommandExt::pre_exec` is an `unsafe fn` because the hook runs in the
  forked child before `execve`, where only async-signal-safe calls are
  sound. The hook makes one raw system call, `ptrace(PTRACE_TRACEME)`, and
  neither allocates nor takes locks.

## License

MIT
