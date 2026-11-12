//! The crate's only `unsafe` code: thin wrappers over `ptrace(2)` and
//! `waitpid(2)`, plus the `pre_exec` hook that makes the child a tracee.
//!
//! Every wrapper passes the kernel either plain integers or a pointer to a
//! local that outlives the call, and turns a `-1` return into
//! [`std::io::Error::last_os_error`].

use std::os::unix::process::CommandExt;
use std::process::Command;

/// The type of `ptrace`'s request argument: `c_uint` in glibc, `c_int`
/// elsewhere.
#[cfg(target_env = "gnu")]
type Request = libc::c_uint;
/// The type of `ptrace`'s request argument: `c_uint` in glibc, `c_int`
/// elsewhere.
#[cfg(not(target_env = "gnu"))]
type Request = libc::c_int;

/// `PTRACE_GET_SYSCALL_INFO` (Linux 5.3). Not in every libc flavour the
/// `libc` crate binds, so spelled out here.
const PTRACE_GET_SYSCALL_INFO: Request = 0x420e;
/// `ptrace_syscall_info.op` for a system-call-entry stop.
pub const SYSCALL_INFO_ENTRY: u8 = 1;
/// `ptrace_syscall_info.op` for a seccomp stop (`SECCOMP_RET_TRACE`).
pub const SYSCALL_INFO_SECCOMP: u8 = 3;

/// The kernel's `struct ptrace_syscall_info` (`linux/ptrace.h`), with the
/// union flattened: `nr` sits at the same offset for the `entry` and
/// `seccomp` variants, which are the only ones read.
#[repr(C)]
#[derive(Debug, Default)]
struct SyscallInfo {
    op: u8,
    pad: [u8; 3],
    arch: u32,
    instruction_pointer: u64,
    stack_pointer: u64,
    nr: u64,
    /// The rest of the union: six arguments, then `ret_data` (padded).
    rest: [u64; 7],
}

fn check(ret: libc::c_long) -> std::io::Result<libc::c_long> {
    if ret == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

/// An integer passed in one of `ptrace`'s pointer-sized arguments.
fn int_arg(value: impl TryInto<usize>) -> *mut libc::c_void {
    std::ptr::without_provenance_mut(value.try_into().unwrap_or(0))
}

/// `ptrace(request, pid, addr, data)`.
#[allow(
    unsafe_code,
    reason = "`ptrace` is a variadic FFI call; callers pass integers or pointers to live locals"
)]
unsafe fn ptrace(
    request: Request,
    pid: libc::pid_t,
    addr: *mut libc::c_void,
    data: *mut libc::c_void,
) -> std::io::Result<libc::c_long> {
    // SAFETY: forwarded from the caller, who guarantees `addr` and `data`
    // are valid for `request`.
    check(unsafe { libc::ptrace(request, pid, addr, data) })
}

/// Makes the child a tracee before it execs: `PTRACE_TRACEME`, after which
/// the kernel stops it with `SIGTRAP` once `execve` succeeds, before the
/// new program runs a single instruction.
#[allow(
    unsafe_code,
    reason = "`CommandExt::pre_exec` is unsafe; the hook makes one async-signal-safe system call"
)]
pub fn trace_me_on_exec(command: &mut Command) {
    // SAFETY: the hook only calls `ptrace(PTRACE_TRACEME)`, a raw system
    // call that is async-signal-safe, touches no Rust-managed state and
    // allocates nothing — sound between `fork` and `exec`.
    unsafe {
        command.pre_exec(|| {
            ptrace(
                libc::PTRACE_TRACEME,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
            .map(drop)
        });
    }
}

/// `PTRACE_SETOPTIONS`.
#[allow(unsafe_code, reason = "ptrace FFI call with integer arguments only")]
pub fn set_options(pid: libc::pid_t, options: libc::c_int) -> std::io::Result<()> {
    // SAFETY: `data` carries the option bits as an integer; no pointer is
    // dereferenced.
    unsafe {
        ptrace(
            libc::PTRACE_SETOPTIONS,
            pid,
            std::ptr::null_mut(),
            int_arg(options),
        )
    }
    .map(drop)
}

/// `PTRACE_SYSCALL`: resumes a stopped tracee until its next system-call
/// boundary, delivering `signal` (0 for none).
#[allow(unsafe_code, reason = "ptrace FFI call with integer arguments only")]
pub fn resume(pid: libc::pid_t, signal: libc::c_int) -> std::io::Result<()> {
    // SAFETY: `data` carries the signal number as an integer.
    unsafe {
        ptrace(
            libc::PTRACE_SYSCALL,
            pid,
            std::ptr::null_mut(),
            int_arg(signal),
        )
    }
    .map(drop)
}

/// `PTRACE_GETEVENTMSG`: the new process's pid at a fork/vfork/clone
/// event stop.
#[allow(unsafe_code, reason = "ptrace FFI call writing to a local")]
pub fn event_message(pid: libc::pid_t) -> std::io::Result<libc::c_ulong> {
    let mut message: libc::c_ulong = 0;
    // SAFETY: `data` points at `message`, a live `unsigned long`, which is
    // what this request writes.
    unsafe {
        ptrace(
            libc::PTRACE_GETEVENTMSG,
            pid,
            std::ptr::null_mut(),
            (&raw mut message).cast(),
        )
    }?;
    Ok(message)
}

/// `PTRACE_GET_SYSCALL_INFO` at a system-call stop: `(op, audit arch,
/// number)`. The number is meaningful for entry and seccomp stops only.
#[allow(unsafe_code, reason = "ptrace FFI call writing to a local")]
pub fn syscall_info(pid: libc::pid_t) -> std::io::Result<(u8, u32, u64)> {
    let mut info = SyscallInfo::default();
    // SAFETY: `addr` is the buffer size and `data` points at `info`, a
    // live buffer of exactly that size; the kernel writes at most that
    // many bytes.
    unsafe {
        ptrace(
            PTRACE_GET_SYSCALL_INFO,
            pid,
            int_arg(std::mem::size_of::<SyscallInfo>()),
            (&raw mut info).cast(),
        )
    }?;
    Ok((info.op, info.arch, info.nr))
}

/// `waitpid(-1, …, __WALL | __WNOTHREAD)`: the next state change of a
/// child or tracee *of the calling thread*, never of another thread's
/// children. Retries on `EINTR`.
#[allow(unsafe_code, reason = "waitpid FFI call writing to a local")]
pub fn wait_any() -> std::io::Result<(libc::pid_t, libc::c_int)> {
    loop {
        let mut status: libc::c_int = 0;
        // SAFETY: `status` is a live `int` for the call's duration.
        let pid = unsafe { libc::waitpid(-1, &raw mut status, libc::__WALL | libc::__WNOTHREAD) };
        if pid >= 0 {
            return Ok((pid, status));
        }
        let err = std::io::Error::last_os_error();
        if err.kind() != std::io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

/// `kill(pid, SIGKILL)`, ignoring failure (the process may be gone).
#[allow(unsafe_code, reason = "kill FFI call with integer arguments only")]
pub fn kill(pid: libc::pid_t) {
    // SAFETY: kill takes two integers.
    unsafe { libc::kill(pid, libc::SIGKILL) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syscall_info_matches_the_kernel_layout() {
        // 24-byte header, then the largest union member (seccomp: nr,
        // six args, ret_data) padded to 64 bytes.
        assert_eq!(std::mem::size_of::<SyscallInfo>(), 88);
        assert_eq!(std::mem::offset_of!(SyscallInfo, arch), 4);
        assert_eq!(std::mem::offset_of!(SyscallInfo, nr), 24);
    }
}
