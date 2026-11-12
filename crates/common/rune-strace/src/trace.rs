//! Tracing a child's system calls with `ptrace(2)`.

use std::collections::HashSet;
use std::process::Command;

use crate::profile::NATIVE_AUDIT_ARCH;
use crate::{Error, Profile, SyscallId, sys};

/// Options for [`trace`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Options {
    /// Also trace every process and thread the child creates (`fork`,
    /// `vfork`, `clone`), as `strace -f` does. On by default: a seccomp
    /// filter is inherited by children, so their calls belong in the
    /// profile too.
    pub follow_forks: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self { follow_forks: true }
    }
}

impl Options {
    /// Sets [`Options::follow_forks`].
    #[must_use]
    pub const fn with_follow_forks(mut self, follow: bool) -> Self {
        self.follow_forks = follow;
        self
    }

    const fn ptrace_options(&self) -> libc::c_int {
        let mut bits =
            libc::PTRACE_O_TRACESYSGOOD | libc::PTRACE_O_TRACEEXEC | libc::PTRACE_O_EXITKILL;
        if self.follow_forks {
            bits |=
                libc::PTRACE_O_TRACEFORK | libc::PTRACE_O_TRACEVFORK | libc::PTRACE_O_TRACECLONE;
        }
        bits
    }
}

/// How the traced child ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Exit {
    /// It exited with this status code.
    Code(i32),
    /// A signal with this number killed it.
    Signal(i32),
}

impl Exit {
    /// Whether it exited with code 0.
    #[must_use]
    pub const fn success(self) -> bool {
        matches!(self, Self::Code(0))
    }
}

/// What [`trace`] observed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Report {
    /// Every system call entered, by architecture and number, with counts.
    /// Includes the `execve` that started the program, which a filter
    /// installed before `exec` has to allow.
    pub profile: Profile,
    /// How the child ended; `None` if that could not be observed (a
    /// multi-threaded `execve` can retire the pid the tracer knew).
    pub exit: Option<Exit>,
    /// How many processes and threads were traced, the child included.
    pub processes: usize,
}

/// Runs `command` to completion under `ptrace` and reports which system
/// calls it (and, by default, its descendants) made.
///
/// Tracing starts when `execve` succeeds, so the calls the profile holds
/// are the program's own, not the spawning process's. The work happens on
/// a dedicated thread, which waits only for its own child and tracees:
/// other children of the calling process are never reaped.
///
/// Use files or [`Stdio::null`](std::process::Stdio::null) for the
/// child's standard streams: the child's handle is internal, so piped
/// output cannot be read. The tracer passes signals through but does not
/// honour job-control stops (`SIGSTOP`, `SIGTSTP`) of the tracees.
///
/// # Errors
///
/// - [`Error::Unavailable`] if this host forbids `ptrace` (Yama
///   `ptrace_scope` 3, a container's seccomp policy) or the kernel is
///   older than 5.3 (`PTRACE_GET_SYSCALL_INFO`).
/// - [`Error::Spawn`] if the program cannot be started.
/// - [`Error::Ptrace`] if a `ptrace` or `waitpid` call fails mid-trace.
pub fn trace(command: &mut Command, options: &Options) -> Result<Report, Error> {
    std::thread::scope(|scope| {
        scope
            .spawn(|| trace_on_this_thread(command, options))
            .join()
            .unwrap_or(Err(Error::TracerPanicked))
    })
}

/// Checks that [`trace`] works on this host by tracing `true` (from
/// `/usr/bin` or `/bin`).
///
/// # Errors
///
/// [`Error::Unavailable`] with the reason when it does not, including when
/// no `true` binary exists to try it with.
pub fn probe() -> Result<(), Error> {
    let program = ["/usr/bin/true", "/bin/true"]
        .into_iter()
        .find(|path| std::path::Path::new(path).is_file())
        .ok_or_else(|| Error::Unavailable {
            detail: "no `true` binary to probe ptrace with".to_owned(),
        })?;
    let mut command = Command::new(program);
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let report = trace(&mut command, &Options::default())?;
    if report.profile.is_empty() {
        return Err(Error::Unavailable {
            detail: "the tracer saw no system calls".to_owned(),
        });
    }
    Ok(())
}

fn unavailable(err: &std::io::Error, what: &str) -> Error {
    Error::Unavailable {
        detail: format!("{what}: {err}"),
    }
}

fn trace_on_this_thread(command: &mut Command, options: &Options) -> Result<Report, Error> {
    sys::trace_me_on_exec(command);
    let child = command.spawn().map_err(|err| match err.raw_os_error() {
        Some(libc::EPERM | libc::EACCES) => unavailable(&err, "PTRACE_TRACEME"),
        _ => Error::Spawn(err),
    })?;
    let root = libc::pid_t::try_from(child.id()).map_err(|_| Error::Ptrace {
        op: "spawn",
        source: std::io::Error::from_raw_os_error(libc::ESRCH),
    })?;
    // The child is reaped through `waitpid` below, never through `child`.
    drop(child);

    let mut tracer = Tracer::new(root);
    let result = tracer.run(options);
    if result.is_err() {
        tracer.kill_all();
    }
    result.map(|()| tracer.into_report())
}

/// The state of one tracing session; lives on the tracer thread.
struct Tracer {
    root: libc::pid_t,
    /// Tracees that have not exited yet.
    live: HashSet<libc::pid_t>,
    /// Tracees whose first stop has been seen.
    started: HashSet<libc::pid_t>,
    profile: Profile,
    exit: Option<Exit>,
}

impl Tracer {
    fn new(root: libc::pid_t) -> Self {
        Self {
            root,
            live: HashSet::from([root]),
            started: HashSet::from([root]),
            profile: Profile::new(),
            exit: None,
        }
    }

    fn into_report(self) -> Report {
        Report {
            profile: self.profile,
            exit: self.exit,
            processes: self.started.len(),
        }
    }

    fn run(&mut self, options: &Options) -> Result<(), Error> {
        self.attach(options)?;
        while !self.live.is_empty() {
            let (pid, status) = match sys::wait_any() {
                Ok(event) => event,
                // Nothing left to wait for: every tracee is gone, even if
                // one vanished without a report.
                Err(err) if err.raw_os_error() == Some(libc::ECHILD) => break,
                Err(source) => {
                    return Err(Error::Ptrace {
                        op: "waitpid",
                        source,
                    });
                }
            };
            self.handle(pid, status)?;
        }
        Ok(())
    }

    /// Waits for the child's post-`execve` stop and starts tracing it.
    fn attach(&mut self, options: &Options) -> Result<(), Error> {
        let (pid, status) = sys::wait_any().map_err(|source| Error::Ptrace {
            op: "waitpid",
            source,
        })?;
        if pid != self.root || !libc::WIFSTOPPED(status) {
            return Err(Error::Unavailable {
                detail: "the child did not stop for the tracer after execve".to_owned(),
            });
        }
        sys::set_options(pid, options.ptrace_options())
            .map_err(|err| unavailable(&err, "PTRACE_SETOPTIONS"))?;
        if let Some(arch) = NATIVE_AUDIT_ARCH {
            // The execve that brought the program in completed before the
            // first stop, so no syscall stop reports it.
            #[allow(
                clippy::cast_sign_loss,
                reason = "system call numbers are non-negative"
            )]
            self.profile
                .record(SyscallId::new(arch, libc::SYS_execve as u64));
        }
        Self::resume(pid, 0)
    }

    fn handle(&mut self, pid: libc::pid_t, status: libc::c_int) -> Result<(), Error> {
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            self.live.remove(&pid);
            if pid == self.root {
                self.exit = Some(if libc::WIFEXITED(status) {
                    Exit::Code(libc::WEXITSTATUS(status))
                } else {
                    Exit::Signal(libc::WTERMSIG(status))
                });
            }
            return Ok(());
        }
        if !libc::WIFSTOPPED(status) {
            return Ok(());
        }
        let signal = libc::WSTOPSIG(status);
        if self.started.insert(pid) {
            // A new child or thread's first stop (always `SIGSTOP`), which
            // can arrive before its parent's fork event.
            self.live.insert(pid);
            if signal == libc::SIGSTOP {
                return Self::resume(pid, 0);
            }
        }
        if signal == libc::SIGTRAP | 0x80 {
            self.on_syscall_stop(pid)?;
            return Self::resume(pid, 0);
        }
        let event = status >> 16;
        if signal == libc::SIGTRAP && event != 0 {
            self.on_event(pid, event);
            return Self::resume(pid, 0);
        }
        // A signal-delivery stop: pass the signal on.
        Self::resume(pid, signal)
    }

    fn on_syscall_stop(&mut self, pid: libc::pid_t) -> Result<(), Error> {
        match sys::syscall_info(pid) {
            Ok((sys::SYSCALL_INFO_ENTRY | sys::SYSCALL_INFO_SECCOMP, arch, nr)) => {
                self.profile.record(SyscallId::new(arch, nr));
                Ok(())
            }
            Ok(_) => Ok(()),
            // The tracee was killed while stopped.
            Err(err) if err.raw_os_error() == Some(libc::ESRCH) => Ok(()),
            Err(err) => Err(unavailable(
                &err,
                "PTRACE_GET_SYSCALL_INFO (needs Linux 5.3)",
            )),
        }
    }

    fn on_event(&mut self, pid: libc::pid_t, event: libc::c_int) {
        let forked = [
            libc::PTRACE_EVENT_FORK,
            libc::PTRACE_EVENT_VFORK,
            libc::PTRACE_EVENT_CLONE,
        ];
        if forked.contains(&event)
            && let Ok(message) = sys::event_message(pid)
            && let Ok(child) = libc::pid_t::try_from(message)
        {
            self.live.insert(child);
        }
    }

    fn resume(pid: libc::pid_t, signal: libc::c_int) -> Result<(), Error> {
        match sys::resume(pid, signal) {
            // Gone already (killed by a signal while stopped); its exit
            // report follows.
            Err(err) if err.raw_os_error() == Some(libc::ESRCH) => Ok(()),
            Err(source) => Err(Error::Ptrace {
                op: "PTRACE_SYSCALL",
                source,
            }),
            Ok(()) => Ok(()),
        }
    }

    /// Kills every tracee and reaps what it can, after a failure.
    fn kill_all(&mut self) {
        for pid in &self.live {
            sys::kill(*pid);
        }
        while !self.live.is_empty() {
            match sys::wait_any() {
                Ok((pid, status)) if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) => {
                    self.live.remove(&pid);
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
    }
}
