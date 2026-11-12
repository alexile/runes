//! Syscall-level hardening via a compiled seccomp-bpf filter, layered on
//! top of the namespace/filesystem boundary as defense in depth.
//!
//! The default deny list is adapted from
//! [Docker's default seccomp profile](https://docs.docker.com/engine/security/seccomp/),
//! a battle-tested, publicly documented list denied across millions of
//! containers daily. Two categories of Docker's list are deliberately
//! **not** carried over here, because they'd break the exact tools this
//! crate exists to sandbox:
//!
//! - `clone`, `unshare`, `setns` — Docker denies these because they let a
//!   *root* container process create nested namespaces and potentially
//!   escape. Our sandboxed process is never root (bwrap keeps your normal
//!   uid mapped), and `clone` in particular is how `pthread_create` makes
//!   every thread — denying it would break any multi-threaded program,
//!   which is most of them (Node.js, in particular, since it's the
//!   runtime Claude Code itself is built on).
//! - `socket`, `socketcall`, `personality`, `userfaultfd` — Docker's own
//!   rationale for these is comparatively soft ("not inherently
//!   dangerous", "largely needed for process migration"), and blocking
//!   `socket` outright would break local Unix-domain-socket IPC (ssh-agent,
//!   gpg-agent, editor language servers, git credential helpers) even
//!   though `sandbox.network = "none"` already removes real network
//!   reachability at the namespace level — the more surgical control.
//!
//! Everything else — kernel module loading, `ptrace`/process-memory
//! access, the kernel keyring, `mount`/`pivot_root`, `io_uring`,
//! time-setting, and other syscalls no ordinary CLI tool has a legitimate
//! reason to call — is denied by default. Remove specific entries via
//! `seccomp.allow` if a wrapped tool genuinely needs one.
//!
//! The list itself ([`rune_seccomp::syscalls::DANGEROUS`]) and the BPF
//! compiler live in [`rune_seccomp`]; this module only maps a
//! [`SeccompSection`] onto it. Compared to the filter this crate used to
//! build itself, `rune-seccomp` also denies x32-ABI calls on `x86_64`
//! (`number | 0x4000_0000`), which would otherwise bypass a denylist.

use rune_seccomp::{Action, Options, Program, syscalls};

use crate::policy::{SeccompSection, WardenError};

/// Names in the default deny list that exist on this architecture, for
/// validating `seccomp.allow` entries against typos. The legacy `x86_64`
/// calls (`_sysctl`, `ustat`, `nfsservctl`) are left out elsewhere.
#[must_use]
pub fn denied_syscall_names() -> Vec<&'static str> {
    syscalls::DANGEROUS
        .iter()
        .copied()
        .filter(|name| syscalls::resolve(name).is_some())
        .collect()
}

/// The [`rune_seccomp`] filter `section` describes: a denylist of the
/// default list minus `seccomp.allow`, plus `seccomp.deny_numbers`.
/// `None` if seccomp filtering is disabled or nothing is left to deny.
fn filter_options(section: &SeccompSection) -> Option<Options> {
    if !section.enabled {
        return None;
    }
    let action = if section.kill {
        Action::KillProcess
    } else {
        Action::EPERM
    };
    let options = Options::denylist(action)
        .with_syscalls(
            denied_syscall_names()
                .into_iter()
                .filter(|name| !section.allow.iter().any(|allowed| allowed == name)),
        )
        .with_syscalls(section.deny_numbers.iter().copied());
    (!options.syscalls.is_empty()).then_some(options)
}

/// Compile `section` into a seccomp-bpf program ready to hand to bwrap's
/// `--seccomp` flag (see [`Program::to_bytes`]), or `Ok(None)` if seccomp
/// filtering is disabled or ends up with an empty rule set.
///
/// # Errors
///
/// [`WardenError::Io`] if the filter cannot be compiled for this
/// architecture, or a `deny_numbers` entry is not a valid system call
/// number.
pub fn compiled_seccomp_program(section: &SeccompSection) -> Result<Option<Program>, WardenError> {
    filter_options(section)
        .map(|options| {
            rune_seccomp::compile(&options)
                .map_err(|err| WardenError::Io(format!("building seccomp filter: {err}")))
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn number(name: &str) -> i64 {
        syscalls::resolve(name).unwrap()
    }

    #[test]
    fn default_filter_compiles() {
        let program = compiled_seccomp_program(&SeccompSection::default())
            .unwrap()
            .expect("default seccomp section should produce a program");
        assert_ne!(program.len(), 0);
        assert_eq!(program.evaluate(number("ptrace")), Some(Action::EPERM));
        assert_eq!(program.evaluate(number("read")), Some(Action::Allow));
    }

    #[test]
    fn disabled_seccomp_compiles_to_nothing() {
        let section = SeccompSection {
            enabled: false,
            ..SeccompSection::default()
        };
        assert!(compiled_seccomp_program(&section).unwrap().is_none());
    }

    #[test]
    fn allow_removes_syscall_from_default_deny_list() {
        let with_ptrace_denied = compiled_seccomp_program(&SeccompSection::default())
            .unwrap()
            .unwrap();

        let section = SeccompSection {
            allow: vec!["ptrace".to_string()],
            ..SeccompSection::default()
        };
        let without_ptrace_denied = compiled_seccomp_program(&section).unwrap().unwrap();

        // Removing a rule changes the compiled program.
        assert_ne!(with_ptrace_denied, without_ptrace_denied);
        assert_eq!(
            without_ptrace_denied.evaluate(number("ptrace")),
            Some(Action::Allow)
        );
        assert_eq!(
            without_ptrace_denied.evaluate(number("mount")),
            Some(Action::EPERM)
        );
    }

    #[test]
    fn allowing_everything_compiles_to_nothing() {
        let section = SeccompSection {
            allow: denied_syscall_names()
                .iter()
                .map(ToString::to_string)
                .collect(),
            ..SeccompSection::default()
        };
        assert!(compiled_seccomp_program(&section).unwrap().is_none());
    }

    #[test]
    fn deny_numbers_extend_the_filter() {
        let base = compiled_seccomp_program(&SeccompSection::default())
            .unwrap()
            .unwrap();
        let section = SeccompSection {
            deny_numbers: vec![9999],
            ..SeccompSection::default()
        };
        let extended = compiled_seccomp_program(&section).unwrap().unwrap();
        assert_ne!(base, extended);
        assert_eq!(extended.evaluate(9999), Some(Action::EPERM));
    }

    #[test]
    fn out_of_range_deny_number_is_an_error() {
        let section = SeccompSection {
            deny_numbers: vec![-1],
            ..SeccompSection::default()
        };
        assert!(compiled_seccomp_program(&section).is_err());
    }

    #[test]
    fn kill_uses_kill_process() {
        let section = SeccompSection {
            kill: true,
            ..SeccompSection::default()
        };
        let program = compiled_seccomp_program(&section).unwrap().unwrap();
        assert_eq!(
            program.evaluate(number("ptrace")),
            Some(Action::KillProcess)
        );
    }

    #[test]
    fn denied_names_are_unique_and_resolve() {
        let names = denied_syscall_names();
        let unique: std::collections::HashSet<&str> = names.iter().copied().collect();
        assert_eq!(
            names.len(),
            unique.len(),
            "duplicate syscall name in deny list"
        );
        assert!(names.contains(&"ptrace"));
        assert!(names.iter().all(|name| syscalls::resolve(name).is_some()));
    }
}
