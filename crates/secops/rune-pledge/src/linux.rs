//! Linux: the filesystem layer is Landlock ([`rune_landlock`]) and the
//! system call layer seccomp-bpf ([`rune_seccomp`]).

use rune_landlock::{Abi, Right, RightSet};
use rune_seccomp::Action;

use crate::{
    Enforcement, Error, Permissions, Profile, Promise, PromiseSet, Report, Status, Violation,
    Warning,
};

const fn rights(list: &[Right]) -> RightSet {
    let mut set = RightSet::EMPTY;
    let mut i = 0;
    while i < list.len() {
        set = set.with(list[i]);
        i += 1;
    }
    set
}

const READ: RightSet = rights(&[Right::ReadFile, Right::ReadDir]);
const WRITE: RightSet = rights(&[Right::WriteFile, Right::Truncate, Right::IoctlDev]);
const CREATE: RightSet = rights(&[
    Right::RemoveDir,
    Right::RemoveFile,
    Right::MakeDir,
    Right::MakeReg,
    Right::MakeSym,
    Right::MakeFifo,
    Right::MakeSock,
    Right::Refer,
]);
const DEVICES: RightSet = rights(&[Right::MakeChar, Right::MakeBlock]);
const EXECUTE: RightSet = rights(&[Right::Execute]);
const UNIX: RightSet = rights(&[Right::ResolveUnix, Right::MakeSock]);

/// The Landlock rights a promise allows anywhere a path rule reaches.
const fn promise_rights(promise: Promise) -> RightSet {
    match promise {
        Promise::Rpath => READ,
        Promise::Wpath => WRITE,
        Promise::Cpath => CREATE,
        Promise::Dpath => DEVICES,
        Promise::Exec => EXECUTE,
        Promise::Unix => UNIX,
        _ => RightSet::EMPTY,
    }
}

fn promises_rights(promises: PromiseSet) -> RightSet {
    promises
        .iter()
        .map(promise_rights)
        .fold(RightSet::EMPTY, RightSet::union)
}

/// The Landlock rights `unveil(2)`-style permissions allow.
const fn permission_rights(permissions: Permissions) -> RightSet {
    let mut set = RightSet::EMPTY;
    if permissions.read() {
        set = set.union(READ);
    }
    if permissions.write() {
        set = set.union(WRITE).with(Right::ResolveUnix);
    }
    if permissions.exec() {
        set = set.union(EXECUTE);
    }
    if permissions.create() {
        set = set.union(CREATE).union(DEVICES);
    }
    set
}

impl Profile {
    /// The Landlock ruleset this profile maps to: every right the latest
    /// ABI handles is restricted, and each [`Profile::path_rules`] entry
    /// grants the rights both its permissions and the promises allow.
    /// Missing paths are skipped, and an older kernel degrades gracefully.
    ///
    /// Only on Linux.
    #[must_use]
    pub fn landlock_options(&self) -> rune_landlock::Options {
        let allowed = promises_rights(self.promises);
        self.path_rules().into_iter().fold(
            rune_landlock::Options::default()
                .with_abi(Abi::LATEST)
                .with_compatibility(rune_landlock::Compatibility::BestEffort)
                .with_skip_missing(true)
                .with_all_threads(self.all_threads),
            |options, rule| {
                let granted = permission_rights(rule.permissions).intersection(allowed);
                if granted.is_empty() {
                    options
                } else {
                    options.with_rule(rule.path, granted)
                }
            },
        )
    }

    /// The seccomp filter this profile maps to: an allowlist of
    /// [`Profile::syscalls`], with every other call getting the
    /// [`Profile::violation`] action.
    ///
    /// Only on Linux.
    #[must_use]
    pub fn seccomp_options(&self) -> rune_seccomp::Options {
        let otherwise = match self.violation {
            Violation::Errno => Action::EPERM,
            Violation::Kill => Action::KillProcess,
            Violation::Log => Action::Log,
        };
        rune_seccomp::Options::allowlist(otherwise)
            .with_syscalls(self.syscalls())
            .with_compatibility(rune_seccomp::Compatibility::BestEffort)
            .with_all_threads(self.all_threads)
    }
}

const fn landlock_status(status: rune_landlock::Status) -> Status {
    match status {
        rune_landlock::Status::FullyEnforced => Status::FullyEnforced,
        rune_landlock::Status::PartiallyEnforced => Status::PartiallyEnforced,
        _ => Status::NotEnforced,
    }
}

const fn seccomp_status(status: rune_seccomp::Status) -> Status {
    match status {
        rune_seccomp::Status::FullyEnforced => Status::FullyEnforced,
        rune_seccomp::Status::PartiallyEnforced => Status::PartiallyEnforced,
        _ => Status::NotEnforced,
    }
}

const fn unsupported(reason: String) -> Error {
    Error::Unsupported { reason }
}

/// Applies `profile` on Linux: Landlock first (seccomp would block its
/// system calls), then seccomp.
pub fn apply(profile: &Profile) -> Result<Report, Error> {
    let required = profile.enforcement == Enforcement::Required;
    let seccomp = profile.seccomp_options();

    // Check everything that can fail before restricting anything.
    let filter_arch = match rune_seccomp::compile(&seccomp) {
        Ok(_) => None,
        Err(rune_seccomp::Error::UnsupportedArch { arch }) => Some(arch),
        Err(source) => {
            return Err(Error::Seccomp {
                source,
                filesystem_restricted: false,
            });
        }
    };
    let landlock_support = rune_landlock::detect();
    // Detected now: the Landlock ruleset may hide `/proc` from seccomp's
    // own detection.
    let seccomp_support = rune_seccomp::detect();
    if required {
        if let Some(arch) = filter_arch {
            return Err(unsupported(format!(
                "seccomp filters are not supported on {arch}"
            )));
        }
        if !landlock_support.is_available() {
            return Err(unsupported(format!("Landlock is {landlock_support}")));
        }
        if seccomp_support == rune_seccomp::Support::NotSupported {
            return Err(unsupported(format!("seccomp is {seccomp_support}")));
        }
    }

    let mut report = Report::not_enforced(Vec::new());
    let landlock = rune_landlock::restrict_self(&profile.landlock_options())?;
    report.filesystem = landlock_status(landlock.status);
    match report.filesystem {
        Status::NotEnforced => report.warn(Warning::FilesystemNotEnforced {
            reason: format!("Landlock is {}", landlock.support),
        }),
        Status::PartiallyEnforced => {
            let mut reasons = Vec::new();
            if !landlock.unenforced.is_empty() {
                let abi = landlock
                    .effective_abi
                    .map_or_else(|| "none".to_owned(), |abi| abi.to_string());
                reasons.push(format!(
                    "the kernel's Landlock ABI {abi} leaves unrestricted: {}",
                    landlock.unenforced
                ));
            }
            if profile.all_threads && !landlock.all_threads {
                reasons.push("only the calling thread is restricted".to_owned());
            }
            report.warn(Warning::FilesystemPartial {
                reason: reasons.join("; "),
            });
        }
        _ => {}
    }
    if !landlock.skipped.is_empty() {
        report.warn(Warning::MissingPaths {
            paths: landlock.skipped.clone(),
        });
    }
    let filesystem_restricted = report.filesystem != Status::NotEnforced;
    report.landlock = Some(landlock);

    if let Some(arch) = filter_arch {
        report.warn(Warning::SyscallsNotEnforced {
            reason: format!("seccomp filters are not supported on {arch}"),
        });
    } else {
        let filter = rune_seccomp::install_with(&seccomp, seccomp_support).map_err(|source| {
            Error::Seccomp {
                source,
                filesystem_restricted,
            }
        })?;
        report.syscalls = seccomp_status(filter.status);
        match report.syscalls {
            Status::NotEnforced => report.warn(Warning::SyscallsNotEnforced {
                reason: if filter.support.is_available() {
                    "the kernel's fallback actions allow every call".to_owned()
                } else {
                    format!("seccomp is {}", filter.support)
                },
            }),
            Status::PartiallyEnforced => {
                let mut reasons: Vec<_> = filter
                    .substitutions
                    .iter()
                    .map(|(wanted, used)| format!("{wanted} replaced by {used}"))
                    .collect();
                if profile.all_threads && !filter.all_threads {
                    reasons.push("only the calling thread is filtered".to_owned());
                }
                report.warn(Warning::SyscallsPartial {
                    reason: reasons.join("; "),
                });
            }
            _ => {}
        }
        report.seccomp = Some(filter);
    }
    report.status = report.filesystem.combine(report.syscalls);
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn every_syscall_name_is_known() {
        for promise in Promise::ALL {
            for name in promise.syscalls() {
                assert!(rune_seccomp::syscalls::is_known(name), "{promise}: {name}");
            }
        }
    }

    #[test]
    fn landlock_rules_intersect_permissions_and_promises() {
        let options = Profile::pledge("stdio rpath")
            .unwrap()
            .with_path("/usr", Permissions::READ_EXEC)
            .with_path("/tmp/work", Permissions::READ_WRITE_CREATE)
            .with_path("/dev", "w".parse().unwrap())
            .landlock_options();
        assert_eq!(options.abi, Abi::LATEST);
        // `x` needs the exec promise and `w` the wpath one: /dev grants
        // nothing and is left out.
        let rules: Vec<_> = options
            .rules
            .iter()
            .map(|rule| (rule.path.clone(), rule.rights))
            .collect();
        assert_eq!(
            rules,
            [
                (PathBuf::from("/usr"), READ),
                (PathBuf::from("/tmp/work"), READ)
            ]
        );
    }

    #[test]
    fn landlock_without_paths_covers_the_root() {
        let options = Profile::pledge("stdio rpath wpath cpath exec")
            .unwrap()
            .landlock_options();
        assert_eq!(options.rules.len(), 1);
        assert_eq!(options.rules[0].path, PathBuf::from("/"));
        assert_eq!(
            options.rules[0].rights,
            READ.union(WRITE).union(CREATE).union(EXECUTE)
        );
        assert!(!options.rules[0].rights.contains(Right::MakeChar));

        // No filesystem promise: an empty ruleset that denies everything.
        assert_eq!(Profile::default().landlock_options().rules, []);
    }

    #[test]
    fn every_right_is_reachable() {
        let all = promises_rights(PromiseSet::ALL);
        assert_eq!(all, RightSet::ALL);
        assert_eq!(permission_rights(Permissions::ALL), RightSet::ALL);
        assert!(permission_rights(Permissions::NONE).is_empty());
    }

    #[test]
    fn seccomp_filter_follows_the_violation() {
        let profile = Profile::pledge("stdio").unwrap();
        let options = profile.seccomp_options();
        assert_eq!(options.default_action, Action::EPERM);
        assert_eq!(options.listed_action, Action::Allow);
        assert!(options.syscalls.contains(&"read".into()));
        assert!(!options.syscalls.contains(&"openat".into()));
        let kill = profile.clone().with_violation(Violation::Kill);
        assert_eq!(kill.seccomp_options().default_action, Action::KillProcess);
        let log = profile
            .with_violation(Violation::Log)
            .with_all_threads(true);
        assert_eq!(log.seccomp_options().default_action, Action::Log);
        assert!(log.seccomp_options().all_threads);
        assert!(log.landlock_options().all_threads);
    }

    #[test]
    fn compiled_filter_allows_exactly_the_promises() {
        if rune_seccomp::Arch::native().is_none() {
            return;
        }
        let program =
            rune_seccomp::compile(&Profile::pledge("stdio rpath").unwrap().seccomp_options())
                .unwrap();
        let number = |name| rune_seccomp::syscalls::resolve(name).unwrap();
        for allowed in ["read", "openat", "exit_group", "futex"] {
            assert_eq!(
                program.evaluate(number(allowed)),
                Some(Action::Allow),
                "{allowed}"
            );
        }
        for denied in ["execve", "socket", "unlinkat", "ptrace", "mount", "setuid"] {
            assert_eq!(
                program.evaluate(number(denied)),
                Some(Action::EPERM),
                "{denied}"
            );
        }
    }
}
