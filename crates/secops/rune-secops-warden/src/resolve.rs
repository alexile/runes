//! Resolving policy entries against the real host filesystem: turning
//! `commands.allow` names into absolute binary paths and `filesystem.deny`
//! entries into directory-vs-file bind decisions.

use std::path::PathBuf;

use crate::policy::{CommandsSection, FilesystemSection};

/// The standard executable directories on a typical Linux system.
///
/// Used both as the fallback command-search path and, in [`Policy::validate`],
/// to catch policies that bind one of these wholesale and so silently defeat
/// `commands.allow`.
///
/// [`Policy::validate`]: crate::Policy::validate
pub const STANDARD_BIN_DIRS: [&str; 6] = [
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
];

/// Directories searched, in order, when a `commands.allow` entry is given
/// as a bare name rather than an explicit path — mirrors normal `PATH`
/// resolution, falling back to the standard binary directories if `PATH`
/// isn't set.
fn default_search_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(path_var) = std::env::var("PATH") {
        dirs.extend(std::env::split_paths(&path_var));
    }
    dirs.extend(STANDARD_BIN_DIRS.iter().map(PathBuf::from));
    dirs
}

/// A `commands.allow` entry resolved to the absolute path of the binary
/// it names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedCommand {
    /// Command name as written in the policy.
    pub name: String,
    /// Absolute path of the resolved binary.
    pub path: PathBuf,
}

/// Resolve each `commands.allow` entry to the absolute path of the binary
/// it names, searching `dirs` in order and stopping at the first match —
/// the same "first hit wins" semantics as a normal `PATH` lookup.
///
/// An entry with an explicit `path` is used as-is without searching.
#[must_use]
pub fn resolve_allowed_binaries_in(
    commands: &CommandsSection,
    dirs: &[PathBuf],
) -> Vec<ResolvedCommand> {
    let mut found = Vec::new();
    for entry in &commands.allow {
        if let Some(explicit) = entry.explicit_path() {
            found.push(ResolvedCommand {
                name: entry.name().to_string(),
                path: explicit.to_path_buf(),
            });
            continue;
        }
        for dir in dirs {
            let candidate = dir.join(entry.name());
            if candidate.is_file() {
                found.push(ResolvedCommand {
                    name: entry.name().to_string(),
                    path: candidate,
                });
                break;
            }
        }
    }
    found.sort_by(|a, b| a.path.cmp(&b.path));
    found.dedup_by(|a, b| a.path == b.path);
    found
}

/// Resolve `commands.allow` against the current `PATH` and the standard
/// binary directories.
#[must_use]
pub fn resolve_allowed_binaries(commands: &CommandsSection) -> Vec<ResolvedCommand> {
    resolve_allowed_binaries_in(commands, &default_search_dirs())
}

/// A `filesystem.deny` entry resolved against the real filesystem.
///
/// The caller needs to know whether to mask it as a directory or a file:
/// bubblewrap masks the two differently (a `--tmpfs` target must be a
/// directory).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedDeny {
    /// Absolute path to hide.
    pub path: PathBuf,
    /// Whether `path` is a directory.
    pub is_dir: bool,
}

/// Resolve each `filesystem.deny` entry's kind (directory vs. file) by
/// stat-ing it on the host.
///
/// A path that doesn't exist on the host is treated as a file, matching
/// bubblewrap's default bind-target behavior.
#[must_use]
pub fn resolve_deny_paths(filesystem: &FilesystemSection) -> Vec<ResolvedDeny> {
    filesystem
        .deny
        .iter()
        .map(|entry| ResolvedDeny {
            path: entry.path.clone(),
            is_dir: entry.path.is_dir(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::CommandRef;

    #[test]
    fn resolve_allowed_binaries_explicit_path_skips_search() {
        let commands = CommandsSection {
            allow: vec![CommandRef::Entry {
                name: "git".to_string(),
                path: Some(PathBuf::from("/opt/custom/git")),
            }],
        };
        let resolved = resolve_allowed_binaries_in(&commands, &[]);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].path, PathBuf::from("/opt/custom/git"));
    }

    #[test]
    fn resolve_allowed_binaries_searches_dirs_first_match_wins() {
        let dir_a = std::env::temp_dir().join(format!(
            "rune-secops-warden-test-a-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let dir_b = std::env::temp_dir().join(format!(
            "rune-secops-warden-test-b-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir_a).unwrap();
        std::fs::create_dir_all(&dir_b).unwrap();
        let bin_a = dir_a.join("fake-cat");
        let bin_b = dir_b.join("fake-cat");
        std::fs::write(&bin_a, "#!/bin/sh\n").unwrap();
        std::fs::write(&bin_b, "#!/bin/sh\n").unwrap();

        let commands = CommandsSection {
            allow: vec![CommandRef::Name("fake-cat".to_string())],
        };
        let resolved = resolve_allowed_binaries_in(&commands, &[dir_a.clone(), dir_b.clone()]);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].path, bin_a);

        std::fs::remove_dir_all(&dir_a).unwrap();
        std::fs::remove_dir_all(&dir_b).unwrap();
    }
}
