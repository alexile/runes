//! Transitive shared-library dependency resolution for allowed commands.
//!
//! A dynamically-linked binary needs its shared libraries (`libc.so.6`,
//! the dynamic linker itself, ...) to be visible in the sandbox to run at
//! all. The naive way to provide that — bind `/usr/lib`, `/lib`, `/lib64`
//! wholesale — silently defeats `commands.allow`: on a typical Linux
//! host those directories contain hundreds of executable files (helper
//! binaries, setuid tools, ...) that become runnable by absolute path
//! from any allowed shell, regardless of what's actually whitelisted.
//! This was found, not assumed: `bash -c '/usr/lib/openssh/ssh-keysign'`
//! ran successfully under a policy whose `commands.allow` never
//! mentioned it, purely because `/usr/lib` was bound wholesale for
//! dynamic linking.
//!
//! [`resolve_library_closure`] replaces that: bind exactly the shared
//! library files an allowed binary actually needs, each individually —
//! the same precise, one-file-at-a-time approach `commands.allow` itself
//! already uses. Nothing containing unrelated executables is ever bound.
//!
//! The actual resolution — parsing `DT_NEEDED`/`PT_INTERP` and walking
//! the dependency graph — lives in [`rune_elf_deps`], a generic,
//! security-unrelated crate extracted from this one: nothing about
//! "what shared libraries does this binary need" is specific to
//! sandboxing. This module is the thin, sandbox-specific wrapper.

use std::path::PathBuf;

/// Every shared library (and interpreter) the given binaries load, transitively.
#[must_use]
pub fn resolve_library_closure(binaries: &[PathBuf]) -> Vec<PathBuf> {
    rune_elf_deps::resolve_library_closure(binaries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_dependencies_of_a_real_dynamic_binary() {
        let sh = PathBuf::from("/usr/bin/sh");
        if !sh.is_file() {
            return;
        }
        let closure = resolve_library_closure(&[sh]);
        assert!(
            closure
                .iter()
                .any(|p| p.to_string_lossy().contains("libc.so")),
            "expected libc in the dependency closure, got {closure:?}"
        );
    }

    #[test]
    fn resolves_the_elf_interpreter_too() {
        let sh = PathBuf::from("/usr/bin/sh");
        if !sh.is_file() {
            return;
        }
        let closure = resolve_library_closure(&[sh]);
        assert!(
            closure
                .iter()
                .any(|p| p.to_string_lossy().contains("ld-linux")),
            "expected the ELF interpreter (dynamic linker) in the closure, got {closure:?}"
        );
    }

    #[test]
    fn nonexistent_binary_does_not_panic() {
        let closure =
            resolve_library_closure(&[PathBuf::from("/definitely/not/a/real/binary/anywhere")]);
        assert!(closure.iter().all(|p| p.is_absolute()));
    }

    #[test]
    fn never_shells_out_to_ldd_or_readelf() {
        // Regression guard: this module must stay a thin wrapper over
        // rune_elf_deps, not grow its own ldd/readelf shell-out again.
        let source = include_str!("deps.rs");
        assert!(
            !source
                .lines()
                .filter(|l| !l.trim_start().starts_with("//"))
                .any(|l| {
                    l.contains("\"ldd\"")
                        || l.contains("Command::new(\"ldd\")")
                        || l.contains("\"readelf\"")
                        || l.contains("Command::new(\"readelf\")")
                }),
            "deps.rs must not shell out to ldd or readelf"
        );
    }
}
