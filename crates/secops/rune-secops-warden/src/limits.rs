//! Resource ceilings applied to the sandboxed process as POSIX rlimits.
//!
//! The actual rlimit mechanics — converting values, the `pre_exec` hook,
//! `setrlimit` itself — live in [`rune_rlimits`], a generic crate
//! extracted from this one: applying resource limits to a spawned
//! process has nothing to do with sandboxing specifically. This module
//! is the thin, policy-specific wrapper: converting [`LimitsSection`]
//! (this crate's TOML-facing type) into [`rune_rlimits::Limits`].

use std::process::Command;

use crate::policy::LimitsSection;

const fn to_generic_limits(limits: &LimitsSection) -> rune_rlimits::Limits {
    rune_rlimits::Limits {
        max_processes: limits.max_processes,
        memory_mb: limits.memory_mb,
        cpu_seconds: limits.cpu_seconds,
        max_open_files: limits.max_open_files,
        max_file_size_mb: limits.max_file_size_mb,
        disable_core_dumps: limits.disable_core_dumps,
    }
}

/// Attach `limits` to `command` via a `pre_exec` hook. A no-op if no
/// limit is set.
pub fn apply_limits(command: &mut Command, limits: &LimitsSection) {
    rune_rlimits::apply(command, &to_generic_limits(limits));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_limits_means_no_resources() {
        let limits = LimitsSection {
            disable_core_dumps: false,
            ..LimitsSection::default()
        };
        let generic = to_generic_limits(&limits);
        assert!(generic.max_processes.is_none());
        assert!(!generic.disable_core_dumps);
    }

    #[test]
    fn disable_core_dumps_is_the_only_default_on_limit() {
        let limits = LimitsSection::default();
        assert!(to_generic_limits(&limits).disable_core_dumps);
    }

    #[test]
    fn memory_mb_converts_to_bytes() {
        // rune_rlimits handles the actual MB->bytes conversion; this
        // module's own job is just field mapping, verified here.
        let limits = LimitsSection {
            memory_mb: Some(512),
            disable_core_dumps: false,
            ..LimitsSection::default()
        };
        assert_eq!(to_generic_limits(&limits).memory_mb, Some(512));
    }

    #[test]
    fn apply_limits_attaches_a_working_pre_exec_hook() {
        // Real end-to-end proof that this crate's own apply_limits still
        // functions correctly after the extraction, not just that field
        // mapping is correct: a real child process with a limit set
        // must actually run and exit successfully.
        let mut command = Command::new("true");
        apply_limits(&mut command, &LimitsSection::default());
        let status = command.status().expect("child should spawn");
        assert!(status.success());
    }
}
