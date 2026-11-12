//! Building a ruleset from [`Options`] and enforcing it on the calling
//! thread.

use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use landlock::{
    CompatLevel, Compatible, PathBeneath, RestrictSelfAttr, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetStatus,
};

use crate::{Abi, Error, RightSet, Support, detect};

/// One allowlist entry: `rights` on `path` and, for a directory,
/// everything beneath it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Rule {
    /// The file or directory hierarchy the rule covers.
    pub path: PathBuf,
    /// The rights granted on it.
    pub rights: RightSet,
}

impl Rule {
    /// A rule granting `rights` on `path`.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>, rights: RightSet) -> Self {
        Self {
            path: path.into(),
            rights,
        }
    }
}

/// What to do when the kernel cannot enforce everything requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum Compatibility {
    /// Enforce what the kernel supports and report the rest in
    /// [`Report::unenforced`]; on a kernel without Landlock, enforce
    /// nothing and report [`Status::NotEnforced`]. The default: Landlock is
    /// usually one layer among several, and an old kernel should not stop
    /// the program from running.
    #[default]
    BestEffort,
    /// Fail with [`Error::Unsupported`] unless the kernel supports the
    /// requested ABI, before anything is restricted.
    HardRequirement,
}

/// A Landlock filesystem sandbox: the rules to allow, and how to apply
/// them.
///
/// Everything not covered by a rule is denied for the rights handled by
/// [`Options::abi`]. Rules are purely additive: a path is accessible with
/// a right if *any* rule covering it grants that right, so a narrower rule
/// cannot take away what a broader one grants.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Options {
    /// The allowlist.
    pub rules: Vec<Rule>,
    /// The ABI to target; its rights are the ones restricted. Default:
    /// [`Abi::V5`], which covers every filesystem right except
    /// [`Right::ResolveUnix`](crate::Right::ResolveUnix).
    pub abi: Abi,
    /// What to do on a kernel older than [`Options::abi`]. Default:
    /// [`Compatibility::BestEffort`].
    pub compatibility: Compatibility,
    /// Leave out rules whose path does not exist (listed in
    /// [`Report::skipped`]) rather than failing with [`Error::Path`].
    /// Skipping only ever grants less. Default: `true`.
    pub skip_missing: bool,
    /// Restrict every thread of the process rather than only the calling
    /// thread ([`Abi::V8`]). On older kernels, best effort restricts only
    /// the calling thread and reports [`Status::PartiallyEnforced`].
    /// Default: `false`.
    pub all_threads: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            rules: Vec::new(),
            abi: Abi::V5,
            compatibility: Compatibility::BestEffort,
            skip_missing: true,
            all_threads: false,
        }
    }
}

impl Options {
    /// Adds a rule granting `rights` on `path`.
    #[must_use]
    pub fn with_rule(mut self, path: impl Into<PathBuf>, rights: RightSet) -> Self {
        self.rules.push(Rule::new(path, rights));
        self
    }

    /// Allows reading files and listing directories under `path`
    /// ([`RightSet::READ`]).
    #[must_use]
    pub fn with_read(self, path: impl Into<PathBuf>) -> Self {
        self.with_rule(path, RightSet::READ)
    }

    /// Allows reading and executing under `path` ([`RightSet::READ_EXEC`]):
    /// system directories such as `/usr`.
    #[must_use]
    pub fn with_read_exec(self, path: impl Into<PathBuf>) -> Self {
        self.with_rule(path, RightSet::READ_EXEC)
    }

    /// Allows executing `path` ([`RightSet::EXEC`]): a program or shared
    /// library.
    #[must_use]
    pub fn with_exec(self, path: impl Into<PathBuf>) -> Self {
        self.with_rule(path, RightSet::EXEC)
    }

    /// Allows everything under `path` ([`RightSet::READ_WRITE`]).
    #[must_use]
    pub fn with_read_write(self, path: impl Into<PathBuf>) -> Self {
        self.with_rule(path, RightSet::READ_WRITE)
    }

    /// Sets [`Options::abi`].
    #[must_use]
    pub const fn with_abi(mut self, abi: Abi) -> Self {
        self.abi = abi;
        self
    }

    /// Sets [`Options::compatibility`].
    #[must_use]
    pub const fn with_compatibility(mut self, compatibility: Compatibility) -> Self {
        self.compatibility = compatibility;
        self
    }

    /// Sets [`Options::skip_missing`].
    #[must_use]
    pub const fn with_skip_missing(mut self, skip_missing: bool) -> Self {
        self.skip_missing = skip_missing;
        self
    }

    /// Sets [`Options::all_threads`].
    #[must_use]
    pub const fn with_all_threads(mut self, all_threads: bool) -> Self {
        self.all_threads = all_threads;
        self
    }

    /// The rights a rule may grant on a target: what it asks for, limited
    /// to what [`Options::abi`] handles (the kernel rejects grants of
    /// unhandled rights) and, for a non-directory, to
    /// [`RightSet::FILE`].
    #[must_use]
    pub fn grantable(&self, rule: &Rule, is_dir: bool) -> RightSet {
        let rights = rule.rights.intersection(RightSet::handled_by(self.abi));
        if is_dir {
            rights
        } else {
            rights.intersection(RightSet::FILE)
        }
    }
}

/// How much of the ruleset the kernel enforces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Status {
    /// Everything requested is enforced.
    FullyEnforced,
    /// The ruleset is enforced, but the kernel is older than requested:
    /// see [`Report::unenforced`].
    PartiallyEnforced,
    /// Nothing is enforced: the kernel does not support Landlock.
    NotEnforced,
}

/// The result of [`restrict_self`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Report {
    /// How much of the ruleset is enforced.
    pub status: Status,
    /// The kernel's Landlock support.
    pub support: Support,
    /// The ABI that was requested ([`Options::abi`]).
    pub requested_abi: Abi,
    /// The ABI actually used, or `None` if Landlock is unavailable.
    pub effective_abi: Option<Abi>,
    /// Rights requested but left unrestricted because the kernel is too
    /// old for them (all of them when [`Status::NotEnforced`]).
    pub unenforced: RightSet,
    /// Number of rules added to the ruleset.
    pub rules: usize,
    /// Rule paths that did not exist and were left out
    /// ([`Options::skip_missing`]).
    pub skipped: Vec<PathBuf>,
    /// `true` if `no_new_privs` is set: the restricted thread and its
    /// children can no longer gain privileges through set-user-ID or
    /// file-capability binaries, which Landlock requires.
    pub no_new_privs: bool,
    /// `true` if the ruleset applies to every thread of the process
    /// rather than only the calling thread.
    pub all_threads: bool,
}

/// Opens `path` without following it into its content (`O_PATH`), for use
/// as a rule's anchor. Returns `None` if it does not exist.
fn open_anchor(path: &Path) -> std::io::Result<Option<(File, bool)>> {
    match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH)
        .open(path)
    {
        Ok(file) => {
            let is_dir = file.metadata()?.is_dir();
            Ok(Some((file, is_dir)))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

fn landlock_error(err: landlock::RulesetError) -> Error {
    Error::Landlock {
        source: Box::new(err),
    }
}

/// Restricts the calling thread, and every process it goes on to `exec`,
/// to `options`' allowlist.
///
/// A Landlock restriction cannot be lifted: it lasts for the rest of the
/// thread's life (or the process's, with [`Options::all_threads`]) and is
/// inherited by children and across `execve`. A later call can only
/// narrow it further. Call it after setup that needs wider access, or in
/// a launcher that then execs the sandboxed program.
///
/// Unless [`Options::all_threads`] is set, only the calling thread is
/// restricted; threads that already exist keep their access.
///
/// It also sets `no_new_privs`, which Landlock requires of unprivileged
/// processes.
///
/// # Errors
///
/// - [`Error::Unsupported`] with [`Compatibility::HardRequirement`] when
///   the kernel is older than [`Options::abi`] or lacks Landlock; nothing
///   has been restricted.
/// - [`Error::Path`] when a rule's path cannot be opened (or does not
///   exist and [`Options::skip_missing`] is off); nothing has been
///   restricted.
/// - [`Error::Landlock`] when the kernel rejects the ruleset.
pub fn restrict_self(options: &Options) -> Result<Report, Error> {
    let support = detect();
    let effective_abi = support.effective_abi(options.abi);
    if options.compatibility == Compatibility::HardRequirement && effective_abi != Some(options.abi)
    {
        return Err(Error::Unsupported {
            requested: options.abi,
            support,
        });
    }

    // Open every anchor before touching the kernel, so a bad path fails
    // cleanly with nothing restricted.
    let mut anchors = Vec::with_capacity(options.rules.len());
    let mut skipped = Vec::new();
    for rule in &options.rules {
        match open_anchor(&rule.path) {
            Ok(Some((file, is_dir))) => {
                let rights = options.grantable(rule, is_dir);
                if !rights.is_empty() {
                    anchors.push((file, rights));
                }
            }
            Ok(None) if options.skip_missing => skipped.push(rule.path.clone()),
            Ok(None) => {
                return Err(Error::Path {
                    path: rule.path.clone(),
                    source: std::io::ErrorKind::NotFound.into(),
                });
            }
            Err(source) => {
                return Err(Error::Path {
                    path: rule.path.clone(),
                    source,
                });
            }
        }
    }

    let level = match options.compatibility {
        Compatibility::BestEffort => CompatLevel::BestEffort,
        Compatibility::HardRequirement => CompatLevel::HardRequirement,
    };
    let rules = anchors.len();
    let mut ruleset = Ruleset::default()
        .set_compatibility(level)
        .handle_access(RightSet::handled_by(options.abi).to_landlock())
        .and_then(Ruleset::create)
        .map_err(landlock_error)?;
    for (file, rights) in anchors {
        ruleset = ruleset
            .add_rule(PathBeneath::new(file, rights.to_landlock()))
            .map_err(landlock_error)?;
    }
    if options.all_threads {
        ruleset = ruleset.all_threads(true).map_err(landlock_error)?;
    }
    let restriction = ruleset.restrict_self().map_err(landlock_error)?;

    let status = match restriction.ruleset {
        RulesetStatus::FullyEnforced => Status::FullyEnforced,
        RulesetStatus::PartiallyEnforced => Status::PartiallyEnforced,
        RulesetStatus::NotEnforced => Status::NotEnforced,
    };
    Ok(Report {
        status,
        support,
        requested_abi: options.abi,
        effective_abi,
        unenforced: support.unenforced_rights(options.abi),
        rules,
        skipped,
        no_new_privs: restriction.no_new_privs,
        all_threads: restriction.all_threads,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Right;

    #[test]
    fn defaults() {
        let options = Options::default();
        assert_eq!(options.rules, []);
        assert_eq!(options.abi, Abi::V5);
        assert_eq!(options.compatibility, Compatibility::BestEffort);
        assert!(options.skip_missing);
        assert!(!options.all_threads);
    }

    #[test]
    fn builders_add_rules_in_order() {
        let options = Options::default()
            .with_read("/a")
            .with_read_exec("/b")
            .with_exec("/c")
            .with_read_write("/d")
            .with_rule("/e", Right::MakeDir.into());
        let rights: Vec<_> = options.rules.iter().map(|r| r.rights).collect();
        assert_eq!(
            rights,
            [
                RightSet::READ,
                RightSet::READ_EXEC,
                RightSet::EXEC,
                RightSet::READ_WRITE,
                Right::MakeDir.into()
            ]
        );
        assert_eq!(options.rules[3].path, PathBuf::from("/d"));
    }

    #[test]
    fn grantable_is_limited_by_abi_and_file_type() {
        let options = Options::default().with_abi(Abi::V2);
        let rule = Rule::new("/x", RightSet::READ_WRITE);
        let on_dir = options.grantable(&rule, true);
        assert_eq!(on_dir, RightSet::handled_by(Abi::V2));
        let on_file = options.grantable(&rule, false);
        assert_eq!(
            on_file.iter().collect::<Vec<_>>(),
            [Right::Execute, Right::WriteFile, Right::ReadFile]
        );
        // Directory-only rights on a file grant nothing.
        let dir_only = Rule::new("/x", Right::ReadDir.into());
        assert!(options.grantable(&dir_only, false).is_empty());
    }

    #[test]
    fn open_anchor_reports_missing_paths() {
        let dir = tempfile::tempdir().unwrap();
        assert!(open_anchor(&dir.path().join("nope")).unwrap().is_none());
        let (_, is_dir) = open_anchor(dir.path()).unwrap().unwrap();
        assert!(is_dir);
        let file = dir.path().join("f");
        std::fs::write(&file, "x").unwrap();
        let (_, is_dir) = open_anchor(&file).unwrap().unwrap();
        assert!(!is_dir);
    }

    /// Runs `body` on a fresh thread. Landlock restricts only the calling
    /// thread, so restricting it leaves the test harness untouched.
    fn on_fresh_thread<T: Send + 'static>(body: impl FnOnce() -> T + Send + 'static) -> T {
        std::thread::spawn(body).join().unwrap()
    }

    #[test]
    fn missing_path_is_an_error_when_not_skipping() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing");
        let options = Options::default()
            .with_read(&missing)
            .with_skip_missing(false);
        // Fails while opening anchors, before any restriction.
        let err = restrict_self(&options).unwrap_err();
        assert!(matches!(err, Error::Path { ref path, .. } if *path == missing));
    }

    #[test]
    fn hard_requirement_fails_before_restricting_on_old_kernels() {
        let support = detect();
        let options = Options::default()
            .with_abi(Abi::LATEST)
            .with_compatibility(Compatibility::HardRequirement);
        if support.abi() == Some(Abi::LATEST) {
            eprintln!("skipping: kernel supports the latest ABI, nothing to fall back from");
            return;
        }
        let err = restrict_self(&options).unwrap_err();
        assert!(matches!(
            err,
            Error::Unsupported { requested: Abi::V9, support: s } if s == support
        ));
    }

    #[test]
    fn enforces_the_allowlist_on_the_calling_thread() {
        if !detect().is_available() {
            eprintln!("skipping: Landlock is not available on this kernel");
            return;
        }
        let allowed = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let readable = allowed.path().join("readable.txt");
        let secret = outside.path().join("secret.txt");
        std::fs::write(&readable, "ok").unwrap();
        std::fs::write(&secret, "no").unwrap();
        let missing = outside.path().join("not-there");

        let (report, inside, blocked, write_blocked) = {
            let (allowed_dir, readable, secret, missing) = (
                allowed.path().to_path_buf(),
                readable,
                secret.clone(),
                missing.clone(),
            );
            on_fresh_thread(move || {
                let options = Options::default()
                    .with_read(&allowed_dir)
                    .with_read(&missing);
                let report = restrict_self(&options).unwrap();
                (
                    report,
                    std::fs::read_to_string(&readable).ok(),
                    std::fs::read_to_string(&secret).is_err(),
                    std::fs::write(allowed_dir.join("new"), "x").is_err(),
                )
            })
        };
        assert_eq!(report.status, Status::FullyEnforced);
        assert_eq!(report.rules, 1);
        assert_eq!(report.skipped, [missing]);
        assert!(report.no_new_privs);
        assert!(report.unenforced.is_empty());
        assert_eq!(inside.as_deref(), Some("ok"));
        assert!(blocked, "a path outside the allowlist must be denied");
        assert!(write_blocked, "a read-only grant must not allow writes");

        // The harness thread was never restricted.
        assert_eq!(std::fs::read_to_string(&secret).unwrap(), "no");
    }

    #[test]
    fn best_effort_degrades_to_the_kernel_abi() {
        let support = detect();
        let Some(kernel) = support.abi() else {
            eprintln!("skipping: Landlock is not available on this kernel");
            return;
        };
        let report =
            on_fresh_thread(|| restrict_self(&Options::default().with_abi(Abi::LATEST)).unwrap());
        assert_eq!(report.effective_abi, Some(kernel));
        assert_eq!(report.unenforced, support.unenforced_rights(Abi::LATEST));
        let expected = if kernel == Abi::LATEST {
            Status::FullyEnforced
        } else {
            Status::PartiallyEnforced
        };
        assert_eq!(report.status, expected);

        // Asking for no more than the kernel has is fully enforced.
        let report = on_fresh_thread(move || {
            restrict_self(
                &Options::default()
                    .with_abi(kernel)
                    .with_compatibility(Compatibility::HardRequirement),
            )
            .unwrap()
        });
        assert_eq!(report.status, Status::FullyEnforced);
    }
}
