//! Building a filter from [`Options`], compiling it to BPF and installing
//! it on the calling thread.

use std::collections::{BTreeMap, BTreeSet};

use seccompiler::{
    BpfProgram, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter, SeccompRule,
};

use crate::action::MAX_ERRNO;
use crate::bpf;
use crate::syscalls::{self, Arch, Syscall};
use crate::{Action, ActionSet, Error, Support, detect};

/// What to do when the kernel cannot enforce everything requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum Compatibility {
    /// Enforce what the kernel supports: replace a missing action by its
    /// [fallback](Action::fallback), restrict only the calling thread when
    /// the kernel cannot synchronise all threads, and install nothing on a
    /// kernel without seccomp. [`Report::status`] says what happened. The
    /// default.
    #[default]
    BestEffort,
    /// Fail with [`Error::Unsupported`] or [`Error::ActionUnavailable`]
    /// unless the filter can be installed exactly as requested.
    HardRequirement,
}

/// A condition on one argument of a system call: `(args[index] & mask) ==
/// value`, compared over all 64 bits (the filter checks both 32-bit halves).
///
/// Seccomp only sees the argument registers, so a condition can test flags
/// and numbers but not what a pointer points to.
///
/// ```
/// use rune_seccomp::ArgMatch;
///
/// // No CLONE_NEWUSER (0x1000_0000) in the first argument.
/// let condition = ArgMatch::none_of(0, 0x1000_0000);
/// assert!(condition.matches(&[0x0011, 0, 0, 0, 0, 0]));
/// assert!(!condition.matches(&[0x1000_0011, 0, 0, 0, 0, 0]));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ArgMatch {
    index: u8,
    mask: u64,
    value: u64,
}

impl ArgMatch {
    /// Matches when `args[index] & mask == value & mask`. `index` must be
    /// below 6, which [`compile`] checks.
    #[must_use]
    pub const fn masked_eq(index: u8, mask: u64, value: u64) -> Self {
        Self {
            index,
            mask,
            value: value & mask,
        }
    }

    /// Matches when none of `bits` is set in `args[index]`.
    #[must_use]
    pub const fn none_of(index: u8, bits: u64) -> Self {
        Self::masked_eq(index, bits, 0)
    }

    /// The argument's index, from 0.
    #[must_use]
    pub const fn index(self) -> u8 {
        self.index
    }

    /// The bits compared.
    #[must_use]
    pub const fn mask(self) -> u64 {
        self.mask
    }

    /// The value the masked argument must equal.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.value
    }

    /// Whether a call with `args` meets the condition, as the compiled
    /// filter decides it. An out-of-range index never matches.
    #[must_use]
    pub fn matches(self, args: &[u64; 6]) -> bool {
        args.get(usize::from(self.index))
            .is_some_and(|arg| arg & self.mask == self.value)
    }

    fn to_seccompiler(self) -> Result<SeccompCondition, Error> {
        if self.index >= 6 {
            return Err(Error::InvalidFilter {
                reason: format!("argument index {} is out of range (0 to 5)", self.index),
            });
        }
        SeccompCondition::new(
            self.index,
            SeccompCmpArgLen::Qword,
            SeccompCmpOp::MaskedEq(self.mask),
            self.value,
        )
        .map_err(|err| invalid(&err))
    }
}

/// A seccomp-bpf filter: a list of system calls, what happens to them, and
/// what happens to every other call.
///
/// [`Options::allowlist`] builds a deny-by-default filter (the listed calls
/// run, everything else gets the deny action); [`Options::denylist`] the
/// reverse. The filter is checked against the native architecture: calls
/// made through another ABI (32-bit compat on `x86_64` or `aarch64`) kill
/// the process, and x32 calls on `x86_64` get the filter's deny action.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Options {
    /// The listed system calls.
    pub syscalls: BTreeSet<Syscall>,
    /// What happens to a listed call.
    pub listed_action: Action,
    /// What happens to every other call.
    pub default_action: Action,
    /// What to do on a kernel that cannot enforce the filter as requested.
    /// Default: [`Compatibility::BestEffort`].
    pub compatibility: Compatibility,
    /// Install the filter on every thread of the process (Linux 3.17),
    /// rather than only the calling one. Default: `false`.
    pub all_threads: bool,
    /// Argument conditions for listed calls: a call listed here gets the
    /// listed action only when its arguments meet every condition, and the
    /// default action otherwise. Set with [`Options::with_syscall_if`].
    pub conditions: BTreeMap<Syscall, Vec<ArgMatch>>,
    /// Calls with an action of their own, checked before the list and the
    /// conditions, such as `ENOSYS` for a call libc should fall back from.
    /// Set with [`Options::with_syscall_action`].
    pub actions: BTreeMap<Syscall, Action>,
}

impl Default for Options {
    /// An empty allowlist that fails every call with `EPERM`: add the calls
    /// the program needs with [`Options::with_syscall`].
    fn default() -> Self {
        Self::allowlist(Action::EPERM)
    }
}

impl Options {
    /// A deny-by-default filter: listed calls are allowed and every other
    /// call gets `otherwise`, typically [`Action::EPERM`], or [`Action::Log`]
    /// to audit what an allowlist is missing without enforcing it.
    #[must_use]
    pub const fn allowlist(otherwise: Action) -> Self {
        Self {
            syscalls: BTreeSet::new(),
            listed_action: Action::Allow,
            default_action: otherwise,
            compatibility: Compatibility::BestEffort,
            all_threads: false,
            conditions: BTreeMap::new(),
            actions: BTreeMap::new(),
        }
    }

    /// An allow-by-default filter: listed calls get `action` and every other
    /// call is allowed. See [`syscalls::DANGEROUS`] for a starting list.
    #[must_use]
    pub const fn denylist(action: Action) -> Self {
        Self {
            syscalls: BTreeSet::new(),
            listed_action: action,
            default_action: Action::Allow,
            compatibility: Compatibility::BestEffort,
            all_threads: false,
            conditions: BTreeMap::new(),
            actions: BTreeMap::new(),
        }
    }

    /// Adds a system call, by name or number, to the list, dropping any
    /// [conditions](Options::with_syscall_if) given for it before.
    #[must_use]
    pub fn with_syscall(mut self, syscall: impl Into<Syscall>) -> Self {
        let syscall = syscall.into();
        self.conditions.remove(&syscall);
        self.syscalls.insert(syscall);
        self
    }

    /// Adds several system calls to the list, as [`Options::with_syscall`].
    #[must_use]
    pub fn with_syscalls<I>(self, syscalls: I) -> Self
    where
        I: IntoIterator,
        I::Item: Into<Syscall>,
    {
        syscalls.into_iter().fold(self, Self::with_syscall)
    }

    /// Lists a system call, but only for calls whose arguments meet every
    /// one of `conditions` (see [`Options::conditions`]). In an allowlist
    /// this allows the call only with those arguments; in a denylist it
    /// denies it only with them.
    ///
    /// ```
    /// use rune_seccomp::{Action, Arch, ArgMatch, Options, compile, syscalls};
    ///
    /// # if Arch::native().is_none() { return Ok(()); }
    /// // Threads and fork, but no new user namespace.
    /// let options = Options::allowlist(Action::EPERM)
    ///     .with_syscall_if("clone", [ArgMatch::none_of(0, 0x1000_0000)]);
    /// let program = compile(&options)?;
    /// let clone = syscalls::resolve("clone").unwrap_or_default();
    /// assert_eq!(program.evaluate_with_args(clone, [0x11, 0, 0, 0, 0, 0]), Some(Action::Allow));
    /// assert_eq!(
    ///     program.evaluate_with_args(clone, [0x1000_0011, 0, 0, 0, 0, 0]),
    ///     Some(Action::EPERM)
    /// );
    /// # Ok::<(), rune_seccomp::Error>(())
    /// ```
    #[must_use]
    pub fn with_syscall_if(
        mut self,
        syscall: impl Into<Syscall>,
        conditions: impl IntoIterator<Item = ArgMatch>,
    ) -> Self {
        let syscall = syscall.into();
        self.conditions
            .entry(syscall.clone())
            .or_default()
            .extend(conditions);
        self.syscalls.insert(syscall);
        self
    }

    /// Gives a system call its own action, whatever the list says (see
    /// [`Options::actions`]).
    ///
    /// ```
    /// use rune_seccomp::{Action, Arch, Options, compile, syscalls};
    ///
    /// # if Arch::native().is_none() { return Ok(()); }
    /// let options = Options::allowlist(Action::EPERM)
    ///     .with_syscall("clone")
    ///     .with_syscall_action("clone3", Action::ENOSYS);
    /// let program = compile(&options)?;
    /// let clone3 = syscalls::resolve("clone3").unwrap_or_default();
    /// assert_eq!(program.evaluate(clone3), Some(Action::ENOSYS));
    /// # Ok::<(), rune_seccomp::Error>(())
    /// ```
    #[must_use]
    pub fn with_syscall_action(mut self, syscall: impl Into<Syscall>, action: Action) -> Self {
        self.actions.insert(syscall.into(), action);
        self
    }

    /// Sets [`Options::listed_action`].
    #[must_use]
    pub const fn with_listed_action(mut self, action: Action) -> Self {
        self.listed_action = action;
        self
    }

    /// Sets [`Options::default_action`].
    #[must_use]
    pub const fn with_default_action(mut self, action: Action) -> Self {
        self.default_action = action;
        self
    }

    /// Sets [`Options::compatibility`].
    #[must_use]
    pub const fn with_compatibility(mut self, compatibility: Compatibility) -> Self {
        self.compatibility = compatibility;
        self
    }

    /// Sets [`Options::all_threads`].
    #[must_use]
    pub const fn with_all_threads(mut self, all_threads: bool) -> Self {
        self.all_threads = all_threads;
        self
    }

    /// The action for calls that should not run: the default action unless
    /// that allows, otherwise the listed action.
    const fn deny_action(&self) -> Action {
        if matches!(self.default_action, Action::Allow) {
            self.listed_action
        } else {
            self.default_action
        }
    }
}

/// A compiled seccomp-bpf program for the native architecture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Program {
    instructions: BpfProgram,
    arch: Arch,
    rules: usize,
    skipped: Vec<String>,
}

impl Program {
    /// The number of BPF instructions (at most 4096).
    #[must_use]
    pub const fn len(&self) -> usize {
        self.instructions.len()
    }

    /// Always `false`: a program has at least an architecture check and a
    /// return.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.instructions.is_empty()
    }

    /// The architecture the program checks for.
    #[must_use]
    pub const fn arch(&self) -> Arch {
        self.arch
    }

    /// The number of system calls the program lists.
    #[must_use]
    pub const fn rules(&self) -> usize {
        self.rules
    }

    /// Listed names that are system calls on another architecture but not
    /// this one, and so were left out.
    #[must_use]
    pub fn skipped(&self) -> &[String] {
        &self.skipped
    }

    /// The program as an array of `struct sock_filter` in native byte
    /// order: the format `bwrap --seccomp FD` and `SECCOMP_SET_MODE_FILTER`
    /// take.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.instructions.len() * 8);
        for insn in &self.instructions {
            bytes.extend_from_slice(&insn.code.to_ne_bytes());
            bytes.push(insn.jt);
            bytes.push(insn.jf);
            bytes.extend_from_slice(&insn.k.to_ne_bytes());
        }
        bytes
    }

    /// What the program decides for native system call `number`, worked out
    /// in memory without installing anything. `None` for a number that is
    /// not a valid system call number.
    #[must_use]
    pub fn evaluate(&self, number: i64) -> Option<Action> {
        self.evaluate_with_args(number, [0; 6])
    }

    /// [`Program::evaluate`] for a call made with the given arguments, for
    /// filters with [argument conditions](Options::with_syscall_if).
    ///
    /// ```
    /// use rune_seccomp::{Action, Arch, ArgMatch, Options, compile, syscalls};
    ///
    /// # if Arch::native().is_none() { return Ok(()); }
    /// // Allow `personality(0)` only.
    /// let options = Options::allowlist(Action::EPERM)
    ///     .with_syscall_if("personality", [ArgMatch::masked_eq(0, u64::MAX, 0)]);
    /// let program = compile(&options)?;
    /// let personality = syscalls::resolve("personality").unwrap_or_default();
    /// assert_eq!(program.evaluate_with_args(personality, [0; 6]), Some(Action::Allow));
    /// assert_eq!(
    ///     program.evaluate_with_args(personality, [0x0040_0000, 0, 0, 0, 0, 0]),
    ///     Some(Action::EPERM)
    /// );
    /// # Ok::<(), rune_seccomp::Error>(())
    /// ```
    #[must_use]
    pub fn evaluate_with_args(&self, number: i64, args: [u64; 6]) -> Option<Action> {
        let number = u32::try_from(number).ok()?;
        bpf::run(&self.instructions, self.arch.audit_value(), number, args)
            .and_then(Action::from_ret)
    }

    /// What the program decides for a call with the raw `seccomp_data`
    /// architecture tag and number, such as a 32-bit compat call or an x32
    /// call (`number | 0x4000_0000`).
    #[must_use]
    pub fn evaluate_raw(&self, audit_arch: u32, number: u32) -> Option<Action> {
        bpf::run(&self.instructions, audit_arch, number, [0; 6]).and_then(Action::from_ret)
    }
}

/// Compiles `options` for the native architecture, using its actions as
/// given (no fallback). This checks the options without touching the
/// kernel.
pub fn compile(options: &Options) -> Result<Program, Error> {
    let arch = Arch::native().ok_or(Error::UnsupportedArch {
        arch: std::env::consts::ARCH,
    })?;
    let actions = [options.listed_action, options.default_action];
    for action in actions.iter().chain(options.actions.values()) {
        if let Action::Errno(errno) = action
            && *errno > MAX_ERRNO
        {
            return Err(Error::InvalidFilter {
                reason: format!("errno {errno} is larger than {MAX_ERRNO}"),
            });
        }
    }
    // The list does nothing when both actions agree, which is a mistake
    // unless some calls have their own action (a fallback can make the two
    // agree, see `plan`).
    let list_is_moot = options.listed_action == options.default_action;
    if list_is_moot && options.actions.is_empty() {
        return Err(Error::InvalidFilter {
            reason: format!(
                "listed and default actions are both {}",
                options.listed_action
            ),
        });
    }

    let mut skipped = Vec::new();
    // `None` lists the call unconditionally; otherwise the call is listed
    // when any of the rules (each a set of conditions) holds.
    let mut rules: BTreeMap<i64, Option<Vec<SeccompRule>>> = BTreeMap::new();
    for syscall in &options.syscalls {
        let Some(number) = resolve(syscall, &mut skipped)? else {
            continue;
        };
        let rule = match options.conditions.get(syscall) {
            Some(conditions) if !conditions.is_empty() => {
                let conditions = conditions
                    .iter()
                    .map(|condition| condition.to_seccompiler())
                    .collect::<Result<_, _>>()?;
                Some(SeccompRule::new(conditions).map_err(|err| invalid(&err))?)
            }
            _ => None,
        };
        match (
            rules.entry(number).or_insert_with(|| Some(Vec::new())),
            rule,
        ) {
            (Some(existing), Some(rule)) => existing.push(rule),
            (entry, _) => *entry = None,
        }
    }
    let mut overrides = BTreeMap::new();
    for (syscall, action) in &options.actions {
        if let Some(number) = resolve(syscall, &mut skipped)? {
            overrides.insert(number, *action);
        }
    }
    if list_is_moot {
        rules.clear();
    }
    let numbers = rules.len();

    let rules: BTreeMap<i64, Vec<SeccompRule>> = rules
        .into_iter()
        .map(|(number, rules)| (number, rules.unwrap_or_default()))
        .collect();
    // seccompiler refuses identical actions even with nothing listed; the
    // listed action is never used then, so any other one will do.
    let listed_action = if list_is_moot {
        if options.default_action == Action::Allow {
            Action::KillProcess
        } else {
            Action::Allow
        }
    } else {
        options.listed_action
    };
    let filter = SeccompFilter::new(
        rules,
        options.default_action.into_seccompiler(),
        listed_action.into_seccompiler(),
        arch.target(),
    )
    .map_err(|err| invalid(&err))?;
    let mut instructions = BpfProgram::try_from(filter).map_err(|err| invalid(&err))?;

    // Calls with their own action go right after seccompiler's
    // three-instruction architecture check (and the x32 guard below).
    let mut prologue = Vec::new();
    if !overrides.is_empty() {
        prologue.push(bpf::stmt(bpf::LD_W_ABS, bpf::NR_OFFSET));
        for (number, action) in &overrides {
            let number = u32::try_from(*number).map_err(|_| Error::InvalidFilter {
                reason: format!("system call number {number} is out of range"),
            })?;
            prologue.push(bpf::jump(bpf::JMP_JEQ_K, number, 0, 1));
            prologue.push(bpf::stmt(bpf::RET_K, action.to_ret()));
        }
    }
    let at = 3.min(instructions.len());
    instructions.splice(at..at, prologue);

    if arch == Arch::X86_64 {
        // x32 calls carry the x86_64 architecture tag and a number with
        // bit 30 set, so they match no listed number. Without this guard
        // `numbers | 0x4000_0000` would bypass a denylist. It goes after
        // seccompiler's three-instruction architecture check.
        let guard = [
            bpf::stmt(bpf::LD_W_ABS, bpf::NR_OFFSET),
            bpf::jump(bpf::JMP_JGE_K, bpf::X32_SYSCALL_BIT, 0, 1),
            bpf::stmt(bpf::RET_K, options.deny_action().to_ret()),
        ];
        let at = 3.min(instructions.len());
        instructions.splice(at..at, guard);
    }
    if instructions.len() > MAX_INSTRUCTIONS {
        return Err(Error::InvalidFilter {
            reason: format!(
                "the filter has {} BPF instructions; the kernel takes at most {MAX_INSTRUCTIONS}",
                instructions.len()
            ),
        });
    }

    Ok(Program {
        instructions,
        arch,
        rules: numbers,
        skipped,
    })
}

/// The native number of `syscall`, or `None` (and the name added to
/// `skipped`) for a call that only exists on another architecture.
fn resolve(syscall: &Syscall, skipped: &mut Vec<String>) -> Result<Option<i64>, Error> {
    match syscall {
        Syscall::Name(name) => match syscalls::resolve(name) {
            Some(number) => Ok(Some(number)),
            None if syscalls::is_known(name) => {
                if !skipped.contains(name) {
                    skipped.push(name.clone());
                }
                Ok(None)
            }
            None => Err(Error::UnknownSyscall { name: name.clone() }),
        },
        Syscall::Number(number) => {
            if (0..i64::from(bpf::X32_SYSCALL_BIT)).contains(number) {
                Ok(Some(*number))
            } else {
                Err(Error::InvalidFilter {
                    reason: format!("system call number {number} is out of range"),
                })
            }
        }
    }
}

/// `BPF_MAXINSNS`.
const MAX_INSTRUCTIONS: usize = 4096;

fn invalid(err: &seccompiler::BackendError) -> Error {
    Error::InvalidFilter {
        reason: err.to_string(),
    }
}

/// How much of the requested filter is in force.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Status {
    /// The filter is installed exactly as requested.
    FullyEnforced,
    /// The filter is installed, but with a fallback action or on the
    /// calling thread only; see [`Report`].
    PartiallyEnforced,
    /// Nothing was installed: the kernel has no seccomp, or the fallbacks
    /// left a filter that allows everything.
    NotEnforced,
}

/// What [`install`] did.
///
/// Check [`Report::status`]: on a kernel without seccomp, [`install`]
/// succeeds with [`Status::NotEnforced`] and nothing is filtered. Ignoring
/// the report is a warning:
///
/// ```compile_fail
/// #![deny(unused_must_use)]
/// fn restrict() -> Result<(), rune_seccomp::Error> {
///     rune_seccomp::install(&rune_seccomp::Options::default())?;
///     Ok(())
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[must_use = "check `status`: the filter may not be enforced at all"]
pub struct Report {
    /// How much of the filter is in force.
    pub status: Status,
    /// What the kernel offers.
    pub support: Support,
    /// The action installed for listed calls.
    pub listed_action: Action,
    /// The action installed for every other call.
    pub default_action: Action,
    /// Requested actions the kernel lacks, each with the fallback used.
    pub substitutions: Vec<(Action, Action)>,
    /// Listed names that are not system calls on this architecture.
    pub skipped: Vec<String>,
    /// The number of system calls listed in the installed filter.
    pub rules: usize,
    /// The program's length in BPF instructions (0 if nothing was installed).
    pub instructions: usize,
    /// Whether the filter was installed on every thread.
    pub all_threads: bool,
}

/// The decisions [`install`] makes before touching the kernel.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Plan {
    options: Options,
    substitutions: Vec<(Action, Action)>,
    /// Nothing worth installing.
    skip: bool,
}

fn plan(options: &Options, support: Support) -> Result<Plan, Error> {
    // Check the options even when nothing will be installed, so that a typo
    // shows up on every kernel.
    compile(options)?;
    let strict = options.compatibility == Compatibility::HardRequirement;
    if support == Support::NotSupported {
        if strict {
            return Err(Error::Unsupported { support });
        }
        return Ok(Plan {
            options: options.clone(),
            substitutions: Vec::new(),
            skip: true,
        });
    }

    let available = support.actions();
    let mut substitutions = Vec::new();
    let mut substitute = |action: Action| -> Result<Action, Error> {
        if available.contains(action) {
            return Ok(action);
        }
        let unavailable = Error::ActionUnavailable {
            action,
            available: if available.is_empty() {
                ActionSet::LEGACY
            } else {
                available
            },
        };
        match action.fallback() {
            Some(fallback) if !strict && available.contains(fallback) => {
                if !substitutions.contains(&(action, fallback)) {
                    substitutions.push((action, fallback));
                }
                Ok(fallback)
            }
            _ => Err(unavailable),
        }
    };
    let listed_action = substitute(options.listed_action)?;
    let default_action = substitute(options.default_action)?;
    let mut planned = options
        .clone()
        .with_listed_action(listed_action)
        .with_default_action(default_action);
    for action in planned.actions.values_mut() {
        let fallback = substitute(*action)?;
        *action = fallback;
    }
    let skip = listed_action == default_action
        && planned
            .actions
            .values()
            .all(|action| *action == default_action);
    Ok(Plan {
        options: planned,
        substitutions,
        skip,
    })
}

/// Installs the filter on the calling thread (or on every thread, with
/// [`Options::all_threads`]), for good: it cannot be removed, and it is
/// inherited by children and kept across `execve`.
///
/// This also sets `no_new_privs`, which the kernel requires of an
/// unprivileged process installing a filter: from then on, `execve` grants
/// no privileges (setuid bits and file capabilities are ignored).
///
/// Everything that allocates happens before the filter goes in, so an
/// allowlist only has to cover what the program does next.
pub fn install(options: &Options) -> Result<Report, Error> {
    install_with(options, detect())
}

/// [`install`], with the kernel's support detected earlier by [`detect`].
///
/// [`detect`] reads `/proc`; a caller that is about to lose access to it
/// (for instance by applying a Landlock ruleset first) detects support
/// beforehand and passes it in, so the right actions are chosen.
pub fn install_with(options: &Options, support: Support) -> Result<Report, Error> {
    let plan = plan(options, support)?;
    let mut report = Report {
        status: Status::NotEnforced,
        support,
        listed_action: plan.options.listed_action,
        default_action: plan.options.default_action,
        substitutions: plan.substitutions,
        skipped: Vec::new(),
        rules: 0,
        instructions: 0,
        all_threads: false,
    };
    if plan.skip {
        return Ok(report);
    }
    let program = compile(&plan.options)?;
    let best_effort = options.compatibility == Compatibility::BestEffort;

    let mut all_threads = options.all_threads;
    let mut result = if all_threads {
        seccompiler::apply_filter_all_threads(&program.instructions)
    } else {
        seccompiler::apply_filter(&program.instructions)
    };
    if all_threads && best_effort && is_einval(&result) {
        // Linux before 3.17 has no SECCOMP_FILTER_FLAG_TSYNC.
        all_threads = false;
        result = seccompiler::apply_filter(&program.instructions);
    }
    match result {
        Ok(()) => {}
        // Without /proc we guessed; the kernel says there is no seccomp.
        Err(_) if support == Support::Unknown && best_effort && is_einval(&result) => {
            return Ok(report);
        }
        Err(seccompiler::Error::Prctl(source) | seccompiler::Error::Seccomp(source)) => {
            return Err(Error::Install { source });
        }
        Err(seccompiler::Error::ThreadSync(thread)) => {
            return Err(Error::ThreadSync { thread });
        }
        Err(other) => {
            return Err(Error::InvalidFilter {
                reason: other.to_string(),
            });
        }
    }

    report.status = if report.substitutions.is_empty() && all_threads == options.all_threads {
        Status::FullyEnforced
    } else {
        Status::PartiallyEnforced
    };
    report.rules = program.rules;
    report.instructions = program.len();
    report.all_threads = all_threads;
    report.skipped = program.skipped;
    Ok(report)
}

fn is_einval(result: &Result<(), seccompiler::Error>) -> bool {
    matches!(
        result,
        Err(seccompiler::Error::Prctl(err) | seccompiler::Error::Seccomp(err))
            if err.raw_os_error() == Some(libc::EINVAL)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn native() -> Option<Arch> {
        let arch = Arch::native();
        if arch.is_none() {
            eprintln!("skipping: unsupported architecture");
        }
        arch
    }

    fn nr(name: &str) -> i64 {
        syscalls::resolve(name).unwrap()
    }

    #[test]
    fn allowlist_allows_listed_calls_and_denies_the_rest() {
        let Some(_) = native() else { return };
        let program = compile(&Options::allowlist(Action::EPERM).with_syscalls([
            "read",
            "write",
            "exit_group",
        ]))
        .unwrap();
        assert_eq!(program.rules(), 3);
        assert_eq!(program.evaluate(nr("read")), Some(Action::Allow));
        assert_eq!(program.evaluate(nr("exit_group")), Some(Action::Allow));
        assert_eq!(program.evaluate(nr("openat")), Some(Action::EPERM));
        assert_eq!(program.evaluate(nr("ptrace")), Some(Action::EPERM));
        assert_eq!(program.evaluate(-1), None);
    }

    #[test]
    fn denylist_denies_listed_calls_only() {
        let Some(_) = native() else { return };
        let program = compile(
            &Options::denylist(Action::Trap)
                .with_syscalls(syscalls::DANGEROUS.iter().copied())
                .with_syscall(nr("getppid")),
        )
        .unwrap();
        assert_eq!(program.evaluate(nr("ptrace")), Some(Action::Trap));
        assert_eq!(program.evaluate(nr("getppid")), Some(Action::Trap));
        assert_eq!(program.evaluate(nr("read")), Some(Action::Allow));
        assert_eq!(program.evaluate(nr("clone")), Some(Action::Allow));
    }

    #[test]
    fn other_architectures_are_killed() {
        let Some(arch) = native() else { return };
        let program = compile(&Options::denylist(Action::EPERM).with_syscall("ptrace")).unwrap();
        assert_eq!(program.arch(), arch);
        // i386 compat calls on x86_64 (AUDIT_ARCH_I386) and arm32 on aarch64.
        for foreign in [0x4000_0003, 0x4000_0028] {
            assert_eq!(program.evaluate_raw(foreign, 0), Some(Action::KillProcess));
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn x32_calls_cannot_bypass_a_denylist() {
        let program = compile(&Options::denylist(Action::EPERM).with_syscall("ptrace")).unwrap();
        let audit = Arch::X86_64.audit_value();
        let ptrace = u32::try_from(nr("ptrace")).unwrap();
        assert_eq!(program.evaluate_raw(audit, ptrace), Some(Action::EPERM));
        // x32 ptrace is 521; any x32 call is denied.
        for x32 in [ptrace, 521, 0] {
            assert_eq!(
                program.evaluate_raw(audit, x32 | bpf::X32_SYSCALL_BIT),
                Some(Action::EPERM)
            );
        }
        let allow = compile(&Options::allowlist(Action::Trap).with_syscall("read")).unwrap();
        assert_eq!(
            allow.evaluate_raw(audit, bpf::X32_SYSCALL_BIT),
            Some(Action::Trap)
        );
    }

    #[test]
    fn invalid_options_are_rejected() {
        let Some(_) = native() else { return };
        let err = compile(&Options::default().with_syscall("raed")).unwrap_err();
        assert!(matches!(err, Error::UnknownSyscall { ref name } if name == "raed"));
        let same = Options::default().with_listed_action(Action::EPERM);
        assert!(matches!(compile(&same), Err(Error::InvalidFilter { .. })));
        let errno = Options::allowlist(Action::Errno(4096));
        assert!(matches!(compile(&errno), Err(Error::InvalidFilter { .. })));
        let number = Options::default().with_syscall(0x4000_0000_i64);
        assert!(matches!(compile(&number), Err(Error::InvalidFilter { .. })));
    }

    #[test]
    fn empty_allowlist_denies_everything() {
        let Some(_) = native() else { return };
        let program = compile(&Options::default()).unwrap();
        assert_eq!(program.rules(), 0);
        assert_eq!(program.evaluate(nr("exit_group")), Some(Action::EPERM));
    }

    #[test]
    fn bytes_are_sock_filter_arrays() {
        let Some(_) = native() else { return };
        let program = compile(&Options::denylist(Action::EPERM).with_syscall("mount")).unwrap();
        let bytes = program.to_bytes();
        assert_eq!(bytes.len(), program.len() * 8);
        // First instruction: BPF_LD|BPF_W|BPF_ABS of seccomp_data.arch.
        assert_eq!(bytes[..2], bpf::LD_W_ABS.to_ne_bytes());
        assert_eq!(bytes[4..8], bpf::ARCH_OFFSET.to_ne_bytes());
    }

    #[test]
    fn plan_falls_back_on_old_kernels() {
        let Some(_) = native() else { return };
        let old = Support::Available {
            actions: ActionSet::LEGACY,
        };
        let options = Options::denylist(Action::KillProcess).with_syscall("ptrace");
        let plan = plan(&options, old).unwrap();
        assert_eq!(plan.options.listed_action, Action::KillThread);
        assert_eq!(
            plan.substitutions,
            vec![(Action::KillProcess, Action::KillThread)]
        );
        assert!(!plan.skip);

        // Logging-only allowlist on a kernel without SECCOMP_RET_LOG: both
        // sides allow, so there is nothing to install.
        let audit = Options::allowlist(Action::Log).with_syscall("read");
        assert!(super::plan(&audit, old).unwrap().skip);

        let strict = options.with_compatibility(Compatibility::HardRequirement);
        assert!(matches!(
            super::plan(&strict, old),
            Err(Error::ActionUnavailable {
                action: Action::KillProcess,
                ..
            })
        ));
    }

    fn args(first: u64) -> [u64; 6] {
        [first, 0, 0, 0, 0, 0]
    }

    #[test]
    fn conditions_restrict_a_listed_call() {
        let Some(_) = native() else { return };
        let none = ArgMatch::none_of(0, 0x1000_0000);
        let program = compile(
            &Options::allowlist(Action::EPERM)
                .with_syscall("read")
                .with_syscall_if("clone", [none]),
        )
        .unwrap();
        let clone = nr("clone");
        assert_eq!(program.rules(), 2);
        assert_eq!(
            program.evaluate_with_args(clone, args(0x11)),
            Some(Action::Allow)
        );
        assert_eq!(
            program.evaluate_with_args(clone, args(0x1000_0011)),
            Some(Action::EPERM)
        );
        assert_eq!(program.evaluate(nr("read")), Some(Action::Allow));
        assert_eq!(program.evaluate(nr("openat")), Some(Action::EPERM));

        // In a denylist the listed action applies only when they hold.
        let deny = compile(
            &Options::denylist(Action::EPERM)
                .with_syscall_if("clone", [ArgMatch::masked_eq(0, 0x1000_0000, 0x1000_0000)]),
        )
        .unwrap();
        assert_eq!(
            deny.evaluate_with_args(clone, args(0x11)),
            Some(Action::Allow)
        );
        assert_eq!(
            deny.evaluate_with_args(clone, args(0x1000_0011)),
            Some(Action::EPERM)
        );
    }

    #[test]
    fn conditions_compare_all_64_bits() {
        let Some(_) = native() else { return };
        let high = 1_u64 << 40;
        let program = compile(
            &Options::allowlist(Action::EPERM)
                .with_syscall_if("personality", [ArgMatch::masked_eq(0, u64::MAX, high | 8)]),
        )
        .unwrap();
        let personality = nr("personality");
        assert_eq!(
            program.evaluate_with_args(personality, args(high | 8)),
            Some(Action::Allow)
        );
        // Same low half, different high half, and the reverse.
        assert_eq!(
            program.evaluate_with_args(personality, args(8)),
            Some(Action::EPERM)
        );
        assert_eq!(
            program.evaluate_with_args(personality, args(high)),
            Some(Action::EPERM)
        );
        // The masked compare loads both halves of args[0].
        let loads: Vec<u32> = program
            .instructions
            .iter()
            .filter(|insn| insn.code == bpf::LD_W_ABS && insn.k >= bpf::ARGS_OFFSET)
            .map(|insn| insn.k)
            .collect();
        assert_eq!(loads, [bpf::ARGS_OFFSET + 4, bpf::ARGS_OFFSET]);
    }

    #[test]
    fn conditions_combine_per_call() {
        let Some(_) = native() else { return };
        let personality = nr("personality");
        let is = |value| ArgMatch::masked_eq(0, u64::MAX, value);
        // Two entries for the same call: either may hold.
        let either = Options::allowlist(Action::EPERM)
            .with_syscall_if("personality", [is(1)])
            .with_syscall_if(personality, [is(2)]);
        let program = compile(&either).unwrap();
        assert_eq!(program.rules(), 1);
        for (value, action) in [(1, Action::Allow), (2, Action::Allow), (3, Action::EPERM)] {
            assert_eq!(
                program.evaluate_with_args(personality, args(value)),
                Some(action)
            );
        }
        // Conditions given together must all hold.
        let both = Options::allowlist(Action::EPERM).with_syscall_if(
            "personality",
            [ArgMatch::none_of(0, 1), ArgMatch::none_of(0, 2)],
        );
        let program = compile(&both).unwrap();
        assert_eq!(
            program.evaluate_with_args(personality, args(4)),
            Some(Action::Allow)
        );
        assert_eq!(
            program.evaluate_with_args(personality, args(2)),
            Some(Action::EPERM)
        );
        // An unconditional entry for the same call wins.
        let program = compile(&either.with_syscall(personality)).unwrap();
        assert_eq!(
            program.evaluate_with_args(personality, args(3)),
            Some(Action::Allow)
        );
    }

    #[test]
    fn invalid_conditions_are_rejected() {
        let Some(_) = native() else { return };
        let options = Options::default().with_syscall_if("read", [ArgMatch::none_of(6, 1)]);
        assert!(matches!(
            compile(&options),
            Err(Error::InvalidFilter { .. })
        ));
        assert!(!ArgMatch::none_of(6, 1).matches(&[0; 6]));
    }

    #[test]
    fn calls_with_their_own_action_come_first() {
        let Some(_) = native() else { return };
        let options = Options::allowlist(Action::EPERM)
            .with_syscalls(["clone", "clone3"])
            .with_syscall_action("clone3", Action::ENOSYS)
            .with_syscall_action("openat", Action::EACCES);
        let program = compile(&options).unwrap();
        assert_eq!(program.evaluate(nr("clone3")), Some(Action::ENOSYS));
        assert_eq!(program.evaluate(nr("openat")), Some(Action::EACCES));
        assert_eq!(program.evaluate(nr("clone")), Some(Action::Allow));
        assert_eq!(program.evaluate(nr("read")), Some(Action::EPERM));

        let errno = Options::default().with_syscall_action("read", Action::Errno(4096));
        assert!(matches!(compile(&errno), Err(Error::InvalidFilter { .. })));
        let unknown = Options::default().with_syscall_action("raed", Action::ENOSYS);
        assert!(matches!(
            compile(&unknown),
            Err(Error::UnknownSyscall { .. })
        ));
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn x32_guard_still_covers_calls_with_their_own_action() {
        let program = compile(
            &Options::denylist(Action::EPERM).with_syscall_action("clone3", Action::ENOSYS),
        )
        .unwrap();
        let audit = Arch::X86_64.audit_value();
        assert_eq!(
            program.evaluate_raw(audit, bpf::X32_SYSCALL_BIT),
            Some(Action::EPERM)
        );
        assert_eq!(program.evaluate(nr("clone3")), Some(Action::ENOSYS));
    }

    #[test]
    fn plan_falls_back_for_calls_with_their_own_action() {
        let Some(_) = native() else { return };
        let old = Support::Available {
            actions: ActionSet::LEGACY,
        };
        // Audit allowlist on an old kernel: the list allows everything,
        // but `ptrace` still has to be killed.
        let options = Options::allowlist(Action::Log)
            .with_syscall("read")
            .with_syscall_action("ptrace", Action::KillProcess)
            .with_syscall_action("bpf", Action::KillProcess);
        let plan = plan(&options, old).unwrap();
        assert!(!plan.skip);
        assert_eq!(
            plan.substitutions,
            vec![
                (Action::Log, Action::Allow),
                (Action::KillProcess, Action::KillThread)
            ]
        );
        let program = compile(&plan.options).unwrap();
        assert_eq!(program.rules(), 0);
        assert_eq!(program.evaluate(nr("ptrace")), Some(Action::KillThread));
        assert_eq!(program.evaluate(nr("openat")), Some(Action::Allow));

        let harmless = Options::allowlist(Action::Log)
            .with_syscall("read")
            .with_syscall_action("ptrace", Action::Log);
        assert!(super::plan(&harmless, old).unwrap().skip);
    }

    #[test]
    fn plan_without_seccomp() {
        let Some(_) = native() else { return };
        let options = Options::default().with_syscall("read");
        assert!(plan(&options, Support::NotSupported).unwrap().skip);
        let strict = options.with_compatibility(Compatibility::HardRequirement);
        assert!(matches!(
            plan(&strict, Support::NotSupported),
            Err(Error::Unsupported { .. })
        ));
        // Typos are reported even when nothing would be installed.
        let typo = Options::default().with_syscall("raed");
        assert!(plan(&typo, Support::NotSupported).is_err());
    }

    #[test]
    fn plan_on_a_modern_kernel_changes_nothing() {
        let Some(_) = native() else { return };
        let modern = Support::Available {
            actions: ActionSet::ALL,
        };
        let options = Options::allowlist(Action::Log).with_syscall("read");
        let plan = plan(&options, modern).unwrap();
        assert_eq!(plan.options, options);
        assert_eq!(plan.substitutions.len(), 0);
    }
}
