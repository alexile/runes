//! TOML policy schema: parsing, hard validation, and advisory warnings.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};

use crate::resolve::{STANDARD_BIN_DIRS, resolve_allowed_binaries};
use crate::seccomp::denied_syscall_names;

/// A parsed sandbox policy, loaded from TOML.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Process, namespace and working-directory settings.
    #[serde(default)]
    pub sandbox: SandboxSection,
    /// Paths bound into or hidden from the sandbox.
    #[serde(default)]
    pub filesystem: FilesystemSection,
    /// Environment variables passed to or set for the sandboxed process.
    #[serde(default)]
    pub env: EnvSection,
    /// Commands the sandboxed process may execute.
    #[serde(default)]
    pub commands: CommandsSection,
    /// Syscall-level hardening, layered on top of the namespace/filesystem
    /// boundary. See [`crate::denied_syscall_names`] for the default deny list.
    #[serde(default)]
    pub seccomp: SeccompSection,
    /// Resource ceilings (processes, memory, CPU, ...) for the sandboxed
    /// process. Unlike every other section, these are opt-in rather than
    /// strict-by-default — see [`LimitsSection`] for why.
    #[serde(default)]
    pub limits: LimitsSection,
    /// Violation/audit logging — see [`AuditSection`]. Opt-in
    /// (`enabled = false` by default): it adds a real `strace` dependency
    /// and overhead to every syscall the sandboxed process makes, which
    /// is the right tradeoff while you're tuning a policy and the wrong
    /// one for routine runs once it's settled.
    #[serde(default, skip_serializing_if = "AuditSection::is_disabled")]
    pub audit: AuditSection,
    /// Domain- and IP/CIDR-scoped network egress, layered on top of
    /// `sandbox.network` — see [`NetworkSection`]. Opt-in (both fields
    /// empty by default): `sandbox.network` alone (`"none"`/`"full"`) is
    /// still the whole story unless you set this.
    #[serde(default, skip_serializing_if = "NetworkSection::is_disabled")]
    pub network: NetworkSection,
}

/// Namespace and top-level sandbox behavior. Every field defaults to its
/// strictest setting, with one deliberate exception: `landlock` defaults
/// to `false` — see its own docs for why.
#[allow(
    clippy::struct_excessive_bools,
    reason = "each flag is an independent, documented switch"
)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxSection {
    /// Network access for the sandboxed process. Defaults to [`Network::None`].
    #[serde(default)]
    pub network: Network,
    /// Kill the sandboxed process if this warden process dies. Defaults to `true`.
    #[serde(default = "default_true")]
    pub die_with_parent: bool,
    /// Run in a new terminal session, preventing the sandboxed process from
    /// injecting keystrokes into the parent terminal via `TIOCSTI`/`TIOCLINUX`.
    /// Defaults to `true`.
    #[serde(default = "default_true")]
    pub new_session: bool,
    /// Give the sandboxed process its own PID namespace (it becomes PID 1
    /// inside the sandbox and cannot see or signal host processes).
    /// Defaults to `true`; disable for tools that misbehave without a real
    /// init process to reap zombies.
    #[serde(default = "default_true")]
    pub unshare_pid: bool,
    /// Apply a Landlock ruleset (see [`crate::run_stub_if_invoked`]) as a
    /// second, independent filesystem enforcement layer alongside the
    /// mount-namespace whitelist — restricting the same paths a second
    /// time, at the VFS/inode level, so a bug in bwrap or the kernel's
    /// namespace code doesn't fully compromise containment on its own.
    /// Defaults to `false`, unlike most of this section: it degrades
    /// gracefully on kernels without Landlock support, but it's still a
    /// meaningfully different code path from every other policy (a
    /// separate stub process now sits between `bwrap` and the real
    /// program — see the module docs), and confirmed live to have real
    /// sharp edges worth opting into deliberately rather than inheriting
    /// silently: a real Claude Code session aborted under it outright
    /// (Bun's runtime hit a `ioctl()` Landlock's newer ABI versions gate
    /// on `/dev`, a path this crate doesn't otherwise have a reason to
    /// know about) before that specific gap was found and closed — other
    /// wrapped tools may yet hit ones that aren't. See the module docs
    /// for what this deliberately does *not* cover
    /// (`deny`/`read_only_override`'s narrowing semantics).
    #[serde(default)]
    pub landlock: bool,
    /// Give the sandboxed process its own IPC namespace. Defaults to `true`.
    #[serde(default = "default_true")]
    pub unshare_ipc: bool,
    /// Give the sandboxed process its own UTS (hostname) namespace.
    /// Defaults to `true`; automatically enabled if `hostname` is set.
    #[serde(default = "default_true")]
    pub unshare_uts: bool,
    /// Hostname to report inside the sandbox. Implies `unshare_uts`.
    #[serde(default)]
    pub hostname: Option<String>,
    /// Working directory for the sandboxed process. Defaults to `None`,
    /// which means "inherit whatever directory the process building this
    /// command happened to be running in" — the same thing bwrap itself
    /// falls back to. That default is easy to get wrong when this crate
    /// is used as a library rather than run from a shell in the right
    /// directory: set this explicitly (e.g. to your project directory)
    /// rather than relying on ambient `cwd`.
    #[serde(default)]
    pub cwd: Option<PathBuf>,
}

impl Default for SandboxSection {
    fn default() -> Self {
        Self {
            network: Network::default(),
            die_with_parent: true,
            new_session: true,
            unshare_pid: true,
            landlock: false,
            unshare_ipc: true,
            unshare_uts: true,
            hostname: None,
            cwd: None,
        }
    }
}

const fn default_true() -> bool {
    true
}

/// Network policy for the sandboxed process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    /// No network access — the network namespace is fully unshared.
    #[default]
    None,
    /// Unrestricted network access (same as the host).
    Full,
}

/// A filesystem path to bind into the sandbox, optionally at a different
/// location (`mount_as`) than it lives at on the host.
///
/// In TOML, this accepts either a bare path string — `"/etc/hosts"` — for
/// the common case (bind exactly this path, read-write/read-only as
/// determined by which array it's in, nothing special), or a table when
/// you need `mount_as`/`create`/`create_content`/
/// `acknowledge_executable_content`: `{ path = "/home/user/.claude",
/// create = "directory", acknowledge_executable_content = true }`. Both
/// forms can appear in the same array. This mirrors [`CommandRef`]'s bare
/// name vs. `{ name, path }` table — the same shorthand-when-you-can,
/// table-when-you-must shape, for the same reason: a policy with dozens
/// of entries (a real project's `commands.allow` and `filesystem.read_only`
/// both routinely get this large) is unreadable if every one of them
/// needs a four-line table just to say "also bind this file."
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(from = "PathEntryRepr", into = "PathEntryRepr")]
pub struct PathEntry {
    /// Host path to bind.
    pub path: PathBuf,
    /// Where to mount `path` inside the sandbox. Defaults to `path` itself.
    pub mount_as: Option<PathBuf>,
    /// If `path` doesn't exist on the host yet, create it as this kind of
    /// entry before binding. Off (`None`) by default: a missing source
    /// path is usually a configuration mistake worth failing loudly on.
    /// Set this for state a tool creates on first run — e.g. a config
    /// file or cache directory that doesn't exist until the sandboxed
    /// program writes it for the first time. Without this,
    /// [`crate::build_command`] would otherwise fail outright on a
    /// genuinely first-ever run, since bwrap refuses to bind a
    /// nonexistent source.
    pub create: Option<PathKind>,
    /// Initial content for a newly created file. Only meaningful when
    /// `create == Some(PathKind::File)` and `path` doesn't already exist;
    /// ignored otherwise. Matters more than it sounds: a program that
    /// expects a JSON config file, for instance, may treat a zero-byte
    /// file as *corrupted* rather than *absent* — set this to `"{}"` (or
    /// whatever that program's empty state looks like) rather than
    /// leaving it `None` and getting an empty file.
    pub create_content: Option<String>,
    /// Acknowledge that `path` is, or may come to contain, executable
    /// files, and bind it anyway even though `commands.allow` is set.
    /// Off by default: [`Policy::validate`] hard-refuses a bind
    /// containing executables under a non-empty `commands.allow`,
    /// because it silently makes every binary in it runnable regardless
    /// of the whitelist — confirmed directly, more than once (`bash -c
    /// '/usr/lib/openssh/ssh-keysign'` running under a policy that never
    /// allowed it; a Claude Code plugin's own installed hook script
    /// under `~/.claude` doing the same). This is deliberately a
    /// property of the individual entry, not one sandbox-wide switch —
    /// acknowledging that your own state directory legitimately holds
    /// executables shouldn't also silently wave through an unrelated
    /// `/usr/bin` bind added later.
    pub acknowledge_executable_content: bool,
}

impl PathEntry {
    /// The path this entry is visible at inside the sandbox.
    #[must_use]
    pub fn target(&self) -> &Path {
        self.mount_as.as_deref().unwrap_or(&self.path)
    }
}

impl From<PathBuf> for PathEntry {
    /// The plain "just bind this path, nothing special" entry — what a
    /// bare TOML string produces, and a convenient way to build one from
    /// Rust too (`path.into()`).
    fn from(path: PathBuf) -> Self {
        Self {
            path,
            mount_as: None,
            create: None,
            create_content: None,
            acknowledge_executable_content: false,
        }
    }
}

/// The on-the-wire shape [`PathEntry`] (de)serializes through — see its
/// docs for why both variants exist. `deny_unknown_fields` here (the same
/// pattern [`CommandRef`] already uses) means a typo'd field name in the
/// table form is a parse error, not a silently-dropped setting.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
enum PathEntryRepr {
    Bare(PathBuf),
    Full {
        path: PathBuf,
        #[serde(default)]
        mount_as: Option<PathBuf>,
        #[serde(default)]
        create: Option<PathKind>,
        #[serde(default)]
        create_content: Option<String>,
        #[serde(default, skip_serializing_if = "is_false")]
        acknowledge_executable_content: bool,
    },
}

#[allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde's skip_serializing_if passes the field by reference"
)]
const fn is_false(value: &bool) -> bool {
    !*value
}

impl From<PathEntryRepr> for PathEntry {
    fn from(repr: PathEntryRepr) -> Self {
        match repr {
            PathEntryRepr::Bare(path) => path.into(),
            PathEntryRepr::Full {
                path,
                mount_as,
                create,
                create_content,
                acknowledge_executable_content,
            } => Self {
                path,
                mount_as,
                create,
                create_content,
                acknowledge_executable_content,
            },
        }
    }
}

impl From<PathEntry> for PathEntryRepr {
    /// The inverse of the `From<PathEntryRepr> for PathEntry` conversion
    /// above, used for serialization: an entry with nothing set beyond
    /// `path` round-trips back out as the bare string a user would have
    /// written by hand, rather than a needlessly verbose table.
    fn from(entry: PathEntry) -> Self {
        if entry.mount_as.is_none()
            && entry.create.is_none()
            && entry.create_content.is_none()
            && !entry.acknowledge_executable_content
        {
            Self::Bare(entry.path)
        } else {
            Self::Full {
                path: entry.path,
                mount_as: entry.mount_as,
                create: entry.create,
                create_content: entry.create_content,
                acknowledge_executable_content: entry.acknowledge_executable_content,
            }
        }
    }
}

/// What kind of filesystem entry to create for a [`PathEntry`] whose
/// `create` field is set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PathKind {
    /// A regular file.
    File,
    /// A directory.
    Directory,
}

/// A path to hide from the sandboxed process, even if it falls under a
/// bound `read_only`/`read_write` ancestor. A narrowing exception within
/// an allowed path, not a general blacklist.
///
/// A single-field entry has no reason to ever be a TOML table — it
/// (de)serializes as a bare path string, e.g. `deny = ["/home/user/.ssh"]`,
/// not `[[filesystem.deny]] \n path = "..."`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(from = "PathBuf", into = "PathBuf")]
pub struct DenyEntry {
    /// Host path to hide.
    pub path: PathBuf,
}

impl From<PathBuf> for DenyEntry {
    fn from(path: PathBuf) -> Self {
        Self { path }
    }
}

impl From<DenyEntry> for PathBuf {
    fn from(entry: DenyEntry) -> Self {
        entry.path
    }
}

/// A symlink to create inside the sandbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SymlinkEntry {
    /// Path the symlink points to.
    pub target: PathBuf,
    /// Path of the symlink inside the sandbox.
    pub link: PathBuf,
}

/// A host device node to pass through into the sandbox (beyond the
/// minimal `/dev` bwrap provides by default). Same bare-string
/// (de)serialization as [`DenyEntry`], for the same reason.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(from = "PathBuf", into = "PathBuf")]
pub struct DeviceEntry {
    /// Host device node to pass through.
    pub path: PathBuf,
}

impl From<PathBuf> for DeviceEntry {
    fn from(path: PathBuf) -> Self {
        Self { path }
    }
}

impl From<DeviceEntry> for PathBuf {
    fn from(entry: DeviceEntry) -> Self {
        entry.path
    }
}

/// Filesystem visibility rules. Anything not listed here is invisible to
/// the sandboxed process.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct FilesystemSection {
    /// Paths bound in read-only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub read_only: Vec<PathEntry>,
    /// Paths bound in read-write.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub read_write: Vec<PathEntry>,
    /// Paths hidden even if they fall under a `read_only`/`read_write`
    /// ancestor (e.g. deny `$HOME/.ssh` while allowing `$HOME`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<DenyEntry>,
    /// Paths forced read-only even if they fall under a `read_write`
    /// ancestor — a narrowing exception like `deny`, but the path stays
    /// visible and readable rather than disappearing. Use this for a
    /// specific file inside an otherwise-writable directory whose
    /// *content* a sandboxed process must never be able to change,
    /// typically because some later, possibly entirely unsandboxed,
    /// process trusts that file enough to execute what it says.
    ///
    /// This exists because of a real, disclosed vulnerability class in
    /// exactly this shape (Claude Code sandbox escape, CVE-2026-25725):
    /// a sandboxed session wrote a malicious `.claude/settings.json`
    /// containing an auto-run hook; nothing bad happened during the
    /// sandboxed session itself, but the *next* time the user ran Claude
    /// Code normally — outside any sandbox — the planted hook executed
    /// with full host privileges. The sandbox correctly contained the
    /// live process; the exposure was a writable *control file* that
    /// silently became a persistence vector for a future, unsandboxed
    /// run. `deny` can't fix this (Claude Code needs to *read* its own
    /// settings to function) — this can: bind the file read-only,
    /// stacked after the read-write parent so it wins.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub read_only_override: Vec<PathEntry>,
    /// Symlinks to create inside the sandbox.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub symlink: Vec<SymlinkEntry>,
    /// Extra host device nodes to expose (e.g. `/dev/dri` for GPU access).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub device: Vec<DeviceEntry>,
}

impl FilesystemSection {
    fn bound_paths(&self) -> impl Iterator<Item = &PathEntry> {
        self.read_only
            .iter()
            .chain(self.read_write.iter())
            .chain(self.read_only_override.iter())
    }
}

/// Cap on how many filesystem entries [`directory_contains_executable`]
/// will inspect before giving up — keeps `Policy::validate` fast even if
/// someone binds something enormous (`/usr`, say); real bin/lib
/// directories trip the check within the first handful of entries.
const EXECUTABLE_SCAN_LIMIT: usize = 50_000;

/// Whether `path` is, or recursively contains, any regular file that
/// counts as "executable content that defeats `commands.allow`" — see
/// [`is_whitelist_defeating_executable`]. `allowed_names` is every name
/// already in `commands.allow`, needed to tell a harmless project script
/// from a genuine bypass. Used to catch "this bind defeats
/// commands.allow" regardless of what the directory is named — a fixed
/// list of "known" bin/lib directory names will always miss some real
/// layout on some real distro; actually looking is what generalizes.
fn directory_contains_executable(path: &Path, allowed_names: &HashSet<&str>) -> bool {
    use std::os::unix::fs::PermissionsExt;

    let mut stack = vec![path.to_path_buf()];
    let mut inspected = 0usize;

    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            inspected += 1;
            if inspected > EXECUTABLE_SCAN_LIMIT {
                return false;
            }
            let entry_path = entry.path();
            // Recurse into real (non-symlink) subdirectories only —
            // `entry.file_type()` doesn't follow symlinks, which avoids
            // ever walking into a symlink cycle.
            if entry.file_type().is_ok_and(|t| t.is_dir()) {
                stack.push(entry_path.clone());
            }
            // Whether this entry is a plain file or a symlink to one,
            // check what it actually resolves to — a `python3 ->
            // python3.11`-style symlink is exactly as runnable as a
            // plain executable, and library directories are full of
            // exactly that pattern. The permission bit alone isn't
            // trusted: an incidental +x on a data file (seen in
            // practice) shouldn't trip a hard validation error, so this
            // also requires the content to actually look executable.
            if let Ok(metadata) = std::fs::metadata(&entry_path)
                && metadata.is_file()
                && metadata.permissions().mode() & 0o111 != 0
                && is_whitelist_defeating_executable(&entry_path, allowed_names)
            {
                return true;
            }
        }
    }
    false
}

/// Whether running `path` directly would grant capability beyond what
/// `commands.allow` already permits — not simply "the kernel would
/// execve this."
///
/// - A raw ELF binary always counts: it's independent code, reachable
///   through nothing else in the policy.
/// - A `#!` shebang script only counts if its interpreter *isn't*
///   already an allowed command. If `sh`/`bash`/`node`/... are already
///   in `commands.allow`, directly exec'ing a project's own
///   `./build.sh` grants nothing an agent couldn't already do via
///   `bash build.sh` — treating it as a violation anyway would fail
///   `Policy::validate` on nearly every real project, since almost any
///   real repository has at least one `chmod +x` script in it,
///   confirmed directly: a bare `#!/bin/sh` script committed to an
///   otherwise-empty project directory was enough to hard-fail
///   policy validation before this distinction existed, directly
///   contradicting "usable out of the box" for the exact common case
///   that phrase is supposed to cover. `#!/usr/bin/env <name>` is
///   handled the same way, using `<name>` rather than `env` itself
///   (`env` being in `commands.allow` wouldn't tell you anything about
///   what it's about to run).
fn is_whitelist_defeating_executable(path: &Path, allowed_names: &HashSet<&str>) -> bool {
    use std::io::Read;
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    let mut buf = [0u8; 256];
    let Ok(n) = file.read(&mut buf) else {
        return false;
    };
    if n >= 4 && &buf[..4] == b"\x7fELF" {
        return true;
    }
    if n < 2 || &buf[..2] != b"#!" {
        return false;
    }
    let line_end = buf[..n].iter().position(|&b| b == b'\n').unwrap_or(n);
    let mut words = std::str::from_utf8(&buf[2..line_end])
        .unwrap_or("")
        .split_whitespace();
    let Some(first) = words.next() else {
        return true; // an empty shebang line is unusual enough to treat conservatively
    };
    let interpreter = Path::new(first).file_name().and_then(|n| n.to_str());
    let interpreter = match interpreter {
        Some("env") => words.next(), // "#!/usr/bin/env python3" — the real interpreter is the next word
        other => other,
    };
    interpreter.is_none_or(|name| !allowed_names.contains(name))
}

/// Environment variable rules. Every variable not covered by `allow` or
/// `set` is stripped before the sandboxed process starts.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct EnvSection {
    /// Variable names passed through from the host environment, if present.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
    /// Variables always injected with a fixed value, regardless of the
    /// host environment. Takes precedence over `allow` for the same name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub set: BTreeMap<String, String>,
}

/// A single allowed command — a bare name (resolved against `PATH`) or an
/// explicit `{ name, path }` table pinning the exact binary to bind.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum CommandRef {
    /// A bare command name, resolved against `PATH`.
    Name(String),
    /// A command pinned to an explicit binary.
    Entry {
        /// Command name.
        name: String,
        /// Absolute path of the binary to bind; resolved against `PATH` when absent.
        #[serde(default)]
        path: Option<PathBuf>,
    },
}

impl CommandRef {
    /// The command name.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Name(name) | Self::Entry { name, .. } => name,
        }
    }

    /// The explicitly pinned binary path, if any.
    #[must_use]
    pub fn explicit_path(&self) -> Option<&Path> {
        match self {
            Self::Name(_) => None,
            Self::Entry { path, .. } => path.as_deref(),
        }
    }
}

/// Commands the sandboxed process is allowed to execute. Nothing else is
/// executable, regardless of what filesystem paths are otherwise visible
/// (see the module-level whitelist caveat).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct CommandsSection {
    /// Allowed commands.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<CommandRef>,
}

/// Syscall filtering, applied to the sandboxed process via a compiled
/// seccomp-bpf program (see [`crate::compiled_seccomp_program`]).
///
/// Defense in depth beneath the namespace/filesystem boundary: even a process
/// that somehow reaches a file it shouldn't can't `ptrace` a sibling, load a
/// kernel module, or remount something to get around the sandbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeccompSection {
    /// Apply the hardened default-deny syscall list. Defaults to `true`.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Syscall names to remove from the default deny list, for tools that
    /// genuinely need one of them (e.g. a real debugger needing `ptrace`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
    /// Additional raw syscall numbers to deny, beyond the curated default
    /// list — an advanced, architecture-specific escape hatch for syscalls
    /// not already covered by name.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny_numbers: Vec<i64>,
    /// Send `SIGSYS` (kill the process) on a denied syscall instead of
    /// returning `EPERM`. `EPERM` (the default, `false`) lets the process
    /// see and report a normal permission error; killing is a harder
    /// boundary but can turn a single blocked syscall deep in a dependency
    /// into a confusing crash with no error message.
    #[serde(default)]
    pub kill: bool,
}

impl Default for SeccompSection {
    fn default() -> Self {
        Self {
            enabled: true,
            allow: Vec::new(),
            deny_numbers: Vec::new(),
            kill: false,
        }
    }
}

/// Resource ceilings for the sandboxed process, applied as POSIX rlimits.
///
/// Unlike filesystem/network/command/env rules, these are **opt-in**
/// (`None` by default) rather than strict-by-default. A safe universal
/// number doesn't exist: too low and a real build or Node's worker-thread
/// pool breaks with a confusing resource error instead of a clear config
/// error; too high and the limit is theater. Filesystem/network/command
/// rules default to "nothing" because "nothing" is always a safe,
/// unambiguous starting point for *scope* — there's no equivalent safe
/// default for *capacity*, so it's left to you to size for your workload.
/// The one exception is `disable_core_dumps`, which defaults to `true`
/// since it has no workflow-breaking downside.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsSection {
    /// Maximum number of processes/threads (`RLIMIT_NPROC`). Caps fork
    /// bombs, but modern runtimes (Node's libuv pool, Rust's thread pools)
    /// can legitimately want dozens to low hundreds of threads.
    ///
    /// Read this limit's scope carefully: on Linux, `RLIMIT_NPROC` is
    /// accounted against the *real UID*, system-wide — not per process
    /// tree and not per PID namespace. If the sandboxed process runs
    /// under the same UID as the rest of your login session (the common
    /// case, since bwrap is unprivileged and doesn't change UID), a fork
    /// bomb inside the sandbox counts against, and can exhaust, the same
    /// process quota your shell and every other program you're running
    /// share — this limit does not, by itself, confine the damage to the
    /// sandbox. Run the sandboxed process under a dedicated UID, or pair
    /// this with a cgroup v2 `pids.max` controller scoped to the sandbox,
    /// if you need the cap to actually stay contained.
    #[serde(default)]
    pub max_processes: Option<u64>,
    /// Maximum virtual address space in megabytes (`RLIMIT_AS`).
    #[serde(default)]
    pub memory_mb: Option<u64>,
    /// Maximum CPU time in seconds (`RLIMIT_CPU`).
    #[serde(default)]
    pub cpu_seconds: Option<u64>,
    /// Maximum open file descriptors (`RLIMIT_NOFILE`).
    #[serde(default)]
    pub max_open_files: Option<u64>,
    /// Maximum size of any single file the process writes, in megabytes
    /// (`RLIMIT_FSIZE`).
    #[serde(default)]
    pub max_file_size_mb: Option<u64>,
    /// Disable core dumps (`RLIMIT_CORE = 0`) so a crashing sandboxed
    /// process can't leave secrets that were in memory sitting in a core
    /// file on disk. Defaults to `true`.
    #[serde(default = "default_true")]
    pub disable_core_dumps: bool,
}

impl Default for LimitsSection {
    fn default() -> Self {
        Self {
            max_processes: None,
            memory_mb: None,
            cpu_seconds: None,
            max_open_files: None,
            max_file_size_mb: None,
            disable_core_dumps: true,
        }
    }
}

/// Violation/audit logging.
///
/// Traces the whole sandboxed run with a host-side `strace` and turns denied filesystem/exec/network syscalls
/// into a readable summary after the run finishes — see
/// [`crate::summarize_audit_log`] for the mechanism.
///
/// Answers "what did the policy actually block?" without guesswork from a bare
/// `ENOENT`/`EACCES` the wrapped program reports on its own, which rarely says
/// *why*.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AuditSection {
    /// Off by default — see this field's parent doc comment on why this
    /// one isn't strict-by-default like most of this schema. Omitted
    /// from serialized output entirely when `false`, same noise-reduction
    /// reasoning as the rest of this schema's optional sections: a
    /// generated policy that isn't using audit mode shouldn't need an
    /// `[audit]\nenabled = false` a reader has to notice is inert.
    #[serde(default, skip_serializing_if = "is_false")]
    pub enabled: bool,
}

impl AuditSection {
    const fn is_disabled(&self) -> bool {
        !self.enabled
    }
}

/// Domain- and IP-scoped network egress allowlisting.
///
/// When either field below is non-empty, the sandboxed process gets a
/// fully isolated network namespace (regardless of `sandbox.network`) whose
/// *only* path out is a host-side CONNECT-only proxy, reachable exclusively via
/// a bind-mounted Unix domain socket — so a process that ignores
/// `HTTP_PROXY`/`HTTPS_PROXY` doesn't get silently unfiltered access the way it
/// would with a shared network namespace and a cooperating-only proxy; it gets
/// no network at all. The real limitation is narrower and still worth stating
/// plainly: this is an HTTP CONNECT tunnel, so it only handles TCP traffic a
/// client routes through an HTTP-style proxy — a program speaking raw TCP/UDP
/// without any proxy awareness has no path out either way, allowed or not.
///
/// A domain allowed via `allowed_domains` is resolved once by the
/// host-side proxy and, unless the resolved address is separately covered
/// by `allowed_ips`, refused if that resolution lands in a private,
/// loopback, link-local, or otherwise non-globally-routable range — the
/// standard defense against a DNS-rebinding attack using an allowed
/// domain to reach an internal service or a cloud metadata endpoint
/// (`169.254.169.254`) that was never meant to be reachable. The proxy,
/// its range list and the pinning are `rune-egress-proxy`'s.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct NetworkSection {
    /// Domains the sandboxed process may reach, to the exclusion of
    /// everything else. Exact match (`"api.anthropic.com"`) or a
    /// `*.`-prefixed wildcard suffix match (`"*.anthropic.com"`, which
    /// does not itself match the bare `anthropic.com`). Still subject to
    /// the DNS-rebinding check described above.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_domains: Vec<String>,
    /// Bare IP addresses or CIDR ranges (`"10.0.0.5"`, `"10.0.0.0/24"`,
    /// IPv4 or IPv6) the sandboxed process may reach by address directly,
    /// *and* the opt-in override for a domain in `allowed_domains` that
    /// legitimately resolves into a private/reserved range (an internal
    /// registry, a private CI runner, ...). A bare-IP `CONNECT` target is
    /// only ever reachable through this list — unlike a hostname target,
    /// there is no "publicly routable, so allow it" fallback for an IP
    /// literal, since a literal bypasses domain-allowlisting entirely.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_ips: Vec<String>,
}

impl NetworkSection {
    const fn is_disabled(&self) -> bool {
        self.allowed_domains.is_empty() && self.allowed_ips.is_empty()
    }
}

/// Errors produced while loading, validating, or acting on a policy.
#[derive(Debug)]
pub enum WardenError {
    /// A file could not be read.
    Io(String),
    /// The policy TOML failed to parse.
    Parse(String),
    /// The `bwrap` (bubblewrap) binary is not on `PATH`.
    BwrapNotFound,
    /// The policy is self-contradictory or unsafe in a way that isn't
    /// worth merely warning about — see [`Policy::validate`].
    Invalid(Vec<String>),
    /// `bwrap` is installed but couldn't actually construct a sandbox on
    /// this host (e.g. unprivileged user namespaces are disabled).
    Preflight(String),
}

impl fmt::Display for WardenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(detail) => write!(formatter, "{detail}"),
            Self::Parse(detail) => write!(formatter, "invalid policy: {detail}"),
            Self::BwrapNotFound => formatter.write_str(
                "bubblewrap ('bwrap') was not found on PATH — install it (e.g. `apt install bubblewrap`) to use rune-secops-warden",
            ),
            Self::Invalid(reasons) => {
                write!(formatter, "policy rejected: {}", reasons.join("; "))
            }
            Self::Preflight(detail) => {
                write!(formatter, "bwrap sandbox self-test failed: {detail}")
            }
        }
    }
}

impl Error for WardenError {}

impl Policy {
    /// Load and parse a policy from a TOML file. Does not run
    /// [`Policy::validate`] — call it explicitly, or use
    /// [`crate::build_command`], which validates for you.
    pub fn load(path: &Path) -> Result<Self, WardenError> {
        let text = std::fs::read_to_string(path)
            .map_err(|err| WardenError::Io(format!("{}: {err}", path.display())))?;
        toml::from_str(&text).map_err(|err| WardenError::Parse(err.to_string()))
    }

    /// Hard validation: reasons this policy must not be used as-is. Unlike
    /// [`Policy::warnings`], these aren't stylistic — they mean the policy
    /// doesn't actually provide the isolation it appears to.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        for entry in &self.network.allowed_ips {
            if let Err(reason) = rune_egress_proxy::Policy::new().allow_ip(entry) {
                errors.push(format!("network.allowed_ips: {reason}"));
            }
        }
        // A malformed pattern used to be accepted and simply never match;
        // now that rune-egress-proxy parses patterns up front, say so here.
        for entry in &self.network.allowed_domains {
            if let Err(reason) = rune_egress_proxy::Policy::new().allow_host(entry) {
                errors.push(format!("network.allowed_domains: {reason}"));
            }
        }

        for entry in self.filesystem.bound_paths() {
            if entry.path == Path::new("/") {
                errors.push(
                    "filesystem.read_only/read_write binds \"/\" — this exposes the entire host filesystem, which can never be intentional".to_string(),
                );
            }
        }

        for entry in &self.filesystem.deny {
            // `symlink_metadata` (unlike `metadata`/`is_dir`) does not
            // follow the symlink, so this actually detects "the deny
            // target itself is a symlink" rather than asking about
            // whatever it points at. Confirmed live: bwrap refuses to
            // mask a path that's already a symlink at bind time
            // ("Can't create file at <path>: No such file or
            // directory"), aborting the whole sandboxed run with an
            // error that gives no hint the cause was `filesystem.deny`
            // — worth catching here with a message that actually says
            // so, rather than only at `bwrap` invocation time.
            if let Ok(metadata) = std::fs::symlink_metadata(&entry.path)
                && metadata.file_type().is_symlink()
            {
                errors.push(format!(
                    "filesystem.deny path {} is itself a symlink — bwrap cannot mask a path that is a symlink at bind time, and this policy would fail outright at run time with a low-level bwrap error. Point this entry at the symlink's real target instead, or remove the symlink",
                    entry.path.display()
                ));
            }
        }

        if !self.commands.allow.is_empty() {
            let allowed_names: HashSet<&str> =
                self.commands.allow.iter().map(CommandRef::name).collect();
            for entry in self.filesystem.bound_paths() {
                if entry.acknowledge_executable_content {
                    continue;
                }
                // Two checks, not one: a fixed name list (`/usr/bin`,
                // `/bin`, ...) is fast but can only catch directories
                // whose danger someone already thought to name — exactly
                // how this whole check first missed `/usr/lib`, `/lib`,
                // `/lib64`, confirmed live: `bash -c
                // '/usr/lib/openssh/ssh-keysign'` ran successfully under
                // a policy whose commands.allow never mentioned it,
                // purely because /usr/lib was bound. Actually scanning
                // the bound directory's real contents for executable
                // files catches that regardless of what the directory
                // happens to be called, on any host, any distro layout.
                let is_known_bin_dir = STANDARD_BIN_DIRS
                    .iter()
                    .any(|dir| entry.path == Path::new(dir));
                let contains_executables =
                    directory_contains_executable(&entry.path, &allowed_names);
                if is_known_bin_dir || contains_executables {
                    errors.push(format!(
                        "filesystem binds {} as well as setting commands.allow — binding a directory containing executable files makes every binary in it runnable, silently defeating the command whitelist. Remove the bind, or set this entry's acknowledge_executable_content = true to confirm that's intended",
                        entry.path.display()
                    ));
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Human-readable warnings about this policy that don't prevent it
    /// from being used, but likely indicate a misconfiguration.
    #[must_use]
    pub fn warnings(&self) -> Vec<String> {
        const PROCESS_INSPECTION_SYSCALLS: [&str; 3] =
            ["ptrace", "process_vm_readv", "process_vm_writev"];

        let mut warnings = Vec::new();
        if self.sandbox.network == Network::Full
            && self.network.allowed_domains.is_empty()
            && self.network.allowed_ips.is_empty()
        {
            warnings
                .push("sandbox.network = \"full\" grants unrestricted network access".to_string());
        }
        if self.filesystem.read_write.is_empty() {
            warnings.push(
                "no filesystem.read_write paths configured — the sandboxed process cannot write anywhere"
                    .to_string(),
            );
        }

        let resolved = resolve_allowed_binaries(&self.commands);
        let resolved_names: HashSet<&str> = resolved.iter().map(|r| r.name.as_str()).collect();
        for entry in &self.commands.allow {
            if !resolved_names.contains(entry.name()) {
                warnings.push(format!(
                    "commands.allow entry '{}' did not resolve to any binary on this host",
                    entry.name()
                ));
            }
        }

        if self.env.allow.iter().any(|name| name == "PATH") && !self.commands.allow.is_empty() {
            warnings.push(
                "env.allow contains \"PATH\" alongside a non-empty commands.allow — this passes \
                 through the calling process's own $PATH rather than a value scoped to the \
                 sandbox, and if that $PATH has a writable directory ahead of the system ones \
                 (a venv, node_modules/.bin, direnv shims), the sandboxed process can shadow an \
                 allowed command's bare name with its own script. Use env.set to pin PATH to \
                 fixed, non-writable directories instead."
                    .to_string(),
            );
        }
        if self.env.allow.iter().any(|name| name == "HOME") {
            warnings.push(
                "env.allow contains \"HOME\" — this passes through the calling process's own \
                 $HOME rather than the path actually bound in the sandbox. Use env.set to pin \
                 HOME explicitly instead."
                    .to_string(),
            );
        }
        if !self.sandbox.unshare_pid {
            warnings.push(
                "sandbox.unshare_pid = false — the sandboxed process shares the host's PID \
                 namespace and can see and signal every host process (bwrap still mounts the \
                 real, unfiltered /proc in this mode), not just its own subtree."
                    .to_string(),
            );
        }

        if !self.seccomp.enabled {
            warnings.push(
                "seccomp.enabled = false — syscall-level hardening (ptrace, mount, kernel keyring, ...) is off"
                    .to_string(),
            );
        }

        if !self.sandbox.unshare_pid
            && self
                .seccomp
                .allow
                .iter()
                .any(|name| PROCESS_INSPECTION_SYSCALLS.contains(&name.as_str()))
        {
            warnings.push(
                "sandbox.unshare_pid = false combined with seccomp.allow permitting a \
                 process-inspection syscall (ptrace/process_vm_readv/process_vm_writev) — the \
                 sandboxed process can now both see every host process AND read or trace their \
                 memory, not just one or the other. Each setting is individually intentional \
                 sometimes, but together they remove two independent layers protecting the rest \
                 of your session at once."
                    .to_string(),
            );
        }
        let known_syscalls = denied_syscall_names();
        for name in &self.seccomp.allow {
            if !known_syscalls.contains(&name.as_str()) {
                warnings.push(format!(
                    "seccomp.allow entry '{name}' does not match any syscall in the default deny list — likely a typo"
                ));
            }
        }

        warnings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_round_trips_through_toml() {
        // Serialize exists so a CLI can print/save a preset-built Policy
        // as a starting-point TOML file — verify it actually round-trips.
        let mut policy = Policy::default();
        policy.filesystem.read_write.push(PathEntry {
            path: PathBuf::from("/home/user/project"),
            mount_as: None,
            create: None,
            create_content: None,
            acknowledge_executable_content: false,
        });
        policy
            .commands
            .allow
            .push(CommandRef::Name("git".to_string()));
        let text = toml::to_string_pretty(&policy).unwrap();
        let round_tripped: Policy = toml::from_str(&text).unwrap();
        assert_eq!(
            round_tripped.filesystem.read_write[0].path,
            policy.filesystem.read_write[0].path
        );
        assert_eq!(round_tripped.commands.allow[0].name(), "git");
    }

    #[test]
    fn path_entry_accepts_a_bare_string_shorthand() {
        let text = r#"
            [filesystem]
            read_only = ["/etc/hosts", "/etc/resolv.conf"]
        "#;
        let policy: Policy = toml::from_str(text).unwrap();
        assert_eq!(policy.filesystem.read_only.len(), 2);
        assert_eq!(
            policy.filesystem.read_only[0].path,
            PathBuf::from("/etc/hosts")
        );
        assert!(policy.filesystem.read_only[0].mount_as.is_none());
        assert!(!policy.filesystem.read_only[0].acknowledge_executable_content);
    }

    #[test]
    fn path_entry_still_accepts_the_full_table_form() {
        let text = r#"
            [filesystem]

            [[filesystem.read_write]]
            path = "/home/user/.claude"
            create = "directory"
            acknowledge_executable_content = true
        "#;
        let policy: Policy = toml::from_str(text).unwrap();
        assert_eq!(
            policy.filesystem.read_write[0].path,
            PathBuf::from("/home/user/.claude")
        );
        assert_eq!(
            policy.filesystem.read_write[0].create,
            Some(PathKind::Directory)
        );
        assert!(policy.filesystem.read_write[0].acknowledge_executable_content);
    }

    #[test]
    fn path_entry_with_unknown_table_field_is_a_parse_error() {
        let text = r#"
            [filesystem]

            [[filesystem.read_write]]
            path = "/home/user/project"
            acknowledgee_executable_content = true
        "#;
        let result: Result<Policy, _> = toml::from_str(text);
        assert!(
            result.is_err(),
            "a typo'd field on a PathEntry table must fail to parse, not silently drop the setting"
        );
    }

    #[test]
    fn plain_path_entry_serializes_back_to_a_bare_string_not_a_table() {
        // The point of the shorthand: a policy built entirely from simple
        // entries should print as a compact array of strings, not force
        // every single one through a 4-line table just because the type
        // theoretically supports one.
        let mut policy = Policy::default();
        policy
            .filesystem
            .read_only
            .push(PathBuf::from("/etc/hosts").into());
        let text = toml::to_string_pretty(&policy).unwrap();
        assert!(
            text.contains(r#"read_only = ["/etc/hosts"]"#),
            "expected a bare string array, got:\n{text}"
        );
        assert!(!text.contains("[[filesystem.read_only]]"));
    }

    #[test]
    fn deny_and_device_entries_serialize_as_bare_strings() {
        let mut policy = Policy::default();
        policy.filesystem.deny.push(DenyEntry {
            path: PathBuf::from("/home/user/.ssh"),
        });
        policy.filesystem.device.push(DeviceEntry {
            path: PathBuf::from("/dev/null"),
        });
        let text = toml::to_string_pretty(&policy).unwrap();
        assert!(text.contains(r#"deny = ["/home/user/.ssh"]"#), "{text}");
        assert!(text.contains(r#"device = ["/dev/null"]"#), "{text}");
    }

    #[test]
    fn empty_sections_are_omitted_from_serialized_output() {
        // Noise reduction: a freshly-init'd policy's untouched sections
        // (no deny paths, no symlinks, no seccomp.allow overrides, ...)
        // shouldn't clutter the file with `field = []` lines a user then
        // has to read past to find what's actually configured.
        let text = toml::to_string_pretty(&Policy::default()).unwrap();
        assert!(!text.contains("deny = []"));
        assert!(!text.contains("symlink = []"));
        assert!(!text.contains("device = []"));
        assert!(!text.contains("allow = []"));
        assert!(!text.contains("deny_numbers = []"));
        assert!(
            !text.contains("[audit]"),
            "an unused [audit] table shouldn't appear at all, got:\n{text}"
        );
    }

    #[test]
    fn audit_enabled_true_still_serializes() {
        let mut policy = Policy::default();
        policy.audit.enabled = true;
        let text = toml::to_string_pretty(&policy).unwrap();
        assert!(text.contains("[audit]"));
        assert!(text.contains("enabled = true"));
        let round_tripped: Policy = toml::from_str(&text).unwrap();
        assert!(round_tripped.audit.enabled);
    }

    #[test]
    fn empty_policy_is_maximally_strict() {
        let policy: Policy = toml::from_str("").unwrap();
        assert_eq!(policy.sandbox.network, Network::None);
        assert!(policy.sandbox.die_with_parent);
        assert!(policy.sandbox.new_session);
        assert!(policy.sandbox.unshare_pid);
        assert!(policy.sandbox.unshare_ipc);
        assert!(policy.sandbox.unshare_uts);
        // The one deliberate exception to "every field defaults to its
        // strictest setting" — see `SandboxSection::landlock`'s docs for
        // why (real, confirmed sharp edges for wrapped tools this crate
        // hasn't traced yet, unlike the `claude_code` preset which turns
        // it on explicitly, having verified it there).
        assert!(!policy.sandbox.landlock);
        assert!(policy.filesystem.read_only.is_empty());
        assert!(policy.filesystem.read_write.is_empty());
        assert_eq!(policy.env.allow, [] as [String; 0]);
        assert!(policy.env.set.is_empty());
        assert!(policy.commands.allow.is_empty());
        assert!(policy.seccomp.enabled);
        assert!(policy.limits.disable_core_dumps);
        assert!(policy.limits.max_processes.is_none());
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn parses_full_policy() {
        let text = r#"
            [sandbox]
            network = "full"
            die_with_parent = false
            new_session = false
            unshare_pid = false
            hostname = "sandbox"

            [filesystem]
            read_only = ["/usr/lib"]
            deny = ["/home/user/.ssh"]
            device = ["/dev/null"]

            [[filesystem.read_write]]
            path = "/home/user/project"
            mount_as = "/workspace"

            [[filesystem.symlink]]
            target = "/usr/lib"
            link = "/lib"

            [env]
            allow = ["PATH", "HOME"]

            [env.set]
            CI = "true"

            [commands]
            allow = ["cat", { name = "git", path = "/usr/bin/git" }]

            [seccomp]
            enabled = false
            allow = ["ptrace"]
            deny_numbers = [335]
            kill = true

            [limits]
            max_processes = 256
            memory_mb = 2048
            cpu_seconds = 600
            max_open_files = 1024
            max_file_size_mb = 512
            disable_core_dumps = false
        "#;
        let policy: Policy = toml::from_str(text).unwrap();
        assert_eq!(policy.sandbox.network, Network::Full);
        assert!(!policy.sandbox.die_with_parent);
        assert!(!policy.sandbox.new_session);
        assert!(!policy.sandbox.unshare_pid);
        assert_eq!(policy.sandbox.hostname.as_deref(), Some("sandbox"));
        assert_eq!(policy.filesystem.read_only.len(), 1);
        assert_eq!(
            policy.filesystem.read_write[0].target(),
            Path::new("/workspace")
        );
        assert_eq!(
            policy.filesystem.deny[0].path,
            PathBuf::from("/home/user/.ssh")
        );
        assert_eq!(policy.filesystem.symlink[0].link, PathBuf::from("/lib"));
        assert_eq!(policy.filesystem.device[0].path, PathBuf::from("/dev/null"));
        assert_eq!(policy.env.allow, vec!["PATH", "HOME"]);
        assert_eq!(policy.env.set.get("CI").map(String::as_str), Some("true"));
        assert_eq!(policy.commands.allow[0].name(), "cat");
        assert_eq!(policy.commands.allow[1].name(), "git");
        assert_eq!(
            policy.commands.allow[1].explicit_path(),
            Some(Path::new("/usr/bin/git"))
        );
        assert!(!policy.seccomp.enabled);
        assert_eq!(policy.seccomp.allow, vec!["ptrace"]);
        assert_eq!(policy.seccomp.deny_numbers, vec![335]);
        assert!(policy.seccomp.kill);
        assert_eq!(policy.limits.max_processes, Some(256));
        assert_eq!(policy.limits.memory_mb, Some(2048));
        assert!(!policy.limits.disable_core_dumps);
    }

    #[test]
    fn validate_rejects_binding_root() {
        let policy = Policy {
            filesystem: FilesystemSection {
                read_only: vec![PathEntry {
                    path: PathBuf::from("/"),
                    mount_as: None,
                    create: None,
                    create_content: None,
                    acknowledge_executable_content: false,
                }],
                ..Default::default()
            },
            ..Default::default()
        };
        let errors = policy.validate().unwrap_err();
        assert!(errors.iter().any(|e| e.contains('"')));
    }

    #[test]
    fn validate_rejects_broad_bin_dir_with_command_whitelist() {
        let policy = Policy {
            filesystem: FilesystemSection {
                read_only: vec![PathEntry {
                    path: PathBuf::from("/usr/bin"),
                    mount_as: None,
                    create: None,
                    create_content: None,
                    acknowledge_executable_content: false,
                }],
                ..Default::default()
            },
            commands: CommandsSection {
                allow: vec![CommandRef::Name("cat".to_string())],
            },
            ..Default::default()
        };
        let errors = policy.validate().unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("acknowledge_executable_content"))
        );
    }

    #[test]
    fn validate_allows_broad_bin_dir_when_acknowledged() {
        let policy = Policy {
            filesystem: FilesystemSection {
                read_only: vec![PathEntry {
                    path: PathBuf::from("/usr/bin"),
                    mount_as: None,
                    create: None,
                    create_content: None,
                    acknowledge_executable_content: true,
                }],
                ..Default::default()
            },
            commands: CommandsSection {
                allow: vec![CommandRef::Name("cat".to_string())],
            },
            ..Default::default()
        };
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn validate_allows_a_project_script_whose_interpreter_is_already_allowed() {
        // Regression test: this is the exact false positive found by
        // actually running policy validation against a real project — a
        // single `chmod +x build.sh` (about as common as a real
        // repository gets) must not hard-fail validate() when `sh` is
        // already in commands.allow, since running the script directly
        // grants nothing `sh build.sh` doesn't already.
        let dir = std::env::temp_dir().join(format!(
            "rune-secops-warden-project-script-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("build.sh");
        std::fs::write(&script, "#!/bin/sh\necho hi\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let policy = Policy {
            filesystem: FilesystemSection {
                read_write: vec![PathEntry {
                    path: dir.clone(),
                    mount_as: None,
                    create: None,
                    create_content: None,
                    acknowledge_executable_content: false,
                }],
                ..Default::default()
            },
            commands: CommandsSection {
                allow: vec![CommandRef::Name("sh".to_string())],
            },
            ..Default::default()
        };
        assert!(
            policy.validate().is_ok(),
            "errors: {:?}",
            policy.validate().unwrap_err()
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn validate_rejects_a_project_script_whose_interpreter_is_not_allowed() {
        let dir = std::env::temp_dir().join(format!(
            "rune-secops-warden-project-script-test-unallowed-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("run.py");
        std::fs::write(&script, "#!/usr/bin/env python3\nprint('hi')\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let policy = Policy {
            filesystem: FilesystemSection {
                read_write: vec![PathEntry {
                    path: dir.clone(),
                    mount_as: None,
                    create: None,
                    create_content: None,
                    acknowledge_executable_content: false,
                }],
                ..Default::default()
            },
            // `sh` is allowed, but not `python3` — the script's actual
            // interpreter — so direct execution is still a real bypass.
            commands: CommandsSection {
                allow: vec![CommandRef::Name("sh".to_string())],
            },
            ..Default::default()
        };
        assert!(policy.validate().is_err());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn validate_still_rejects_a_raw_elf_binary_regardless_of_commands_allow() {
        let dir = std::env::temp_dir().join(format!(
            "rune-secops-warden-project-elf-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let binary = dir.join("prebuilt-tool");
        // Not a real, runnable ELF — just enough of a header for the
        // content-sniffing check, which is all `validate()` inspects.
        std::fs::write(&binary, b"\x7fELF\x02\x01\x01\x00").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let policy = Policy {
            filesystem: FilesystemSection {
                read_write: vec![PathEntry {
                    path: dir.clone(),
                    mount_as: None,
                    create: None,
                    create_content: None,
                    acknowledge_executable_content: false,
                }],
                ..Default::default()
            },
            commands: CommandsSection {
                allow: vec![CommandRef::Name("sh".to_string())],
            },
            ..Default::default()
        };
        assert!(
            policy.validate().is_err(),
            "a standalone ELF binary must still trip validate() even with commands.allow set — \
             it's independent code, not reachable through any allowed interpreter"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn unresolvable_command_is_silently_absent_but_warned_about() {
        let commands = CommandsSection {
            allow: vec![CommandRef::Name(
                "rune-secops-warden-definitely-not-a-real-binary".to_string(),
            )],
        };
        let resolved = crate::resolve::resolve_allowed_binaries_in(&commands, &[]);
        assert_eq!(resolved, [] as [crate::ResolvedCommand; 0]);

        let policy = Policy {
            commands,
            filesystem: FilesystemSection {
                read_write: vec![PathEntry {
                    path: PathBuf::from("/tmp"),
                    mount_as: None,
                    create: None,
                    create_content: None,
                    acknowledge_executable_content: false,
                }],
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(
            policy
                .warnings()
                .iter()
                .any(|w| w.contains("did not resolve to any binary"))
        );
    }

    #[test]
    fn warnings_flag_full_network_and_missing_write_paths() {
        let mut policy = Policy::default();
        policy.sandbox.network = Network::Full;
        let warnings = policy.warnings();
        assert_eq!(warnings.len(), 2);
    }

    #[test]
    fn warnings_silent_on_full_network_when_domain_filtering_active() {
        // network.allowed_domains overrides sandbox.network = "full" to
        // actually mean "filtered to these domains" (see
        // build_bwrap_args's forced --unshare-net) — the blanket "grants
        // unrestricted network access" warning would be actively
        // misleading here, not just redundant.
        let mut policy = Policy::default();
        policy.sandbox.network = Network::Full;
        policy.network.allowed_domains = vec!["api.anthropic.com".to_string()];
        policy.filesystem.read_write.push(PathEntry {
            path: PathBuf::from("/home/user/project"),
            mount_as: None,
            create: None,
            create_content: None,
            acknowledge_executable_content: false,
        });
        assert_eq!(policy.warnings(), [] as [String; 0]);
    }

    #[test]
    fn warnings_silent_on_full_network_when_ip_filtering_active() {
        let mut policy = Policy::default();
        policy.sandbox.network = Network::Full;
        policy.network.allowed_ips = vec!["10.0.0.0/24".to_string()];
        policy.filesystem.read_write.push(PathEntry {
            path: PathBuf::from("/home/user/project"),
            mount_as: None,
            create: None,
            create_content: None,
            acknowledge_executable_content: false,
        });
        assert_eq!(policy.warnings(), [] as [String; 0]);
    }

    #[test]
    fn validate_accepts_well_formed_allowed_ips() {
        let mut policy = Policy::default();
        policy.network.allowed_ips = vec![
            "10.0.0.5".to_string(),
            "10.0.0.0/24".to_string(),
            "fc00::/7".to_string(),
        ];
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn validate_rejects_malformed_allowed_ips() {
        let mut policy = Policy::default();
        policy.network.allowed_ips = vec!["not-an-ip".to_string()];
        let errors = policy.validate().unwrap_err();
        assert!(
            errors.iter().any(|e| e.contains("network.allowed_ips")),
            "got: {errors:?}"
        );
    }

    #[test]
    fn validate_rejects_malformed_allowed_domains() {
        let mut policy = Policy::default();
        policy.network.allowed_domains = vec!["api.anthropic.com".to_string(), "*.".to_string()];
        let errors = policy.validate().unwrap_err();
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].contains("network.allowed_domains"));
    }

    #[test]
    fn validate_rejects_out_of_range_prefix() {
        let mut policy = Policy::default();
        policy.network.allowed_ips = vec!["10.0.0.0/40".to_string()];
        assert!(policy.validate().is_err());
    }

    #[test]
    fn network_section_round_trips_allowed_ips_through_toml() {
        let mut policy = Policy::default();
        policy.network.allowed_ips = vec!["10.0.0.0/24".to_string()];
        let text = toml::to_string_pretty(&policy).unwrap();
        let round_tripped: Policy = toml::from_str(&text).unwrap();
        assert_eq!(round_tripped.network.allowed_ips, vec!["10.0.0.0/24"]);
    }

    #[test]
    fn warnings_empty_for_reasonable_policy() {
        let mut policy = Policy::default();
        policy.filesystem.read_write.push(PathEntry {
            path: PathBuf::from("/home/user/project"),
            mount_as: None,
            create: None,
            create_content: None,
            acknowledge_executable_content: false,
        });
        assert_eq!(policy.warnings(), [] as [String; 0]);
    }

    #[test]
    fn warnings_flag_seccomp_typo() {
        let mut policy = Policy::default();
        policy.filesystem.read_write.push(PathEntry {
            path: PathBuf::from("/home/user/project"),
            mount_as: None,
            create: None,
            create_content: None,
            acknowledge_executable_content: false,
        });
        policy.seccomp.allow = vec!["ptracee".to_string()];
        assert!(
            policy
                .warnings()
                .iter()
                .any(|w| w.contains("does not match"))
        );
    }

    #[test]
    fn warnings_flag_path_passthrough_with_commands_allowed() {
        let mut policy = Policy::default();
        policy.filesystem.read_write.push(PathEntry {
            path: PathBuf::from("/home/user/project"),
            mount_as: None,
            create: None,
            create_content: None,
            acknowledge_executable_content: false,
        });
        policy.env.allow = vec!["PATH".to_string()];
        policy.commands.allow = vec![CommandRef::Name("ls".to_string())];
        assert!(policy.warnings().iter().any(|w| w.contains("\"PATH\"")));
    }

    #[test]
    fn warnings_silent_on_path_passthrough_with_no_commands_allowed() {
        let mut policy = Policy::default();
        policy.filesystem.read_write.push(PathEntry {
            path: PathBuf::from("/home/user/project"),
            mount_as: None,
            create: None,
            create_content: None,
            acknowledge_executable_content: false,
        });
        policy.env.allow = vec!["PATH".to_string()];
        assert!(!policy.warnings().iter().any(|w| w.contains("\"PATH\"")));
    }

    #[test]
    fn warnings_flag_home_passthrough() {
        let mut policy = Policy::default();
        policy.filesystem.read_write.push(PathEntry {
            path: PathBuf::from("/home/user/project"),
            mount_as: None,
            create: None,
            create_content: None,
            acknowledge_executable_content: false,
        });
        policy.env.allow = vec!["HOME".to_string()];
        assert!(policy.warnings().iter().any(|w| w.contains("\"HOME\"")));
    }

    #[test]
    fn unknown_top_level_field_is_a_parse_error_not_silently_ignored() {
        // Regression guard: without `deny_unknown_fields`, a typo like
        // `commnads.allow = [...]` (missing the sandboxed process's
        // entire intended whitelist) or a reference to a field that used
        // to exist and was renamed/removed (`sandbox.allow_broad_bin_dirs`,
        // superseded by `PathEntry::acknowledge_executable_content`)
        // would silently parse as an empty/default policy instead of
        // failing loudly — the worst possible failure mode for a
        // whitelist-only security tool's own config format.
        let text = r"
            [sandbox]
            allow_broad_bin_dirs = true
        ";
        let result: Result<Policy, _> = toml::from_str(text);
        assert!(
            result.is_err(),
            "a removed/unknown field must fail to parse, not silently succeed"
        );
    }

    #[test]
    fn unknown_command_entry_field_is_a_parse_error() {
        let text = r#"
            [commands]
            allow = [{ name = "git", pth = "/usr/bin/git" }]
        "#;
        let result: Result<Policy, _> = toml::from_str(text);
        assert!(
            result.is_err(),
            "a typo'd field in a commands.allow entry must fail to parse, not silently drop the pinned path"
        );
    }

    #[test]
    fn validate_rejects_symlink_deny_target() {
        let dir = std::env::temp_dir().join(format!(
            "rune-secops-warden-symlink-deny-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let real = dir.join("real.env");
        std::fs::write(&real, "API_KEY=shh").unwrap();
        let link = dir.join(".env");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let policy = Policy {
            filesystem: FilesystemSection {
                deny: vec![DenyEntry { path: link }],
                ..Default::default()
            },
            ..Default::default()
        };
        let errors = policy.validate().unwrap_err();
        assert!(errors.iter().any(|e| e.contains("is itself a symlink")));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn validate_allows_non_symlink_deny_target() {
        let policy = Policy {
            filesystem: FilesystemSection {
                deny: vec![DenyEntry {
                    path: PathBuf::from("/home/user/project/.env"),
                }],
                ..Default::default()
            },
            ..Default::default()
        };
        // Doesn't exist on disk at all — that's fine, only an *existing
        // symlink* is rejected, matching resolve_deny_paths' own
        // "missing path treated as a file" convention.
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn warnings_flag_shared_pid_namespace_combined_with_ptrace_allowed() {
        let mut policy = Policy::default();
        policy.filesystem.read_write.push(PathEntry {
            path: PathBuf::from("/home/user/project"),
            mount_as: None,
            create: None,
            create_content: None,
            acknowledge_executable_content: false,
        });
        policy.sandbox.unshare_pid = false;
        policy.seccomp.allow = vec!["ptrace".to_string()];
        let warnings = policy.warnings();
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("both see every host process"))
        );
    }

    #[test]
    fn warnings_flag_shared_pid_namespace() {
        let mut policy = Policy::default();
        policy.filesystem.read_write.push(PathEntry {
            path: PathBuf::from("/home/user/project"),
            mount_as: None,
            create: None,
            create_content: None,
            acknowledge_executable_content: false,
        });
        policy.sandbox.unshare_pid = false;
        assert!(policy.warnings().iter().any(|w| w.contains("unshare_pid")));
    }
}
