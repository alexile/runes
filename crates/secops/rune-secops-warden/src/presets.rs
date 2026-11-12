//! Ready-made policies for known AI coding agents.
//!
//! Building a working policy from scratch requires knowing exactly what
//! files, subprocesses, and network access a closed-source binary needs —
//! information that normally only comes from tracing a real run (`strace
//! -f -e trace=openat,connect,execve`). [`claude_code`] is exactly that:
//! derived from tracing a real `claude -p "..."` invocation end to end,
//! not guessed from documentation. Notable findings baked in here:
//!
//! - Claude Code needs **real network access** — there is no useful
//!   sandbox of an AI agent that can't reach its own API, so this preset
//!   sets `sandbox.network = "full"`. The value of sandboxing it is in
//!   the filesystem/command/syscall boundary, not network denial; see the
//!   crate-level docs for why domain-level allowlisting isn't offered.
//! - It needs the **full system CA bundle** (`/etc/ssl`) for TLS, plus
//!   `/etc/resolv.conf`, `/etc/nsswitch.conf`, `/etc/hosts`,
//!   `/etc/host.conf`, and `/etc/gai.conf` for DNS resolution — glibc's
//!   resolver reads all of these, not just `resolv.conf`.
//! - It reads `/etc/machine-id`, `/etc/os-release`, and `/etc/localtime`
//!   during startup.
//! - It shells out to `git` (repo status), and — via `/bin/sh -c "ps -o
//!   command= -p <pid>"` — to `sh` and `ps` (parent-shell detection). All
//!   three need to be in `commands.allow` or those checks silently fail.
//! - It reads and writes `~/.claude` (credentials, session transcripts,
//!   plugin hooks) and `~/.local/state/claude` (a version lock file) —
//!   both need `read_write`. `~/.claude.json` and `~/.claude/settings.json`
//!   are read-write from Claude Code's own perspective too (confirmed by
//!   tracing a real session: `.claude.json` is rewritten via an atomic
//!   temp-file-then-`rename()` on every single invocation, even a
//!   trivial one-shot prompt) but are deliberately forced read-only here
//!   via `read_only_override` — both are config-as-code a sandboxed
//!   session could otherwise plant to control a *future*, unsandboxed
//!   run (CVE-2026-25725 for `settings.json`'s hooks; MCP server
//!   definitions for `.claude.json`) — see the comment at their
//!   definition below for how "safe to lock down" was actually verified
//!   rather than assumed.
//! - Its own binary is a single self-contained executable (a
//!   [Bun](https://bun.sh) build) that re-execs *itself* with a different
//!   `argv[0]` to behave as a bundled `rg` (ripgrep) — so once the
//!   binary itself is reachable, no separate `rg` entry is needed.
//! - **The sharpest edge, found the hard way:** `$HOME` and the sandbox's
//!   working directory must be set to values consistent with what was
//!   actually bound. A generic `env.allow = ["HOME"]` passes through
//!   *this process's own* `$HOME` — not `options.home` — and if those
//!   two differ (e.g. testing with a scratch home while your shell's real
//!   `$HOME` is still `/home/you`), Claude Code ends up looking for its
//!   config at a `$HOME` that isn't the one anything was bound under, and
//!   the resulting early filesystem error was enough to hard-abort the
//!   whole process rather than fail gracefully. `env.set["HOME"]` and
//!   `sandbox.cwd` are pinned explicitly below for exactly this reason —
//!   don't move them back to passthrough/ambient-`cwd` behavior.
//!
//! # Example
//!
//! ```rust,no_run
//! use rune_secops_warden::{build_command, presets};
//! use std::path::PathBuf;
//!
//! let claude_binary = PathBuf::from("/home/user/.local/share/claude/versions/2.1.233");
//! let policy = presets::claude_code(&presets::ClaudeCodeOptions {
//!     claude_binary: claude_binary.clone(),
//!     home: PathBuf::from("/home/user"),
//!     project_dirs: vec![PathBuf::from("/home/user/project")],
//!     ..Default::default()
//! });
//! let program = claude_binary.to_str().unwrap();
//! let mut command = build_command(&policy, program, &[]).unwrap();
//! ```

use std::collections::BTreeMap;
use std::path::PathBuf;

use rune_sandbox_preset::{DNS_FILES, HOST_IDENTITY_FILES, SAFE_PATH, TLS_PATHS};

use crate::policy::{
    CommandRef, CommandsSection, DenyEntry, EnvSection, FilesystemSection, Network, PathEntry,
    PathKind, Policy, SandboxSection,
};
use crate::resolve::resolve_allowed_binaries;

/// The binaries Claude Code's own startup and Bash tool require.
///
/// Verified by tracing a real session, then separately by watching a real
/// agentic Bash-tool call fail without `bash` present.
///
/// This is what [`claude_code`] allows by default. Nothing more: the
/// whitelist model this whole crate is built on means the base state is
/// maximally restrictive, and *you* widen it — via `extra_allowed_commands`
/// (or `--allow` on the CLI), or by editing the `Policy` this function
/// returns — not the preset guessing at a "reasonable" toolkit for you.
pub const REQUIRED_TOOLS: &[&str] = &["git", "sh", "bash", "ps", "ls"];

/// Inputs to [`claude_code`]. Only `claude_binary` and `home` are
/// required in practice — everything else has a usable default, but you
/// will almost always want to set `project_dirs`.
pub struct ClaudeCodeOptions {
    /// Path to the real Claude Code binary — e.g. the target of
    /// `readlink -f "$(which claude)"`, since the `~/.local/bin/claude`
    /// symlink itself doesn't need to be (and by default isn't) visible.
    pub claude_binary: PathBuf,
    /// The user's home directory on the host.
    pub home: PathBuf,
    /// Project directories to grant read-write access to.
    pub project_dirs: Vec<PathBuf>,
    /// Network mode. Defaults to [`Network::Full`] — Claude Code cannot
    /// function without reaching its API; see the module docs.
    pub network: Network,
    /// Commands to allow beyond [`REQUIRED_TOOLS`] — e.g. `node`, `cargo`,
    /// `grep`, whatever the project actually needs. Empty by default:
    /// this is how you widen the sandbox, not a bundled toolkit.
    pub extra_allowed_commands: Vec<CommandRef>,
    /// Additional paths to deny even though they fall under a bound
    /// ancestor — e.g. a project's `.env` file. Empty by default because
    /// a preset can't know your project's specific secrets; you should
    /// usually add to this.
    pub extra_deny: Vec<DenyEntry>,
    /// Additional paths forced read-only even though they fall under a
    /// bound read-write ancestor — see
    /// [`FilesystemSection::read_only_override`][crate::FilesystemSection]
    /// for the vulnerability class this guards against. Empty by default;
    /// consider adding your project's `.claude/settings.local.json` and
    /// `.mcp.json` here if you want to accept the tradeoff of a sandboxed
    /// session never being able to (legitimately or otherwise) change
    /// your project's own hook/MCP-server configuration. Not defaulted
    /// on for those two paths because editing them is sometimes exactly
    /// what you're asking the agent to do (e.g. "add an MCP server for
    /// X") — locking them down by default would silently break that.
    pub extra_read_only_override: Vec<PathEntry>,
}

impl Default for ClaudeCodeOptions {
    fn default() -> Self {
        Self {
            claude_binary: PathBuf::new(),
            home: PathBuf::new(),
            project_dirs: Vec::new(),
            network: Network::Full,
            extra_allowed_commands: Vec::new(),
            extra_deny: Vec::new(),
            extra_read_only_override: Vec::new(),
        }
    }
}

fn ro(path: impl Into<PathBuf>) -> PathEntry {
    path.into().into()
}

fn rw(path: impl Into<PathBuf>) -> PathEntry {
    path.into().into()
}

/// A `read_write` directory entry for state a tool creates on first run:
/// bound in even if it doesn't exist on the host yet.
fn rw_create_dir(path: impl Into<PathBuf>) -> PathEntry {
    PathEntry {
        path: path.into(),
        mount_as: None,
        create: Some(PathKind::Directory),
        create_content: None,
        acknowledge_executable_content: false,
    }
}

/// Build a policy for sandboxing the native Claude Code CLI.
///
/// Verified by tracing and then running a real `claude -p "..."` session
/// end to end through this crate's [`crate::build_command`] — see the
/// module docs for exactly what was found and why each entry is here.
///
/// The returned [`Policy`] is a plain, fully mutable value: layer your
/// own `filesystem.deny` entries, tighten `commands.allow`, or add
/// `[limits]`/`[seccomp]` overrides directly on the fields before passing
/// it to [`crate::build_command`].
pub fn claude_code(options: &ClaudeCodeOptions) -> Policy {
    let home = &options.home;

    // Deliberately no wholesale /lib, /lib64, /usr/lib binds here: build_command
    // resolves the exact shared-library closure of everything in
    // commands.allow and binds those files individually (see
    // crate::resolve_library_closure). Binding whole library directories
    // was tried first and found, empirically, to defeat commands.allow —
    // /usr/lib alone holds hundreds of executable helper binaries that
    // become runnable by absolute path from any allowed shell.
    //
    // The DNS, host-identity and CA-bundle lists are shared with
    // rune-sandbox-preset's `network_tool`, so a file found missing by
    // tracing one reaches both.
    let mut read_only: Vec<PathEntry> = DNS_FILES
        .iter()
        .chain(HOST_IDENTITY_FILES)
        .chain(TLS_PATHS)
        .map(|path| ro(*path))
        .collect();
    let gitconfig = home.join(".gitconfig");
    if gitconfig.is_file() {
        read_only.push(ro(gitconfig));
    }

    let mut read_write = vec![
        PathEntry {
            acknowledge_executable_content: true,
            // Claude Code's own plugin system installs real, executable
            // hook scripts under here (confirmed live —
            // `~/.claude/plugins/.../hooks/*.sh`, mode 755, real shebang
            // lines) as part of normal, expected operation, and this
            // path is already read-write regardless: an agent with
            // `bash` allowed can already write new executable content
            // here, so a scan of what's already present adds little.
            // Kept as an explicit, narrow acknowledgment rather than a
            // sandbox-wide escape hatch, so it doesn't also wave through
            // an unrelated bind added later.
            ..rw_create_dir(home.join(".claude"))
        },
        rw_create_dir(home.join(".local/state/claude")),
    ];
    read_write.extend(options.project_dirs.iter().cloned().map(rw));

    // Forced read-only, not merely absent from `read_write` — both files
    // below need to still *exist and be readable* for Claude Code to
    // start, only writes need to stop, which is exactly what
    // `read_only_override` is for.
    //
    // `settings.json`: the file a real, disclosed Claude Code sandbox
    // escape (CVE-2026-25725) exploited by having a *sandboxed* session
    // write a hook here that then auto-ran the *next time the user
    // launched Claude Code normally, outside any sandbox at all*.
    //
    // `.claude.json`: the sibling risk of the identical shape flagged (but
    // left open, pending exactly this trace) elsewhere in this crate's
    // history — it stores MCP server definitions, arbitrary commands
    // Claude Code will spawn, so a sandboxed session planting one here is
    // the same persistence-into-an-unsandboxed-future-run attack as
    // `settings.json`, just via `.mcp` config instead of a hook. Verified
    // safe to lock down by tracing a real, unsandboxed `claude -p`
    // session with `strace -f -e trace=openat,rename,unlink`: it rewrites
    // this file on *every single invocation*, even a trivial one-shot
    // prompt with no project/session-specific need, via the standard
    // atomic write pattern (`.claude.json.tmp.<pid>.<rand>` then
    // `rename()` over the original) — but a full diff of what changed
    // across that rewrite showed only operational telemetry/bookkeeping
    // (`cachedGrowthBookFeatures`, `cachedExperimentData`,
    // `clientDataCacheSlots`, timestamps, startup counters), never
    // anything a user would notice missing. Confirmed end to end by then
    // actually running a real `claude -p` session inside a sandbox with
    // this override applied: it completed normally (exit 0, correct
    // answer), and the file was provably untouched
    // (`sha256sum` identical before/after) — no crash, no visible
    // degradation, exactly the graceful "just doesn't persist
    // non-essential state" outcome the earlier, unverified guess wasn't
    // willing to assume. `create_content` mirrors the existing "must be
    // valid JSON, not just present" requirement — an empty file reads to
    // Claude Code as *corrupted*, not *first run*.
    let mut read_only_override = vec![
        PathEntry {
            create: Some(PathKind::File),
            create_content: Some("{}".to_string()),
            ..ro(home.join(".claude/settings.json"))
        },
        PathEntry {
            create: Some(PathKind::File),
            create_content: Some("{}".to_string()),
            ..ro(home.join(".claude.json"))
        },
    ];
    read_only_override.extend(options.extra_read_only_override.iter().cloned());

    // `sh` covers the internal `sh -c "ps -o command= -p <pid>"`
    // parent-shell check seen in the traced startup. It is *not* what
    // powers the interactive Bash tool the agent actually uses to run
    // commands on your behalf — that's a separate code path that
    // specifically execs `bash` and fails outright ("No suitable shell
    // found") if it isn't present, regardless of $SHELL. Both are
    // required; this was only found by watching a real agentic session
    // try to use its Bash tool and fail.
    let mut allow: Vec<CommandRef> = REQUIRED_TOOLS
        .iter()
        .map(|name| CommandRef::Name((*name).to_string()))
        .collect();
    allow.push(CommandRef::Entry {
        name: "claude".to_string(),
        path: Some(options.claude_binary.clone()),
    });
    allow.extend(options.extra_allowed_commands.iter().cloned());
    let commands = CommandsSection { allow };

    let mut env_set = BTreeMap::new();
    // Deliberately *not* in `env.allow`: that passes through this process's
    // own ambient $HOME, which is unrelated to (and often different from)
    // `options.home` — the path everything above was just bound under.
    // Getting this wrong doesn't just misdirect config; Claude Code reads
    // $HOME-relative paths on startup, and hitting one that isn't bound in
    // the sandbox (because the *real* $HOME was leaked through instead of
    // `options.home`) is what actually caused the crash this preset exists
    // to avoid — the seccomp filter and namespaces were both red herrings.
    env_set.insert("HOME".to_string(), home.to_string_lossy().into_owned());
    // Deliberately *not* in `env.allow` either, for a sharper reason than
    // $HOME: passing through the calling process's own ambient $PATH can
    // hand the sandboxed agent a privilege escalation, not just a wrong
    // value. A dev shell's real $PATH routinely has writable, project-local
    // directories ahead of /usr/bin (node_modules/.bin, a venv, direnv
    // shims) — confirmed directly: with a writable directory earlier on
    // $PATH, a sandboxed `bash` can write an executable named `ls` there
    // and have every later bare `ls` invocation run it instead of the real
    // one, with no error. The fake binary gains nothing new (it's exactly
    // as sandboxed as the shell that wrote it), but it *does* mean
    // commands.allow is only as trustworthy as $PATH's ordering — so pin a
    // fixed, standard-directories-only $PATH instead of inheriting
    // whatever the host process happened to have.
    env_set.insert("PATH".to_string(), SAFE_PATH.to_string());
    // Same failure mode again, caught the same way (run it for real and
    // watch what breaks): passing through the calling process's own
    // ambient $SHELL pointed the sandboxed Claude Code at *this
    // developer's* shell (zsh, fish, whatever) rather than the `sh` that
    // was actually bound above. Claude Code's own Bash tool execs
    // `$SHELL` directly; if that path doesn't exist inside the sandbox,
    // the tool fails outright with "No suitable shell found" — silently,
    // in a way that's easy to mistake for the sandbox "safely" blocking
    // something, when what actually happened is the agent's shell never
    // worked at all. Point it at whatever `sh` really resolved to instead
    // of the host's preference.
    if let Some(sh) = resolve_allowed_binaries(&commands)
        .into_iter()
        .find(|resolved| resolved.name == "sh")
    {
        env_set.insert("SHELL".to_string(), sh.path.to_string_lossy().into_owned());
    }

    Policy {
        sandbox: SandboxSection {
            network: options.network,
            // Same reasoning as $HOME above: don't inherit whatever
            // directory the calling process happens to be in.
            cwd: options.project_dirs.first().cloned(),
            // Unlike `SandboxSection::default()` (`false` — see its own
            // docs on why Landlock defaults off at the library level):
            // this preset's whole reason to exist is a policy verified
            // against real Claude Code sessions, and that verification
            // now specifically includes `sandbox.landlock = true` (traced
            // and fixed a real abort under it — Bun's runtime hit a
            // denied `ioctl()` on `/dev` before `landlock_layer` accounted
            // for bwrap's own unconditional `/proc`/`/dev`/`/tmp`/`/run`
            // mounts). On by default here for the one target this crate
            // has actually confirmed it works for.
            landlock: true,
            ..SandboxSection::default()
        },
        filesystem: FilesystemSection {
            read_only,
            read_write,
            deny: options.extra_deny.clone(),
            read_only_override,
            ..FilesystemSection::default()
        },
        env: EnvSection {
            allow: ["USER", "LANG", "LC_ALL", "TERM"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            set: env_set,
        },
        commands,
        ..Policy::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn claude_code_preset_is_internally_consistent() {
        let policy = claude_code(&ClaudeCodeOptions {
            claude_binary: PathBuf::from("/opt/claude/claude-bin"),
            home: PathBuf::from("/home/user"),
            project_dirs: vec![PathBuf::from("/home/user/project")],
            ..Default::default()
        });

        assert!(policy.validate().is_ok());
        assert_eq!(policy.sandbox.network, Network::Full);
        // Unlike `SandboxSection::default()` (`false`) — this preset
        // turns Landlock on explicitly, having actually verified it
        // against a real Claude Code session (see the field's own docs
        // for the real crash that verification caught and fixed).
        assert!(policy.sandbox.landlock);
        assert!(
            policy
                .filesystem
                .read_write
                .iter()
                .any(|e| e.path == Path::new("/home/user/.claude"))
        );
        assert!(policy.commands.allow.iter().any(|c| c.name() == "claude"
            && c.explicit_path() == Some(std::path::Path::new("/opt/claude/claude-bin"))));
        // Regression: found by running a real agentic session and watching
        // its Bash tool fail with "No suitable shell found" — it execs
        // `bash` specifically, not just whatever `sh` resolves to.
        assert!(policy.commands.allow.iter().any(|c| c.name() == "bash"));
    }

    #[test]
    fn claude_code_preset_protects_settings_json_from_the_sandboxed_session_itself() {
        // Regression test for the vulnerability class CVE-2026-25725
        // demonstrated for real: a sandboxed Claude Code session writes
        // settings.json, and that hook auto-runs the next time the user
        // launches Claude Code normally — no sandbox involved at all.
        let policy = claude_code(&ClaudeCodeOptions {
            claude_binary: PathBuf::from("/opt/claude/claude-bin"),
            home: PathBuf::from("/home/user"),
            project_dirs: vec![PathBuf::from("/home/user/project")],
            ..Default::default()
        });
        assert!(policy.validate().is_ok());
        assert!(
            policy
                .filesystem
                .read_only_override
                .iter()
                .any(|e| e.path == Path::new("/home/user/.claude/settings.json")),
            "settings.json must be forced read-only even though ~/.claude is read-write"
        );
    }

    #[test]
    fn claude_code_preset_protects_claude_json_from_the_sandboxed_session_itself() {
        // Regression test for the P0 item GOAL.md left open: `.claude.json`
        // stores MCP server definitions (arbitrary commands Claude Code
        // will spawn), the same persistence-into-a-future-unsandboxed-run
        // risk shape as settings.json/CVE-2026-25725. Verified safe to
        // lock down by tracing a real session (rewritten via atomic
        // temp-then-rename on every invocation, but only ever with
        // operational telemetry, never anything a user would miss) and by
        // then actually running a real sandboxed `claude -p` session with
        // this override applied end to end: it completed normally with
        // the file provably untouched. See the comment at this override's
        // definition in `claude_code` for the full trace.
        let policy = claude_code(&ClaudeCodeOptions {
            claude_binary: PathBuf::from("/opt/claude/claude-bin"),
            home: PathBuf::from("/home/user"),
            project_dirs: vec![PathBuf::from("/home/user/project")],
            ..Default::default()
        });
        assert!(policy.validate().is_ok());
        assert!(
            !policy
                .filesystem
                .read_write
                .iter()
                .any(|e| e.path == Path::new("/home/user/.claude.json")),
            ".claude.json must not also be bound read_write — read_only_override only wins \
             over a read_write bind of the same path because it's applied after it in bwrap \
             argument order; leaving a duplicate read_write entry around would be silently \
             relying on that ordering rather than actually removing the write path"
        );
        assert!(
            policy
                .filesystem
                .read_only_override
                .iter()
                .any(|e| e.path == Path::new("/home/user/.claude.json")),
            ".claude.json must be forced read-only"
        );
    }

    #[test]
    fn shared_system_files_are_unchanged() {
        // The lists now come from rune-sandbox-preset; pin the exact
        // entries and order this preset was verified with.
        let policy = claude_code(&ClaudeCodeOptions {
            claude_binary: PathBuf::from("/opt/claude/claude-bin"),
            home: PathBuf::from("/nonexistent-home"),
            project_dirs: vec![PathBuf::from("/nonexistent-home/project")],
            ..Default::default()
        });
        let read_only: Vec<_> = policy
            .filesystem
            .read_only
            .iter()
            .map(|e| e.path.clone())
            .collect();
        let expected: Vec<PathBuf> = [
            "/etc/resolv.conf",
            "/etc/nsswitch.conf",
            "/etc/hosts",
            "/etc/host.conf",
            "/etc/gai.conf",
            "/etc/machine-id",
            "/etc/os-release",
            "/etc/localtime",
            "/etc/ssl",
            "/usr/share/ca-certificates",
        ]
        .into_iter()
        .map(PathBuf::from)
        .collect();
        assert_eq!(read_only, expected);
        assert_eq!(
            policy.env.set.get("PATH").map(String::as_str),
            Some("/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
        );
    }

    #[test]
    fn extra_read_only_override_is_included() {
        let policy = claude_code(&ClaudeCodeOptions {
            claude_binary: PathBuf::from("/opt/claude/claude-bin"),
            home: PathBuf::from("/home/user"),
            project_dirs: vec![PathBuf::from("/home/user/project")],
            extra_read_only_override: vec![PathEntry {
                path: PathBuf::from("/home/user/project/.mcp.json"),
                mount_as: None,
                create: None,
                create_content: None,
                acknowledge_executable_content: false,
            }],
            ..Default::default()
        });
        assert!(
            policy
                .filesystem
                .read_only_override
                .iter()
                .any(|e| e.path == Path::new("/home/user/project/.mcp.json"))
        );
    }

    #[test]
    fn claude_code_preset_pins_home_and_cwd_instead_of_inheriting_ambient_values() {
        // Regression test: env.allow = ["HOME"] would pass through *this
        // process's* $HOME, not `options.home`; a mismatch between the two
        // is what caused the underlying agent to hard-crash inside the
        // sandbox (see the module docs). HOME must come from `env.set`,
        // pinned to the same path everything was bound under, and
        // `sandbox.cwd` must not silently inherit this process's cwd.
        let policy = claude_code(&ClaudeCodeOptions {
            claude_binary: PathBuf::from("/opt/claude/claude-bin"),
            home: PathBuf::from("/scratch/fake-home"),
            project_dirs: vec![PathBuf::from("/scratch/fake-home/project")],
            ..Default::default()
        });
        assert!(!policy.env.allow.contains(&"HOME".to_string()));
        assert_eq!(
            policy.env.set.get("HOME").map(String::as_str),
            Some("/scratch/fake-home")
        );
        assert_eq!(
            policy.sandbox.cwd,
            Some(PathBuf::from("/scratch/fake-home/project"))
        );
    }

    #[test]
    fn claude_code_preset_pins_shell_to_the_resolved_sh_not_the_ambient_one() {
        // Regression test: env.allow = ["SHELL"] would pass through *this
        // process's* $SHELL (zsh, fish, whatever the developer runs) —
        // and Claude Code's own Bash tool execs $SHELL directly. Point a
        // sandboxed agent at a shell that isn't the one actually bound in
        // commands.allow and its Bash tool fails outright ("No suitable
        // shell found"), which is easy to mistake for the sandbox
        // correctly blocking something when nothing was ever tested.
        let policy = claude_code(&ClaudeCodeOptions {
            claude_binary: PathBuf::from("/opt/claude/claude-bin"),
            home: PathBuf::from("/scratch/fake-home"),
            project_dirs: vec![PathBuf::from("/scratch/fake-home/project")],
            ..Default::default()
        });
        assert!(!policy.env.allow.contains(&"SHELL".to_string()));
        let shell = policy
            .env
            .set
            .get("SHELL")
            .expect("SHELL must be pinned via env.set");
        assert!(
            policy
                .commands
                .allow
                .iter()
                .any(|c| c.name() == "sh" && c.explicit_path().is_none()),
            "SHELL should point at the same `sh` entry commands.allow resolves"
        );
        assert!(
            shell.ends_with("/sh"),
            "SHELL should resolve to a real sh binary, got {shell}"
        );
    }

    #[test]
    fn default_allow_list_is_exactly_the_required_floor() {
        let policy = claude_code(&ClaudeCodeOptions {
            claude_binary: PathBuf::from("/opt/claude/claude-bin"),
            home: PathBuf::from("/home/user"),
            project_dirs: vec![PathBuf::from("/home/user/project")],
            ..Default::default()
        });
        for tool in REQUIRED_TOOLS {
            assert!(policy.commands.allow.iter().any(|c| c.name() == *tool));
        }
        // Nothing beyond the floor + the claude binary itself.
        assert_eq!(policy.commands.allow.len(), REQUIRED_TOOLS.len() + 1);
        assert!(!policy.commands.allow.iter().any(|c| c.name() == "curl"));
        assert!(!policy.commands.allow.iter().any(|c| c.name() == "python3"));
    }

    #[test]
    fn extra_allowed_commands_widen_the_default_floor() {
        let policy = claude_code(&ClaudeCodeOptions {
            claude_binary: PathBuf::from("/opt/claude/claude-bin"),
            home: PathBuf::from("/home/user"),
            project_dirs: vec![PathBuf::from("/home/user/project")],
            extra_allowed_commands: vec![CommandRef::Name("node".to_string())],
            ..Default::default()
        });
        assert!(policy.commands.allow.iter().any(|c| c.name() == "node"));
        assert!(policy.commands.allow.iter().any(|c| c.name() == "git"));
    }

    #[test]
    fn claude_code_preset_includes_run_project_dirs() {
        let policy = claude_code(&ClaudeCodeOptions {
            claude_binary: PathBuf::from("/opt/claude/claude-bin"),
            home: PathBuf::from("/home/user"),
            project_dirs: vec![
                PathBuf::from("/home/user/project-a"),
                PathBuf::from("/home/user/project-b"),
            ],
            ..Default::default()
        });
        assert!(
            policy
                .filesystem
                .read_write
                .iter()
                .any(|e| e.path == Path::new("/home/user/project-a"))
        );
        assert!(
            policy
                .filesystem
                .read_write
                .iter()
                .any(|e| e.path == Path::new("/home/user/project-b"))
        );
    }

    #[test]
    fn extra_allowed_commands_and_deny_entries_are_included() {
        let policy = claude_code(&ClaudeCodeOptions {
            claude_binary: PathBuf::from("/opt/claude/claude-bin"),
            home: PathBuf::from("/home/user"),
            project_dirs: vec![PathBuf::from("/home/user/project")],
            extra_allowed_commands: vec![CommandRef::Name("npm".to_string())],
            extra_deny: vec![DenyEntry {
                path: PathBuf::from("/home/user/project/.env"),
            }],
            ..Default::default()
        });
        assert!(policy.commands.allow.iter().any(|c| c.name() == "npm"));
        assert!(
            policy
                .filesystem
                .deny
                .iter()
                .any(|e| e.path == Path::new("/home/user/project/.env"))
        );
    }
}
