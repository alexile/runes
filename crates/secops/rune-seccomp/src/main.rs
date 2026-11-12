//! `rune-seccomp`: run a program under a seccomp-bpf system call filter.
//!
//! ```text
//! rune-seccomp --deny-dangerous -- make test
//! rune-seccomp --action log --allow read --allow write -- ./tool
//! rune-seccomp --detect
//! ```
//!
//! Exit status: the program's own, or 125 when the filter cannot be set
//! up, 126 when the program cannot be executed (including when the filter
//! denies it) and 127 when it does not exist.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use std::ffi::OsString;
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, ValueEnum};
use rune_seccomp::{
    Action, Compatibility, Options, Status, Syscall, compile, detect, install, syscalls,
};

/// What listed (or, with --allow, unlisted) system calls get.
#[derive(Clone, Copy, ValueEnum)]
enum Verdict {
    /// Fail the call with --errno.
    Errno,
    /// Send SIGSYS.
    Trap,
    /// Allow the call, but log it to the kernel audit log.
    Log,
    /// Kill the calling thread.
    KillThread,
    /// Kill the process.
    KillProcess,
}

/// Run a program under a seccomp-bpf system call filter.
///
/// With --allow, every system call not allowed gets --action (deny by
/// default); with --deny or --deny-dangerous, the listed calls do. Calls
/// are named ("openat") or numbered for this architecture.
#[derive(Parser)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "each bool is an independent command-line flag"
)]
#[command(name = "rune-seccomp", version, about)]
struct Cli {
    /// Allow this system call; deny every other one.
    #[arg(long, value_name = "SYSCALL", conflicts_with_all = ["deny", "deny_dangerous"])]
    allow: Vec<String>,
    /// Deny this system call; allow every other one.
    #[arg(long, value_name = "SYSCALL")]
    deny: Vec<String>,
    /// Deny system calls ordinary programs do not need (module loading,
    /// ptrace, mount, the keyring, io-uring and so on).
    #[arg(long)]
    deny_dangerous: bool,
    /// What denied calls get.
    #[arg(long, value_enum, default_value = "errno")]
    action: Verdict,
    /// The errno denied calls fail with, for --action errno (1 = EPERM).
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u16).range(0..=4095))]
    errno: u16,
    /// Filter every thread, not only the launcher's (it has one anyway).
    #[arg(long)]
    all_threads: bool,
    /// Fail rather than fall back when the kernel lacks seccomp or an action.
    #[arg(long)]
    strict: bool,
    /// Report what is enforced on stderr before running the program.
    #[arg(short, long)]
    verbose: bool,
    /// Write the compiled filter (raw BPF instructions, as bwrap --seccomp
    /// reads it) to FILE and exit.
    #[arg(long, value_name = "FILE")]
    emit: Option<PathBuf>,
    /// Print the kernel's seccomp support and exit.
    #[arg(long, exclusive = true)]
    detect: bool,
    /// Print this architecture's system call names and numbers and exit.
    #[arg(long, exclusive = true)]
    list: bool,
    /// The program to run, and its arguments.
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        required_unless_present_any = ["detect", "list", "emit"],
        value_name = "PROGRAM"
    )]
    command: Vec<OsString>,
}

fn syscall(arg: &str) -> Syscall {
    arg.parse::<i64>()
        .map_or_else(|_| Syscall::from(arg), Syscall::from)
}

impl Cli {
    const fn deny_action(&self) -> Action {
        match self.action {
            Verdict::Errno => Action::Errno(self.errno),
            Verdict::Trap => Action::Trap,
            Verdict::Log => Action::Log,
            Verdict::KillThread => Action::KillThread,
            Verdict::KillProcess => Action::KillProcess,
        }
    }

    fn options(&self) -> Options {
        let options = if self.allow.is_empty() {
            let mut options = Options::denylist(self.deny_action())
                .with_syscalls(self.deny.iter().map(|arg| syscall(arg)));
            if self.deny_dangerous {
                options = options.with_syscalls(syscalls::DANGEROUS.iter().copied());
            }
            options
        } else {
            Options::allowlist(self.deny_action())
                .with_syscalls(self.allow.iter().map(|arg| syscall(arg)))
        };
        options
            .with_all_threads(self.all_threads)
            .with_compatibility(if self.strict {
                Compatibility::HardRequirement
            } else {
                Compatibility::BestEffort
            })
    }
}

fn emit(options: &Options, path: &PathBuf) -> Result<(), String> {
    let program = compile(options).map_err(|err| err.to_string())?;
    let mut file =
        std::fs::File::create(path).map_err(|err| format!("{}: {err}", path.display()))?;
    file.write_all(&program.to_bytes())
        .map_err(|err| format!("{}: {err}", path.display()))
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if cli.detect {
        println!("seccomp: {}", detect());
        return ExitCode::SUCCESS;
    }
    if cli.list {
        for (name, number) in syscalls::native() {
            println!("{number}\t{name}");
        }
        return ExitCode::SUCCESS;
    }
    if cli.allow.is_empty() && cli.deny.is_empty() && !cli.deny_dangerous {
        eprintln!("rune-seccomp: give --allow, --deny or --deny-dangerous");
        return ExitCode::from(125);
    }
    let options = cli.options();
    if let Some(path) = &cli.emit {
        return match emit(&options, path) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("rune-seccomp: {err}");
                ExitCode::from(125)
            }
        };
    }

    let report = match install(&options) {
        Ok(report) => report,
        Err(err) => {
            eprintln!("rune-seccomp: {err}");
            return ExitCode::from(125);
        }
    };
    if cli.verbose {
        let status = match report.status {
            Status::FullyEnforced => "fully enforced",
            Status::PartiallyEnforced => "partially enforced",
            _ => "not enforced",
        };
        eprintln!(
            "rune-seccomp: {status}, {} rule(s), {} instruction(s), listed: {}, default: {}; seccomp {}",
            report.rules,
            report.instructions,
            report.listed_action,
            report.default_action,
            report.support
        );
        for (requested, fallback) in &report.substitutions {
            eprintln!("rune-seccomp: {requested} unavailable, using {fallback}");
        }
        for name in &report.skipped {
            eprintln!("rune-seccomp: skipped {name} (not a system call on this architecture)");
        }
    }

    let Some((program, args)) = cli.command.split_first() else {
        return ExitCode::from(125);
    };
    let err = std::process::Command::new(program).args(args).exec();
    eprintln!(
        "rune-seccomp: cannot execute {}: {err}",
        program.to_string_lossy()
    );
    ExitCode::from(if err.kind() == std::io::ErrorKind::NotFound {
        127
    } else {
        126
    })
}
