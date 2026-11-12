//! `rune-pledge`: run a program with pledge-style reduced capabilities.
//!
//! ```text
//! rune-pledge --path rx:/usr --path rx:/lib64 --path r:/etc 'stdio rpath' -- /usr/bin/cat /etc/hostname
//! rune-pledge --print 'stdio inet'
//! ```
//!
//! The `exec` promise is always added, since the program has to be
//! executed. Exit status: the program's own, or 125 when the profile is
//! invalid or cannot be applied, 126 when the program cannot be executed
//! (including when the profile denies it) and 127 when it does not exist.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use rune_pledge::{Enforcement, Permissions, Profile, Promise, Violation, reduce_capabilities};

/// Run a program with pledge-style reduced capabilities.
///
/// PROMISES is a pledge(2) promise string, such as 'stdio rpath inet'.
/// On Linux it becomes a Landlock ruleset and a seccomp filter; elsewhere
/// nothing is restricted and a warning is printed.
#[derive(Parser)]
#[command(name = "rune-pledge", version, about)]
struct Cli {
    /// Promises to keep: stdio rpath wpath cpath dpath fattr exec proc id
    /// inet unix.
    promises: String,
    /// Restrict the filesystem to PATH with unveil(2)-style permissions
    /// (any of r, w, x, c), as PERMS:PATH. Repeatable. Without it, the
    /// promises apply to the whole filesystem.
    #[arg(short, long = "path", value_name = "PERMS:PATH", value_parser = parse_path)]
    paths: Vec<(Permissions, PathBuf)>,
    /// What a denied system call does.
    #[arg(long, value_enum, default_value_t = OnViolation::Errno)]
    violation: OnViolation,
    /// Fail unless both Landlock and seccomp are available.
    #[arg(long)]
    required: bool,
    /// Print warnings about what is not enforced on stderr.
    #[arg(short, long)]
    verbose: bool,
    /// Print the system calls and path rules the profile maps to, and exit.
    #[arg(long)]
    print: bool,
    /// The program to run, and its arguments.
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        required_unless_present = "print",
        value_name = "PROGRAM"
    )]
    command: Vec<OsString>,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum OnViolation {
    /// Fail the call with EPERM.
    Errno,
    /// Kill the process with SIGSYS.
    Kill,
    /// Allow the call and log it to the kernel audit log.
    Log,
}

fn parse_path(arg: &str) -> Result<(Permissions, PathBuf), String> {
    let (perms, path) = arg
        .split_once(':')
        .ok_or_else(|| format!("expected PERMS:PATH, got `{arg}`"))?;
    let perms = perms.parse().map_err(|err| format!("{err}"))?;
    Ok((perms, PathBuf::from(path)))
}

impl Cli {
    fn profile(&self) -> Result<Profile, rune_pledge::Error> {
        let mut profile = Profile::pledge(&self.promises)?
            .with_violation(match self.violation {
                OnViolation::Errno => Violation::Errno,
                OnViolation::Kill => Violation::Kill,
                OnViolation::Log => Violation::Log,
            })
            .with_enforcement(if self.required {
                Enforcement::Required
            } else {
                Enforcement::BestEffort
            });
        if !self.print {
            profile = profile.with_promise(Promise::Exec);
        }
        for (perms, path) in &self.paths {
            profile = profile.with_path(path, *perms);
        }
        Ok(profile)
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let profile = match cli.profile() {
        Ok(profile) => profile,
        Err(err) => {
            eprintln!("rune-pledge: {err}");
            return ExitCode::from(125);
        }
    };
    if cli.print {
        println!("promises: {}", profile.promises);
        for rule in profile.path_rules() {
            println!("path: {} {}", rule.permissions, rule.path.display());
        }
        println!(
            "syscalls: {}",
            profile.syscalls().into_iter().collect::<Vec<_>>().join(" ")
        );
        return ExitCode::SUCCESS;
    }

    let report = match reduce_capabilities(&profile) {
        Ok(report) => report,
        Err(err) => {
            eprintln!("rune-pledge: {err}");
            return ExitCode::from(125);
        }
    };
    if cli.verbose {
        eprintln!("rune-pledge: {}", report.status);
        for warning in &report.warnings {
            eprintln!("rune-pledge: {warning}");
        }
    }

    let Some((program, args)) = cli.command.split_first() else {
        return ExitCode::from(125);
    };
    run(program, args)
}

#[cfg(unix)]
fn run(program: &OsString, args: &[OsString]) -> ExitCode {
    use std::os::unix::process::CommandExt;
    let err = std::process::Command::new(program).args(args).exec();
    exec_failed(program, &err)
}

#[cfg(not(unix))]
fn run(program: &OsString, args: &[OsString]) -> ExitCode {
    match std::process::Command::new(program).args(args).status() {
        Ok(status) => ExitCode::from(
            status
                .code()
                .and_then(|c| u8::try_from(c).ok())
                .unwrap_or(1),
        ),
        Err(err) => exec_failed(program, &err),
    }
}

fn exec_failed(program: &OsString, err: &std::io::Error) -> ExitCode {
    eprintln!(
        "rune-pledge: cannot execute {}: {err}",
        program.to_string_lossy()
    );
    ExitCode::from(if err.kind() == std::io::ErrorKind::NotFound {
        127
    } else {
        126
    })
}
