//! `rune-landlock`: run a program under a Landlock filesystem allowlist.
//!
//! ```text
//! rune-landlock --read-exec /usr --read /etc --read-write . -- make test
//! rune-landlock --detect
//! ```
//!
//! Exit status: the program's own, or 125 when the sandbox cannot be set
//! up, 126 when the program cannot be executed (including when the
//! allowlist denies it) and 127 when it does not exist.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use std::ffi::OsString;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use rune_landlock::{Abi, Compatibility, Options, Status, detect, restrict_self};

/// Run a program under a Landlock filesystem allowlist.
///
/// Everything not granted by a --read, --read-exec, --exec or --read-write
/// rule is denied to the program and everything it starts.
#[derive(Parser)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "each bool is an independent command-line flag"
)]
#[command(name = "rune-landlock", version, about)]
struct Cli {
    /// Allow reading files and listing directories under PATH.
    #[arg(long, value_name = "PATH")]
    read: Vec<PathBuf>,
    /// Allow reading and executing under PATH (system directories).
    #[arg(long, value_name = "PATH")]
    read_exec: Vec<PathBuf>,
    /// Allow executing the file PATH.
    #[arg(long, value_name = "PATH")]
    exec: Vec<PathBuf>,
    /// Allow everything under PATH.
    #[arg(long, value_name = "PATH")]
    read_write: Vec<PathBuf>,
    /// Landlock ABI version to target (1-9).
    #[arg(long, default_value_t = 5, value_parser = clap::value_parser!(u32).range(1..=9))]
    abi: u32,
    /// Fail unless the kernel supports the requested ABI.
    #[arg(long)]
    strict: bool,
    /// Fail when a rule's path does not exist, instead of skipping it.
    #[arg(long)]
    no_skip_missing: bool,
    /// Report the enforcement status on stderr before running the program.
    #[arg(short, long)]
    verbose: bool,
    /// Print the kernel's Landlock support and exit.
    #[arg(long, exclusive = true)]
    detect: bool,
    /// The program to run, and its arguments.
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        required_unless_present = "detect",
        value_name = "PROGRAM"
    )]
    command: Vec<OsString>,
}

impl Cli {
    fn options(&self) -> Options {
        let mut options = Options::default()
            .with_abi(Abi::from_number(self.abi).unwrap_or(Abi::V5))
            .with_skip_missing(!self.no_skip_missing)
            .with_compatibility(if self.strict {
                Compatibility::HardRequirement
            } else {
                Compatibility::BestEffort
            });
        for path in &self.read {
            options = options.with_read(path);
        }
        for path in &self.read_exec {
            options = options.with_read_exec(path);
        }
        for path in &self.exec {
            options = options.with_exec(path);
        }
        for path in &self.read_write {
            options = options.with_read_write(path);
        }
        options
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if cli.detect {
        println!("landlock: {}", detect());
        return ExitCode::SUCCESS;
    }

    let report = match restrict_self(&cli.options()) {
        Ok(report) => report,
        Err(err) => {
            eprintln!("rune-landlock: {err}");
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
            "rune-landlock: {status}, requested ABI {}, landlock {}, {} rule(s)",
            report.requested_abi, report.support, report.rules
        );
        if !report.unenforced.is_empty() {
            eprintln!("rune-landlock: unenforced rights: {}", report.unenforced);
        }
        for path in &report.skipped {
            eprintln!("rune-landlock: skipped missing {}", path.display());
        }
    }

    let Some((program, args)) = cli.command.split_first() else {
        return ExitCode::from(125);
    };
    let err = std::process::Command::new(program).args(args).exec();
    eprintln!(
        "rune-landlock: cannot execute {}: {err}",
        program.to_string_lossy()
    );
    ExitCode::from(if err.kind() == std::io::ErrorKind::NotFound {
        127
    } else {
        126
    })
}
