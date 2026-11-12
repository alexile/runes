//! `rune-which` command-line tool: locate executables on `PATH` or in
//! given directories.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use rune_which::Finder;

/// Locate executables on PATH or in given directories, honouring PATHEXT.
#[derive(Parser)]
#[command(name = "rune-which", version, about)]
struct Cli {
    /// Executable names to look up.
    #[arg(required = true)]
    names: Vec<String>,
    /// Print every match, not just the first.
    #[arg(short, long)]
    all: bool,
    /// Search this directory before PATH (repeatable).
    #[arg(long = "dir", value_name = "DIR")]
    dirs: Vec<PathBuf>,
    /// Do not search PATH, only the --dir directories.
    #[arg(long)]
    no_path: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    // PATHEXT (on Windows) from the environment; PATH is added below,
    // after the --dir directories, and kept as an OsString.
    let mut finder = Finder::from_env(|name| {
        if name == "PATH" {
            None
        } else {
            std::env::var(name).ok()
        }
    })
    .with_dirs(&cli.dirs);
    if !cli.no_path
        && let Some(path) = std::env::var_os("PATH")
    {
        finder = finder.with_path_var(path);
    }
    if let Ok(cwd) = std::env::current_dir() {
        finder = finder.with_cwd(cwd);
    }

    let mut status = ExitCode::SUCCESS;
    for name in &cli.names {
        let found = if cli.all {
            finder.find_all(name)
        } else {
            finder.find(name).into_iter().collect()
        };
        if found.is_empty() {
            eprintln!("rune-which: no {name} found");
            status = ExitCode::FAILURE;
        }
        for path in found {
            println!("{}", path.display());
        }
    }
    status
}
