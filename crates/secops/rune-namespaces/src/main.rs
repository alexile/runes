//! `rune-namespaces`: run a program in fresh Linux namespaces.
//!
//! ```text
//! rune-namespaces --system --rw . --chdir "$PWD" --env PATH -- make test
//! rune-namespaces --backend unshare --share-net=false -- curl example.com
//! rune-namespaces --probe
//! ```
//!
//! Exit status: the program's own, or 125 when the sandbox cannot be set
//! up, 126 when the program (or `bwrap`) cannot be executed and 127 when
//! it does not exist.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use std::ffi::OsString;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, ValueEnum};
use rune_namespaces::{
    Access, Backend, EnvPolicy, MaskKind, Mount, MountPlan, Namespace, NamespaceSet, Options, probe,
};

#[derive(Clone, Copy, ValueEnum)]
enum BackendArg {
    Bwrap,
    Unshare,
}

/// Run a program in fresh Linux namespaces.
///
/// Under bwrap (the default) the program sees an empty root with /proc,
/// /dev, /tmp and /run, plus whatever --ro, --rw and --system bind in, no
/// network, and an empty environment apart from --env and --setenv.
#[derive(Parser)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "each bool is an independent command-line flag"
)]
#[command(name = "rune-namespaces", version, about)]
struct Cli {
    /// How to build the sandbox. `unshare` keeps the host filesystem and
    /// has no PID namespace.
    #[arg(long, value_enum, default_value = "bwrap")]
    backend: BackendArg,
    /// Bind PATH read-only.
    #[arg(long, value_name = "PATH")]
    ro: Vec<PathBuf>,
    /// Bind PATH read-write.
    #[arg(long, value_name = "PATH")]
    rw: Vec<PathBuf>,
    /// Mount an empty private tmpfs at PATH.
    #[arg(long, value_name = "PATH")]
    tmpfs: Vec<PathBuf>,
    /// Hide PATH (a file or directory) from the binds.
    #[arg(long, value_name = "PATH")]
    mask: Vec<PathBuf>,
    /// Bind the system directories (/usr, /lib, ...) read-only.
    #[arg(long)]
    system: bool,
    /// Keep the host network.
    #[arg(long)]
    share_net: bool,
    /// Pass NAME (or a PREFIX* pattern) through from the environment.
    #[arg(long, value_name = "NAME")]
    env: Vec<OsString>,
    /// Set NAME=VALUE in the sandbox.
    #[arg(long, value_name = "NAME=VALUE", value_parser = parse_assignment)]
    setenv: Vec<(String, String)>,
    /// Hostname inside the sandbox.
    #[arg(long)]
    hostname: Option<String>,
    /// Working directory inside the sandbox.
    #[arg(long, value_name = "DIR")]
    chdir: Option<PathBuf>,
    /// Print the bwrap arguments instead of running anything.
    #[arg(long)]
    print_args: bool,
    /// Check whether the backend works on this host, and exit.
    #[arg(long)]
    probe: bool,
    /// The program to run, and its arguments.
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        required_unless_present = "probe",
        value_name = "PROGRAM"
    )]
    command: Vec<OsString>,
}

fn parse_assignment(s: &str) -> Result<(String, String), String> {
    s.split_once('=')
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .ok_or_else(|| format!("expected NAME=VALUE, got {s:?}"))
}

impl Cli {
    const fn backend(&self) -> Backend {
        match self.backend {
            BackendArg::Bwrap => Backend::Bwrap,
            BackendArg::Unshare => Backend::Unshare,
        }
    }

    fn options(&self) -> Result<Options, String> {
        let unshare = matches!(self.backend, BackendArg::Unshare);
        let mut mounts = if unshare {
            MountPlan::new()
        } else {
            MountPlan::isolated()
        };
        if self.system {
            mounts = mounts.with_system_read_only();
        }
        for path in &self.ro {
            mounts = mounts.with_bind(path, path, Access::ReadOnly, false);
        }
        for path in &self.rw {
            mounts = mounts.with_bind(path, path, Access::ReadWrite, false);
        }
        for path in &self.tmpfs {
            mounts = mounts.with_tmpfs(path);
        }
        for path in &self.mask {
            match Mount::mask(path) {
                Ok(Some(mount)) => mounts.push(mount),
                Ok(None) => mounts = mounts.with_mask(path, MaskKind::File),
                Err(err) => return Err(format!("cannot inspect {}: {err}", path.display())),
            }
        }
        let mut env = EnvPolicy::default();
        for name in &self.env {
            env = env.with_allow(name.clone());
        }
        for (name, value) in &self.setenv {
            env = env.with_set(name, value);
        }
        let mut namespaces = NamespaceSet::ALL;
        if unshare {
            namespaces = namespaces.without(Namespace::Pid);
        }
        if self.share_net {
            namespaces = namespaces.without(Namespace::Net);
        }
        let mut options = Options::default()
            .with_backend(self.backend())
            .with_namespaces(namespaces)
            .with_mounts(mounts)
            .with_env(env);
        if let Some(hostname) = &self.hostname {
            options = options.with_hostname(hostname);
        }
        if let Some(dir) = &self.chdir {
            options = options.with_cwd(dir);
        }
        Ok(options)
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if cli.probe {
        return match probe(&cli.backend()) {
            Ok(()) => {
                println!("namespaces: available");
                ExitCode::SUCCESS
            }
            Err(err) => {
                println!("namespaces: unavailable: {err}");
                ExitCode::FAILURE
            }
        };
    }
    let options = match cli.options() {
        Ok(options) => options,
        Err(err) => {
            eprintln!("rune-namespaces: {err}");
            return ExitCode::from(125);
        }
    };
    let Some((program, args)) = cli.command.split_first() else {
        return ExitCode::from(125);
    };
    if cli.print_args {
        return match options.bwrap_args(program, args, None) {
            Ok(bwrap_args) => {
                println!(
                    "{}",
                    bwrap_args
                        .iter()
                        .map(|a| a.to_string_lossy())
                        .collect::<Vec<_>>()
                        .join(" ")
                );
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("rune-namespaces: {err}");
                ExitCode::from(125)
            }
        };
    }
    let mut command = match options.command(program, args) {
        Ok(command) => command,
        Err(err) => {
            eprintln!("rune-namespaces: {err}");
            return ExitCode::from(125);
        }
    };
    let err = command.exec();
    eprintln!(
        "rune-namespaces: cannot execute {}: {err}",
        command.get_program().to_string_lossy()
    );
    ExitCode::from(if err.kind() == std::io::ErrorKind::NotFound {
        127
    } else {
        126
    })
}
