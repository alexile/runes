//! `rune-sandbox-preset` command-line tool: run a program in a ready-made
//! sandbox preset, or print the `bwrap` arguments it would use.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use rune_sandbox_preset::{
    DevToolOptions, Egress, Network, NetworkToolOptions, Preset, dev_tool, network_tool,
    secret_masks,
};

/// Run a program in a ready-made sandbox preset (bubblewrap namespaces and a
/// seccomp filter).
#[derive(Parser)]
#[command(name = "rune-sandbox-preset", version, about)]
struct Cli {
    /// Print the bwrap arguments instead of running the program.
    #[arg(long, global = true)]
    print: bool,
    #[command(subcommand)]
    preset: PresetArg,
}

#[derive(Subcommand)]
enum PresetArg {
    /// An offline developer tool working on one project: no network.
    DevTool {
        /// The project directory (read-write, working directory). Its
        /// .env-style secret files are masked.
        #[arg(long)]
        project: PathBuf,
        #[command(flatten)]
        common: Common,
    },
    /// A tool that needs the network.
    NetworkTool {
        /// A read-write working directory.
        #[arg(long)]
        work_dir: Option<PathBuf>,
        /// Host path of a running rune-egress-proxy Unix socket: the tool
        /// gets no network but that socket.
        #[arg(long, value_name = "PATH")]
        proxy_socket: Option<PathBuf>,
        #[command(flatten)]
        common: Common,
    },
}

#[derive(clap::Args)]
struct Common {
    /// Extra readable host path.
    #[arg(long, value_name = "PATH")]
    read_only: Vec<PathBuf>,
    /// Extra writable host path.
    #[arg(long, value_name = "PATH")]
    read_write: Vec<PathBuf>,
    /// $HOME inside the sandbox (default /tmp); must be visible.
    #[arg(long)]
    home: Option<PathBuf>,
    /// The program to run, and its arguments.
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
    command: Vec<String>,
}

fn build(preset: PresetArg) -> Result<(Preset, Vec<String>), Box<dyn std::error::Error>> {
    Ok(match preset {
        PresetArg::DevTool { project, common } => {
            let mut options = DevToolOptions::new(&project).with_masks(secret_masks(&project)?);
            options.read_only = common.read_only;
            options.read_write = common.read_write;
            options.home = common.home;
            (dev_tool(&options), common.command)
        }
        PresetArg::NetworkTool {
            work_dir,
            proxy_socket,
            common,
        } => {
            let mut options = NetworkToolOptions::default();
            options.work_dir = work_dir;
            options.read_only = common.read_only;
            options.read_write = common.read_write;
            options.home = common.home;
            if let Some(socket) = proxy_socket {
                // The proxy enforces its own allowlist; the policy here only
                // documents the preset.
                options.network =
                    Network::Proxied(Egress::new(rune_egress_proxy::Policy::new(), socket));
            }
            (network_tool(&options), common.command)
        }
    })
}

fn run(cli: Cli) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let (preset, command) = build(cli.preset)?;
    let Some((program, args)) = command.split_first() else {
        return Err("no program given".into());
    };
    if cli.print {
        let args = preset
            .namespace_options()?
            .bwrap_args(program, args, None)?;
        for arg in args {
            println!("{}", arg.to_string_lossy());
        }
        return Ok(ExitCode::SUCCESS);
    }
    let status = preset.command(program, args)?.status()?;
    Ok(status
        .code()
        .and_then(|code| u8::try_from(code).ok())
        .map_or(ExitCode::FAILURE, ExitCode::from))
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}
