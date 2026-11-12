//! `rune-egress-proxy` command-line tool: run an allowlisted, default-deny
//! HTTP CONNECT proxy on a TCP address or a Unix domain socket, logging
//! every decision to stderr.

use std::net::TcpListener;
use std::os::unix::fs::FileTypeExt;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use rune_egress_proxy::{DEFAULT_MAX_HEAD_LEN, Policy, Proxy};

/// Allowlisted, default-deny HTTP CONNECT egress proxy.
#[derive(Parser)]
#[command(name = "rune-egress-proxy", version, about)]
struct Cli {
    /// TCP address to listen on.
    #[arg(long, default_value = "127.0.0.1:3128", conflicts_with = "unix")]
    listen: String,
    /// Listen on a Unix domain socket at this path instead (a stale socket there is replaced).
    #[arg(long)]
    unix: Option<PathBuf>,
    /// Allowed host pattern: `api.example.com` or `*.example.com` (repeatable).
    #[arg(long = "allow-host", value_name = "PATTERN")]
    hosts: Vec<String>,
    /// Allowed IP address or CIDR range (repeatable).
    #[arg(long = "allow-ip", value_name = "CIDR")]
    ips: Vec<String>,
    /// Allowed port (repeatable); every port when omitted.
    #[arg(long = "allow-port", value_name = "PORT")]
    ports: Vec<u16>,
    /// Largest accepted request head, in bytes.
    #[arg(long, default_value_t = DEFAULT_MAX_HEAD_LEN)]
    max_head_len: usize,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let policy = cli
        .ports
        .iter()
        .fold(Policy::new(), |policy, &port| policy.allow_port(port))
        .allow_hosts(&cli.hosts)?
        .allow_ips(&cli.ips)?;
    let proxy = Proxy::new(policy)
        .with_max_head_len(cli.max_head_len)
        .with_observer(|event| eprintln!("{event}"));
    if let Some(path) = cli.unix {
        // Replace a stale socket, but never delete any other kind of file.
        if std::fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_socket()) {
            std::fs::remove_file(&path)?;
        }
        let listener = std::os::unix::net::UnixListener::bind(&path)?;
        eprintln!("listening on {}", path.display());
        proxy.serve_unix(&listener)
    }
    let listener = TcpListener::bind(&cli.listen)?;
    eprintln!("listening on {}", listener.local_addr()?);
    proxy.serve_tcp(&listener)
}
