//! `rune-heartbeat` command-line tool: missing-heartbeat/liveness detector over a keyed stream of pings.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::Parser;
use rune_heartbeat::HeartbeatMonitor;
use std::io::{self, BufRead};
use std::time::{Duration, Instant};

/// Read "<key> <`offset_ms`>" ping lines from stdin and report which keys are
/// missing (silent longer than the timeout) as of a given evaluation time.
#[derive(Parser)]
#[command(name = "rune-heartbeat")]
struct Args {
    /// Liveness timeout in milliseconds.
    #[arg(long)]
    timeout_ms: u64,

    /// Evaluation time, in milliseconds after program start.
    #[arg(long)]
    now_ms: u64,
}

fn main() {
    let args = Args::parse();
    let t0 = Instant::now();
    let mut monitor = HeartbeatMonitor::new(Duration::from_millis(args.timeout_ms));

    for line in io::stdin().lock().lines().map_while(Result::ok) {
        let Some((key, offset_str)) = line.split_once(' ') else {
            eprintln!("rune-heartbeat: skipping malformed line: {line}");
            continue;
        };
        let Ok(offset) = offset_str.parse::<u64>() else {
            eprintln!("rune-heartbeat: skipping malformed line: {line}");
            continue;
        };
        monitor.ping(key.to_string(), t0 + Duration::from_millis(offset));
    }

    let now = t0 + Duration::from_millis(args.now_ms);
    let mut missing = monitor.missing(now);
    missing.sort();
    for key in missing {
        println!("{key}");
    }
}
