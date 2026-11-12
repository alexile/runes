//! `rune-reorder` command-line tool: windowed reordering buffer for out-of-sequence timestamped/sequenced items.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::Parser;
use rune_reorder::Reorder;
use std::io::{self, BufRead};

/// Reorder "<seq> <text>" lines read from stdin into ascending sequence order.
#[derive(Parser)]
#[command(name = "rune-reorder")]
struct Args {
    /// Maximum number of buffered out-of-order items before a gap is forced through.
    #[arg(long, default_value_t = 64)]
    window: usize,
}

fn main() {
    let args = Args::parse();
    let mut reorder = Reorder::new(args.window);

    for line in io::stdin().lock().lines().map_while(Result::ok) {
        let Some((seq_str, item)) = line.split_once(' ') else {
            eprintln!("rune-reorder: skipping malformed line: {line}");
            continue;
        };
        let Ok(seq) = seq_str.parse::<u64>() else {
            eprintln!("rune-reorder: skipping malformed line: {line}");
            continue;
        };
        for ready in reorder.push(seq, item.to_string()) {
            println!("{ready}");
        }
    }

    for ready in reorder.flush() {
        println!("{ready}");
    }
}
