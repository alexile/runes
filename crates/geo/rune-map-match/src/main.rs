//! `rune-map-match` command-line tool: snap a noisy position stream onto the nearest edges of a supplied road/path graph.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::Parser;
use rune_map_match::{Edge, match_trace};
use std::fs;
use std::process::ExitCode;

/// Snap each point in a trace file onto the nearest edge from an edges file.
///
/// Both files are JSON. `edges.json`: `[{"id":0,"from":[0.0,0.0],"to":[10.0,0.0]}, ...]`.
/// `trace.json`: `[[1.0,1.0], [5.0,-1.0], ...]`.
#[derive(Parser)]
#[command(name = "rune-map-match")]
struct Args {
    edges_path: String,
    trace_path: String,
}

#[derive(serde::Deserialize)]
struct EdgeJson {
    id: usize,
    from: (f64, f64),
    to: (f64, f64),
}

fn main() -> ExitCode {
    let args = Args::parse();

    let edges_raw = match fs::read_to_string(&args.edges_path) {
        Ok(s) => s,
        Err(err) => {
            eprintln!("rune-map-match: {}: {err}", args.edges_path);
            return ExitCode::FAILURE;
        }
    };
    let trace_raw = match fs::read_to_string(&args.trace_path) {
        Ok(s) => s,
        Err(err) => {
            eprintln!("rune-map-match: {}: {err}", args.trace_path);
            return ExitCode::FAILURE;
        }
    };

    let edges: Vec<EdgeJson> = match serde_json::from_str(&edges_raw) {
        Ok(v) => v,
        Err(err) => {
            eprintln!("rune-map-match: parsing edges: {err}");
            return ExitCode::FAILURE;
        }
    };
    let trace: Vec<(f64, f64)> = match serde_json::from_str(&trace_raw) {
        Ok(v) => v,
        Err(err) => {
            eprintln!("rune-map-match: parsing trace: {err}");
            return ExitCode::FAILURE;
        }
    };

    let edges: Vec<Edge> = edges
        .into_iter()
        .map(|e| Edge {
            id: e.id,
            from: e.from,
            to: e.to,
        })
        .collect();

    for (i, matched) in match_trace(&trace, &edges).into_iter().enumerate() {
        match matched {
            Some((edge_id, (x, y))) => println!("{i}: edge {edge_id} -> ({x:.4}, {y:.4})"),
            None => println!("{i}: no match"),
        }
    }

    ExitCode::SUCCESS
}
