//! `rune-mvt` command-line tool: encode features as Mapbox Vector Tile protobuf.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::Parser;
use rune_mvt::{Layer, Tile};
use std::process::ExitCode;

/// Encode a set of point features into a Mapbox Vector Tile and write the
/// resulting protobuf bytes to a file.
#[derive(Parser)]
#[command(name = "rune-mvt")]
struct Args {
    /// Name of the single layer to emit.
    #[arg(long, default_value = "layer")]
    layer: String,

    /// Tile extent: the size of the tile-local coordinate grid.
    #[arg(long, default_value_t = 4096)]
    extent: u32,

    /// Path to write the encoded tile bytes to.
    #[arg(long)]
    output: String,

    /// Point features as `x,y` tile-local integer coordinates.
    #[arg(required = true)]
    points: Vec<String>,
}

fn parse_point(s: &str) -> Result<(i32, i32), String> {
    let (x, y) = s
        .split_once(',')
        .ok_or_else(|| format!("invalid point `{s}`, expected `x,y`"))?;
    let x: i32 = x
        .trim()
        .parse()
        .map_err(|_| format!("invalid x coordinate in `{s}`"))?;
    let y: i32 = y
        .trim()
        .parse()
        .map_err(|_| format!("invalid y coordinate in `{s}`"))?;
    Ok((x, y))
}

fn main() -> ExitCode {
    let args = Args::parse();

    let mut layer = Layer::with_extent(&args.layer, args.extent);
    for raw in &args.points {
        match parse_point(raw) {
            Ok((x, y)) => {
                // A point is never degenerate, so it is always added.
                layer.add_point_feature(x, y, &[]);
            }
            Err(err) => {
                eprintln!("rune-mvt: {err}");
                return ExitCode::FAILURE;
            }
        }
    }

    let mut tile = Tile::new();
    tile.add_layer(layer);
    let bytes = tile.encode();

    match std::fs::write(&args.output, &bytes) {
        Ok(()) => {
            println!("wrote {} bytes to {}", bytes.len(), args.output);
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("rune-mvt: {err}");
            ExitCode::FAILURE
        }
    }
}
