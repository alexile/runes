//! `rune-tz-lookup` command-line tool: offline timezone-from-coordinates lookup.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::Parser;
use rune_tz_lookup::estimate_utc_offset_hours;

/// Estimate the UTC offset for a latitude/longitude coordinate.
#[derive(Parser)]
#[command(name = "rune-tz-lookup")]
struct Args {
    lat: f64,
    lon: f64,
}

fn main() {
    let args = Args::parse();
    let offset = estimate_utc_offset_hours(args.lat, args.lon);
    let line = serde_json::json!({
        "lat": args.lat,
        "lon": args.lon,
        "utc_offset_hours": offset,
    });
    println!("{line}");
}
