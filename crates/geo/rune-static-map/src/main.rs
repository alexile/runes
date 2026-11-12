//! `rune-static-map` command-line tool: build static-map image request parameters/URLs from a set of features.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::Parser;
use rune_static_map::StaticMapRequest;
use std::process::ExitCode;

/// Build the query-parameter string for a generic static-map-image request.
#[derive(Parser)]
#[command(name = "rune-static-map")]
struct Args {
    /// Map center as `lat,lon`.
    #[arg(long)]
    center: String,

    /// Zoom level.
    #[arg(long)]
    zoom: u8,

    /// Image size as `WIDTHxHEIGHT`.
    #[arg(long)]
    size: String,

    /// A marker as `lat,lon,label_or_color`. May be given multiple times.
    #[arg(long = "marker")]
    markers: Vec<String>,

    /// An already-encoded polyline to attach as the `path` overlay.
    #[arg(long)]
    polyline: Option<String>,
}

fn parse_lat_lon(s: &str) -> Result<(f64, f64), String> {
    let (lat, lon) = s
        .split_once(',')
        .ok_or_else(|| format!("invalid `lat,lon` value `{s}`"))?;
    let lat: f64 = lat
        .trim()
        .parse()
        .map_err(|_| format!("invalid latitude in `{s}`"))?;
    let lon: f64 = lon
        .trim()
        .parse()
        .map_err(|_| format!("invalid longitude in `{s}`"))?;
    Ok((lat, lon))
}

fn parse_size(s: &str) -> Result<(u32, u32), String> {
    let (w, h) = s
        .split_once('x')
        .ok_or_else(|| format!("invalid size `{s}`, expected `WIDTHxHEIGHT`"))?;
    let w: u32 = w
        .trim()
        .parse()
        .map_err(|_| format!("invalid width in `{s}`"))?;
    let h: u32 = h
        .trim()
        .parse()
        .map_err(|_| format!("invalid height in `{s}`"))?;
    Ok((w, h))
}

fn parse_marker(s: &str) -> Result<(f64, f64, String), String> {
    let mut parts = s.splitn(3, ',');
    let lat = parts
        .next()
        .ok_or_else(|| format!("invalid marker `{s}`"))?;
    let lon = parts
        .next()
        .ok_or_else(|| format!("invalid marker `{s}`, expected `lat,lon,label`"))?;
    let label = parts
        .next()
        .ok_or_else(|| format!("invalid marker `{s}`, expected `lat,lon,label`"))?;
    let lat: f64 = lat
        .trim()
        .parse()
        .map_err(|_| format!("invalid latitude in marker `{s}`"))?;
    let lon: f64 = lon
        .trim()
        .parse()
        .map_err(|_| format!("invalid longitude in marker `{s}`"))?;
    Ok((lat, lon, label.to_string()))
}

fn main() -> ExitCode {
    let args = Args::parse();

    let center = match parse_lat_lon(&args.center) {
        Ok(c) => c,
        Err(err) => {
            eprintln!("rune-static-map: {err}");
            return ExitCode::FAILURE;
        }
    };

    let size = match parse_size(&args.size) {
        Ok(s) => s,
        Err(err) => {
            eprintln!("rune-static-map: {err}");
            return ExitCode::FAILURE;
        }
    };

    let mut request = StaticMapRequest::new(center, args.zoom, size);

    for raw in &args.markers {
        match parse_marker(raw) {
            Ok((lat, lon, label)) => request = request.add_marker(lat, lon, &label),
            Err(err) => {
                eprintln!("rune-static-map: {err}");
                return ExitCode::FAILURE;
            }
        }
    }

    if let Some(polyline) = &args.polyline {
        request = request.with_polyline(polyline);
    }

    println!("{}", request.build_query_string());
    ExitCode::SUCCESS
}
