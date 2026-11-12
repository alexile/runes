//! `rune-pcap` command-line tool: list the packets of a pcap or pcapng
//! file, one line each.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use std::fmt::Write as _;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use rune_packet::{Packet, Transport};
use rune_pcap::{CaptureReader, Error, Format, Record};

/// List the packets of a pcap or pcapng file, one line each.
#[derive(Parser)]
#[command(name = "rune-pcap", version, about)]
struct Cli {
    /// Capture file to read (`-` for standard input).
    file: PathBuf,
    /// Stop after this many packets.
    #[arg(short = 'c', long)]
    count: Option<u64>,
    /// Refuse records or blocks longer than this many bytes.
    #[arg(long, default_value_t = rune_pcap::DEFAULT_MAX_RECORD_LEN)]
    max_record_len: u32,
}

fn describe(packet: &Packet<'_>) -> String {
    let mut out = String::new();
    if let Some(ip) = packet.ip {
        let ports = packet
            .transport
            .and_then(|t| Some((t.src_port()?, t.dst_port()?)));
        match ports {
            Some((sp, dp)) => write!(
                out,
                "{} > {}",
                SocketAddr::new(ip.src(), sp),
                SocketAddr::new(ip.dst(), dp)
            ),
            None => write!(out, "{} > {}", ip.src(), ip.dst()),
        }
        .ok();
        out.push_str(match packet.transport {
            Some(Transport::Tcp(_)) => " TCP",
            Some(Transport::Udp(_)) => " UDP",
            Some(Transport::Icmpv4(_)) => " ICMP",
            Some(Transport::Icmpv6(_)) => " ICMPv6",
            _ => "",
        });
    } else if let Some(arp) = packet.arp {
        write!(out, "ARP op {}", arp.operation.0).ok();
    } else if let Some(eth) = packet.ethernet {
        write!(out, "ethertype 0x{:04x}", eth.ethertype.0).ok();
    }
    if let Some(err) = &packet.error {
        write!(out, " [{err}]").ok();
    }
    out
}

fn line(rec: &Record<'_>) -> String {
    let ts = rec
        .timestamp
        .map_or_else(|| "-".to_owned(), |t| t.to_string());
    let what = rec
        .dissect()
        .map_or_else(|| format!("({})", rec.link_type), |p| describe(&p));
    format!(
        "{ts} if{} {}/{} {what}",
        rec.interface_id,
        rec.data.len(),
        rec.original_len
    )
}

fn run(cli: &Cli) -> Result<(), Error> {
    let input: Box<dyn io::Read> = if cli.file.as_os_str() == "-" {
        Box::new(io::stdin().lock())
    } else {
        Box::new(File::open(&cli.file)?)
    };
    let mut reader =
        CaptureReader::new(BufReader::new(input))?.with_max_record_len(cli.max_record_len);
    let mut out = BufWriter::new(io::stdout().lock());
    let format = match reader.format() {
        Format::PcapNg => "pcapng",
        _ => "pcap",
    };
    writeln!(out, "# {format}")?;
    let mut n = 0u64;
    while cli.count.is_none_or(|c| n < c) {
        let Some(rec) = reader.next_packet()? else {
            break;
        };
        writeln!(out, "{}", line(&rec))?;
        n += 1;
    }
    out.flush()?;
    Ok(())
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}
