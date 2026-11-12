//! `rune-hex` command-line tool: hex encode and decode files and stdin.
//!
//! Both directions stream, so large inputs are handled in constant memory.

use clap::{Parser, Subcommand};
use rune_hex::{
    DecodeOptions,
    io::{DecodeWriter, EncodeWriter},
};
use std::{
    fs::File,
    io::{self, BufWriter, Read, Write},
    process::ExitCode,
};

/// Hex encode and decode bytes, files, and stdin.
#[derive(Parser)]
#[command(name = "rune-hex", version, author)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Encode bytes to hex
    Encode {
        /// File to encode (omit or use - for stdin)
        file: Option<String>,
        /// Output uppercase hex
        #[arg(short, long)]
        upper: bool,
        /// Start a new line after this many bytes (0 = one line)
        #[arg(short, long, value_name = "BYTES", default_value_t = 0)]
        wrap: usize,
        /// Text to put between bytes, e.g. ":" or " "
        #[arg(short, long, value_name = "TEXT", default_value = "")]
        separator: String,
    },
    /// Decode hex to raw bytes
    ///
    /// Whitespace between bytes and a leading 0x are always accepted.
    Decode {
        /// Hex string to decode, or - to read from stdin (the default)
        input: Option<String>,
        /// Read the hex text from this file instead
        #[arg(short, long, conflicts_with = "input")]
        file: Option<String>,
        /// Also accept this character between bytes (repeatable), e.g. -s : -s -
        #[arg(short, long = "separator", value_name = "CHAR")]
        separators: Vec<char>,
    },
}

fn main() -> ExitCode {
    let result = match Cli::parse().command {
        Command::Encode {
            file,
            upper,
            wrap,
            separator,
        } => open(file.as_deref()).and_then(|input| encode(input, upper, wrap, &separator)),
        Command::Decode {
            input,
            file,
            separators,
        } => decode_cmd(input.as_deref(), file.as_deref(), &separators),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        // A closed pipe (`rune-hex encode big.bin | head`) is not a failure.
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("rune-hex: {e}");
            ExitCode::FAILURE
        }
    }
}

fn open(path: Option<&str>) -> io::Result<Box<dyn Read>> {
    match path {
        None | Some("-") => Ok(Box::new(io::stdin().lock())),
        Some(p) => File::open(p)
            .map(|f| Box::new(f) as Box<dyn Read>)
            .map_err(|e| io::Error::new(e.kind(), format!("{p}: {e}"))),
    }
}

fn encode(mut input: impl Read, upper: bool, wrap: usize, separator: &str) -> io::Result<()> {
    let mut out = BufWriter::new(io::stdout().lock());
    if wrap == 0 && separator.is_empty() {
        let mut enc = EncodeWriter::new(&mut out).uppercase(upper);
        io::copy(&mut input, &mut enc)?;
    } else {
        let mut buf = vec![0u8; 64 * 1024];
        let mut pair = [0u8; 2];
        let mut count = 0usize;
        loop {
            let n = match input.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            for &byte in &buf[..n] {
                if count > 0 {
                    if wrap > 0 && count.is_multiple_of(wrap) {
                        out.write_all(b"\n")?;
                    } else {
                        out.write_all(separator.as_bytes())?;
                    }
                }
                let text = if upper {
                    rune_hex::encode_upper_to_slice([byte], &mut pair)
                } else {
                    rune_hex::encode_to_slice([byte], &mut pair)
                };
                out.write_all(text.map_err(io::Error::from)?.as_bytes())?;
                count += 1;
            }
        }
    }
    out.write_all(b"\n")?;
    out.flush()
}

fn decode_cmd(input: Option<&str>, file: Option<&str>, separators: &[char]) -> io::Result<()> {
    let mut options = DecodeOptions::new()
        .allow_prefix(true)
        .skip_whitespace(true);
    for &sep in separators {
        let byte = u8::try_from(sep)
            .ok()
            .filter(|b| b.is_ascii() && !b.is_ascii_hexdigit())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("separator {sep:?} must be an ASCII character other than a hex digit"),
                )
            })?;
        options = options.separator(byte);
    }

    let mut out = BufWriter::new(io::stdout().lock());
    let mut dec = DecodeWriter::with_options(&mut out, options);
    match (input, file) {
        (Some(text), None) if text != "-" => dec.write_all(text.as_bytes())?,
        (_, path) => {
            io::copy(&mut open(path)?, &mut dec)?;
        }
    }
    dec.finish()?;
    out.flush()
}
