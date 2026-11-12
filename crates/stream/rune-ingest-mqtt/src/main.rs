//! `rune-ingest-mqtt` command-line tool: minimal MQTT subscriber normalizing messages into a typed event channel.

// Binaries report results on stdout; the lint targets library code.
#![allow(clippy::print_stdout)]

use clap::Parser;
use rune_ingest_mqtt::subscribe_qos0;
use std::process::ExitCode;

/// Subscribe to an MQTT topic filter and print each normalized message as JSON.
#[derive(Parser)]
#[command(name = "rune-ingest-mqtt")]
struct Args {
    /// Broker address, e.g. `localhost:1883`.
    addr: String,
    /// Topic filter to subscribe to, e.g. `sensors/#`.
    topic_filter: String,
    /// MQTT client id to present during CONNECT.
    #[arg(long, default_value = "rune-ingest-mqtt")]
    client_id: String,
}

fn main() -> ExitCode {
    let args = Args::parse();

    let result = subscribe_qos0(&args.addr, &args.client_id, &args.topic_filter, |msg| {
        let line = serde_json::json!({
            "topic": msg.topic,
            "payload": msg.payload,
            "received_at_ms": msg.received_at_ms,
        });
        println!("{line}");
    });

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("rune-ingest-mqtt: {err:?}");
            ExitCode::FAILURE
        }
    }
}
