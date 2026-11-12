//! Global installation. Its own test binary, since the global subscriber can
//! be set once per process.

use rune_telemetry::{Error, Telemetry, TelemetryConfig};

#[test]
fn installs_once_globally() {
    let config = TelemetryConfig::default().with_filter("off");
    let guard = Telemetry::new(config.clone())
        .with_writer(std::io::sink)
        .install()
        .unwrap();
    tracing::info!("goes to the global subscriber");
    let second = Telemetry::new(config).with_writer(std::io::sink).install();
    assert_eq!(second.unwrap_err(), Error::AlreadyInitialized);
    assert_eq!(
        rune_telemetry::init().unwrap_err(),
        Error::AlreadyInitialized
    );
    guard.shutdown().unwrap();
}
