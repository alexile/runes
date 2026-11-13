//! The only test that touches the process environment. It lives in its own
//! binary with a single test function, so no other thread reads the
//! environment while it is changed.

#![allow(unsafe_code, reason = "exercises the unsafe opt-in API")]
#![allow(clippy::unwrap_used, reason = "test")]

use rune_config::{ConfigLoader, Dotenv, EnvMapping, EnvReader, Source};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Config {
    name: String,
    count: u32,
}

#[test]
fn load_into_process_env_then_read_it_back() {
    let env = Dotenv::parse("RCPT_NAME=from-file\nRCPT_COUNT=3\n").unwrap();
    // SAFETY: this binary runs exactly one test, so no other thread exists
    // that could read or write the environment concurrently.
    let set = unsafe { env.load_into_process_env(false) }.unwrap();
    assert_eq!(set, 2);

    // Existing variables are kept unless overwriting is asked for.
    let again = Dotenv::parse("RCPT_NAME=other\n").unwrap();
    // SAFETY: as above.
    assert_eq!(unsafe { again.load_into_process_env(false) }.unwrap(), 0);
    assert_eq!(std::env::var("RCPT_NAME").unwrap(), "from-file");
    // SAFETY: as above.
    assert_eq!(unsafe { again.load_into_process_env(true) }.unwrap(), 1);
    assert_eq!(std::env::var("RCPT_NAME").unwrap(), "other");

    let config: Config = EnvReader::new().prefix("RCPT_").from_env().unwrap();
    assert_eq!((config.name.as_str(), config.count), ("other", 3));

    let loaded = ConfigLoader::new()
        .with_process_env(&EnvMapping::new().prefix("RCPT_"))
        .load()
        .unwrap();
    assert_eq!(
        loaded.source_of("count"),
        Some(&Source::Env("RCPT_COUNT".into()))
    );

    // A NUL byte is refused before anything is set.
    let nul = Dotenv::parse("RCPT_OK=1\nRCPT_NUL=\"a\0b\"\n").unwrap();
    // SAFETY: as above.
    let err = unsafe { nul.load_into_process_env(true) }.unwrap_err();
    assert_eq!(err.line, 2);
    assert!(std::env::var_os("RCPT_OK").is_none());
}
