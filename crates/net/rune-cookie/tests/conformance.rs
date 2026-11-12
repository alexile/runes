//! The RFC 6265 conformance corpus of the IETF httpstate working group
//! (<https://github.com/abarth/http-state>, `tests/data`), the suite the
//! RFC was validated against and that browsers and `tough-cookie` run.
//!
//! - `data/parser.json`: for each test, the `Set-Cookie` headers received
//!   in a response from `http://home.example.org:8888/cookie-parser?<test>`
//!   and the cookies expected in the next request (to `sent-to`, resolved
//!   against that URL, or `/cookie-parser-result?<test>`), in order.
//!   `DISABLED_*` tests are disabled upstream; `OPTIONAL_*` tests cover
//!   behaviour the RFC leaves open, and are checked separately below.
//! - `data/dates.json` and `data/dates-bsd.json` (Chromium, BSD licence,
//!   header kept): cookie dates and their IMF-fixdate, or `null` when the
//!   date must not parse.

#![allow(clippy::unwrap_used, reason = "test helpers")]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rune_cookie::{CookieJar, JarOptions, RequestContext, format_cookie_date, parse_cookie_date};
use serde_json::Value;
use url::Url;

/// 2011-01-01: between the expired and live `Expires` dates the corpus
/// uses (2007, 2019, 2027).
fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_293_840_000)
}

struct Case {
    name: String,
    received: Vec<String>,
    sent_to: Option<String>,
    sent: Vec<(String, String)>,
}

fn cases() -> Vec<Case> {
    let corpus: Value = serde_json::from_str(include_str!("data/parser.json")).unwrap();
    corpus
        .as_array()
        .unwrap()
        .iter()
        .map(|case| Case {
            name: case["test"].as_str().unwrap().to_owned(),
            received: case["received"]
                .as_array()
                .unwrap()
                .iter()
                .map(|h| h.as_str().unwrap().to_owned())
                .collect(),
            sent_to: case
                .get("sent-to")
                .and_then(Value::as_str)
                .map(str::to_owned),
            sent: case["sent"]
                .as_array()
                .unwrap()
                .iter()
                .map(|c| {
                    (
                        c["name"].as_str().unwrap().to_owned(),
                        c["value"].as_str().unwrap().to_owned(),
                    )
                })
                .collect(),
        })
        .collect()
}

/// Runs one case; `Err` describes the mismatch.
fn run(case: &Case, options: &JarOptions) -> Result<(), String> {
    let lower = case.name.to_ascii_lowercase();
    let origin = Url::parse(&format!(
        "http://home.example.org:8888/cookie-parser?{lower}"
    ))
    .unwrap();
    let default_target = format!("/cookie-parser-result?{lower}");
    let target = origin
        .join(case.sent_to.as_deref().unwrap_or(&default_target))
        .unwrap();
    let ctx = RequestContext::http();
    let mut jar = CookieJar::with_options(options.clone());
    for header in &case.received {
        // Refused cookies are part of the test: only what is sent counts.
        let _ = jar.store(&origin, header, &ctx, now());
    }
    let sent: Vec<(String, String)> = jar
        .cookies_for(&target, &ctx, now())
        .unwrap()
        .into_iter()
        .map(|c| (c.name.clone(), c.value.clone()))
        .collect();
    if sent == case.sent {
        Ok(())
    } else {
        Err(format!(
            "{}: received {:?}, sent to {target}\n  expected {:?}\n  got      {:?}",
            case.name, case.received, case.sent, sent
        ))
    }
}

fn run_all(options: &JarOptions, prefix_filter: impl Fn(&str) -> bool) -> usize {
    let cases = cases();
    let selected: Vec<&Case> = cases.iter().filter(|c| prefix_filter(&c.name)).collect();
    let failures: Vec<String> = selected
        .iter()
        .filter_map(|case| run(case, options).err())
        .collect();
    assert!(
        failures.is_empty(),
        "{} of {} cases failed:\n{}",
        failures.len(),
        selected.len(),
        failures.join("\n")
    );
    selected.len()
}

fn required(name: &str) -> bool {
    !name.starts_with("DISABLED_") && !name.starts_with("OPTIONAL_")
}

#[test]
fn parser_corpus_rfc6265() {
    let count = run_all(&JarOptions::rfc6265(), required);
    assert_eq!(count, 214);
}

#[test]
fn parser_corpus_default_options() {
    run_all(&JarOptions::default(), required);
}

/// The behaviour RFC 6265 recommends for the optional cases: an empty
/// `Domain` attribute is ignored (§5.2.3), and trailing-dot domains do not
/// match.
#[test]
fn parser_corpus_optional() {
    let count = run_all(&JarOptions::rfc6265(), |name| name.starts_with("OPTIONAL_"));
    assert_eq!(count, 4);
}

fn date_cases(text: &str) -> Vec<(String, Option<String>)> {
    // dates-bsd.json starts with a `//` licence header.
    let json: String = text
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    let cases: Value = serde_json::from_str(&json).unwrap();
    cases
        .as_array()
        .unwrap()
        .iter()
        .map(|case| {
            (
                case["test"].as_str().unwrap().to_owned(),
                case["expected"].as_str().map(str::to_owned),
            )
        })
        .collect()
}

fn check_dates(text: &str) -> usize {
    let cases = date_cases(text);
    let failures: Vec<String> = cases
        .iter()
        .filter_map(|(input, expected)| {
            let got = parse_cookie_date(input).map(format_cookie_date);
            (got != *expected).then(|| format!("{input:?}: expected {expected:?}, got {got:?}"))
        })
        .collect();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    cases.len()
}

#[test]
fn date_examples() {
    assert_eq!(check_dates(include_str!("data/dates.json")), 15);
}

#[test]
fn date_examples_bsd() {
    assert_eq!(check_dates(include_str!("data/dates-bsd.json")), 55);
}
