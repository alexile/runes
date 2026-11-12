//! Property tests: no adapter panics on arbitrary statuses and bodies,
//! scores stay within 0-100, and timestamp parsing never panics.

#![cfg(all(
    feature = "abuseipdb",
    feature = "greynoise",
    feature = "shodan",
    feature = "censys"
))]
#![allow(clippy::unwrap_used, reason = "proptest bodies")]

use std::net::IpAddr;

use proptest::prelude::*;
use rune_ip_intel::{
    AbuseIpDb, Censys, GreyNoise, HttpResponse, ReputationProvider, ShodanInternetDb, parse_time,
};
use rune_secret_ref::SecretValue;

fn providers() -> Vec<Box<dyn ReputationProvider>> {
    vec![
        Box::new(AbuseIpDb::new(SecretValue::new("k"))),
        Box::new(GreyNoise::new()),
        Box::new(ShodanInternetDb::new()),
        Box::new(Censys::new(&SecretValue::new("a"), &SecretValue::new("b"))),
    ]
}

/// JSON-ish bodies: provider field names with random values.
fn body() -> impl Strategy<Value = String> {
    let value = prop_oneof![
        Just("null".to_owned()),
        any::<i64>().prop_map(|n| n.to_string()),
        any::<bool>().prop_map(|b| b.to_string()),
        "[a-z0-9:. -]{0,12}".prop_map(|s| format!("\"{s}\"")),
        proptest::collection::vec(any::<i32>(), 0..4).prop_map(|v| format!("{v:?}")),
        Just(r#"[{"categories":[1,99,-1],"port":70000,"service_name":"X"}]"#.to_owned()),
    ];
    let key = prop_oneof![
        Just("abuseConfidenceScore"),
        Just("reports"),
        Just("lastReportedAt"),
        Just("classification"),
        Just("last_seen"),
        Just("ports"),
        Just("tags"),
        Just("services"),
        Just("labels"),
        Just("last_updated_at"),
        Just("isWhitelisted"),
    ];
    proptest::collection::vec((key, value), 0..6).prop_map(|fields| {
        let inner: Vec<String> = fields.iter().map(|(k, v)| format!("\"{k}\":{v}")).collect();
        let obj = format!("{{{}}}", inner.join(","));
        format!(r#"{{"data":{obj},"result":{obj},{}}}"#, inner.join(",")).replace(",}", "}")
    })
}

proptest! {
    #[test]
    fn adapters_never_panic(
        status in prop_oneof![Just(200u16), Just(404), Just(429), 100u16..600],
        text in body(),
        junk in proptest::collection::vec(any::<u8>(), 0..64),
        use_junk in any::<bool>(),
    ) {
        let ip: IpAddr = "198.51.100.7".parse().unwrap();
        let bytes = if use_junk { junk } else { text.into_bytes() };
        let response = HttpResponse::new(status).with_body(bytes);
        for provider in providers() {
            if let Ok(verdict) = provider.parse(ip, &response) {
                prop_assert!(verdict.score.is_none_or(|s| s <= 100));
                prop_assert_eq!(verdict.ip, ip);
                prop_assert_eq!(verdict.provider, provider.name());
            }
        }
    }

    #[test]
    fn parse_time_never_panics(text in "\\PC{0,40}") {
        let _ = parse_time(&text);
    }

    #[test]
    fn parse_time_agrees_across_offsets(secs in 0i64..4_000_000_000, offset_min in -720i64..=840) {
        let utc = rune_epoch::to_utc_string(secs);
        prop_assert_eq!(parse_time(&utc), Some(secs));
        let local = rune_epoch::to_utc_string(secs + offset_min * 60);
        let sign = if offset_min < 0 { '-' } else { '+' };
        let abs = offset_min.abs();
        let text = format!("{}{sign}{:02}:{:02}", &local[..19], abs / 60, abs % 60);
        prop_assert_eq!(parse_time(&text), Some(secs));
    }
}
