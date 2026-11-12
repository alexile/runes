//! Round trips over real-world exports from Chrome, Firefox and Charles.

#![allow(clippy::unwrap_used, reason = "test helpers")]

use rune_har::{Har, ReadOptions, WriteOptions, parse, read, write};
use rune_http_model::{HttpExchange, HttpVersion};
use serde_json::Value;

const CHROME: &[u8] = include_bytes!("fixtures/chrome.har");
const FIREFOX: &[u8] = include_bytes!("fixtures/firefox.har");
const CHARLES: &[u8] = include_bytes!("fixtures/charles.har");
const ALL: [(&str, &[u8]); 3] = [
    ("chrome", CHROME),
    ("firefox", FIREFOX),
    ("charles", CHARLES),
];

fn exchanges(input: &[u8]) -> Vec<HttpExchange> {
    let report = read(input, &ReadOptions::default()).unwrap();
    assert!(report.warnings.is_empty(), "{:?}", report.warnings);
    report.exchanges
}

/// Checks the fields HAR 1.2 marks required are present.
fn assert_spec_shape(document: &str) {
    let value: Value = serde_json::from_str(document).unwrap();
    let log = &value["log"];
    assert_eq!(log["version"], "1.2");
    for key in ["name", "version"] {
        assert!(log["creator"][key].is_string(), "creator.{key}");
    }
    for entry in log["entries"].as_array().unwrap() {
        for key in [
            "startedDateTime",
            "time",
            "request",
            "response",
            "cache",
            "timings",
        ] {
            assert!(entry.get(key).is_some(), "entry.{key}");
        }
        for key in [
            "method",
            "url",
            "httpVersion",
            "cookies",
            "headers",
            "queryString",
            "headersSize",
            "bodySize",
        ] {
            assert!(entry["request"].get(key).is_some(), "request.{key}");
        }
        for key in [
            "status",
            "statusText",
            "httpVersion",
            "cookies",
            "headers",
            "content",
            "redirectURL",
            "headersSize",
            "bodySize",
        ] {
            assert!(entry["response"].get(key).is_some(), "response.{key}");
        }
        for key in ["size", "mimeType"] {
            assert!(
                entry["response"]["content"].get(key).is_some(),
                "content.{key}"
            );
        }
        for key in ["send", "wait", "receive"] {
            assert!(
                entry["timings"][key].as_f64().unwrap() >= 0.0,
                "timings.{key}"
            );
        }
    }
}

#[test]
fn documents_round_trip_losslessly() {
    for (name, input) in ALL {
        let parsed = parse(input).unwrap();
        assert!(parsed.warnings.is_empty(), "{name}: {:?}", parsed.warnings);
        for pretty in [false, true] {
            let json = parsed.har.to_json(pretty).unwrap();
            let again = parse(json.as_bytes()).unwrap();
            assert_eq!(again.har, parsed.har, "{name}");
            assert_eq!(again.warnings, []);
        }
    }
}

#[test]
fn documents_keep_exporter_fields() {
    let har = parse(CHROME).unwrap().har;
    let json: Value = serde_json::from_str(&har.to_json(false).unwrap()).unwrap();
    let entry = &json["log"]["entries"][1];
    assert_eq!(
        entry["_initiator"]["stack"]["callFrames"][0]["functionName"],
        "addToCart"
    );
    assert_eq!(entry["_resourceType"], "fetch");
    assert_eq!(entry["timings"]["_blocked_queueing"], 0.3);
    let on_load = json["log"]["pages"][0]["pageTimings"]["onLoad"]
        .as_f64()
        .unwrap();
    assert!((on_load - 980.123).abs() < 1e-3);
    assert_eq!(
        har.log.entries[0].request.cookies[0].extra["sameSite"],
        "Lax"
    );

    let har = parse(CHARLES).unwrap().har;
    assert_eq!(har.log.creator.name, "Charles Proxy");
    assert_eq!(
        har.log.entries[0].response.extra["_charlesStatus"],
        "COMPLETE"
    );
    assert_eq!(har.log.entries[1].response.status, 204); // written as "204"

    let har = parse(FIREFOX).unwrap().har;
    assert_eq!(har.log.browser.as_ref().unwrap().name, "Firefox");
    assert_eq!(har.log.pages[0].title, "Login – Example");
    assert_eq!(har.log.entries[0].request.body_size, 0);
}

#[test]
fn exchanges_round_trip() {
    for (name, input) in ALL {
        let first = exchanges(input);
        for options in [
            WriteOptions::default(),
            WriteOptions::default().with_pretty(true),
        ] {
            let written = write(&first, &options).unwrap();
            assert_spec_shape(&written);
            assert_eq!(exchanges(written.as_bytes()), first, "{name}");
        }
        // Through the document model as well.
        let har = Har::from_exchanges(&first, &WriteOptions::default());
        assert_eq!(har.to_exchanges(&ReadOptions::default()).exchanges, first);
    }
}

#[test]
fn chrome() {
    let all = exchanges(CHROME);
    assert_eq!(all.len(), 5);
    let [page, cart, logo, pdf, blocked] = all.as_slice() else {
        unreachable!()
    };

    assert_eq!(page.tool, "har");
    assert_eq!(page.request.http_version, HttpVersion::Http2);
    assert_eq!(page.request.headers.len(), 4, "pseudo-headers dropped");
    assert_eq!(
        page.request.header("cookie"),
        Some("sid=fake-session; consent=yes")
    );
    assert_eq!(page.started_at_unix_milliseconds, 1_772_619_330_120);
    assert_eq!(page.timings.total_milliseconds, 216);
    assert_eq!(page.timings.time_to_headers_milliseconds, Some(207));
    assert_eq!(page.remote_address.as_deref(), Some("[2001:db8::10]"));
    let response = page.response.as_ref().unwrap();
    assert_eq!(response.reason, None);
    assert_eq!(response.header_values("set-cookie").count(), 2);
    assert!(
        response
            .body
            .as_utf8()
            .unwrap()
            .contains("Caf\u{e9} \u{2615}")
    );
    assert!(!response.body.truncated);

    assert_eq!(
        cart.request.body.as_utf8(),
        Some(r#"{"sku":"BK-17","qty":2,"gift":true}"#)
    );
    assert_eq!(
        cart.response.as_ref().unwrap().location(),
        Some("/api/cart/9")
    );

    assert_eq!(logo.request.http_version, HttpVersion::Http3);
    assert_eq!(logo.remote_address, None);
    let body = &logo.response.as_ref().unwrap().body;
    assert_eq!(&body.as_bytes()[..4], b"\x89PNG");

    let body = &pdf.response.as_ref().unwrap().body;
    assert!(body.is_empty());
    assert_eq!((body.truncated, body.total_len), (true, Some(48_211)));

    assert!(blocked.response.is_none());
    assert_eq!(blocked.error.as_deref(), Some("net::ERR_BLOCKED_BY_CLIENT"));
    assert_eq!(blocked.request.http_version, HttpVersion::Http11);

    let with_pseudo = read(CHROME, &ReadOptions::default().with_pseudo_headers(true)).unwrap();
    assert_eq!(with_pseudo.exchanges[0].request.headers.len(), 8);
    assert_eq!(
        with_pseudo.exchanges[0].request.header(":path"),
        Some("/?utm_source=mail&q=caf%C3%A9")
    );
}

#[test]
fn firefox() {
    let all = exchanges(FIREFOX);
    let [page, login, font] = all.as_slice() else {
        unreachable!()
    };
    // 09:00:00.012+02:00
    assert_eq!(page.started_at_unix_milliseconds, 1_777_618_800_012);
    assert_eq!(page.timings.time_to_headers_milliseconds, Some(113));
    // Firefox counts characters, not bytes: a smaller size is no truncation.
    assert!(!page.response.as_ref().unwrap().body.truncated);

    assert_eq!(
        login.request.body.as_utf8(),
        Some("user=alice&pass=not-a-real-pass&x=%21")
    );
    let response = login.response.as_ref().unwrap();
    assert_eq!(
        (response.status, response.reason.as_deref()),
        (302, Some("Found"))
    );
    assert!(response.body.is_empty());
    assert_eq!(login.timings.time_to_headers_milliseconds, Some(45));

    assert_eq!(
        &font.response.as_ref().unwrap().body.as_bytes()[..4],
        b"wOF2"
    );
}

#[test]
fn charles() {
    let all = exchanges(CHARLES);
    let [list, put, connect] = all.as_slice() else {
        unreachable!()
    };
    let body = &list.response.as_ref().unwrap().body;
    assert_eq!(body.as_utf8(), Some(r#"{"items":[3,4],"next":null}"#));
    assert_eq!(list.timings.time_to_headers_milliseconds, Some(161));

    assert_eq!(put.timings.total_milliseconds, 92); // written as "92"
    assert_eq!(put.request.body.as_bytes(), [0, 1, 2, 3, 4, 255]);
    let response = put.response.as_ref().unwrap();
    assert_eq!(
        (response.status, response.reason.as_deref()),
        (204, Some("No Content"))
    );

    assert!(connect.response.is_none());
    assert_eq!(connect.error.as_deref(), Some("Connect timed out"));
    assert_eq!(connect.notes.as_deref(), Some("Connect timed out"));
    assert_eq!(connect.timings.time_to_headers_milliseconds, Some(3001));
}

#[test]
fn ids_and_tools_survive_a_round_trip() {
    let mut all = exchanges(CHARLES);
    for (index, exchange) in all.iter_mut().enumerate() {
        exchange.id = rune_http_model::ExchangeId(100 + index as u64);
        exchange.tool = "proxy".to_owned();
    }
    let written = write(&all, &WriteOptions::default()).unwrap();
    let again = read(
        written.as_bytes(),
        &ReadOptions::default().with_tool("other"),
    )
    .unwrap();
    assert_eq!(again.exchanges, all);
}
