//! Reading and round-tripping Burp Suite exports: proxy history saved with
//! base64 payloads, a site map saved as plain text, and a scanner issues
//! report (`tests/fixtures/`), plus the quirks seen in the wild.

#![allow(clippy::unwrap_used, reason = "test helpers")]

use rune_burp_xml::{ExportKind, ReadOptions, ReadReport, WriteOptions, parse_time, read, write};
use rune_http_model::{ExchangeId, HttpExchange, HttpVersion};

const PROXY_HISTORY: &[u8] = include_bytes!("fixtures/proxy-history.xml");
const SITE_MAP_PLAIN: &[u8] = include_bytes!("fixtures/site-map-plain.xml");
const ISSUES: &[u8] = include_bytes!("fixtures/issues.xml");
const ALL: [(&str, &[u8]); 3] = [
    ("proxy-history", PROXY_HISTORY),
    ("site-map-plain", SITE_MAP_PLAIN),
    ("issues", ISSUES),
];

fn clean(input: &[u8], options: &ReadOptions) -> ReadReport {
    let report = read(input, options).unwrap();
    assert_eq!(report.warnings, [], "unexpected warnings");
    report
}

fn response_body(exchange: &HttpExchange) -> &[u8] {
    exchange.response.as_ref().unwrap().body.as_bytes()
}

#[test]
fn proxy_history() {
    let report = clean(PROXY_HISTORY, &ReadOptions::default());
    assert_eq!(report.kind, ExportKind::Items);
    assert_eq!(report.burp_version.as_deref(), Some("2024.1.1.4"));
    assert_eq!(
        report.export_time.as_deref(),
        Some("Tue Mar 05 14:25:02 CET 2024")
    );
    assert_eq!(report.exchanges.len(), 6);
    for (index, exchange) in report.exchanges.iter().enumerate() {
        assert_eq!(exchange.id, ExchangeId(index as u64));
        assert_eq!(exchange.tool, "burp");
        assert!(exchange.request.raw.is_some());
    }

    let cart = &report.exchanges[0];
    assert_eq!(
        cart.request.url,
        "https://shop.example.test/api/cart?id=7&ref=home"
    );
    assert_eq!(cart.request.method, "GET");
    assert_eq!(cart.request.http_version, HttpVersion::Http11);
    assert_eq!(
        cart.request.header("Cookie"),
        Some("session=fake-session-0001; theme=dark")
    );
    assert_eq!(cart.request.headers.len(), 6);
    assert_eq!(
        cart.started_at_unix_milliseconds,
        parse_time("Tue Mar 05 13:22:31 UTC 2024").unwrap()
    );
    assert_eq!(cart.remote_address.as_deref(), Some("192.0.2.10"));
    assert_eq!(cart.notes.as_deref(), Some("cart <json> & gzip"));
    let response = cart.response.as_ref().unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.reason.as_deref(), Some("OK"));
    assert_eq!(response.body.content_encoding.as_deref(), Some("gzip"));
    assert_eq!(&response.body.as_bytes()[..2], [0x1f, 0x8b]);

    let login = &report.exchanges[1];
    assert_eq!(login.request.http_version, HttpVersion::Http2);
    assert_eq!(
        login.request.body.as_utf8(),
        Some("username=alice&password=not-a-real-password&r=1")
    );
    assert_eq!(login.status(), Some(302));
    let redirect = login.response.as_ref().unwrap();
    assert_eq!(redirect.http_version, HttpVersion::Http2);
    assert_eq!(redirect.location(), Some("/account"));
    assert_eq!(login.notes, None);

    let csv = &report.exchanges[2];
    assert_eq!(
        csv.request.url,
        "http://legacy.example.test:8080/report/export.csv"
    );
    assert_eq!(response_body(csv), b"id,name,price\r\n1,Mug,12.50\r\n");
    let raw = csv.response.as_ref().unwrap().raw.as_ref().unwrap();
    assert!(
        raw.as_bytes().ends_with(b"0\r\n\r\n"),
        "raw keeps the chunks"
    );

    let logo = &report.exchanges[3];
    assert_eq!(&response_body(logo)[..8], b"\x89PNG\r\n\x1a\n");

    let timed_out = &report.exchanges[4];
    assert_eq!(timed_out.request.method, "DELETE");
    assert_eq!(timed_out.response, None);
    assert_eq!(timed_out.notes.as_deref(), Some("no response: timed out"));

    let pdf = report.exchanges[5].response.as_ref().unwrap();
    assert!(pdf.body.truncated);
    assert_eq!(pdf.body.total_len, Some(5_000_000));
}

#[test]
fn site_map_saved_without_base64() {
    let report = clean(SITE_MAP_PLAIN, &ReadOptions::default());
    assert_eq!(report.exchanges.len(), 2);
    let search = &report.exchanges[0];
    assert_eq!(
        search.request.url,
        "http://intranet.example.test/search?q=a%20b"
    );
    assert_eq!(
        search.started_at_unix_milliseconds,
        parse_time("Wed Mar 06 14:00:01 UTC 2024").unwrap()
    );
    assert_eq!(response_body(search), b"<html><p>2 hits</p></html>");
    // CRLF line ends inside CDATA are kept byte for byte.
    assert!(
        search
            .request
            .raw
            .as_ref()
            .unwrap()
            .as_bytes()
            .starts_with(b"GET /search?q=a%20b HTTP/1.1\r\nHost:")
    );

    let notes = &report.exchanges[1];
    assert_eq!(notes.request.method, "PUT");
    assert_eq!(
        notes.request.body.as_utf8(),
        Some(r#"{"text":"a ]]> b & c < d"}"#)
    );
    let response = notes.response.as_ref().unwrap();
    assert_eq!(response.status, 204);
    assert_eq!(response.reason.as_deref(), Some("No Content"));
}

#[test]
fn scanner_issues() {
    let report = clean(ISSUES, &ReadOptions::default());
    assert_eq!(report.kind, ExportKind::Issues);
    let labels: Vec<_> = report
        .exchanges
        .iter()
        .map(|exchange| exchange.label.as_deref().unwrap())
        .collect();
    assert_eq!(
        labels,
        [
            "Cross-site scripting (reflected)",
            "Cross-site scripting (reflected)",
            "Robots.txt file"
        ]
    );
    let xss = &report.exchanges[0];
    assert_eq!(
        xss.request.url,
        "https://shop.example.test/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
    );
    assert_eq!(xss.remote_address.as_deref(), Some("192.0.2.10"));
    assert_eq!(xss.started_at_unix_milliseconds, 0);
    assert!(String::from_utf8_lossy(response_body(xss)).contains("<script>alert(1)</script>"));
    assert_eq!(
        report.exchanges[2].request.url,
        "https://shop.example.test/robots.txt"
    );
}

#[test]
fn exports_round_trip() {
    for (name, input) in ALL {
        // With raw bytes: Burp's own bytes are written back verbatim.
        let first = clean(input, &ReadOptions::default());
        let xml = write(&first.exchanges, &WriteOptions::default());
        let mut second = clean(xml.as_bytes(), &ReadOptions::default());
        if first.kind == ExportKind::Issues {
            // An items export has no place for the issue name.
            for exchange in &mut second.exchanges {
                assert_eq!(exchange.label, None);
            }
            let mut unlabelled = first.exchanges.clone();
            for exchange in &mut unlabelled {
                exchange.label = None;
            }
            assert_eq!(second.exchanges, unlabelled, "{name}");
        } else {
            assert_eq!(second.exchanges, first.exchanges, "{name}");
        }

        // Without raw bytes: messages are re-serialized from the model.
        let options = ReadOptions::default().with_raw(false);
        let parsed = clean(input, &options);
        let xml = write(&parsed.exchanges, &WriteOptions::default());
        let again = clean(xml.as_bytes(), &options);
        for (left, right) in parsed.exchanges.iter().zip(&again.exchanges) {
            assert_eq!(left.request, right.request, "{name}");
            assert_eq!(left.response, right.response, "{name}");
        }
    }
}

#[test]
fn written_exports_look_like_burp() {
    let report = clean(PROXY_HISTORY, &ReadOptions::default());
    let options = WriteOptions::default()
        .with_burp_version("2024.1.1.4")
        .with_export_time(parse_time("Tue Mar 05 13:25:02 UTC 2024").unwrap());
    let xml = write(&report.exchanges, &options);
    assert!(xml.starts_with("<?xml version=\"1.0\"?>\n<!DOCTYPE items ["));
    assert!(xml.contains(
        "<items burpVersion=\"2024.1.1.4\" exportTime=\"Tue Mar 05 13:25:02 UTC 2024\">"
    ));
    assert!(xml.contains("<host ip=\"198.51.100.7\">legacy.example.test</host>"));
    assert!(xml.contains("<port>8080</port>"));
    assert!(xml.contains("<path><![CDATA[/report/export.csv]]></path>"));
    assert!(xml.contains("<extension>csv</extension>"));
    assert!(xml.contains("<mimetype>JSON</mimetype>"));
    assert!(xml.contains("<comment>cart &lt;json&gt; &amp; gzip</comment>"));
    assert!(
        xml.contains("<responselength>5000"),
        "states the full length"
    );
    assert_eq!(xml.matches("<item>").count(), 6);
}

#[test]
fn bad_items_are_skipped_with_warnings() {
    let input = br#"<items>
  <item><url>https://h.test/a</url><request base64="true">!!notbase64</request></item>
  <item><url>https://h.test/b</url><request base64="true"></request></item>
  <item><url>https://h.test/c</url><request>not http</request></item>
  <item><request>GET /no-host HTTP/1.1

</request></item>
  <item><time>yesterday</time><request>GET /d HTTP/1.1
Host: h.test

</request><response base64="true">%%%</response></item>
  <item><time>Tue Jan 02 03:04:05 XYZ 2024</time><protocol>https</protocol><host>h.test</host><port>8443</port>
    <request>GET /e HTTP/1.1

</request><response>garbage</response></item>
  <item><request>GET http://proxy.test/f HTTP/1.1

</request></item>
</items>"#;
    let report = read(input, &ReadOptions::default()).unwrap();
    let urls: Vec<&str> = report
        .exchanges
        .iter()
        .map(|exchange| exchange.request.url.as_str())
        .collect();
    assert_eq!(
        urls,
        [
            "http://h.test/d",
            "https://h.test:8443/e",
            "http://proxy.test/f"
        ]
    );
    let ids: Vec<u64> = report
        .exchanges
        .iter()
        .map(|exchange| exchange.id.0)
        .collect();
    assert_eq!(ids, [4, 5, 6]);
    let warnings: Vec<(Option<usize>, &str)> = report
        .warnings
        .iter()
        .map(|warning| (warning.item, warning.code))
        .collect();
    assert_eq!(
        warnings,
        [
            (Some(0), "invalid_base64"),
            (Some(1), "empty_request"),
            (Some(2), "invalid_request"),
            (Some(3), "no_host"),
            (Some(4), "invalid_time"),
            (Some(4), "invalid_response"),
            (Some(5), "time_zone_assumed_utc"),
            (Some(5), "invalid_response"),
        ]
    );
    assert_eq!(
        report.warnings[0].to_string(),
        "item 0: skipped: request is not valid base64"
    );
    assert_eq!(report.exchanges[1].response, None);
}

#[test]
fn truncated_documents_limits_and_encodings() {
    let item = "<item><url>https://h.test/</url><request>GET / HTTP/1.1\n\n</request></item>";
    let truncated = format!("<items>{item}{item}<item><url>https://h.te");
    let report = read(truncated.as_bytes(), &ReadOptions::default()).unwrap();
    assert_eq!(report.exchanges.len(), 2);
    assert_eq!(report.warnings[0].code, "truncated");

    let many = format!("\u{feff}<items>{item}{item}{item}</items>");
    let report = read(many.as_bytes(), &ReadOptions::default().with_max_items(2)).unwrap();
    assert_eq!(report.exchanges.len(), 2);
    assert_eq!(report.warnings[0].code, "max_items");

    let mut latin1 = b"<items><item><url>https://h.test/</url><comment>caf\xe9</comment>".to_vec();
    latin1.extend_from_slice(b"<request>GET / HTTP/1.1\n\n</request></item></items>");
    let report = read(&latin1, &ReadOptions::default().with_tool("import")).unwrap();
    assert_eq!(report.warnings[0].code, "invalid_utf8");
    assert_eq!(report.exchanges[0].notes.as_deref(), Some("caf\u{fffd}"));
    assert_eq!(report.exchanges[0].tool, "import");

    assert_eq!(
        read(b"<items/>", &ReadOptions::default())
            .unwrap()
            .exchanges,
        []
    );
    assert_eq!(
        read(b"<html/>", &ReadOptions::default())
            .unwrap_err()
            .code(),
        "not_burp"
    );
    assert_eq!(
        read(b"", &ReadOptions::default()).unwrap_err().code(),
        "not_burp"
    );
}

#[test]
fn chunked_decoding_can_be_switched_off() {
    let options = ReadOptions::default().with_decode_chunked(false);
    let report = clean(PROXY_HISTORY, &options);
    assert!(response_body(&report.exchanges[2]).starts_with(b"f\r\nid,name,price"));
}
