//! Property tests: exchanges survive a Burp export, reading is a fixpoint
//! after one pass, and reading never panics.

use proptest::collection::vec;
use proptest::option;
use proptest::prelude::*;
use rune_burp_xml::{ReadOptions, WriteOptions, format_time, parse_time, read, write};
use rune_http_model::{
    ExchangeId, HeaderEntry, HttpBody, HttpExchange, HttpRequest, HttpResponse, HttpVersion,
};

/// `9999-12-31T23:59:59Z`, in seconds.
const MAX_SECONDS: u64 = 253_402_300_799;

fn version() -> impl Strategy<Value = HttpVersion> {
    proptest::sample::select(HttpVersion::ALL.to_vec())
}

/// Header fields that survive a message head: token names (without the
/// framing and coding headers the reader interprets) and values without
/// surrounding whitespace or line breaks.
fn headers() -> impl Strategy<Value = Vec<HeaderEntry>> {
    let name = "[A-Za-z][A-Za-z0-9-]{0,10}".prop_filter("interpreted header", |name| {
        !name.eq_ignore_ascii_case("transfer-encoding")
            && !name.eq_ignore_ascii_case("content-encoding")
    });
    let value = "([!-~]([ -~]{0,12}[!-~])?)?";
    vec(
        (name, value).prop_map(|(name, value)| HeaderEntry::new(name, value)),
        0..5,
    )
}

fn body() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        vec(any::<u8>(), 0..48),
        "[ -~\r\n]{0,32}".prop_map(String::into_bytes),
    ]
}

fn request() -> impl Strategy<Value = HttpRequest> {
    (
        "[A-Z]{1,8}",
        "https?://[a-z0-9.-]{1,12}(:[0-9]{1,5})?(/[A-Za-z0-9._~%-]{0,8}){0,3}(\\?[A-Za-z0-9=&%]{0,12})?",
        version(),
        headers(),
        body(),
    )
        .prop_map(|(method, url, version, headers, body)| {
            let mut request = HttpRequest::new(method, url).with_headers(headers);
            request.http_version = version;
            request.body = HttpBody::new(body);
            request
        })
}

fn response() -> impl Strategy<Value = HttpResponse> {
    (
        100_u16..1000,
        option::of("[!-~]([ -~]{0,10}[!-~])?"),
        version(),
        headers(),
        body(),
        option::of(1_u64..1_000_000),
    )
        .prop_map(|(status, reason, version, headers, body, missing)| {
            let mut response = HttpResponse::new(status).with_headers(headers);
            response.reason = reason;
            response.http_version = version;
            let len = body.len() as u64;
            response.body = HttpBody::new(body);
            if let Some(missing) = missing {
                response.body.truncated = true;
                response.body.total_len = Some(len + missing);
            }
            response
        })
}

fn exchanges() -> impl Strategy<Value = Vec<HttpExchange>> {
    vec(
        (
            request(),
            option::of(response()),
            0..=MAX_SECONDS,
            option::of("[0-9]{1,3}(\\.[0-9]{1,3}){3}"),
            option::of("[A-Za-z0-9<>&\"' ]{0,6}[A-Za-z0-9<>&\"']"),
        ),
        0..6,
    )
    .prop_map(|items| {
        items
            .into_iter()
            .enumerate()
            .map(|(index, (request, response, seconds, address, notes))| {
                let mut exchange = HttpExchange::new(ExchangeId(index as u64), "burp", request)
                    .with_started_at(seconds * 1000);
                exchange.response = response;
                exchange.remote_address = address;
                exchange.notes = notes;
                exchange
            })
            .collect()
    })
}

/// A Burp item with arbitrary text where the messages go.
fn loose_items() -> impl Strategy<Value = String> {
    vec(
        (
            "[ -~\r\n]{0,60}",
            "[ -~\r\n]{0,60}",
            any::<bool>(),
            "[ -~]{0,30}",
        ),
        0..4,
    )
    .prop_map(|items| {
        let mut xml = String::from("<items>");
        for (request, response, base64, extra) in items {
            let (request, response) = if base64 {
                (
                    format!(
                        "<request base64=\"true\">{}</request>",
                        rune_base64_encode(request.as_bytes())
                    ),
                    format!(
                        "<response base64=\"true\">{}</response>",
                        rune_base64_encode(response.as_bytes())
                    ),
                )
            } else {
                (
                    format!(
                        "<request><![CDATA[{}]]></request>",
                        request.replace("]]>", "")
                    ),
                    format!(
                        "<response><![CDATA[{}]]></response>",
                        response.replace("]]>", "")
                    ),
                )
            };
            let extra = extra.replace(['<', '&'], "");
            xml.push_str("<item><host>h.test</host><time>");
            xml.push_str(&extra);
            xml.push_str("</time>");
            xml.push_str(&request);
            xml.push_str(&response);
            xml.push_str("</item>");
        }
        xml.push_str("</items>");
        xml
    })
}

/// Standard base64, written out here so the tests need no extra crate.
fn rune_base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        for (index, shift) in [18, 12, 6, 0].into_iter().enumerate() {
            if index <= chunk.len() {
                out.push(char::from(ALPHABET[(n >> shift & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

proptest! {
    #[test]
    fn exchanges_round_trip(exchanges in exchanges()) {
        let xml = write(&exchanges, &WriteOptions::default());
        let report = read(xml.as_bytes(), &ReadOptions::default().with_raw(false)).unwrap();
        prop_assert!(report.warnings.is_empty(), "{:?}", report.warnings);
        prop_assert_eq!(report.exchanges, exchanges);
    }

    #[test]
    fn raw_bytes_are_written_verbatim(exchanges in exchanges()) {
        let xml = write(&exchanges, &WriteOptions::default());
        let first = read(xml.as_bytes(), &ReadOptions::default()).unwrap();
        let again = write(&first.exchanges, &WriteOptions::default());
        let second = read(again.as_bytes(), &ReadOptions::default()).unwrap();
        prop_assert_eq!(second.exchanges, first.exchanges);
    }

    #[test]
    fn reading_is_a_fixpoint_after_one_pass(xml in loose_items()) {
        let options = ReadOptions::default().with_raw(false);
        let mut first = read(xml.as_bytes(), &options).unwrap().exchanges;
        // Skipped items leave gaps in the ids; a written export has none.
        for (index, exchange) in first.iter_mut().enumerate() {
            exchange.id = ExchangeId(index as u64);
        }
        let written = write(&first, &WriteOptions::default());
        let second = read(written.as_bytes(), &options).unwrap();
        prop_assert_eq!(second.exchanges, first);
    }

    #[test]
    fn reading_never_panics(input in vec(any::<u8>(), 0..256), text in "<items>[ -~\r\n]{0,200}") {
        let _ = read(&input, &ReadOptions::default());
        let _ = read(text.as_bytes(), &ReadOptions::default());
    }

    #[test]
    fn times_round_trip(seconds in 0..=MAX_SECONDS, text in ".{0,40}") {
        prop_assert_eq!(parse_time(&format_time(seconds * 1000)), Some(seconds * 1000));
        let _ = parse_time(&text);
    }
}
