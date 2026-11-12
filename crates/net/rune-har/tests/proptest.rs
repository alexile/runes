//! Property tests: exchanges survive HAR, and reading never panics.

use proptest::collection::vec;
use proptest::option;
use proptest::prelude::*;
use rune_har::{ReadOptions, WriteOptions, parse, read, write};
use rune_http_model::{
    ExchangeId, HeaderEntry, HttpBody, HttpExchange, HttpRequest, HttpResponse, HttpVersion,
    RedirectHop, Timings,
};
use serde_json::{Value, json};

/// Largest exact integer in an `f64`; HAR writes times as JSON numbers.
const EXACT: u64 = 1 << 53;
/// `9999-12-31T23:59:59.999Z`.
const MAX_TIME: u64 = 253_402_300_799_999;

fn text() -> impl Strategy<Value = String> {
    prop_oneof![".{0,12}", "[a-zA-Z0-9 =&;:/?%+-]{0,16}"]
}

fn non_empty() -> impl Strategy<Value = String> {
    ".{1,12}"
}

fn headers() -> impl Strategy<Value = Vec<HeaderEntry>> {
    vec(
        ("[A-Za-z][A-Za-z0-9-]{0,10}", text())
            .prop_map(|(name, value)| HeaderEntry::new(name, value)),
        0..5,
    )
}

fn bytes() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        vec(any::<u8>(), 0..32),
        ".{0,24}".prop_map(String::into_bytes),
    ]
}

fn version() -> impl Strategy<Value = HttpVersion> {
    proptest::sample::select(HttpVersion::ALL.to_vec())
}

/// A request body: any bytes, with capture metadata.
fn request_body() -> impl Strategy<Value = HttpBody> {
    (
        bytes(),
        option::of(non_empty()),
        any::<bool>(),
        option::of(any::<u64>()),
    )
        .prop_map(|(bytes, coding, truncated, total)| {
            let mut body = HttpBody::new(bytes);
            body.content_encoding = coding;
            body.truncated = truncated;
            body.total_len = total;
            body
        })
}

/// A response body. HAR's `content.size` carries the full length, so a
/// known full length is longer than the captured bytes.
fn response_body() -> impl Strategy<Value = HttpBody> {
    (
        bytes(),
        option::of(non_empty()),
        any::<bool>(),
        option::of(1..1_000_000_u64),
    )
        .prop_map(|(bytes, coding, truncated, extra)| {
            let mut body = HttpBody::new(bytes);
            body.content_encoding = coding;
            body.truncated = truncated || extra.is_some();
            body.total_len = extra.map(|extra| body.len() as u64 + extra);
            body
        })
}

fn response() -> impl Strategy<Value = HttpResponse> {
    (
        1..=u16::MAX,
        option::of(non_empty()),
        version(),
        headers(),
        response_body(),
    )
        .prop_map(|(status, reason, version, headers, body)| {
            let mut response = HttpResponse::new(status)
                .with_version(version)
                .with_headers(headers)
                .with_body(body);
            response.reason = reason;
            response
        })
}

fn exchange() -> impl Strategy<Value = HttpExchange> {
    let request = (non_empty(), text(), version(), headers(), request_body()).prop_map(
        |(method, url, version, headers, body)| {
            HttpRequest::new(method, url)
                .with_version(version)
                .with_headers(headers)
                .with_body(body)
        },
    );
    let timings = (0..EXACT, option::of(0..EXACT)).prop_map(|(total, to_headers)| Timings {
        time_to_headers_milliseconds: to_headers,
        total_milliseconds: total,
    });
    let extras = (
        option::of(non_empty()),
        option::of(non_empty()),
        option::of(non_empty()),
        vec(text(), 0..3),
        vec((any::<u16>(), text()), 0..3),
    );
    (
        (any::<u64>(), text(), request, option::of(response())),
        (option::of(non_empty()), 0..=MAX_TIME, timings),
        extras,
    )
        .prop_map(
            |(
                (id, tool, request, response),
                (error, started, timings),
                (remote, label, notes, tags, hops),
            )| {
                let mut exchange = HttpExchange::new(ExchangeId(id), tool, request)
                    .with_started_at(started)
                    .with_timings(timings)
                    .with_redirect_chain(
                        hops.into_iter()
                            .map(|(status, location)| RedirectHop::new(status, location))
                            .collect(),
                    );
                exchange.response = response;
                exchange.error = error;
                exchange.remote_address = remote;
                exchange.label = label;
                exchange.notes = notes;
                exchange.tags = tags;
                exchange
            },
        )
}

/// Arbitrary JSON leaves, to hit every lenient field reader.
fn leaf() -> impl Strategy<Value = Value> {
    prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::from),
        any::<i64>().prop_map(Value::from),
        any::<f64>()
            .prop_filter("finite", |f| f.is_finite())
            .prop_map(Value::from),
        ".{0,8}".prop_map(Value::from),
        "[0-9.+-]{1,6}".prop_map(Value::from),
        Just(json!([])),
        Just(json!({})),
        Just(Value::from("base64")),
        Just(Value::from("2024-01-02T03:04:05.678+01:00")),
    ]
}

fn object(keys: &'static [&'static str], value: BoxedStrategy<Value>) -> BoxedStrategy<Value> {
    vec((proptest::sample::select(keys), value), 0..keys.len() + 1)
        .prop_map(|pairs| {
            Value::Object(
                pairs
                    .into_iter()
                    .map(|(key, value)| (key.to_owned(), value))
                    .collect(),
            )
        })
        .boxed()
}

/// HAR-shaped entries with arbitrary values in every known field.
fn har_like() -> impl Strategy<Value = Value> {
    let leaf = leaf().boxed();
    let name_values = vec(object(&["name", "value"], leaf.clone()), 0..3)
        .prop_map(Value::from)
        .boxed();
    let field = prop_oneof![3 => leaf.clone(), 1 => name_values].boxed();
    let body = object(
        &[
            "size",
            "mimeType",
            "text",
            "encoding",
            "params",
            "_encoding",
            "_truncated",
            "_totalLen",
            "_contentEncoding",
        ],
        field.clone(),
    );
    let request = object(
        &[
            "method",
            "url",
            "httpVersion",
            "headers",
            "cookies",
            "queryString",
            "headersSize",
            "bodySize",
        ],
        field.clone(),
    );
    let response = object(
        &[
            "status",
            "statusText",
            "httpVersion",
            "headers",
            "redirectURL",
            "_error",
            "comment",
        ],
        field.clone(),
    );
    let entry = (
        request,
        response,
        body.clone(),
        body,
        object(
            &[
                "blocked",
                "dns",
                "connect",
                "send",
                "wait",
                "receive",
                "_waitEstimated",
            ],
            leaf,
        ),
        object(
            &[
                "startedDateTime",
                "time",
                "serverIPAddress",
                "comment",
                "_id",
                "_tool",
                "_tags",
                "_label",
                "_redirectChain",
            ],
            field,
        ),
    )
        .prop_map(
            |(mut request, mut response, post, content, timings, mut entry)| {
                request["postData"] = post;
                response["content"] = content;
                entry["request"] = request;
                entry["response"] = response;
                entry["timings"] = timings;
                entry
            },
        );
    vec(entry, 0..4).prop_map(|entries| json!({"log": {"version": "1.2", "entries": entries}}))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn exchanges_survive_har(exchanges in vec(exchange(), 0..4)) {
        let written = write(&exchanges, &WriteOptions::default()).unwrap();
        let report = read(written.as_bytes(), &ReadOptions::default()).unwrap();
        prop_assert!(report.warnings.is_empty(), "{:?}", report.warnings);
        prop_assert_eq!(report.exchanges, exchanges);
    }

    #[test]
    fn reading_never_panics_on_text(input in ".{0,64}") {
        let _ = parse(input.as_bytes());
        let _ = read(input.as_bytes(), &ReadOptions::default());
    }

    #[test]
    fn reading_never_panics_on_bytes(input in vec(any::<u8>(), 0..64)) {
        let _ = read(&input, &ReadOptions::default());
    }

    /// Whatever reads, writes and reads back to the same exchanges, and
    /// the document model re-reads to itself.
    #[test]
    fn read_write_is_a_fixpoint(document in har_like()) {
        let input = serde_json::to_vec(&document).unwrap();
        let first = read(&input, &ReadOptions::default()).unwrap();
        let written = write(&first.exchanges, &WriteOptions::default()).unwrap();
        let second = read(written.as_bytes(), &ReadOptions::default()).unwrap();
        prop_assert_eq!(second.exchanges, first.exchanges);

        let har = parse(&input).unwrap().har;
        let again = parse(har.to_json(false).unwrap().as_bytes()).unwrap().har;
        prop_assert_eq!(again.log.entries.len(), har.log.entries.len());
    }
}
