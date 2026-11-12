//! Round-trip properties: bodies and exchanges survive JSON byte-exactly,
//! base64 bodies decode their own encoding, and the parsers never panic.

use proptest::prelude::*;
use rune_http_model::{
    ExchangeId, HeaderEntry, HttpBody, HttpExchange, HttpRequest, HttpResponse, HttpVersion,
    RedirectHop, Timings, header_values, headers_from_pairs, remove_header, set_header,
};

fn body() -> impl Strategy<Value = HttpBody> {
    (
        prop_oneof![
            proptest::collection::vec(any::<u8>(), 0..64),
            any::<String>().prop_map(String::into_bytes),
        ],
        proptest::option::of("[a-z]{1,8}"),
        any::<bool>(),
        proptest::option::of(any::<u64>()),
    )
        .prop_map(|(bytes, encoding, truncated, total_len)| {
            let mut body = HttpBody::new(bytes);
            body.content_encoding = encoding;
            body.truncated = truncated;
            body.total_len = total_len;
            body
        })
}

fn headers() -> impl Strategy<Value = Vec<HeaderEntry>> {
    proptest::collection::vec(
        (any::<String>(), any::<String>()).prop_map(|(n, v)| HeaderEntry::new(n, v)),
        0..6,
    )
}

fn version() -> impl Strategy<Value = HttpVersion> {
    proptest::sample::select(HttpVersion::ALL.to_vec())
}

fn exchange() -> impl Strategy<Value = HttpExchange> {
    let request = (
        any::<String>(),
        any::<String>(),
        version(),
        headers(),
        body(),
        proptest::option::of(body()),
    )
        .prop_map(|(method, url, version, headers, body, raw)| {
            let mut request = HttpRequest::new(method, url)
                .with_version(version)
                .with_headers(headers)
                .with_body(body);
            request.raw = raw;
            request
        });
    let response = proptest::option::of(
        (
            any::<u16>(),
            proptest::option::of(any::<String>()),
            headers(),
            body(),
        )
            .prop_map(|(status, reason, headers, body)| {
                let mut response = HttpResponse::new(status)
                    .with_headers(headers)
                    .with_body(body);
                response.reason = reason;
                response
            }),
    );
    (
        any::<u64>(),
        any::<String>(),
        any::<u64>(),
        request,
        response,
        proptest::option::of(any::<String>()),
        proptest::collection::vec((any::<u16>(), any::<String>()), 0..3),
        (proptest::option::of(any::<u64>()), any::<u64>()),
        proptest::collection::vec(any::<String>(), 0..3),
    )
        .prop_map(
            |(id, tool, started, request, response, error, hops, timings, tags)| {
                let mut exchange = HttpExchange::new(ExchangeId(id), tool, request)
                    .with_started_at(started)
                    .with_redirect_chain(
                        hops.into_iter()
                            .map(|(status, location)| RedirectHop::new(status, location))
                            .collect(),
                    )
                    .with_timings(Timings {
                        time_to_headers_milliseconds: timings.0,
                        total_milliseconds: timings.1,
                    });
                exchange.response = response;
                exchange.error = error;
                exchange.tags = tags;
                exchange
            },
        )
}

proptest! {
    #[test]
    fn body_json_round_trip(body in body()) {
        let json = serde_json::to_string(&body).unwrap();
        let back: HttpBody = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(back, body);
    }

    #[test]
    fn base64_round_trip(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
        let body = HttpBody::new(bytes.clone());
        let back = HttpBody::from_base64(&body.to_base64()).unwrap();
        prop_assert_eq!(back.as_bytes(), bytes.as_slice());
    }

    #[test]
    fn exchange_json_round_trip(exchange in exchange()) {
        let json = serde_json::to_vec(&exchange).unwrap();
        let back: HttpExchange = serde_json::from_slice(&json).unwrap();
        prop_assert_eq!(back, exchange);
    }

    #[test]
    fn set_header_leaves_exactly_one(
        pairs in proptest::collection::vec(("[a-cA-C]", "[a-z]{0,3}"), 0..8),
        name in "[a-cA-C]",
    ) {
        let mut headers = headers_from_pairs(pairs);
        let others: Vec<_> = headers.iter().filter(|h| !h.is(&name)).cloned().collect();
        set_header(&mut headers, &name, "v");
        prop_assert_eq!(header_values(&headers, &name).collect::<Vec<_>>(), vec!["v"]);
        remove_header(&mut headers, &name);
        prop_assert_eq!(headers, others);
    }

    #[test]
    fn parsers_never_panic(text in any::<String>()) {
        let _ = HttpVersion::parse(&text);
        let _ = text.parse::<HttpVersion>();
        let _ = HttpBody::from_base64(&text);
        let _ = serde_json::from_str::<HttpExchange>(&text);
        let _ = serde_json::from_str::<HttpBody>(&text);
    }
}
