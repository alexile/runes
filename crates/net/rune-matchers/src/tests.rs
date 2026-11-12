use std::time::Instant;

use super::*;
use rune_http_model::{ExchangeId, HttpBody, HttpExchange, HttpRequest, HttpResponse, Timings};

fn exchange(body: HttpBody) -> HttpExchange {
    let request = HttpRequest::new("POST", "http://host.test/login?next=/admin")
        .with_header("X-Req", "alpha")
        .with_body(HttpBody::from_text("user=bob&pass=hunter2"));
    let mut exchange = HttpExchange::new(ExchangeId(1), "test", request).with_response(
        HttpResponse::new(200)
            .with_header("Server", "nginx/1.25")
            .with_header("Content-Type", "text/html")
            .with_header("X-Powered-By", "PHP/8.1")
            .with_header("Set-Cookie", "session=abc123; Path=/; HttpOnly")
            .with_header("Set-Cookie", "csrf=tok42")
            .with_body(body),
    );
    exchange.timings = Timings {
        time_to_headers_milliseconds: None,
        total_milliseconds: 1500,
    };
    exchange
}

fn html() -> HttpExchange {
    exchange(HttpBody::from_text(
        "<title>Admin Login</title>\nWelcome Back\nid=1234 id=5678",
    ))
}

fn no_response() -> HttpExchange {
    HttpExchange::new(ExchangeId(2), "test", HttpRequest::get("http://host.test/"))
}

fn check(matcher: &Matcher, exchange: &HttpExchange) -> bool {
    matcher.matches(exchange).expect("compiles")
}

#[test]
fn word_matcher_with_condition_negative_and_case() {
    let ex = html();
    assert!(check(&Matcher::word(["Admin", "nope"]), &ex));
    assert!(!check(
        &Matcher::word(["Admin", "nope"]).with_condition(MatchCondition::And),
        &ex
    ));
    assert!(check(
        &Matcher::word(["Admin", "Welcome"]).with_condition(MatchCondition::And),
        &ex
    ));
    assert!(!check(&Matcher::word(["admin login"]), &ex));
    assert!(check(&Matcher::word(["admin login"]).ignoring_case(), &ex));
    assert!(check(&Matcher::word(["nope"]).negated(), &ex));
    assert!(!check(&Matcher::word(["Admin"]).negated(), &ex));
    // Regex metacharacters in words are literal.
    assert!(!check(&Matcher::word(["Adm.n"]), &ex));
    assert!(!check(&Matcher::word(Vec::<String>::new()), &ex));
}

#[test]
fn regex_matcher_with_condition_and_case() {
    let ex = html();
    assert!(check(&Matcher::regex([r"id=\d{4}"]), &ex));
    assert!(!check(&Matcher::regex([r"(?m)^welcome back$"]), &ex));
    assert!(check(
        &Matcher::regex([r"(?m)^welcome back$"]).ignoring_case(),
        &ex
    ));
    assert!(!check(
        &Matcher::regex([r"id=\d{4}", "zzz"]).with_condition(MatchCondition::And),
        &ex
    ));
    assert!(check(&Matcher::regex(["zzz"]).negated(), &ex));
}

#[test]
fn status_size_and_time_matchers() {
    let ex = html();
    assert!(check(&Matcher::status([301, 200]), &ex));
    assert!(!check(&Matcher::status([404]), &ex));
    assert!(check(&Matcher::status([404]).negated(), &ex));
    let len = ex
        .response
        .as_ref()
        .expect("response")
        .body
        .as_bytes()
        .len();
    assert!(check(
        &Matcher::new(MatcherKind::Size { size: vec![1, len] }),
        &ex
    ));
    assert!(check(
        &Matcher::new(MatcherKind::Size { size: vec![3] }).with_part(ResponsePart::Status),
        &ex
    ));
    let slow = |op, milliseconds| TimeComparison { op, milliseconds };
    let window = Matcher::new(MatcherKind::Time {
        time: vec![slow(Comparison::Ge, 1000), slow(Comparison::Lt, 2000)],
    })
    .with_condition(MatchCondition::And);
    assert!(check(&window, &ex));
    let too_slow = Matcher::new(MatcherKind::Time {
        time: vec![slow(Comparison::Gt, 5000)],
    });
    assert!(!check(&too_slow, &ex));
    // Time does not need a response.
    assert!(check(&too_slow.negated(), &no_response()));
}

#[test]
fn binary_matcher_runs_on_raw_bytes() {
    let mut bytes = vec![0x50, 0x4b, 0x03, 0x04, 0xff, 0xfe, 0x00, 0x80];
    bytes.extend_from_slice(b"tail");
    let ex = exchange(HttpBody::new(bytes));
    let binary = |hex: &[&str]| {
        Matcher::new(MatcherKind::Binary {
            binary: hex.iter().map(|h| (*h).to_owned()).collect(),
        })
    };
    assert!(check(&binary(&["504b0304"]), &ex));
    assert!(check(&binary(&["ff fe 00 80"]), &ex));
    assert!(!check(&binary(&["fffe0081"]), &ex));
    assert!(!check(
        &binary(&["504b0304", "deadbeef"]).with_condition(MatchCondition::And),
        &ex
    ));
    let error = binary(&["abc"]).matches(&ex).expect_err("odd hex");
    assert_eq!(error.code(), "invalid_hex");
    assert!(binary(&["zz"]).matches(&ex).is_err());
}

#[test]
fn header_matcher() {
    let ex = html();
    let header = |name: &str, value: Option<&str>| {
        Matcher::new(MatcherKind::Header {
            name: name.to_owned(),
            value: value.map(str::to_owned),
        })
    };
    assert!(check(&header("server", None), &ex));
    assert!(check(&header("SERVER", Some(r"^nginx/\d")), &ex));
    assert!(!check(&header("Server", Some("^NGINX")), &ex));
    assert!(check(
        &header("Server", Some("^NGINX")).ignoring_case(),
        &ex
    ));
    // Any of several same-named headers may match.
    assert!(check(&header("set-cookie", Some("^csrf=")), &ex));
    assert!(check(&header("x-missing", None).negated(), &ex));
}

#[test]
fn json_pointer_matcher() {
    let ex = exchange(HttpBody::from_text(
        r#"{"user":{"role":"admin","ids":[7,8]},"ok":true}"#,
    ));
    let json = |pointer: &str, value: Option<serde_json::Value>| {
        Matcher::new(MatcherKind::JsonPointer {
            pointer: pointer.to_owned(),
            value,
        })
    };
    assert!(check(&json("/user/role", None), &ex));
    assert!(check(&json("/user/role", Some("admin".into())), &ex));
    assert!(!check(&json("/user/role", Some("guest".into())), &ex));
    assert!(check(&json(".user.ids[1]", Some(8.into())), &ex));
    assert!(check(&json("ok", Some(true.into())), &ex));
    assert!(!check(&json("/missing", None), &ex));
    assert!(!check(&json("/user", None), &html()));
    assert!(json(".a[x]", None).matches(&ex).is_err());
}

#[test]
fn part_selection() {
    let ex = html();
    let on = |part: ResponsePart, word: &str| Matcher::word([word]).with_part(part);
    assert!(check(
        &on(ResponsePart::Headers, "X-Powered-By: PHP/8.1"),
        &ex
    ));
    assert!(!check(&on(ResponsePart::Body, "X-Powered-By"), &ex));
    assert!(check(
        &on(ResponsePart::Header("x-powered-by".into()), "PHP"),
        &ex
    ));
    assert!(!check(
        &on(ResponsePart::Header("server".into()), "PHP"),
        &ex
    ));
    assert!(check(&on(ResponsePart::Status, "200"), &ex));
    assert!(check(&on(ResponsePart::All, "Server: nginx"), &ex));
    assert!(check(&on(ResponsePart::All, "Welcome Back"), &ex));
    assert!(check(&on(ResponsePart::Raw, "HTTP/1.1 200"), &ex));
    assert!(check(&on(ResponsePart::RequestBody, "hunter2"), &ex));
    assert!(check(
        &on(ResponsePart::RequestHeaders, "X-Req: alpha"),
        &ex
    ));
    assert!(check(&on(ResponsePart::Url, "next=/admin"), &ex));
    assert!(check(&on(ResponsePart::Time, "1500"), &ex));
    // Request parts work without a response; response parts never match,
    // even negated.
    assert!(check(&on(ResponsePart::Url, "host.test"), &no_response()));
    assert!(!check(&Matcher::word(["x"]).negated(), &no_response()));
    assert!(!check(&Matcher::status([200]).negated(), &no_response()));
}

#[test]
fn matcher_set_and_or_and_fired() {
    let ex = html();
    let set = |condition| {
        MatcherSet::new(
            vec![Matcher::status([200]), Matcher::word(["nope"])],
            condition,
        )
    };
    assert!(set(MatchCondition::Or).matches(&ex).expect("compiles"));
    assert!(!set(MatchCondition::And).matches(&ex).expect("compiles"));
    let compiled = set(MatchCondition::Or).compile().expect("compiles");
    assert_eq!(compiled.fired(&ex), Some(vec![0]));
    assert_eq!(
        set(MatchCondition::And)
            .compile()
            .expect("compiles")
            .fired(&ex),
        None
    );
    assert!(!MatcherSet::default().matches(&ex).expect("compiles"));
}

#[test]
fn regex_extractor_with_group() {
    let ex = html();
    let extractor = Extractor::new(ExtractorKind::Regex {
        regex: vec![r"id=(\d+)".into()],
        group: 1,
    });
    assert_eq!(extractor.extract(&ex).expect("ok"), vec!["1234", "5678"]);
    let whole = Extractor::new(ExtractorKind::Regex {
        regex: vec![r"<title>[^<]+".into()],
        group: 0,
    });
    assert_eq!(whole.extract(&ex).expect("ok"), vec!["<title>Admin Login"]);
    let bad_group = Extractor::new(ExtractorKind::Regex {
        regex: vec![r"id=(\d+)".into()],
        group: 2,
    });
    assert_eq!(
        bad_group.extract(&ex).expect_err("no group").code(),
        "invalid_regex_group"
    );
    assert_eq!(
        extractor.extract(&no_response()).expect("ok"),
        Vec::<String>::new()
    );
}

#[test]
fn kval_header_and_cookie_extractors() {
    let ex = html();
    let kval = Extractor::new(ExtractorKind::Kval {
        kval: vec!["x_powered_by".into(), "session".into()],
    });
    assert_eq!(kval.extract(&ex).expect("ok"), vec!["PHP/8.1", "abc123"]);
    let header = Extractor::new(ExtractorKind::Header {
        header: vec!["set-cookie".into()],
    });
    assert_eq!(
        header.extract(&ex).expect("ok"),
        vec!["session=abc123; Path=/; HttpOnly", "csrf=tok42"]
    );
    let cookie = Extractor::new(ExtractorKind::Cookie {
        cookie: vec!["CSRF".into()],
    });
    assert_eq!(cookie.extract(&ex).expect("ok"), vec!["tok42"]);
}

#[test]
fn json_extractor_pointer_and_jq_lite() {
    let ex = exchange(HttpBody::from_text(
        r#"{"data":{"token":"t0k","items":[{"id":1},{"id":2}]},"n":null}"#,
    ));
    let extractor = Extractor::new(ExtractorKind::Json {
        json: vec![
            "/data/token".into(),
            ".data.items[1].id".into(),
            "data.items".into(),
            "/missing".into(),
        ],
    });
    assert_eq!(
        extractor.extract(&ex).expect("ok"),
        vec!["t0k", "2", r#"[{"id":1},{"id":2}]"#]
    );
    assert_eq!(
        extractor.extract(&html()).expect("ok"),
        Vec::<String>::new()
    );
}

#[test]
fn xpath_extractor_subset() {
    let ex = exchange(HttpBody::from_text(
        r#"<?xml version="1.0"?><root><user id="7"><name>Ann &amp; Bo</name></user><user id="9"><name><![CDATA[Cy]]></name></user><meta/></root>"#,
    ));
    let xpath = |path: &str, attribute: Option<&str>| {
        Extractor::new(ExtractorKind::Xpath {
            xpath: vec![path.to_owned()],
            attribute: attribute.map(str::to_owned),
        })
    };
    assert_eq!(
        xpath("/root/user/name", None).extract(&ex).expect("ok"),
        vec!["Ann & Bo", "Cy"]
    );
    assert_eq!(
        xpath("//name/text()", None).extract(&ex).expect("ok"),
        vec!["Ann & Bo", "Cy"]
    );
    assert_eq!(
        xpath("//user/@id", None).extract(&ex).expect("ok"),
        vec!["7", "9"]
    );
    assert_eq!(
        xpath("/root/*", Some("id")).extract(&ex).expect("ok"),
        vec!["7", "9"]
    );
    assert_eq!(xpath("/root/user", None).extract(&ex).expect("ok").len(), 2);
    for unsupported in ["//user[1]", "root/user", "/root//name", "count(//user)"] {
        assert_eq!(
            xpath(unsupported, None)
                .extract(&ex)
                .expect_err(unsupported)
                .code(),
            "invalid_path"
        );
    }
}

#[test]
fn regex_limits_reject_untrusted_patterns() {
    let ex = html();
    // Small pattern, huge compiled program: exceeds the 1 MiB size limit.
    let huge = Matcher::regex([r"\w{1000}\w{1000}"]);
    let error = huge.matches(&ex).expect_err("size limit");
    assert_eq!(error.code(), "invalid_regex");
    assert!(matches!(error, MatchError::Regex { .. }));
    let long = Matcher::regex(["a".repeat(MAX_PATTERN_LEN + 1)]);
    assert!(matches!(long.compile(), Err(MatchError::Regex { .. })));
    // Backreferences and lookaround are unsupported.
    assert!(Matcher::regex([r"(a)\1"]).compile().is_err());
    assert!(Matcher::regex([r"a(?=b)"]).compile().is_err());
}

#[test]
#[cfg(feature = "schemars")]
fn matcher_set_serde_round_trip() {
    let set = MatcherSet::new(
        vec![
            Matcher::word(["admin"])
                .with_part(ResponsePart::Header("server".into()))
                .with_condition(MatchCondition::And)
                .negated()
                .ignoring_case(),
            Matcher::status([200]),
            Matcher::new(MatcherKind::JsonPointer {
                pointer: "/a".into(),
                value: Some(serde_json::json!({"b": [1]})),
            }),
            Matcher::new(MatcherKind::Time {
                time: vec![TimeComparison {
                    op: Comparison::Ge,
                    milliseconds: 5000,
                }],
            }),
        ],
        MatchCondition::And,
    );
    let json = serde_json::to_value(&set).expect("serialize");
    assert_eq!(json["matchers"][0]["type"], "word");
    assert_eq!(json["matchers"][0]["part"]["header"], "server");
    assert_eq!(json["condition"], "and");
    let back: MatcherSet = serde_json::from_value(json).expect("deserialize");
    assert_eq!(back, set);
    // nuclei-style minimal input with defaults.
    let parsed: Matcher =
        serde_json::from_str(r#"{"type":"regex","regex":["a+"],"part":"all"}"#).expect("parse");
    assert_eq!(parsed.part, ResponsePart::All);
    assert_eq!(parsed.condition, MatchCondition::Or);
    let schema = schemars::schema_for!(MatcherSet);
    assert!(
        serde_json::to_string(&schema)
            .expect("schema")
            .contains("json_pointer")
    );
}

#[test]
fn compiled_regex_matcher_is_fast() {
    // 100 KB body; the token sits early so each evaluation measures matcher
    // overhead (no recompilation, no body copies), not a full-body scan.
    let mut body = String::from("<html><head><title>x</title></head><body>token=deadbeef01;");
    while body.len() < 100 * 1024 {
        body.push_str("lorem ipsum dolor sit amet, consectetur adipiscing elit. ");
    }
    let ex = exchange(HttpBody::from_text(body));
    let compiled = Matcher::regex([r"token=[0-9a-f]{8}"])
        .compile()
        .expect("compiles");
    assert!(compiled.matches(&ex));
    let start = Instant::now();
    let mut hits = 0_u32;
    for _ in 0..10_000 {
        hits += u32::from(compiled.matches(&ex));
    }
    let elapsed = start.elapsed();
    assert_eq!(hits, 10_000);
    assert!(elapsed.as_millis() < 50, "took {elapsed:?}");
}
