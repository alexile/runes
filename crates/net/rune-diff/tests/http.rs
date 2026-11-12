//! Structural HTTP diffs over rune-http-model messages.

#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]

use rune_diff::{
    BodyDiff, HeaderChangeKind, HttpDiffOptions, HttpDiffer, JsonChangeKind, MaskOptions,
};
use rune_http_model::{ExchangeId, HttpBody, HttpExchange, HttpRequest, HttpResponse};

fn differ() -> HttpDiffer {
    HttpDiffer::new(&HttpDiffOptions::default()).unwrap()
}

fn html(body: &str) -> HttpResponse {
    HttpResponse::new(200)
        .with_header("Content-Type", "text/html; charset=utf-8")
        .with_header("Date", "Thu, 12 Nov 2026 10:00:00 GMT")
        .with_header("X-Request-Id", "abc")
        .with_body(body.to_owned())
}

#[test]
fn volatile_responses_are_equivalent() {
    let a = html(
        "<html><head><meta name=\"csrf-token\" content=\"Zx81\"></head>\n\
         <body>Generated 2026-11-12 10:00:00 req 123e4567-e89b-12d3-a456-426614174000\n\
         <script nonce=\"aa11\">x()</script></body></html>\n",
    )
    .with_header("Set-Cookie", "sid=9f8e7d6c5b4a39281706f5e4d3c2b1a0; Path=/");
    let b = html(
        "<html><head><meta name=\"csrf-token\" content=\"Qp02\"></head>\n\
         <body>Generated 2026-11-12 10:00:05 req 00000000-1111-2222-3333-444444444444\n\
         <script nonce=\"bb22\">x()</script></body></html>\n",
    )
    .with_header("Set-Cookie", "sid=0a1b2c3d4e5f60718293a4b5c6d7e8f9; Path=/");
    let mut b = b;
    b.set_header("Date", "Thu, 12 Nov 2026 10:00:05 GMT");
    b.set_header("X-Request-Id", "def");
    let diff = differ().diff_responses(&a, &b);
    assert!(diff.is_equivalent(), "{diff}");
    assert!((diff.similarity() - 1.0).abs() < f64::EPSILON);

    // The strict differ sees every difference.
    let strict = HttpDiffer::new(&HttpDiffOptions::strict()).unwrap();
    let diff = strict.diff_responses(&a, &b);
    let names: Vec<_> = diff.headers.iter().map(|h| h.name.as_str()).collect();
    assert_eq!(names, ["date", "set-cookie", "x-request-id"]);
    assert!(matches!(diff.body, BodyDiff::Text(_)));
}

#[test]
fn reports_status_headers_and_text_body() {
    let a = html("<h1>Welcome</h1>\n<p>Hello ann</p>\n<footer>x</footer>\n")
        .with_header("X-Frame-Options", "DENY");
    let mut b = html("<h1>Welcome</h1>\n<p>SQL syntax error near '1''</p>\n<footer>x</footer>\n")
        .with_header("Server", "nginx")
        .with_header("x-frame-options", "SAMEORIGIN");
    b.status = 500;
    let diff = differ().diff_responses(&a, &b);
    assert_eq!(
        diff.status.as_ref().map(|s| (s.old, s.new)),
        Some((200, 500))
    );
    assert_eq!(diff.headers.len(), 2);
    assert_eq!(diff.headers[0].name, "server");
    assert!(matches!(
        diff.headers[0].kind,
        HeaderChangeKind::Added { .. }
    ));
    assert_eq!(
        diff.headers[1].kind,
        HeaderChangeKind::Changed {
            old: vec!["DENY".into()],
            new: vec!["SAMEORIGIN".into()]
        }
    );
    let BodyDiff::Text(text) = &diff.body else {
        panic!("expected a text diff, got {:?}", diff.body);
    };
    assert_eq!(
        text.unified(1),
        "@@ -1,3 +1,3 @@\n <h1>Welcome</h1>\n-<p>Hello ann</p>\n+<p>SQL syntax error near '1''</p>\n <footer>x</footer>\n"
    );
    assert!((text.ratio() - 2.0 / 3.0).abs() < 1e-9);
    assert!(
        diff.similarity().abs() < f64::EPSILON,
        "status change zeroes similarity"
    );
    let shown = diff.to_string();
    assert!(
        shown.starts_with("status: 200 -> 500\nheader server: added \"nginx\"\n"),
        "{shown}"
    );
}

#[test]
fn json_bodies_diff_structurally() {
    let json = |body: &str| {
        HttpResponse::new(200)
            .with_header("Content-Type", "application/json")
            .with_body(body.to_owned())
    };
    let a = json(
        r#"{"id":7,"role":"user","items":[1,2,3],"meta":{"requestId":"r-1","at":"2026-11-12T10:00:00Z"}}"#,
    );
    let b = json(
        r#"{"items":[1,2,3,4],"role":"admin","id":7,"meta":{"requestId":"r-2","at":"2026-11-12T10:00:01Z"}}"#,
    );
    let options = HttpDiffOptions::default().with_ignored_json_pointer("/meta/requestId");
    let diff = HttpDiffer::new(&options).unwrap().diff_responses(&a, &b);
    let BodyDiff::Json { changes, .. } = &diff.body else {
        panic!("expected JSON, got {:?}", diff.body);
    };
    let got: Vec<_> = changes
        .iter()
        .map(|c| (c.pointer.as_str(), &c.kind))
        .collect();
    assert_eq!(
        got,
        [
            ("/items/3", &JsonChangeKind::Added { value: "4".into() }),
            (
                "/role",
                &JsonChangeKind::Changed {
                    old: "\"user\"".into(),
                    new: "\"admin\"".into()
                }
            ),
        ]
    );
    assert!(diff.similarity() > 0.5 && diff.similarity() < 1.0);

    // Key order and whitespace alone are not differences.
    let c = json("{ \"b\": 1,\n \"a\": [true] }");
    let d = json(r#"{"a":[true],"b":1}"#);
    assert!(differ().diff_responses(&c, &d).is_equivalent());
    // Invalid pointers are rejected up front.
    assert!(HttpDiffer::new(&HttpDiffOptions::default().with_ignored_json_pointer("x")).is_err());
}

#[test]
fn binary_and_encoded_bodies() {
    let a = HttpResponse::new(200).with_body(vec![0xff, 0x00, 0x01]);
    let b = HttpResponse::new(200).with_body(vec![0xff, 0x00, 0x02, 0x03]);
    let diff = differ().diff_responses(&a, &b);
    assert_eq!(
        diff.body,
        BodyDiff::Binary {
            old_len: 3,
            new_len: 4
        }
    );
    let gz = |bytes: &[u8]| {
        HttpResponse::new(200)
            .with_body(HttpBody::new(bytes.to_vec()).with_content_encoding("gzip"))
    };
    assert!(matches!(
        differ().diff_responses(&gz(b"x"), &gz(b"y")).body,
        BodyDiff::Binary { .. }
    ));
    assert!(
        differ()
            .diff_responses(&gz(b"x"), &gz(b"x"))
            .is_equivalent()
    );
    // Over the text limit only equality counts.
    let small = HttpDiffer::new(&HttpDiffOptions::default().with_max_text_len(2)).unwrap();
    let r = small.diff_responses(
        &HttpResponse::new(200).with_body("abc"),
        &HttpResponse::new(200).with_body("abd"),
    );
    assert!(matches!(r.body, BodyDiff::Binary { .. }));
}

#[test]
fn payload_reflections_can_be_masked() {
    let page = |q: &str| HttpResponse::new(200).with_body(format!("<p>No results for {q}</p>\n"));
    let opts = HttpDiffOptions::default().with_mask(
        MaskOptions::default()
            .with_literal("' OR 1=1--")
            .with_literal("' OR 1=2--"),
    );
    let differ = HttpDiffer::new(&opts).unwrap();
    assert!(
        differ
            .diff_responses(&page("' OR 1=1--"), &page("' OR 1=2--"))
            .is_equivalent()
    );
}

#[test]
fn requests_and_exchanges() {
    let req = |csrf: &str, role: &str| {
        HttpRequest::post(format!("https://app.test/api/users?_={csrf}"))
            .with_header("Content-Type", "application/x-www-form-urlencoded")
            .with_body(format!("name=ann&role={role}"))
    };
    let differ = differ();
    let diff = differ.diff_requests(&req("1731400000", "user"), &req("1731400009", "admin"));
    assert!(diff.url.is_none(), "epoch cache-buster is masked");
    assert!(matches!(diff.body, BodyDiff::Text(_)));
    assert!(diff.to_string().contains("-name=ann&role=user"));

    let ex = |status: Option<u16>| {
        let e = HttpExchange::new(ExchangeId(1), "test", req("1", "user"));
        match status {
            Some(s) => e.with_response(HttpResponse::new(s)),
            None => e,
        }
    };
    let d = differ.diff_exchanges(&ex(Some(200)), &ex(Some(403)));
    assert!(d.request.is_equivalent());
    assert_eq!(d.response.unwrap().status.unwrap().new, 403);
    let d = differ.diff_exchanges(&ex(Some(200)), &ex(None));
    assert!(d.response.is_none());
    assert_eq!(
        d.response_presence.map(|p| (p.old, p.new)),
        Some((true, false))
    );
}

#[test]
fn default_shortcut() {
    let a = HttpResponse::new(200)
        .with_header("Date", "x")
        .with_body("same");
    let b = HttpResponse::new(200)
        .with_header("Date", "y")
        .with_body("same");
    assert!(rune_diff::diff_responses(&a, &b).is_equivalent());
}
