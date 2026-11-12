//! End-to-end tests over small hand-written response fixtures.

use rune_http_model::{HttpResponse, HttpVersion};

use crate::*;

fn nginx() -> Observations {
    Observations::new()
        .with_response(
            ProbeKind::Baseline,
            HttpResponse::new(200)
                .with_reason("OK")
                .with_headers([
                    ("Server", "nginx/1.24.0"),
                    ("Date", "Thu, 12 Nov 2026 10:00:00 GMT"),
                    ("Content-Type", "text/html"),
                    ("Content-Length", "615"),
                    ("Last-Modified", "Tue, 11 Apr 2023 01:45:34 GMT"),
                    ("Connection", "keep-alive"),
                    ("ETag", "\"6434bbbe-267\""),
                    ("Accept-Ranges", "bytes"),
                ]),
        )
        .with_response(
            ProbeKind::NotFound,
            HttpResponse::new(404)
                .with_reason("Not Found")
                .with_headers([("Server", "nginx/1.24.0"), ("Content-Type", "text/html")])
                .with_body(
                    "<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n\
                     <center><h1>404 Not Found</h1></center>\r\n<hr><center>nginx/1.24.0</center>\r\n\
                     </body>\r\n</html>\r\n",
                ),
        )
        .with_response(
            ProbeKind::Options,
            HttpResponse::new(405)
                .with_reason("Not Allowed")
                .with_header("Server", "nginx/1.24.0"),
        )
}

fn go_server() -> Observations {
    Observations::new().with_response(
        ProbeKind::NotFound,
        HttpResponse::new(404)
            .with_reason("Not Found")
            .with_headers([
                ("Content-Type", "text/plain; charset=utf-8"),
                ("X-Content-Type-Options", "nosniff"),
                ("Date", "Thu, 12 Nov 2026 10:00:00 GMT"),
                ("Content-Length", "19"),
            ])
            .with_body("404 page not found\n"),
    )
}

#[test]
fn nginx_is_identified_with_version() {
    let report = analyze(&nginx(), &Database::builtin());
    let best = &report.candidates[0];
    assert_eq!(best.name, "nginx");
    assert_eq!(best.confidence, 100);
    assert_eq!(best.version.as_deref(), Some("1.24.0"));
    assert!(
        best.evidence
            .iter()
            .any(|e| e.note.contains("<center>nginx"))
    );
    assert_eq!(report.candidates.len(), 1);
    // `Not Allowed` is nginx's own phrase for 405.
    let options = report.features.shape(ProbeKind::Options).unwrap();
    assert_eq!(options.reason, ReasonForm::NonStandard);
    assert!(report.fingerprint.hash.starts_with("11c08s_"));
}

#[test]
fn go_is_identified_without_server_header() {
    let candidates = Database::builtin().identify(&go_server());
    assert_eq!(candidates[0].name, "Go net/http");
    assert_eq!(candidates[0].confidence, 70);
    assert_eq!(candidates[0].version, None);
}

#[test]
fn fingerprint_ignores_values_and_bodies() {
    let mut other = nginx();
    let changed = HttpResponse::new(200)
        .with_reason("OK")
        .with_headers([
            ("Server", "nginx/1.24.0"),
            ("Date", "Fri, 13 Nov 2026 11:11:11 GMT"),
            ("Content-Type", "text/html"),
            ("Content-Length", "1"),
            ("Last-Modified", "x"),
            ("Connection", "keep-alive"),
            ("ETag", "\"1\""),
            ("Accept-Ranges", "bytes"),
        ])
        .with_body("different");
    other = other.with_response(ProbeKind::Baseline, changed);
    assert_eq!(fingerprint(&nginx()), fingerprint(&other));
}

#[test]
fn fingerprint_tracks_order_casing_and_probes() {
    let base = fingerprint(&nginx());
    let reordered = nginx().with_response(
        ProbeKind::Baseline,
        HttpResponse::new(200)
            .with_reason("OK")
            .with_headers([("Date", "x"), ("Server", "nginx")]),
    );
    assert_ne!(base, fingerprint(&reordered));
    let lowered = nginx().with_response(
        ProbeKind::Baseline,
        HttpResponse::new(200)
            .with_reason("OK")
            .with_version(HttpVersion::Http2)
            .with_headers([("server", "nginx"), ("date", "x")]),
    );
    let fp = fingerprint(&lowered);
    assert!(fp.hash.starts_with("20l02s_"), "{fp}");
    let with_http10 = nginx().with_response(ProbeKind::Http10, HttpResponse::new(200));
    assert_ne!(base, fingerprint(&with_http10));
}

#[test]
fn known_answer_fingerprint() {
    let observations = Observations::new()
        .with_response(
            ProbeKind::Baseline,
            HttpResponse::new(200)
                .with_raw(b"HTTP/1.1 200 OK\r\nServer: demo\r\nDate: x\r\n\r\n".to_vec()),
        )
        .with_response(
            ProbeKind::Options,
            HttpResponse::new(200).with_header("Allow", "GET, HEAD, OPTIONS"),
        );
    let fp = fingerprint(&observations);
    assert_eq!(
        fp.raw,
        "11t02s_server,date_base=200:s:t:;nf=-;opt=200:x:t:;um=-;h10=-;methods=GET,HEAD,OPTIONS"
    );
    assert_eq!(fp.hash, KAT_HASH);
}

/// Independently computed: `sha256("server,date")[..12]` and
/// `sha256(<behaviour string>)[..12]` with Python's hashlib.
const KAT_HASH: &str = "11t02s_c3493bcb8706_5ab5b96e8b10";

#[test]
fn passive_single_response_works() {
    let observations = Observations::new().with_response(
        ProbeKind::NotFound,
        HttpResponse::new(404).with_header("Server", "Microsoft-IIS/10.0"),
    );
    let report = analyze(&observations, &Database::builtin());
    assert!(report.fingerprint.hash.starts_with("11t01x_"));
    assert_eq!(report.candidates[0].name, "Microsoft IIS");
    assert_eq!(report.candidates[0].version.as_deref(), Some("10.0"));
}

#[cfg(feature = "serde")]
#[test]
fn signatures_round_trip_through_json() {
    let signatures = builtin_signatures();
    let json = serde_json::to_string(&signatures).unwrap();
    let back: Vec<Signature> = serde_json::from_str(&json).unwrap();
    assert_eq!(back, signatures);
    let report = analyze(&nginx(), &Database::from_signatures(back).unwrap());
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["candidates"][0]["name"], "nginx");
}
