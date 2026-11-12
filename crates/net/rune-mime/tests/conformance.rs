//! Conformance against RFC examples and real-world senders.

use rune_http_model::{HttpRequest, HttpResponse};
use rune_mime::{
    Charset, ContentDisposition, MediaType, MultipartOptions, parse_multipart_body,
    parse_request_multipart, parse_response_multipart, response_charset,
};

/// What Chromium sends for a form with a text field and a file input.
#[test]
fn chromium_form_data() {
    let body = "------WebKitFormBoundary7MA4YWxkTrZu0gW\r\n\
Content-Disposition: form-data; name=\"comment\"\r\n\
\r\n\
<script>alert(1)</script>\r\n\
------WebKitFormBoundary7MA4YWxkTrZu0gW\r\n\
Content-Disposition: form-data; name=\"upload\"; filename=\"shell.php.jpg\"\r\n\
Content-Type: image/jpeg\r\n\
\r\n\
<?php system($_GET['c']); ?>\r\n\
------WebKitFormBoundary7MA4YWxkTrZu0gW--\r\n";
    let request = HttpRequest::post("https://app.example.test/post")
        .with_header(
            "Content-Type",
            "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW",
        )
        .with_body(body);
    let form = parse_request_multipart(&request, &MultipartOptions::default()).unwrap();
    assert_eq!(form.parts.len(), 2);
    assert_eq!(
        form.field("comment").unwrap().body,
        b"<script>alert(1)</script>"
    );
    let upload = form.field("upload").unwrap();
    assert_eq!(upload.filename().as_deref(), Some("shell.php.jpg"));
    assert_eq!(
        upload.content_type().unwrap().unwrap(),
        MediaType::new("image", "jpeg").unwrap()
    );
    // Byte ranges point back into the request body.
    let raw = request.body.as_bytes();
    assert_eq!(
        &raw[upload.body_range.clone()],
        b"<?php system($_GET['c']); ?>"
    );
    assert!(raw[upload.headers_range.clone()].starts_with(b"Content-Disposition"));
}

/// RFC 9110 §14.6: a `multipart/byteranges` response.
#[test]
fn rfc9110_byteranges() {
    let body = "--THIS_STRING_SEPARATES\r\n\
Content-Type: application/pdf\r\n\
Content-Range: bytes 500-999/8000\r\n\
\r\n\
...the first range...\r\n\
--THIS_STRING_SEPARATES\r\n\
Content-Type: application/pdf\r\n\
Content-Range: bytes 7000-7999/8000\r\n\
\r\n\
...the second range\r\n\
--THIS_STRING_SEPARATES--\r\n";
    let response = HttpResponse::new(206)
        .with_header(
            "Content-Type",
            "multipart/byteranges; boundary=THIS_STRING_SEPARATES",
        )
        .with_body(body);
    let parts = parse_response_multipart(&response, &MultipartOptions::default()).unwrap();
    assert_eq!(parts.parts.len(), 2);
    assert_eq!(
        parts.parts[1].header("content-range"),
        Some("bytes 7000-7999/8000")
    );
    assert_eq!(parts.parts[1].body, b"...the second range");
}

/// RFC 2046 §5.1.7-style nesting: `multipart/mixed` inside form data.
#[test]
fn nested_multipart() {
    let body = b"--outer\r\n\
Content-Disposition: form-data; name=\"files\"\r\n\
Content-Type: multipart/mixed; boundary=inner\r\n\
\r\n\
--inner\r\n\
Content-Disposition: file; filename=\"a.txt\"\r\n\
\r\n\
A\r\n\
--inner\r\n\
Content-Disposition: file; filename=\"b.txt\"\r\n\
\r\n\
B\r\n\
--inner--\r\n\
--outer--\r\n";
    let outer_type = MediaType::parse("multipart/form-data; boundary=outer").unwrap();
    let options = MultipartOptions::default();
    let outer = parse_multipart_body(&outer_type, body, &options).unwrap();
    let files = outer.field("files").unwrap();
    let inner_type = files.content_type().unwrap().unwrap();
    let inner = parse_multipart_body(&inner_type, files.body, &options).unwrap();
    let names: Vec<_> = inner
        .parts
        .iter()
        .filter_map(rune_mime::Part::filename)
        .collect();
    assert_eq!(names, ["a.txt", "b.txt"]);
    assert!(inner.closed);
}

#[test]
fn not_multipart_and_missing_boundary() {
    let options = MultipartOptions::default();
    let request = HttpRequest::post("https://x.test/").with_header("Content-Type", "text/plain");
    assert!(matches!(
        parse_request_multipart(&request, &options),
        Err(rune_mime::MimeError::NotMultipart(_))
    ));
    let request =
        HttpRequest::post("https://x.test/").with_header("Content-Type", "multipart/form-data");
    assert_eq!(
        parse_request_multipart(&request, &options),
        Err(rune_mime::MimeError::MissingBoundary)
    );
    let request = HttpRequest::post("https://x.test/");
    assert_eq!(
        parse_request_multipart(&request, &options),
        Err(rune_mime::MimeError::Empty)
    );
}

/// RFC 2231 §4 / RFC 8187 §3.2.3 examples.
#[test]
fn extended_parameters() {
    let mt = MediaType::parse(
        "application/x-stuff; title*=us-ascii'en-us'This%20is%20%2A%2A%2Afun%2A%2A%2A",
    )
    .unwrap();
    assert_eq!(mt.param("title"), Some("This is ***fun***"));

    let cd =
        ContentDisposition::parse("attachment; title*=UTF-8'de'n%c3%a4chstes%20Kapitel").unwrap();
    assert_eq!(cd.param("title"), Some("nächstes Kapitel"));
}

#[test]
fn response_charset_falls_through() {
    let response = HttpResponse::new(200)
        .with_header("Content-Type", "text/html")
        .with_body("<meta http-equiv=content-type content='text/html;charset=Shift_JIS'>");
    assert_eq!(
        response_charset(&response).charset,
        Charset::Other("shift_jis".into())
    );
    let response = HttpResponse::new(200).with_body(&b"\xff\xfe<\x00"[..]);
    assert_eq!(response_charset(&response).charset, Charset::Utf16Le);
}
