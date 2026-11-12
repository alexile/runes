//! Integration tests: eligible responses are compressed per
//! `Accept-Encoding`; small, binary and already-encoded ones are not.

#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]

use std::collections::VecDeque;
use std::convert::Infallible;
use std::io::Read;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Method, Request, StatusCode, header},
    response::IntoResponse,
    routing::get,
};
use bytes::Bytes;
use http_body::Frame;
use http_body_util::BodyExt;
use rune_axum_compression::{Compression, CompressionLayer, Encoding};
use tower::ServiceExt;

fn big_text() -> String {
    "lorem ipsum dolor sit amet, ".repeat(200)
}

fn app(config: Compression) -> Router {
    Router::new()
        .route("/text", get(|| async { big_text() }))
        .route("/small", get(|| async { "tiny" }))
        .route(
            "/json",
            get(|| async {
                (
                    [
                        (header::CONTENT_TYPE, "application/json"),
                        (header::ETAG, "\"v1\""),
                    ],
                    format!("[{}0]", "1,".repeat(1000)),
                )
            }),
        )
        .route(
            "/png",
            get(|| async { ([(header::CONTENT_TYPE, "image/png")], vec![0u8; 4096]) }),
        )
        .route(
            "/pre",
            get(|| async {
                (
                    [
                        (header::CONTENT_TYPE, "text/plain"),
                        (header::CONTENT_ENCODING, "br"),
                    ],
                    big_text(),
                )
            }),
        )
        .route(
            "/stream",
            get(|| async {
                let mut frames: VecDeque<_> = (0..50)
                    .map(|i| Frame::data(Bytes::from(format!("chunk {i} {}\n", "x".repeat(40)))))
                    .collect();
                let mut trailers = HeaderMap::new();
                trailers.insert("x-checksum", "abc".parse().unwrap());
                frames.push_back(Frame::trailers(trailers));
                (
                    [(header::CONTENT_TYPE, "text/plain")],
                    Body::new(Frames(frames)),
                )
                    .into_response()
            }),
        )
        .layer(CompressionLayer::new(config))
}

/// A body yielding `frames` one by one, of unknown length.
struct Frames(VecDeque<Frame<Bytes>>);

impl http_body::Body for Frames {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        Poll::Ready(self.0.pop_front().map(Ok))
    }
}

async fn get_with(app: Router, path: &str, accept: Option<&str>) -> axum::response::Response {
    let mut req = Request::builder().uri(path);
    if let Some(ae) = accept {
        req = req.header(header::ACCEPT_ENCODING, ae);
    }
    app.oneshot(req.body(Body::empty()).unwrap()).await.unwrap()
}

async fn body_bytes(res: axum::response::Response) -> Vec<u8> {
    res.into_body().collect().await.unwrap().to_bytes().to_vec()
}

fn gunzip(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(data)
        .read_to_end(&mut out)
        .unwrap();
    out
}

#[tokio::test]
async fn gzip_round_trip() {
    let res = get_with(app(Compression::new()), "/text", Some("gzip")).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()[header::CONTENT_ENCODING], "gzip");
    assert_eq!(res.headers()[header::VARY], "accept-encoding");
    assert!(res.headers().get(header::CONTENT_LENGTH).is_none());
    let body = body_bytes(res).await;
    assert!(body.len() < big_text().len() / 4);
    assert_eq!(gunzip(&body), big_text().as_bytes());
}

#[tokio::test]
async fn deflate_round_trip() {
    let res = get_with(app(Compression::new()), "/text", Some("deflate")).await;
    assert_eq!(res.headers()[header::CONTENT_ENCODING], "deflate");
    let body = body_bytes(res).await;
    let mut out = Vec::new();
    flate2::read::ZlibDecoder::new(&body[..])
        .read_to_end(&mut out)
        .unwrap();
    assert_eq!(out, big_text().as_bytes());
}

#[cfg(feature = "br")]
#[tokio::test]
async fn brotli_round_trip() {
    let res = get_with(app(Compression::new()), "/text", Some("gzip, deflate, br")).await;
    assert_eq!(res.headers()[header::CONTENT_ENCODING], "br");
    let body = body_bytes(res).await;
    let mut out = Vec::new();
    brotli::Decompressor::new(&body[..], 4096)
        .read_to_end(&mut out)
        .unwrap();
    assert_eq!(out, big_text().as_bytes());
}

#[cfg(feature = "zstd")]
#[tokio::test]
async fn zstd_round_trip() {
    let res = get_with(app(Compression::new()), "/text", Some("gzip, br, zstd")).await;
    assert_eq!(res.headers()[header::CONTENT_ENCODING], "zstd");
    let body = body_bytes(res).await;
    assert_eq!(zstd::decode_all(&body[..]).unwrap(), big_text().as_bytes());
}

#[tokio::test]
async fn no_accept_encoding_is_identity_but_varies() {
    let res = get_with(app(Compression::new()), "/text", None).await;
    assert!(res.headers().get(header::CONTENT_ENCODING).is_none());
    assert_eq!(res.headers()[header::VARY], "accept-encoding");
    assert_eq!(body_bytes(res).await, big_text().as_bytes());
}

#[tokio::test]
async fn refused_codings_are_identity() {
    for ae in ["gzip;q=0, deflate;q=0", "identity", "compress", "*;q=0"] {
        let res = get_with(app(Compression::new()), "/text", Some(ae)).await;
        assert!(
            res.headers().get(header::CONTENT_ENCODING).is_none(),
            "{ae}"
        );
        assert_eq!(body_bytes(res).await, big_text().as_bytes());
    }
}

#[tokio::test]
async fn client_weights_respected() {
    let res = get_with(
        app(Compression::new()),
        "/text",
        Some("gzip;q=0.1, deflate;q=0.8"),
    )
    .await;
    assert_eq!(res.headers()[header::CONTENT_ENCODING], "deflate");
}

#[tokio::test]
async fn small_body_skipped() {
    let res = get_with(app(Compression::new()), "/small", Some("gzip")).await;
    assert!(res.headers().get(header::CONTENT_ENCODING).is_none());
    assert!(res.headers().get(header::VARY).is_none());
    assert_eq!(body_bytes(res).await, b"tiny");

    // Lowering the threshold compresses it.
    let res = get_with(app(Compression::new().min_size(0)), "/small", Some("gzip")).await;
    assert_eq!(res.headers()[header::CONTENT_ENCODING], "gzip");
    assert_eq!(gunzip(&body_bytes(res).await), b"tiny");
}

#[tokio::test]
async fn binary_type_skipped() {
    let res = get_with(app(Compression::new()), "/png", Some("gzip")).await;
    assert!(res.headers().get(header::CONTENT_ENCODING).is_none());
    assert_eq!(body_bytes(res).await, vec![0u8; 4096]);
}

#[tokio::test]
async fn already_encoded_skipped() {
    let res = get_with(app(Compression::new()), "/pre", Some("gzip")).await;
    assert_eq!(res.headers()[header::CONTENT_ENCODING], "br");
    assert_eq!(body_bytes(res).await, big_text().as_bytes());
}

#[tokio::test]
async fn strong_etag_is_weakened() {
    let res = get_with(app(Compression::new()), "/json", Some("gzip")).await;
    assert_eq!(res.headers()[header::CONTENT_ENCODING], "gzip");
    assert_eq!(res.headers()[header::ETAG], "W/\"v1\"");

    let res = get_with(app(Compression::new()), "/json", None).await;
    assert_eq!(res.headers()[header::ETAG], "\"v1\"");
}

#[tokio::test]
async fn head_passes_through() {
    let req = Request::builder()
        .method(Method::HEAD)
        .uri("/text")
        .header(header::ACCEPT_ENCODING, "gzip")
        .body(Body::empty())
        .unwrap();
    let res = app(Compression::new()).oneshot(req).await.unwrap();
    assert!(res.headers().get(header::CONTENT_ENCODING).is_none());
}

#[tokio::test]
async fn streaming_body_and_trailers() {
    let res = get_with(app(Compression::new()), "/stream", Some("gzip")).await;
    assert_eq!(res.headers()[header::CONTENT_ENCODING], "gzip");
    let collected = res.into_body().collect().await.unwrap();
    let trailers = collected.trailers().cloned().unwrap();
    assert_eq!(trailers["x-checksum"], "abc");
    let expected = (0..50)
        .map(|i| {
            format!(
                "chunk {i} {}
",
                "x".repeat(40)
            )
        })
        .collect::<Vec<_>>()
        .concat();
    assert_eq!(gunzip(&collected.to_bytes()), expected.as_bytes());
}

#[tokio::test]
async fn restricted_encodings() {
    let config = Compression::new().encodings([Encoding::Deflate]);
    let res = get_with(app(config), "/text", Some("gzip, deflate")).await;
    assert_eq!(res.headers()[header::CONTENT_ENCODING], "deflate");
}
