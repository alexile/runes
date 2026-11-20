//! Transcription, image generation and speech against a loopback mock
//! server. No test touches the network.

#![allow(clippy::unwrap_used, reason = "test helpers")]

use std::time::Duration;

use rune_chain_core::testing::http::{MockResponse, MockServer};
use rune_chain_core::{
    AudioFormat, GeneratedImage, ImageFormat, ImageGenerationModel, ImageGenerationRequest,
    ImageResponseFormat, LlmErrorKind, SpeechModel, SpeechRequest, TimestampGranularity,
    TranscriptionFormat, TranscriptionModel, TranscriptionRequest,
};
use rune_chain_openai::OpenAi;
use serde_json::json;

fn client(server: &MockServer, model: &str) -> OpenAi {
    OpenAi::new("sk-test")
        .model(model)
        .base_url(format!("{}/v1", server.base_url()))
        .http_client(reqwest::Client::builder().no_proxy().build().unwrap())
        .retry_delay(Duration::ZERO)
}

/// Split a multipart body into `(headers, value)` pairs.
fn parts(body: &[u8], boundary: &str) -> Vec<(String, Vec<u8>)> {
    let delim = format!("--{boundary}");
    let text = body;
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(pos) = find(rest, delim.as_bytes()) {
        rest = &rest[pos + delim.len()..];
        if rest.starts_with(b"--") {
            break;
        }
        let rest_trim = rest.strip_prefix(b"\r\n").unwrap();
        let head_end = find(rest_trim, b"\r\n\r\n").unwrap();
        let head = String::from_utf8(rest_trim[..head_end].to_vec()).unwrap();
        let after = &rest_trim[head_end + 4..];
        let end = find(after, format!("\r\n{delim}").as_bytes()).unwrap();
        out.push((head, after[..end].to_vec()));
        rest = &after[end + 2..];
    }
    out
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

#[test]
fn transcription_sends_multipart_and_decodes_verbose_json() {
    let reply = json!({
        "task": "transcribe",
        "language": "english",
        "duration": 2.0,
        "text": "Hello world.",
        "segments": [{ "id": 0, "start": 0.0, "end": 2.0, "text": "Hello world." }],
        "words": [
            { "word": "Hello", "start": 0.0, "end": 0.8 },
            { "word": "world", "start": 0.9, "end": 1.6 }
        ]
    });
    let server = MockServer::start([MockResponse::json(200, reply.to_string())]).unwrap();
    let llm = client(&server, "whisper-1");
    // Binary audio with CR/LF and dashes, and a hostile file name.
    let audio: Vec<u8> = (0..=255u8).chain(*b"\r\n--x\r\n").collect();
    let req = TranscriptionRequest::new(audio.clone(), "../sec\"ret\r\n.mp3")
        .language("en")
        .prompt("Names: Ada.\r\nLine two")
        .temperature(0.2)
        .response_format(TranscriptionFormat::VerboseJson)
        .timestamp_granularity(TimestampGranularity::Word)
        .timestamp_granularity(TimestampGranularity::Segment);
    let out = tokio_test::block_on(llm.transcribe(&req)).unwrap();
    assert_eq!(out.text, "Hello world.");
    assert_eq!(out.language.as_deref(), Some("english"));
    assert_eq!(out.duration, Some(2.0));
    assert_eq!(out.segments.len(), 1);
    assert_eq!(out.words.len(), 2);
    assert_eq!(out.words[1].text, "world");

    let reqs = server.finish().unwrap();
    let r = &reqs[0];
    assert_eq!(r.method, "POST");
    assert_eq!(r.path, "/v1/audio/transcriptions");
    assert_eq!(r.header("authorization"), Some("Bearer sk-test"));
    let ct = r.header("content-type").unwrap();
    let boundary = ct
        .strip_prefix("multipart/form-data; boundary=")
        .unwrap()
        .to_string();
    let p = parts(&r.body, &boundary);
    let names: Vec<String> = p
        .iter()
        .map(|(h, _)| {
            h.split("name=\"")
                .nth(1)
                .unwrap()
                .split('"')
                .next()
                .unwrap()
                .to_string()
        })
        .collect();
    assert_eq!(
        names,
        [
            "model",
            "language",
            "prompt",
            "temperature",
            "response_format",
            "timestamp_granularities[]",
            "timestamp_granularities[]",
            "file"
        ]
    );
    let value = |i: usize| String::from_utf8(p[i].1.clone()).unwrap();
    assert_eq!(value(0), "whisper-1");
    assert_eq!(value(1), "en");
    assert_eq!(value(2), "Names: Ada.\r\nLine two");
    assert_eq!(value(3), "0.2");
    assert_eq!(value(4), "verbose_json");
    assert_eq!(value(5), "word");
    assert_eq!(value(6), "segment");
    let (file_head, file_body) = &p[7];
    assert!(
        file_head.contains("filename=\"sec_ret__.mp3\""),
        "{file_head}"
    );
    assert!(file_head.contains("Content-Type: audio/mpeg"));
    assert_eq!(file_body, &audio);
}

#[test]
fn transcription_text_format_and_upload_cap() {
    let server = MockServer::start([MockResponse::new(200, "text/plain", "Just text.\n")]).unwrap();
    let llm = client(&server, "gpt-4o-transcribe").max_upload_bytes(4);
    let req = TranscriptionRequest::new(vec![1, 2, 3, 4], "a.wav")
        .response_format(TranscriptionFormat::Text);
    let out = tokio_test::block_on(llm.transcribe(&req)).unwrap();
    assert_eq!(out.text, "Just text.");
    server.finish().unwrap();

    // Too big: rejected before any request is made.
    let too_big = TranscriptionRequest::new(vec![0; 5], "a.wav");
    let err = tokio_test::block_on(llm.transcribe(&too_big)).unwrap_err();
    assert_eq!(err.kind(), LlmErrorKind::InvalidRequest);
    assert!(err.message().contains("upload limit"));
}

#[test]
fn media_errors_are_classified_and_scrubbed() {
    let key = "sk-live-0123456789abcdef";
    let echo = format!(r#"{{"error":{{"message":"Incorrect API key provided: {key}"}}}}"#);
    let server = MockServer::start([
        MockResponse::json(401, echo),
        MockResponse::json(400, r#"{"error":{"message":"Your request was rejected by the safety system.","code":"content_policy_violation"}}"#),
        MockResponse::json(429, r#"{"error":{"message":"slow down"}}"#).with_header("retry-after", "120"),
    ])
    .unwrap();
    let llm = client(&server, "gpt-image-1").api_key(key);
    tokio_test::block_on(async {
        let e = llm
            .transcribe(&TranscriptionRequest::new(vec![1], "a.wav"))
            .await
            .unwrap_err();
        assert_eq!(e.kind(), LlmErrorKind::Auth);
        assert!(!e.to_string().contains(key), "{e}");

        let e = llm
            .generate_image(&ImageGenerationRequest::new("cat"))
            .await
            .unwrap_err();
        assert_eq!(e.status(), Some(400));
        assert!(e.message().contains("safety system"));

        let e = llm
            .synthesize(&SpeechRequest::new("hi", "alloy"))
            .await
            .unwrap_err();
        assert!(e.is_rate_limit());
        assert_eq!(e.retry_after(), Some(Duration::from_secs(120)));
    });
    assert_eq!(server.finish().unwrap().len(), 3);
}

#[test]
fn images_decode_base64_and_send_options() {
    let png = b"\x89PNG\r\n\x1a\n-fake-png-";
    let reply = json!({
        "created": 1,
        "data": [{ "b64_json": rune_base64::encode(png) }],
        "output_format": "png",
        "usage": { "total_tokens": 100 }
    });
    let server = MockServer::start([MockResponse::json(200, reply.to_string())]).unwrap();
    let llm = client(&server, "gpt-image-1");
    let req = ImageGenerationRequest::new("A red fox")
        .size("1024x1024")
        .n(1)
        .quality("high")
        .output_format(ImageFormat::Png);
    let out = tokio_test::block_on(llm.generate_image(&req)).unwrap();
    assert_eq!(out.images.len(), 1);
    assert_eq!(out.images[0].bytes(), Some(&png[..]));
    assert!(
        matches!(&out.images[0], GeneratedImage::Bytes { mime_type, .. } if mime_type == "image/png")
    );

    let reqs = server.finish().unwrap();
    assert_eq!(reqs[0].path, "/v1/images/generations");
    assert_eq!(
        reqs[0].json().unwrap(),
        json!({
            "model": "gpt-image-1",
            "prompt": "A red fox",
            "n": 1,
            "size": "1024x1024",
            "quality": "high",
            "output_format": "png"
        })
    );
}

#[test]
fn image_urls_and_revised_prompt() {
    let ok = json!({ "data": [{ "url": "https://cdn.example.com/a.png", "revised_prompt": "A small red fox" }] });
    let bad = json!({ "data": [{ "url": "http://cdn.example.com/a.png" }] });
    let server = MockServer::start([
        MockResponse::json(200, ok.to_string()),
        MockResponse::json(200, bad.to_string()),
    ])
    .unwrap();
    let llm = client(&server, "dall-e-3");
    let req = ImageGenerationRequest::new("fox")
        .style("natural")
        .response_format(ImageResponseFormat::Url);
    tokio_test::block_on(async {
        let out = llm.generate_image(&req).await.unwrap();
        assert_eq!(out.images[0].url(), Some("https://cdn.example.com/a.png"));
        assert_eq!(out.revised_prompt.as_deref(), Some("A small red fox"));
        let e = llm.generate_image(&req).await.unwrap_err();
        assert_eq!(e.kind(), LlmErrorKind::InvalidResponse);
        assert!(e.message().contains("only https"));
    });
    let reqs = server.finish().unwrap();
    let body = reqs[0].json().unwrap();
    assert_eq!(body["response_format"], "url");
    assert_eq!(body["style"], "natural");
}

#[test]
fn media_response_cap_applies_to_images_and_audio() {
    let big = json!({ "data": [{ "b64_json": rune_base64::encode(&[0u8; 4096]) }] });
    let server = MockServer::start([
        MockResponse::json(200, big.to_string()),
        MockResponse::new(200, "audio/mpeg", vec![0u8; 4096]),
    ])
    .unwrap();
    let llm = client(&server, "gpt-image-1").max_media_response_bytes(1024);
    tokio_test::block_on(async {
        let e = llm
            .generate_image(&ImageGenerationRequest::new("x"))
            .await
            .unwrap_err();
        assert_eq!(e.kind(), LlmErrorKind::InvalidResponse);
        assert!(e.message().contains("1024-byte limit"), "{e}");
        let e = llm
            .synthesize(&SpeechRequest::new("hi", "alloy"))
            .await
            .unwrap_err();
        assert!(e.message().contains("1024-byte limit"), "{e}");
    });
    server.finish().unwrap();
}

#[test]
fn speech_sends_options_and_returns_audio() {
    let audio = b"ID3\x04fake-mp3".to_vec();
    let server = MockServer::start([
        MockResponse::new(200, "audio/mpeg", audio.clone()),
        MockResponse::new(200, "application/octet-stream", b"OggS".to_vec()),
    ])
    .unwrap();
    let llm = client(&server, "gpt-4o-mini-tts");
    tokio_test::block_on(async {
        let req = SpeechRequest::new("Hello there", "coral")
            .format(AudioFormat::Mp3)
            .speed(1.5)
            .instructions("Calm.");
        let out = llm.synthesize(&req).await.unwrap();
        assert_eq!(out.audio, audio);
        assert_eq!(out.mime_type, "audio/mpeg");
        // Non-audio content type: fall back to the requested format.
        let out = llm
            .synthesize(&SpeechRequest::new("x", "coral").format(AudioFormat::Opus))
            .await
            .unwrap();
        assert_eq!(out.mime_type, "audio/ogg");
    });
    let reqs = server.finish().unwrap();
    assert_eq!(reqs[0].path, "/v1/audio/speech");
    assert_eq!(
        reqs[0].json().unwrap(),
        json!({
            "model": "gpt-4o-mini-tts",
            "input": "Hello there",
            "voice": "coral",
            "response_format": "mp3",
            "speed": 1.5,
            "instructions": "Calm."
        })
    );
}

#[test]
fn azure_routes_media_through_the_deployment() {
    let server =
        MockServer::start([MockResponse::new(200, "audio/wav", b"RIFF".to_vec())]).unwrap();
    let llm = OpenAi::azure(server.base_url(), "tts", "azure-key-123456")
        .http_client(reqwest::Client::builder().no_proxy().build().unwrap());
    tokio_test::block_on(llm.synthesize(&SpeechRequest::new("hi", "alloy"))).unwrap();
    let reqs = server.finish().unwrap();
    assert_eq!(
        reqs[0].path,
        "/openai/deployments/tts/audio/speech?api-version=2024-10-21"
    );
    assert_eq!(reqs[0].header("api-key"), Some("azure-key-123456"));
}
