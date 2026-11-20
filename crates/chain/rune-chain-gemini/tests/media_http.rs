//! Image generation and speech against a loopback mock of the Gemini API.
//! No test touches the network.

#![allow(clippy::unwrap_used, reason = "test helpers")]

use rune_chain_core::testing::http::{MockResponse, MockServer};
use rune_chain_core::{
    AudioFormat, ImageFormat, ImageGenerationModel, ImageGenerationRequest, LlmErrorKind,
    SpeechModel, SpeechRequest,
};
use rune_chain_gemini::Gemini;
use serde_json::json;

const KEY: &str = "AIzaSy-test-key-0123";

fn client(server: &MockServer, model: &str) -> Gemini {
    let http = reqwest::Client::builder().no_proxy().build().unwrap();
    Gemini::new(KEY)
        .model(model)
        .base_url(format!("{}/v1beta", server.base_url()))
        .http_client(http)
        .max_retries(0)
}

#[test]
fn imagen_predict_round_trip() {
    let png = b"\x89PNG\r\n\x1a\nimagen";
    let reply = json!({
        "predictions": [
            { "bytesBase64Encoded": rune_base64::encode(png), "mimeType": "image/png" },
            { "bytesBase64Encoded": rune_base64::encode(b"\xFF\xD8\xFFjpeg"), "mimeType": "image/jpeg" }
        ]
    });
    let server = MockServer::start([MockResponse::json(200, reply.to_string())]).unwrap();
    let llm = client(&server, "imagen-4.0-generate-001");
    let req = ImageGenerationRequest::new("A koi pond")
        .n(2)
        .size("1792x1024")
        .output_format(ImageFormat::Png);
    let out = tokio_test::block_on(llm.generate_image(&req)).unwrap();
    assert_eq!(out.images.len(), 2);
    assert_eq!(out.images[0].bytes(), Some(&png[..]));

    let reqs = server.finish().unwrap();
    assert_eq!(
        reqs[0].path,
        "/v1beta/models/imagen-4.0-generate-001:predict"
    );
    assert_eq!(reqs[0].header("x-goog-api-key"), Some(KEY));
    assert_eq!(
        reqs[0].json().unwrap(),
        json!({
            "instances": [{ "prompt": "A koi pond" }],
            "parameters": {
                "sampleCount": 2,
                "aspectRatio": "16:9",
                "outputOptions": { "mimeType": "image/png" }
            }
        })
    );
}

#[test]
fn gemini_image_model_reads_inline_data() {
    let png = b"\x89PNG\r\n\x1a\nnative";
    let reply = json!({
        "candidates": [{
            "content": { "role": "model", "parts": [
                { "text": "Here you go." },
                { "inlineData": { "mimeType": "image/png", "data": rune_base64::encode(png) } }
            ]},
            "finishReason": "STOP"
        }]
    });
    let blocked = json!({ "promptFeedback": { "blockReason": "SAFETY" } });
    let server = MockServer::start([
        MockResponse::json(200, reply.to_string()),
        MockResponse::json(200, blocked.to_string()),
    ])
    .unwrap();
    let llm = client(&server, "gemini-2.5-flash-image");
    tokio_test::block_on(async {
        let out = llm
            .generate_image(&ImageGenerationRequest::new("A koi").size("1:1"))
            .await
            .unwrap();
        assert_eq!(out.images[0].bytes(), Some(&png[..]));
        let e = llm
            .generate_image(&ImageGenerationRequest::new("bad"))
            .await
            .unwrap_err();
        assert_eq!(e.kind(), LlmErrorKind::Provider);
        assert!(e.message().contains("SAFETY"));
        // More than one image is refused locally.
        let e = llm
            .generate_image(&ImageGenerationRequest::new("x").n(2))
            .await
            .unwrap_err();
        assert_eq!(e.kind(), LlmErrorKind::Unsupported);
    });
    let reqs = server.finish().unwrap();
    assert_eq!(
        reqs[0].path,
        "/v1beta/models/gemini-2.5-flash-image:generateContent"
    );
    let body = reqs[0].json().unwrap();
    assert_eq!(
        body["generationConfig"],
        json!({ "responseModalities": ["TEXT", "IMAGE"], "imageConfig": { "aspectRatio": "1:1" } })
    );
}

#[test]
fn tts_wraps_pcm_in_wav() {
    let pcm: Vec<u8> = (0..64).collect();
    let reply = json!({
        "candidates": [{ "content": { "parts": [
            { "inlineData": { "mimeType": "audio/L16;codec=pcm;rate=24000", "data": rune_base64::encode(&pcm) } }
        ]}, "finishReason": "STOP" }]
    });
    let server = MockServer::start([
        MockResponse::json(200, reply.to_string()),
        MockResponse::json(200, reply.to_string()),
    ])
    .unwrap();
    let llm = client(&server, "gemini-2.5-flash-preview-tts");
    tokio_test::block_on(async {
        let out = llm
            .synthesize(&SpeechRequest::new("Hello", "Kore"))
            .await
            .unwrap();
        assert_eq!(out.mime_type, "audio/wav");
        assert_eq!(&out.audio[..4], b"RIFF");
        assert_eq!(&out.audio[44..], &pcm[..]);
        let raw = llm
            .synthesize(&SpeechRequest::new("Hello", "Kore").format(AudioFormat::Pcm))
            .await
            .unwrap();
        assert_eq!(raw.audio, pcm);
        assert_eq!(raw.mime_type, "audio/L16;codec=pcm;rate=24000");
    });
    let reqs = server.finish().unwrap();
    let body = reqs[0].json().unwrap();
    assert_eq!(
        body["generationConfig"]["responseModalities"],
        json!(["AUDIO"])
    );
    assert_eq!(
        body["generationConfig"]["speechConfig"]["voiceConfig"]["prebuiltVoiceConfig"]["voiceName"],
        "Kore"
    );
}

#[test]
fn media_errors_and_caps() {
    let echo = format!(
        r#"{{"error":{{"code":400,"message":"API key not valid: {KEY}","status":"INVALID_ARGUMENT"}}}}"#
    );
    let big =
        json!({ "predictions": [{ "bytesBase64Encoded": rune_base64::encode(&[0u8; 4096]) }] });
    let server = MockServer::start([
        MockResponse::json(400, echo),
        MockResponse::json(200, big.to_string()),
    ])
    .unwrap();
    let llm = client(&server, "imagen-4.0-generate-001").max_response_bytes(1024);
    tokio_test::block_on(async {
        let e = llm
            .generate_image(&ImageGenerationRequest::new("x"))
            .await
            .unwrap_err();
        assert!(!e.to_string().contains(KEY), "{e}");
        assert_eq!(e.status(), Some(400));
        let e = llm
            .generate_image(&ImageGenerationRequest::new("x"))
            .await
            .unwrap_err();
        assert_eq!(e.kind(), LlmErrorKind::InvalidResponse);
    });
    server.finish().unwrap();
}
