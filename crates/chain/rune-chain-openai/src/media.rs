//! Audio transcription (`/audio/transcriptions`), image generation
//! (`/images/generations`) and speech (`/audio/speech`).

use async_trait::async_trait;
use rune_chain_core::{
    AudioFormat, GeneratedImage, ImageFormat, ImageGenerationModel, ImageGenerationRequest,
    ImageGenerationResponse, ImageResponseFormat, LlmError, LlmErrorKind, MAX_IMAGE_URL_LEN,
    SpeechModel, SpeechRequest, SpeechResponse, TranscriptionFormat, TranscriptionModel,
    TranscriptionRequest, TranscriptionResponse, TranscriptionSegment,
};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::http;
use crate::{OpenAi, Provider};

/// Default cap on an uploaded audio file: 25 MiB, `OpenAI`'s limit.
pub const DEFAULT_MAX_UPLOAD_BYTES: usize = 25 << 20;
/// Default cap on an image-generation or speech response body (64 MiB).
pub const DEFAULT_MAX_MEDIA_RESPONSE_BYTES: usize = 64 << 20;
/// Longest text `OpenAI`'s speech endpoint accepts, in characters.
pub const MAX_SPEECH_INPUT_CHARS: usize = 4096;
/// Longest image prompt sent, in characters (gpt-image's limit).
pub const MAX_IMAGE_PROMPT_CHARS: usize = 32_000;

const TRANSCRIPTIONS_PATH: &str = "/audio/transcriptions";
const IMAGES_PATH: &str = "/images/generations";
const SPEECH_PATH: &str = "/audio/speech";
const MAX_FILENAME_BYTES: usize = 200;

fn invalid(message: impl Into<String>) -> LlmError {
    LlmError::new(LlmErrorKind::InvalidRequest, message)
}

// ── multipart/form-data ──────────────────────────────────────────────────────

/// A `multipart/form-data` body built in memory, so it can be resent on a
/// retry and carries an exact `Content-Length`.
struct Multipart {
    boundary: String,
    body: Vec<u8>,
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// A boundary that occurs in none of `parts`.
fn pick_boundary(parts: &[&[u8]]) -> String {
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let mut n: u128 = seed ^ (parts.iter().map(|p| p.len() as u128).sum::<u128>() << 64);
    loop {
        let boundary = format!("rune-chain-{n:032x}");
        if !parts.iter().any(|p| contains(p, boundary.as_bytes())) {
            return boundary;
        }
        n = n.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
    }
}

/// Keep a file name safe inside a quoted `Content-Disposition` parameter:
/// the last path component only, no quotes, backslashes or control
/// characters, at most [`MAX_FILENAME_BYTES`].
fn sanitize_filename(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or_default();
    let mut out = String::with_capacity(base.len().min(MAX_FILENAME_BYTES));
    for c in base.chars() {
        let c = if c == '"' || c.is_control() { '_' } else { c };
        if out.len() + c.len_utf8() > MAX_FILENAME_BYTES {
            break;
        }
        out.push(c);
    }
    if out.trim().is_empty() {
        "audio".to_string()
    } else {
        out
    }
}

impl Multipart {
    fn new(fields: &[(&str, String)], file: (&str, &str, &[u8])) -> Self {
        let (filename, mime, data) = file;
        let mut parts: Vec<&[u8]> = fields.iter().map(|(_, v)| v.as_bytes()).collect();
        parts.push(data);
        let boundary = pick_boundary(&parts);
        let text_len: usize = fields.iter().map(|(k, v)| k.len() + v.len() + 100).sum();
        let mut body = Vec::with_capacity(data.len() + text_len + 300);
        for (name, value) in fields {
            body.extend_from_slice(
                format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n")
                    .as_bytes(),
            );
            body.extend_from_slice(value.as_bytes());
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; \
                 filename=\"{filename}\"\r\nContent-Type: {mime}\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(data);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        Self { boundary, body }
    }

    fn content_type(&self) -> String {
        format!("multipart/form-data; boundary={}", self.boundary)
    }
}

// ── transcription ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct TranscriptionJson {
    #[serde(default)]
    text: String,
    #[serde(default)]
    language: Option<String>,
    #[serde(default)]
    duration: Option<f64>,
    #[serde(default)]
    segments: Vec<SegmentJson>,
    #[serde(default)]
    words: Vec<WordJson>,
}

#[derive(Deserialize)]
struct SegmentJson {
    start: f64,
    end: f64,
    #[serde(default)]
    text: String,
}

#[derive(Deserialize)]
struct WordJson {
    start: f64,
    end: f64,
    word: String,
}

fn decode_transcription(
    body: &[u8],
    format: Option<TranscriptionFormat>,
) -> Result<TranscriptionResponse, LlmError> {
    if let Some(TranscriptionFormat::Text | TranscriptionFormat::Srt | TranscriptionFormat::Vtt) =
        format
    {
        let text = std::str::from_utf8(body)
            .map_err(|_| LlmError::invalid_response("transcription is not valid UTF-8"))?;
        let text = if format == Some(TranscriptionFormat::Text) {
            text.trim_end()
        } else {
            text
        };
        return Ok(TranscriptionResponse::from_text(text));
    }
    let parsed: TranscriptionJson = serde_json::from_slice(body)
        .map_err(|e| LlmError::invalid_response(format!("transcription response: {e}")))?;
    let mut out = TranscriptionResponse::from_text(parsed.text)
        .with_segments(
            parsed
                .segments
                .into_iter()
                .map(|s| TranscriptionSegment::new(s.start, s.end, s.text))
                .collect(),
        )
        .with_words(
            parsed
                .words
                .into_iter()
                .map(|w| TranscriptionSegment::new(w.start, w.end, w.word))
                .collect(),
        );
    if let Some(lang) = parsed.language {
        out = out.with_language(lang);
    }
    if let Some(d) = parsed.duration {
        out = out.with_duration(d);
    }
    Ok(out)
}

impl OpenAi {
    fn transcription_body(&self, req: &TranscriptionRequest) -> Result<Multipart, LlmError> {
        req.validate()?;
        if req.audio.len() > self.max_upload_bytes {
            return Err(invalid(format!(
                "audio file is {} bytes; the upload limit is {} bytes",
                req.audio.len(),
                self.max_upload_bytes
            )));
        }
        let mut fields: Vec<(&str, String)> = vec![("model", self.model_id().to_string())];
        if let Some(lang) = &req.language {
            fields.push(("language", lang.clone()));
        }
        if let Some(prompt) = &req.prompt {
            fields.push(("prompt", prompt.clone()));
        }
        if let Some(t) = req.temperature {
            fields.push(("temperature", t.to_string()));
        }
        if let Some(f) = req.response_format {
            fields.push(("response_format", f.as_str().to_string()));
        }
        for g in &req.timestamp_granularities {
            fields.push(("timestamp_granularities[]", g.as_str().to_string()));
        }
        let filename = sanitize_filename(&req.filename);
        Ok(Multipart::new(
            &fields,
            (&filename, req.mime_type(), &req.audio),
        ))
    }
}

/// `POST /audio/transcriptions` as `multipart/form-data` with this client's
/// model (`whisper-1`, `gpt-4o-transcribe`, `gpt-4o-mini-transcribe`, or a
/// compatible server's). Uploads over
/// [`max_upload_bytes`](OpenAi::max_upload_bytes) fail locally.
#[async_trait]
impl TranscriptionModel for OpenAi {
    async fn transcribe(
        &self,
        request: &TranscriptionRequest,
    ) -> Result<TranscriptionResponse, LlmError> {
        let url = self.endpoint_url(TRANSCRIPTIONS_PATH)?;
        let form = self.transcription_body(request)?;
        let content_type = form.content_type();
        let response = self.send_payload(url, form.body, &content_type).await?;
        let body = http::read_body(response, self.response_limit(), false).await?;
        decode_transcription(&body, request.response_format).map_err(|e| self.scrub(e))
    }
}

// ── image generation ─────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct ImagesJson {
    #[serde(default)]
    data: Vec<ImageItem>,
    #[serde(default)]
    output_format: Option<String>,
}

#[derive(Deserialize)]
struct ImageItem {
    #[serde(default)]
    b64_json: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    revised_prompt: Option<String>,
}

/// Only plain `https` URLs without credentials, of bounded length, are
/// handed back to the caller.
fn check_image_url(url: &str) -> Result<(), LlmError> {
    if url.len() > MAX_IMAGE_URL_LEN {
        return Err(LlmError::invalid_response("image URL is too long"));
    }
    let parsed = reqwest::Url::parse(url)
        .map_err(|_| LlmError::invalid_response("image URL is not a valid URL"))?;
    if parsed.scheme() != "https" {
        return Err(LlmError::invalid_response(format!(
            "refusing image URL with scheme `{}`; only https is accepted",
            parsed.scheme()
        )));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() || parsed.host().is_none() {
        return Err(LlmError::invalid_response(
            "image URL must have a host and no credentials",
        ));
    }
    Ok(())
}

fn format_from_name(name: &str) -> Option<ImageFormat> {
    match name {
        "png" => Some(ImageFormat::Png),
        "jpeg" | "jpg" => Some(ImageFormat::Jpeg),
        "webp" => Some(ImageFormat::Webp),
        _ => None,
    }
}

fn decode_images(
    body: &[u8],
    requested: Option<ImageFormat>,
) -> Result<ImageGenerationResponse, LlmError> {
    let parsed: ImagesJson = serde_json::from_slice(body)
        .map_err(|e| LlmError::invalid_response(format!("image response: {e}")))?;
    let fallback = parsed
        .output_format
        .as_deref()
        .and_then(format_from_name)
        .or(requested)
        .unwrap_or(ImageFormat::Png);
    let mut revised_prompt = None;
    let mut images = Vec::with_capacity(parsed.data.len());
    for (i, item) in parsed.data.into_iter().enumerate() {
        if revised_prompt.is_none() {
            revised_prompt = item.revised_prompt.filter(|p| !p.is_empty());
        }
        let image = match (item.b64_json, item.url) {
            (Some(b64), _) => {
                let data = rune_base64::decode(b64.trim()).map_err(|_| {
                    LlmError::invalid_response(format!("image {i}: invalid base64"))
                })?;
                if data.is_empty() {
                    return Err(LlmError::invalid_response(format!("image {i} is empty")));
                }
                let format = ImageFormat::sniff(&data).unwrap_or(fallback);
                GeneratedImage::Bytes {
                    data,
                    mime_type: format.mime_type().to_string(),
                }
            }
            (None, Some(url)) => {
                check_image_url(&url)?;
                GeneratedImage::Url { url }
            }
            (None, None) => {
                return Err(LlmError::invalid_response(format!(
                    "image {i} has neither `b64_json` nor `url`"
                )));
            }
        };
        images.push(image);
    }
    if images.is_empty() {
        return Err(LlmError::invalid_response("the response holds no images"));
    }
    let out = ImageGenerationResponse::new(images);
    Ok(match revised_prompt {
        Some(p) => out.with_revised_prompt(p),
        None => out,
    })
}

impl OpenAi {
    /// gpt-image models always return base64 and reject `response_format`.
    fn is_gpt_image(&self) -> bool {
        let id = self.model_id();
        let id = id.strip_prefix("openai/").unwrap_or(id);
        id.starts_with("gpt-image") || id.starts_with("chatgpt-image")
    }

    fn image_body(&self, req: &ImageGenerationRequest) -> Result<Value, LlmError> {
        req.validate()?;
        if req.prompt.chars().count() > MAX_IMAGE_PROMPT_CHARS {
            return Err(invalid(format!(
                "image prompt exceeds {MAX_IMAGE_PROMPT_CHARS} characters"
            )));
        }
        let mut body = Map::new();
        body.insert("model".into(), json!(self.model_id()));
        body.insert("prompt".into(), json!(req.prompt));
        if let Some(n) = req.n {
            body.insert("n".into(), json!(n));
        }
        for (key, value) in [
            ("size", &req.size),
            ("quality", &req.quality),
            ("style", &req.style),
        ] {
            if let Some(v) = value {
                body.insert(key.into(), json!(v));
            }
        }
        if let Some(f) = req.output_format {
            body.insert("output_format".into(), json!(f.as_str()));
        }
        match (req.response_format, self.is_gpt_image()) {
            (Some(ImageResponseFormat::Url), true) => {
                return Err(LlmError::unsupported(format!(
                    "`{}` returns images inline only; drop the URL response format",
                    self.model_id()
                )));
            }
            (Some(ImageResponseFormat::Url), false) => {
                body.insert("response_format".into(), json!("url"));
            }
            (Some(ImageResponseFormat::Bytes), false) => {
                body.insert("response_format".into(), json!("b64_json"));
            }
            _ => {}
        }
        Ok(Value::Object(body))
    }
}

/// `POST /images/generations` with this client's model (`gpt-image-1`,
/// `dall-e-3`, …). Base64 images are decoded and their type sniffed; URL
/// results must be `https`. The response body is capped by
/// [`max_media_response_bytes`](OpenAi::max_media_response_bytes).
#[async_trait]
impl ImageGenerationModel for OpenAi {
    async fn generate_image(
        &self,
        request: &ImageGenerationRequest,
    ) -> Result<ImageGenerationResponse, LlmError> {
        let url = self.endpoint_url(IMAGES_PATH)?;
        let payload = serde_json::to_vec(&self.image_body(request)?)
            .map_err(|e| LlmError::other(format!("encode request: {e}")))?;
        let response = self.send_payload(url, payload, "application/json").await?;
        let body = http::read_body(response, self.max_media_response_bytes, false).await?;
        decode_images(&body, request.output_format).map_err(|e| self.scrub(e))
    }
}

// ── speech ───────────────────────────────────────────────────────────────────

impl OpenAi {
    fn speech_body(&self, req: &SpeechRequest) -> Result<Value, LlmError> {
        req.validate()?;
        if matches!(self.provider(), Provider::OpenAi | Provider::AzureOpenAi) {
            if req.text.chars().count() > MAX_SPEECH_INPUT_CHARS {
                return Err(invalid(format!(
                    "speech text exceeds {MAX_SPEECH_INPUT_CHARS} characters; split it"
                )));
            }
            if let Some(speed) = req.speed
                && !(0.25..=4.0).contains(&speed)
            {
                return Err(invalid("speech speed must be between 0.25 and 4.0"));
            }
        }
        let mut body = Map::new();
        body.insert("model".into(), json!(self.model_id()));
        body.insert("input".into(), json!(req.text));
        body.insert("voice".into(), json!(req.voice));
        if let Some(f) = req.format {
            body.insert("response_format".into(), json!(f.as_str()));
        }
        if let Some(speed) = req.speed {
            body.insert("speed".into(), json!(speed));
        }
        if let Some(i) = &req.instructions {
            body.insert("instructions".into(), json!(i));
        }
        Ok(Value::Object(body))
    }
}

/// `POST /audio/speech` with this client's model (`gpt-4o-mini-tts`,
/// `tts-1`, `tts-1-hd`, …). The audio body is capped by
/// [`max_media_response_bytes`](OpenAi::max_media_response_bytes).
#[async_trait]
impl SpeechModel for OpenAi {
    async fn synthesize(&self, request: &SpeechRequest) -> Result<SpeechResponse, LlmError> {
        let url = self.endpoint_url(SPEECH_PATH)?;
        let payload = serde_json::to_vec(&self.speech_body(request)?)
            .map_err(|e| LlmError::other(format!("encode request: {e}")))?;
        let response = self.send_payload(url, payload, "application/json").await?;
        let header_mime = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.split(';').next().unwrap_or_default().trim().to_string())
            .filter(|v| v.starts_with("audio/"));
        let audio = http::read_body(response, self.max_media_response_bytes, false).await?;
        if audio.is_empty() {
            return Err(LlmError::invalid_response("the speech response is empty"));
        }
        let mime = header_mime.unwrap_or_else(|| {
            request
                .format
                .unwrap_or(AudioFormat::Mp3)
                .mime_type()
                .to_string()
        });
        Ok(SpeechResponse::new(audio, mime))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filenames_are_sanitized() {
        assert_eq!(sanitize_filename("memo.m4a"), "memo.m4a");
        assert_eq!(
            sanitize_filename("../../etc/pa\"ss\r\nwd.wav"),
            "pa_ss__wd.wav"
        );
        assert_eq!(sanitize_filename("C:\\x\\y.mp3"), "y.mp3");
        assert_eq!(sanitize_filename("dir/"), "audio");
        assert!(sanitize_filename(&"é".repeat(500)).len() <= MAX_FILENAME_BYTES);
    }

    #[test]
    fn boundary_avoids_payload() {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let b = pick_boundary(&[b"abc"]);
        assert!(b.starts_with("rune-chain-"));
        // A payload that contains a candidate boundary forces another one.
        let trap = format!("xx rune-chain-{n:032x} yy");
        let b = pick_boundary(&[trap.as_bytes()]);
        assert!(!trap.contains(&b));
    }

    #[test]
    fn image_urls_must_be_https() {
        assert!(check_image_url("https://cdn.example.com/a.png?sig=1").is_ok());
        for bad in [
            "http://cdn.example.com/a.png",
            "file:///etc/passwd",
            "data:image/png;base64,AAAA",
            "javascript:alert(1)",
            "https://user:pw@cdn.example.com/a.png",
            "not a url",
        ] {
            let e = check_image_url(bad).unwrap_err();
            assert_eq!(e.kind(), LlmErrorKind::InvalidResponse, "{bad}");
        }
        let long = format!("https://a.com/{}", "x".repeat(MAX_IMAGE_URL_LEN));
        assert!(check_image_url(&long).is_err());
    }

    #[test]
    fn decodes_b64_and_sniffs_type() {
        let png = rune_base64::encode(b"\x89PNG\r\n\x1a\nrest");
        let jpg = rune_base64::encode(&[0xFF, 0xD8, 0xFF, 0x00]);
        let body = format!(
            r#"{{"data":[{{"b64_json":"{png}","revised_prompt":"a cat"}},{{"b64_json":"{jpg}"}}],"output_format":"webp"}}"#
        );
        let out = decode_images(body.as_bytes(), None).unwrap();
        assert_eq!(out.revised_prompt.as_deref(), Some("a cat"));
        assert_eq!(out.images.len(), 2);
        assert_eq!(
            out.images[0],
            GeneratedImage::Bytes {
                data: b"\x89PNG\r\n\x1a\nrest".to_vec(),
                mime_type: "image/png".into()
            }
        );
        assert!(
            matches!(&out.images[1], GeneratedImage::Bytes { mime_type, .. } if mime_type == "image/jpeg")
        );
        // Unknown magic falls back to the reported format.
        let other = rune_base64::encode(b"????");
        let body = format!(r#"{{"data":[{{"b64_json":"{other}"}}],"output_format":"webp"}}"#);
        let out = decode_images(body.as_bytes(), None).unwrap();
        assert!(
            matches!(&out.images[0], GeneratedImage::Bytes { mime_type, .. } if mime_type == "image/webp")
        );
    }

    #[test]
    fn rejects_bad_image_payloads() {
        for body in [
            r#"{"data":[{"b64_json":"!!!not base64"}]}"#,
            r#"{"data":[{"b64_json":""}]}"#,
            r#"{"data":[{"url":"http://insecure.example.com/a.png"}]}"#,
            r#"{"data":[{}]}"#,
            r#"{"data":[]}"#,
            "not json",
        ] {
            let e = decode_images(body.as_bytes(), None).unwrap_err();
            assert_eq!(e.kind(), LlmErrorKind::InvalidResponse, "{body}");
        }
    }

    #[test]
    fn decodes_transcriptions() {
        let verbose = br#"{"text":"Hi there.","language":"english","duration":1.5,
            "segments":[{"id":0,"start":0.0,"end":1.5,"text":"Hi there.","tokens":[1]}],
            "words":[{"word":"Hi","start":0.0,"end":0.4},{"word":"there","start":0.5,"end":1.1}]}"#;
        let out = decode_transcription(verbose, Some(TranscriptionFormat::VerboseJson)).unwrap();
        assert_eq!(out.text, "Hi there.");
        assert_eq!(out.language.as_deref(), Some("english"));
        assert_eq!(out.duration, Some(1.5));
        assert_eq!(
            out.segments,
            [TranscriptionSegment::new(0.0, 1.5, "Hi there.")]
        );
        assert_eq!(out.words[1], TranscriptionSegment::new(0.5, 1.1, "there"));

        let plain = decode_transcription(b"Hello.\n", Some(TranscriptionFormat::Text)).unwrap();
        assert_eq!(plain.text, "Hello.");
        let srt = "1\n00:00:00,000 --> 00:00:01,000\nHello.\n\n";
        let out = decode_transcription(srt.as_bytes(), Some(TranscriptionFormat::Srt)).unwrap();
        assert_eq!(out.text, srt);
        assert_eq!(
            decode_transcription(br#"{"text":"ok"}"#, None)
                .unwrap()
                .text,
            "ok"
        );
        assert!(decode_transcription(b"<html>", None).is_err());
        assert!(decode_transcription(&[0xFF, 0xFE], Some(TranscriptionFormat::Text)).is_err());
    }

    #[test]
    fn upload_cap_is_enforced_locally() {
        let llm = OpenAi::new("k").model("whisper-1").max_upload_bytes(8);
        let e = llm
            .transcription_body(&TranscriptionRequest::new(vec![0; 9], "a.wav"))
            .err()
            .unwrap();
        assert_eq!(e.kind(), LlmErrorKind::InvalidRequest);
        assert!(
            llm.transcription_body(&TranscriptionRequest::new(vec![0; 8], "a.wav"))
                .is_ok()
        );
    }

    #[test]
    fn image_body_respects_model_family() {
        let gpt = OpenAi::new("k").model("gpt-image-1");
        let req = ImageGenerationRequest::new("cat").response_format(ImageResponseFormat::Bytes);
        assert!(
            gpt.image_body(&req)
                .unwrap()
                .get("response_format")
                .is_none()
        );
        let url_req = ImageGenerationRequest::new("cat").response_format(ImageResponseFormat::Url);
        assert_eq!(
            gpt.image_body(&url_req).unwrap_err().kind(),
            LlmErrorKind::Unsupported
        );
        let dalle = OpenAi::new("k").model("dall-e-3");
        assert_eq!(
            dalle.image_body(&req).unwrap()["response_format"],
            "b64_json"
        );
        let long = ImageGenerationRequest::new("x".repeat(MAX_IMAGE_PROMPT_CHARS + 1));
        assert!(dalle.image_body(&long).is_err());
    }

    #[test]
    fn speech_limits_apply_to_openai_only() {
        let long = SpeechRequest::new("x".repeat(MAX_SPEECH_INPUT_CHARS + 1), "alloy");
        assert!(OpenAi::new("k").speech_body(&long).is_err());
        assert!(
            OpenAi::vllm("http://localhost:1/v1", "kokoro")
                .speech_body(&long)
                .is_ok()
        );
        let fast = SpeechRequest::new("hi", "alloy").speed(5.0);
        assert!(OpenAi::new("k").speech_body(&fast).is_err());
    }
}
