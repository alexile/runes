//! Image generation (Imagen `predict` and Gemini image-output models) and
//! speech (Gemini TTS models).

use async_trait::async_trait;
use rune_chain_core::{
    AudioFormat, GeneratedImage, ImageFormat, ImageGenerationModel, ImageGenerationRequest,
    ImageGenerationResponse, ImageResponseFormat, LlmError, LlmErrorKind, SpeechModel,
    SpeechRequest, SpeechResponse,
};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::Gemini;
use crate::types::GenerateContentResponse;

/// Sample rate assumed when a TTS response does not state one.
const DEFAULT_PCM_RATE: u32 = 24_000;
/// Aspect ratios Imagen and the Gemini image models accept.
const ASPECT_RATIOS: [(&str, f64); 5] = [
    ("1:1", 1.0),
    ("3:4", 0.75),
    ("4:3", 4.0 / 3.0),
    ("9:16", 9.0 / 16.0),
    ("16:9", 16.0 / 9.0),
];

/// A provider-supplied reason, cut short and without control characters.
fn short(text: &str) -> String {
    text.chars().filter(|c| !c.is_control()).take(200).collect()
}

fn decode_b64(data: &str, what: &str) -> Result<Vec<u8>, LlmError> {
    let bytes = rune_base64::decode(data.trim())
        .map_err(|_| LlmError::invalid_response(format!("{what}: invalid base64")))?;
    if bytes.is_empty() {
        return Err(LlmError::invalid_response(format!("{what} is empty")));
    }
    Ok(bytes)
}

/// `"16:9"` passes through; `"1536x1024"` maps to the closest supported
/// ratio; anything else is not an aspect ratio.
fn aspect_ratio(size: &str) -> Option<&'static str> {
    if let Some((name, _)) = ASPECT_RATIOS.iter().find(|(name, _)| *name == size) {
        return Some(name);
    }
    let (w, h) = size.split_once(['x', 'X'])?;
    let (w, h): (u32, u32) = (w.trim().parse().ok()?, h.trim().parse().ok()?);
    if w == 0 || h == 0 {
        return None;
    }
    let ratio = f64::from(w) / f64::from(h);
    ASPECT_RATIOS
        .iter()
        .min_by(|a, b| (a.1 - ratio).abs().total_cmp(&(b.1 - ratio).abs()))
        .map(|(name, _)| *name)
}

/// Turn a size into Imagen / Gemini image parameters: an aspect ratio, or
/// an image size such as `"1K"` / `"2K"`.
fn size_params(size: Option<&str>) -> Result<(Option<&'static str>, Option<String>), LlmError> {
    let Some(size) = size
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "auto")
    else {
        return Ok((None, None));
    };
    if let Some(ratio) = aspect_ratio(size) {
        return Ok((Some(ratio), None));
    }
    if matches!(size, "1K" | "2K" | "4K") {
        return Ok((None, Some(size.to_string())));
    }
    Err(LlmError::new(
        LlmErrorKind::InvalidRequest,
        format!(
            "unsupported image size `{}`; use an aspect ratio such as `16:9`, `WxH`, or `1K`/`2K`",
            short(size)
        ),
    ))
}

fn is_imagen(model: &str) -> bool {
    model.starts_with("imagen")
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PredictResponse {
    #[serde(default)]
    predictions: Vec<Prediction>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Prediction {
    #[serde(default)]
    bytes_base64_encoded: Option<String>,
    #[serde(default)]
    mime_type: Option<String>,
    #[serde(default)]
    prompt: Option<String>,
    #[serde(default)]
    rai_filtered_reason: Option<String>,
}

fn image_mime(data: &[u8], reported: Option<&str>, requested: Option<ImageFormat>) -> String {
    ImageFormat::sniff(data).map_or_else(
        || {
            reported.filter(|m| m.starts_with("image/")).map_or_else(
                || {
                    requested
                        .unwrap_or(ImageFormat::Png)
                        .mime_type()
                        .to_string()
                },
                str::to_string,
            )
        },
        |f| f.mime_type().to_string(),
    )
}

fn decode_predictions(
    body: &[u8],
    requested: Option<ImageFormat>,
) -> Result<ImageGenerationResponse, LlmError> {
    let parsed: PredictResponse = serde_json::from_slice(body)
        .map_err(|e| LlmError::invalid_response(format!("image response: {e}")))?;
    let mut images = Vec::with_capacity(parsed.predictions.len());
    let mut revised = None;
    let mut filtered = None;
    for (i, p) in parsed.predictions.into_iter().enumerate() {
        let Some(b64) = p.bytes_base64_encoded else {
            filtered = filtered.or(p.rai_filtered_reason);
            continue;
        };
        let data = decode_b64(&b64, &format!("image {i}"))?;
        let mime_type = image_mime(&data, p.mime_type.as_deref(), requested);
        if revised.is_none() {
            revised = p.prompt.filter(|s| !s.is_empty());
        }
        images.push(GeneratedImage::Bytes { data, mime_type });
    }
    if images.is_empty() {
        return Err(filtered.map_or_else(
            || LlmError::invalid_response("the response holds no images"),
            |reason| LlmError::provider(format!("every image was filtered: {}", short(&reason))),
        ));
    }
    let out = ImageGenerationResponse::new(images);
    Ok(match revised {
        Some(p) => out.with_revised_prompt(p),
        None => out,
    })
}

/// Pull inline media of `kind` (`"image/"` or `"audio/"`) out of a
/// `generateContent` response. Blocked prompts and empty answers are errors.
fn inline_parts(body: &[u8], kind: &str) -> Result<Vec<(String, String)>, LlmError> {
    let wire: GenerateContentResponse = serde_json::from_slice(body)
        .map_err(|e| LlmError::invalid_response(format!("response: {e}")))?;
    if let Some(reason) = wire.prompt_feedback.and_then(|f| f.block_reason) {
        return Err(LlmError::provider(format!(
            "prompt blocked: {}",
            short(&reason)
        )));
    }
    let mut finish = None;
    let mut out = Vec::new();
    for candidate in wire.candidates {
        finish = finish.or(candidate.finish_reason);
        for part in candidate.content.map(|c| c.parts).unwrap_or_default() {
            if let Some(blob) = part.inline_data
                && blob.mime_type.starts_with(kind)
            {
                out.push((blob.mime_type, blob.data));
            }
        }
    }
    if out.is_empty() {
        let what = kind.trim_end_matches('/');
        return Err(match finish {
            Some(reason) if reason != "STOP" => LlmError::provider(format!(
                "no {what} returned (finish reason {})",
                short(&reason)
            )),
            _ => LlmError::invalid_response(format!("the response holds no {what}")),
        });
    }
    Ok(out)
}

impl Gemini {
    fn imagen_body(req: &ImageGenerationRequest) -> Result<Value, LlmError> {
        let (ratio, image_size) = size_params(req.size.as_deref())?;
        let mut params = Map::new();
        if let Some(n) = req.n {
            params.insert("sampleCount".into(), json!(n));
        }
        if let Some(r) = ratio {
            params.insert("aspectRatio".into(), json!(r));
        }
        if let Some(s) = image_size {
            params.insert("imageSize".into(), json!(s));
        }
        if let Some(f) = req.output_format {
            params.insert("outputOptions".into(), json!({ "mimeType": f.mime_type() }));
        }
        Ok(json!({
            "instances": [{ "prompt": req.prompt }],
            "parameters": params,
        }))
    }

    fn native_image_body(&self, req: &ImageGenerationRequest) -> Result<Value, LlmError> {
        if req.n.is_some_and(|n| n > 1) {
            return Err(LlmError::unsupported(format!(
                "`{}` returns one image per request; call it again for more",
                self.model_id()
            )));
        }
        let (ratio, image_size) = size_params(req.size.as_deref())?;
        let mut image_config = Map::new();
        if let Some(r) = ratio {
            image_config.insert("aspectRatio".into(), json!(r));
        }
        if let Some(s) = image_size {
            image_config.insert("imageSize".into(), json!(s));
        }
        let mut config = Map::new();
        config.insert("responseModalities".into(), json!(["TEXT", "IMAGE"]));
        if !image_config.is_empty() {
            config.insert("imageConfig".into(), Value::Object(image_config));
        }
        Ok(json!({
            "contents": [{ "role": "user", "parts": [{ "text": req.prompt }] }],
            "generationConfig": config,
        }))
    }
}

/// Imagen models (`imagen-…`) go through `:predict`; any other model id is
/// treated as a Gemini image-output model (e.g. `gemini-2.5-flash-image`)
/// and called with `generateContent` and `responseModalities: [TEXT, IMAGE]`.
///
/// `size` takes an aspect ratio (`"16:9"`), a `WxH` size (mapped to the
/// closest supported ratio) or `"1K"`/`"2K"`. `quality` and `style` have no
/// Gemini equivalent and are ignored; URL output is not supported.
#[async_trait]
impl ImageGenerationModel for Gemini {
    async fn generate_image(
        &self,
        request: &ImageGenerationRequest,
    ) -> Result<ImageGenerationResponse, LlmError> {
        request.validate()?;
        if request.response_format == Some(ImageResponseFormat::Url) {
            return Err(LlmError::unsupported(
                "Gemini returns images inline only; drop the URL response format",
            ));
        }
        let transport = self.transport();
        let scrub = |e: LlmError| e.map_message(|m| transport.credential.scrub(&m));
        if is_imagen(self.model_id()) {
            let url = transport.model_url(self.model_id(), "predict")?;
            let body = transport
                .post_json(&url, &Self::imagen_body(request)?)
                .await?;
            return decode_predictions(&body, request.output_format).map_err(scrub);
        }
        let url = transport.model_url(self.model_id(), "generateContent")?;
        let body = transport
            .post_json(&url, &self.native_image_body(request)?)
            .await?;
        let parts = inline_parts(&body, "image/").map_err(scrub)?;
        let images = parts
            .into_iter()
            .enumerate()
            .map(|(i, (mime, b64))| {
                let data = decode_b64(&b64, &format!("image {i}"))?;
                let mime_type = image_mime(&data, Some(&mime), request.output_format);
                Ok(GeneratedImage::Bytes { data, mime_type })
            })
            .collect::<Result<Vec<_>, LlmError>>()?;
        Ok(ImageGenerationResponse::new(images))
    }
}

// ── speech ───────────────────────────────────────────────────────────────────

/// The `rate=` parameter of an `audio/L16;codec=pcm;rate=24000` type.
fn pcm_rate(mime: &str) -> u32 {
    mime.split(';')
        .filter_map(|p| p.trim().strip_prefix("rate="))
        .find_map(|r| r.parse().ok())
        .filter(|r| (1..=384_000).contains(r))
        .unwrap_or(DEFAULT_PCM_RATE)
}

/// Wrap 16-bit mono little-endian PCM in a WAV header.
fn wav(pcm: &[u8], rate: u32) -> Result<Vec<u8>, LlmError> {
    let data_len = u32::try_from(pcm.len())
        .ok()
        .filter(|n| *n <= u32::MAX - 36)
        .ok_or_else(|| LlmError::invalid_response("audio too long for a WAV file"))?;
    let mut out = Vec::with_capacity(pcm.len() + 44);
    out.extend_from_slice(b"RIFF");
    out.extend_from_slice(&(36 + data_len).to_le_bytes());
    out.extend_from_slice(b"WAVEfmt ");
    out.extend_from_slice(&16u32.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes()); // PCM
    out.extend_from_slice(&1u16.to_le_bytes()); // mono
    out.extend_from_slice(&rate.to_le_bytes());
    out.extend_from_slice(&(rate * 2).to_le_bytes()); // byte rate
    out.extend_from_slice(&2u16.to_le_bytes()); // block align
    out.extend_from_slice(&16u16.to_le_bytes()); // bits per sample
    out.extend_from_slice(b"data");
    out.extend_from_slice(&data_len.to_le_bytes());
    out.extend_from_slice(pcm);
    Ok(out)
}

impl Gemini {
    fn speech_body(req: &SpeechRequest) -> Result<Value, LlmError> {
        req.validate()?;
        if req.speed.is_some_and(|s| (s - 1.0).abs() > f32::EPSILON) {
            return Err(LlmError::unsupported(
                "Gemini TTS has no speed setting; describe the pace in `instructions`",
            ));
        }
        if !matches!(req.format, None | Some(AudioFormat::Wav | AudioFormat::Pcm)) {
            return Err(LlmError::unsupported(
                "Gemini TTS returns PCM; ask for `Wav` or `Pcm`",
            ));
        }
        // Gemini TTS takes delivery directions as part of the prompt.
        let text = match &req.instructions {
            Some(i) if !i.trim().is_empty() => format!("{}: {}", i.trim(), req.text),
            _ => req.text.clone(),
        };
        Ok(json!({
            "contents": [{ "role": "user", "parts": [{ "text": text }] }],
            "generationConfig": {
                "responseModalities": ["AUDIO"],
                "speechConfig": {
                    "voiceConfig": { "prebuiltVoiceConfig": { "voiceName": req.voice } }
                }
            }
        }))
    }
}

/// Gemini TTS models (e.g. `gemini-2.5-flash-preview-tts`) through
/// `generateContent` with `responseModalities: [AUDIO]` and a prebuilt
/// voice (`"Kore"`, `"Puck"`, …). The model returns 16-bit mono PCM; it is
/// wrapped in a WAV header unless [`AudioFormat::Pcm`] is asked for. Other
/// formats and `speed` are not supported; `instructions` are prepended to
/// the text as a direction.
#[async_trait]
impl SpeechModel for Gemini {
    async fn synthesize(&self, request: &SpeechRequest) -> Result<SpeechResponse, LlmError> {
        let body = Self::speech_body(request)?;
        let transport = self.transport();
        let url = transport.model_url(self.model_id(), "generateContent")?;
        let bytes = transport.post_json(&url, &body).await?;
        let parts = inline_parts(&bytes, "audio/")
            .map_err(|e| e.map_message(|m| transport.credential.scrub(&m)))?;
        let mime = parts[0].0.clone();
        let mut pcm = Vec::new();
        for (i, (_, b64)) in parts.iter().enumerate() {
            pcm.extend_from_slice(&decode_b64(b64, &format!("audio part {i}"))?);
        }
        drop(parts);
        if request.format == Some(AudioFormat::Pcm) {
            return Ok(SpeechResponse::new(pcm, mime));
        }
        Ok(SpeechResponse::new(
            wav(&pcm, pcm_rate(&mime))?,
            "audio/wav",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_map_to_aspect_ratios() {
        assert_eq!(aspect_ratio("16:9"), Some("16:9"));
        assert_eq!(aspect_ratio("1024x1024"), Some("1:1"));
        assert_eq!(aspect_ratio("1536x1024"), Some("4:3"));
        assert_eq!(aspect_ratio("1024x1792"), Some("9:16"));
        assert_eq!(aspect_ratio("0x10"), None);
        assert_eq!(aspect_ratio("big"), None);
        assert_eq!(size_params(Some("2K")).unwrap(), (None, Some("2K".into())));
        assert_eq!(size_params(Some("auto")).unwrap(), (None, None));
        assert!(size_params(Some("huge")).is_err());
    }

    #[test]
    fn wav_header_is_well_formed() {
        let w = wav(&[1, 0, 2, 0], 24_000).unwrap();
        assert_eq!(w.len(), 48);
        assert_eq!(&w[..4], b"RIFF");
        assert_eq!(u32::from_le_bytes(w[4..8].try_into().unwrap()), 40);
        assert_eq!(&w[8..16], b"WAVEfmt ");
        assert_eq!(u32::from_le_bytes(w[24..28].try_into().unwrap()), 24_000);
        assert_eq!(u32::from_le_bytes(w[28..32].try_into().unwrap()), 48_000);
        assert_eq!(&w[36..40], b"data");
        assert_eq!(u32::from_le_bytes(w[40..44].try_into().unwrap()), 4);
        assert_eq!(&w[44..], &[1, 0, 2, 0]);
    }

    #[test]
    fn pcm_rate_parsing() {
        assert_eq!(pcm_rate("audio/L16;codec=pcm;rate=16000"), 16_000);
        assert_eq!(pcm_rate("audio/L16; rate=48000"), 48_000);
        assert_eq!(pcm_rate("audio/L16"), DEFAULT_PCM_RATE);
        assert_eq!(pcm_rate("audio/L16;rate=0"), DEFAULT_PCM_RATE);
        assert_eq!(pcm_rate("audio/L16;rate=99999999999"), DEFAULT_PCM_RATE);
    }

    #[test]
    fn speech_options_are_checked() {
        assert!(Gemini::speech_body(&SpeechRequest::new("hi", "Kore")).is_ok());
        let e = Gemini::speech_body(&SpeechRequest::new("hi", "Kore").speed(1.5)).unwrap_err();
        assert_eq!(e.kind(), LlmErrorKind::Unsupported);
        let e = Gemini::speech_body(&SpeechRequest::new("hi", "Kore").format(AudioFormat::Mp3))
            .unwrap_err();
        assert_eq!(e.kind(), LlmErrorKind::Unsupported);
        let body =
            Gemini::speech_body(&SpeechRequest::new("hi", "Kore").instructions("Whisper")).unwrap();
        assert_eq!(body["contents"][0]["parts"][0]["text"], "Whisper: hi");
    }

    #[test]
    fn predictions_decode_and_filter() {
        let png = rune_base64::encode(b"\x89PNG\r\n\x1a\nx");
        let body = format!(
            r#"{{"predictions":[{{"bytesBase64Encoded":"{png}","mimeType":"image/png","prompt":"better"}},{{"raiFilteredReason":"x"}}]}}"#
        );
        let out = decode_predictions(body.as_bytes(), None).unwrap();
        assert_eq!(out.images.len(), 1);
        assert_eq!(out.revised_prompt.as_deref(), Some("better"));
        let e = decode_predictions(br#"{"predictions":[{"raiFilteredReason":"unsafe"}]}"#, None)
            .unwrap_err();
        assert!(e.message().contains("filtered"));
        assert!(
            decode_predictions(br#"{"predictions":[{"bytesBase64Encoded":"%%"}]}"#, None).is_err()
        );
        assert!(decode_predictions(b"{}", None).is_err());
    }
}
